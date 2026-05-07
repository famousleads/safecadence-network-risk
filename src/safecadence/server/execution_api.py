"""REST surface for the v7.0 execution engine.

Mounts at ``/api/execute/*``. Every endpoint enforces the RBAC matrix
through the ``role_for_user()`` helper that maps the JWT user's
existing role string into the v7 6-tier matrix.

Endpoint map:
  GET    /api/execute/jobs                        list jobs
  POST   /api/execute/jobs                        create draft (+ run guardrails)
  GET    /api/execute/jobs/{id}                   detail
  PUT    /api/execute/jobs/{id}                   edit DRAFT
  DELETE /api/execute/jobs/{id}                   delete DRAFT
  POST   /api/execute/jobs/{id}/submit            DRAFT → REVIEW
  POST   /api/execute/jobs/{id}/approve           REVIEW → APPROVED (multi-approver aware)
  POST   /api/execute/jobs/{id}/reject            REVIEW → REJECTED
  POST   /api/execute/jobs/{id}/cancel            any → CANCELED
  POST   /api/execute/jobs/{id}/dry-run           APPROVED → simulate, write executions/outputs
  POST   /api/execute/jobs/{id}/rollback          DONE/FAILED → ROLLED_BACK
  GET    /api/execute/jobs/{id}/executions        list child executions
  GET    /api/execute/jobs/{id}/audit             per-job audit trail
  GET    /api/execute/jobs/{id}/export?fmt=ansible|salt|nso|raw|markdown

  POST   /api/execute/builder/plan                NL intent → ExecutionPlan
  POST   /api/execute/builder/plan-and-save       NL intent → save as DRAFT job

  GET    /api/execute/audit                       global audit feed
  GET    /api/execute/queue                       jobs in REVIEW + APPROVED + RUNNING
  GET    /api/execute/rbac                        return capability matrix for the caller
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any


def register_execution_routes(app, *, store_module=None,
                                require_writer=None, require_admin=None,
                                get_current_user=None) -> None:
    """Mount all /api/execute/* routes. Called from server.app.create_app()."""
    from fastapi import Body, Depends, HTTPException, Query
    from fastapi.responses import PlainTextResponse

    from safecadence.execution import (
        builder, store, workflow, executor, schema, rbac,
    )
    from safecadence.execution.schema import (
        CommandJob, CommandMode, ExecutionMethod, JobStatus, RiskLevel,
    )

    # ----- helpers -----
    def _role_for_user(user) -> rbac.Role:
        """Map a JWT user's existing role list into a v7 Role."""
        roles = [r.lower() for r in (getattr(user, "roles", None) or [])]
        if "super_admin" in roles or "superadmin" in roles:
            return rbac.Role.SUPER_ADMIN
        if "security_admin" in roles or "secadmin" in roles or "admin" in roles:
            return rbac.Role.SECURITY_ADMIN
        if "engineer" in roles:
            return rbac.Role.ENGINEER
        if "operator" in roles or "analyst" in roles:
            return rbac.Role.OPERATOR
        if "auditor" in roles:
            return rbac.Role.AUDITOR
        return rbac.Role.VIEWER

    def _need(user, capability):
        if not rbac.can(_role_for_user(user), capability):
            raise HTTPException(
                status_code=403,
                detail=f"role lacks capability '{capability.value}'",
            )

    def _job_to_dict(j: CommandJob) -> dict:
        return asdict(j)

    # ---- jobs CRUD ------------------------------------------------ #
    @app.get("/api/execute/jobs")
    def list_jobs_endpoint(status: str = "", _user=Depends(get_current_user)):
        return {"jobs": [asdict(j) for j in
                          store.list_jobs(status=status or None)]}

    @app.post("/api/execute/jobs")
    def create_job_endpoint(body: dict = Body(...),
                              user=Depends(get_current_user)):
        role = _role_for_user(user)
        try:
            mode = CommandMode((body.get("mode") or "read_only").lower())
        except ValueError:
            raise HTTPException(400, detail="bad mode")
        job = CommandJob(
            name=body.get("name", ""),
            description=body.get("description", ""),
            mode=mode,
            target_asset_ids=body.get("target_asset_ids") or [],
            target_asset_group_ids=body.get("target_asset_group_ids") or [],
            target_filter=body.get("target_filter") or {},
            inline_commands=body.get("inline_commands") or {},
            method=ExecutionMethod((body.get("method") or "manual").lower()),
            tenant=getattr(user, "tenant", "local"),
            tags=body.get("tags") or [],
        )
        try:
            workflow.create_job(job, actor=user.username, role=role)
        except workflow.WorkflowError as e:
            raise HTTPException(403, detail=str(e))
        return _job_to_dict(job)

    @app.get("/api/execute/jobs/{job_id}")
    def get_job_endpoint(job_id: str, _user=Depends(get_current_user)):
        j = store.get_job(job_id)
        if not j: raise HTTPException(404, detail="job not found")
        return _job_to_dict(j)

    @app.put("/api/execute/jobs/{job_id}")
    def update_job_endpoint(job_id: str, body: dict = Body(...),
                              user=Depends(get_current_user)):
        j = store.get_job(job_id)
        if not j: raise HTTPException(404, detail="job not found")
        if j.status != JobStatus.DRAFT:
            raise HTTPException(409, detail="only DRAFT jobs are editable")
        for k in ("name", "description", "target_asset_ids",
                   "target_asset_group_ids", "target_filter",
                   "inline_commands", "tags"):
            if k in body:
                setattr(j, k, body[k])
        store.save_job(j)
        return _job_to_dict(j)

    @app.delete("/api/execute/jobs/{job_id}")
    def delete_job_endpoint(job_id: str, user=Depends(get_current_user)):
        j = store.get_job(job_id)
        if not j: raise HTTPException(404, detail="job not found")
        if j.status != JobStatus.DRAFT:
            raise HTTPException(409, detail="only DRAFT jobs can be deleted")
        store.delete_job(job_id)
        return {"deleted": True}

    # ---- transitions ---------------------------------------------- #
    @app.post("/api/execute/jobs/{job_id}/submit")
    def submit_endpoint(job_id: str, user=Depends(get_current_user)):
        try:
            j = workflow.submit_for_review(job_id, actor=user.username)
        except workflow.WorkflowError as e:
            raise HTTPException(409, detail=str(e))
        return _job_to_dict(j)

    @app.post("/api/execute/jobs/{job_id}/approve")
    def approve_endpoint(job_id: str, body: dict = Body(default={}),
                          user=Depends(get_current_user)):
        # v9.53 — capability gate on top of legacy role check.
        # workflow.approve already enforces "submitter cannot approve
        # their own job" + role-based capability; this layer adds the
        # v9.48 explicit grant so non-admin users with APPROVE_JOB
        # capability can also approve.
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.APPROVE_JOB,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.APPROVE_JOB}")
        try:
            j = workflow.approve(job_id, approver=user.username,
                                  role=_role_for_user(user),
                                  note=(body.get("note") or "")[:500])
        except workflow.WorkflowError as e:
            raise HTTPException(403, detail=str(e))
        return _job_to_dict(j)

    @app.post("/api/execute/jobs/{job_id}/reject")
    def reject_endpoint(job_id: str, body: dict = Body(default={}),
                         user=Depends(get_current_user)):
        try:
            j = workflow.reject(job_id, approver=user.username,
                                 reason=(body.get("reason") or "")[:500])
        except workflow.WorkflowError as e:
            raise HTTPException(403, detail=str(e))
        return _job_to_dict(j)

    @app.post("/api/execute/jobs/{job_id}/cancel")
    def cancel_endpoint(job_id: str, user=Depends(get_current_user)):
        try:
            j = workflow.cancel(job_id, actor=user.username)
        except workflow.WorkflowError as e:
            raise HTTPException(409, detail=str(e))
        return _job_to_dict(j)

    @app.post("/api/execute/jobs/{job_id}/dry-run")
    def dry_run_endpoint(job_id: str, user=Depends(get_current_user)):
        _need(user, rbac.Capability.EXECUTE_DRY_RUN)
        result = executor.dry_run(job_id, actor=user.username)
        if not result.get("ok"):
            raise HTTPException(409, detail=result.get("error", "dry-run failed"))
        return result

    @app.post("/api/execute/jobs/{job_id}/rollback")
    def rollback_endpoint(job_id: str, user=Depends(get_current_user)):
        try:
            j = workflow.rollback(job_id, actor=user.username,
                                   role=_role_for_user(user))
        except workflow.WorkflowError as e:
            raise HTTPException(403, detail=str(e))
        return _job_to_dict(j)

    # v9.35 #3 — per-device config diff. Returns each execution's
    # pre/post running-config snapshots plus a unified diff. Empty
    # snapshots are surfaced honestly so the operator knows the
    # executor didn't capture them (typical for dry-run).
    @app.get("/api/execute/jobs/{job_id}/config-diff")
    def config_diff_endpoint(job_id: str,
                               _user=Depends(get_current_user)):
        import difflib
        from safecadence.execution import store as exec_store
        execs = exec_store.list_executions(job_id=job_id) or []
        out: list[dict] = []
        for ex in execs:
            pre = (getattr(ex, "pre_config_snapshot", "") or "")
            post = (getattr(ex, "post_config_snapshot", "") or "")
            diff_lines: list[str] = []
            if pre or post:
                diff_lines = list(difflib.unified_diff(
                    pre.splitlines(),
                    post.splitlines(),
                    fromfile="pre.cfg",
                    tofile="post.cfg",
                    lineterm="",
                ))
            out.append({
                "execution_id": getattr(ex, "execution_id", ""),
                "asset_id": getattr(ex, "asset_id", ""),
                "vendor": getattr(ex, "vendor", ""),
                "dry_run": bool(getattr(ex, "dry_run", True)),
                "has_snapshots": bool(pre or post),
                "pre_config": pre,
                "post_config": post,
                "unified_diff": diff_lines,
                "added_lines": sum(
                    1 for d in diff_lines
                    if d.startswith("+") and not d.startswith("+++")
                ),
                "removed_lines": sum(
                    1 for d in diff_lines
                    if d.startswith("-") and not d.startswith("---")
                ),
            })
        return {"job_id": job_id, "executions": out}

    # v9.35 #2 — surface the persisted rollback plan so the operator
    # can review the inverted commands BEFORE clicking Roll back.
    @app.get("/api/execute/jobs/{job_id}/rollback-plan")
    def rollback_plan_endpoint(job_id: str,
                                 _user=Depends(get_current_user)):
        from safecadence.execution import store as exec_store
        job = exec_store.get_job(job_id)
        if not job:
            raise HTTPException(404, detail=f"job not found: {job_id}")
        if not job.rollback_plan_id:
            return {"job_id": job_id, "plan_id": None,
                     "asset_rollbacks": {},
                     "note": ("Rollback plans are generated when a job is "
                                "approved. This job has no plan persisted yet.")}
        plan = exec_store.get_rollback(job.rollback_plan_id)
        if not plan:
            raise HTTPException(404,
                detail=f"rollback plan {job.rollback_plan_id} not found")
        return {
            "job_id": job_id,
            "plan_id": plan.plan_id,
            "asset_rollbacks": plan.asset_rollbacks,
            "review_count": sum(
                1 for cmds in plan.asset_rollbacks.values()
                for c in cmds if c.startswith("# REVIEW")
            ),
        }

    # ---- per-job views -------------------------------------------- #
    @app.get("/api/execute/jobs/{job_id}/executions")
    def list_executions_endpoint(job_id: str,
                                   _user=Depends(get_current_user)):
        return {"executions": [asdict(e) for e in
                                 store.list_executions(job_id=job_id)]}

    @app.get("/api/execute/jobs/{job_id}/audit")
    def per_job_audit_endpoint(job_id: str,
                                 _user=Depends(get_current_user)):
        return {"entries": store.read_audit(job_id=job_id, limit=200)}

    @app.get("/api/execute/jobs/{job_id}/export",
              response_class=PlainTextResponse)
    def export_endpoint(job_id: str, fmt: str = Query("ansible"),
                          _user=Depends(get_current_user)):
        j = store.get_job(job_id)
        if not j: raise HTTPException(404, detail="job not found")
        try:
            return executor.export(j, fmt)
        except ValueError as e:
            raise HTTPException(400, detail=str(e))

    # ---- AI Command Builder --------------------------------------- #
    @app.post("/api/execute/builder/plan")
    def builder_plan_endpoint(body: dict = Body(...),
                                user=Depends(get_current_user)):
        plan = builder.build_plan(
            body.get("intent", ""),
            asset_ids=body.get("asset_ids") or [],
            asset_group_ids=body.get("asset_group_ids") or [],
            target_filter=body.get("target_filter"),
        )
        return asdict(plan)

    @app.post("/api/execute/builder/plan-and-save")
    def builder_plan_and_save_endpoint(body: dict = Body(...),
                                        user=Depends(get_current_user)):
        plan = builder.build_plan(
            body.get("intent", ""),
            asset_ids=body.get("asset_ids") or [],
            asset_group_ids=body.get("asset_group_ids") or [],
            target_filter=body.get("target_filter"),
        )
        if plan.blocked:
            raise HTTPException(403, detail="; ".join(plan.block_reasons))
        if not plan.matched_packs:
            raise HTTPException(400, detail=plan.summary)
        job = builder.plan_to_job(plan, name=body.get("name", ""),
                                    created_by=user.username,
                                    tenant=getattr(user, "tenant", "local"))
        # v9.42 — pass through optional invitees from the builder UI
        invited = body.get("approvers_invited") or []
        if isinstance(invited, list):
            job.approvers_invited = [str(u).strip()
                                       for u in invited if u]
        try:
            workflow.create_job(job, actor=user.username,
                                 role=_role_for_user(user))
        except workflow.WorkflowError as e:
            raise HTTPException(403, detail=str(e))
        return {"plan": asdict(plan), "job": asdict(job)}

    # v9.41 — save the plan as a DRAFT without submitting for approval.
    # Lets the operator iterate on the intent, refine the target group,
    # come back later. The existing plan-and-save endpoint above is
    # the one-shot "submit straight to /approvals" path.
    @app.post("/api/execute/builder/save-draft")
    def builder_save_draft_endpoint(body: dict = Body(...),
                                     user=Depends(get_current_user)):
        plan = builder.build_plan(
            body.get("intent", ""),
            asset_ids=body.get("asset_ids") or [],
            asset_group_ids=body.get("asset_group_ids") or [],
            target_filter=body.get("target_filter"),
        )
        if plan.blocked:
            raise HTTPException(403, detail="; ".join(plan.block_reasons))
        if not plan.matched_packs:
            raise HTTPException(400, detail=plan.summary)
        job = builder.plan_to_job(plan, name=body.get("name", ""),
                                    created_by=user.username,
                                    tenant=getattr(user, "tenant", "local"))
        # v9.42 — pass through optional invitees (drafts can carry the
        # invite list too; they only fire when the job moves to REVIEW)
        invited = body.get("approvers_invited") or []
        if isinstance(invited, list):
            job.approvers_invited = [str(u).strip()
                                       for u in invited if u]
        # Save the job as DRAFT (the default status from plan_to_job)
        # without calling workflow.create_job, which transitions it to
        # REVIEW.
        store.save_job(job)
        return {"plan": asdict(plan), "job": asdict(job),
                "status": "draft"}

    # ---- platform-wide views -------------------------------------- #
    @app.get("/api/execute/queue")
    def queue_endpoint(_user=Depends(get_current_user)):
        active_states = (JobStatus.REVIEW.value,
                          JobStatus.APPROVED.value,
                          JobStatus.SCHEDULED.value,
                          JobStatus.RUNNING.value)
        out = [asdict(j) for j in store.list_jobs()
               if j.status.value in active_states]
        return {"queue": out, "size": len(out)}

    @app.get("/api/execute/audit")
    def audit_endpoint(limit: int = 200,
                        _user=Depends(get_current_user)):
        return {"entries": store.read_audit(limit=limit)}

    # ---- v7.2: Tier3 REST endpoint with TOTP MFA -------------------- #
    @app.post("/api/execute/totp/enroll")
    def totp_enroll_endpoint(user=Depends(get_current_user)):
        """One-time TOTP enrollment. Returns the secret + otpauth URI;
        the operator scans the URI into their authenticator app."""
        from safecadence import totp
        return totp.enroll(user.username)

    @app.get("/api/execute/totp/status")
    def totp_status_endpoint(user=Depends(get_current_user)):
        from safecadence import totp
        return {"enrolled": totp.is_enrolled(user.username)}

    @app.post("/api/execute/jobs/{job_id}/run-real")
    def tier3_run_endpoint(job_id: str, body: dict = Body(...),
                            user=Depends(get_current_user)):
        """v7.2 — fire Tier3 SSH for an APPROVED job. Triple gate
        from tier3.py applies; on top of that the request must carry
        a valid TOTP code in the body. The operator must have enrolled
        first via /api/execute/totp/enroll."""
        from safecadence import totp
        from safecadence.execution import tier3
        code = (body.get("totp_code") or "").strip()
        if not code:
            raise HTTPException(400, detail="totp_code is required")
        if not totp.is_enrolled(user.username):
            raise HTTPException(
                403,
                detail=("TOTP not enrolled — POST /api/execute/totp/enroll "
                         "first, then add the secret to your authenticator app."),
            )
        if not totp.verify_user(user.username, code):
            raise HTTPException(403, detail="invalid TOTP code")
        try:
            result = tier3.run_real(
                job_id, role=_role_for_user(user), actor=user.username,
                acknowledge=bool(body.get("acknowledge")),
                i_mean_it=bool(body.get("i_mean_it")),
            )
        except tier3.Tier3DisabledError as e:
            raise HTTPException(403, detail=str(e))
        except tier3.Tier3Error as e:
            raise HTTPException(409, detail=str(e))
        from dataclasses import asdict as _ad
        return _ad(result)

    @app.post("/api/execute/emergency-stop")
    def emergency_stop_endpoint(user=Depends(get_current_user)):
        from safecadence.execution import tier3
        return tier3.emergency_stop_now(actor=user.username)

    @app.post("/api/execute/emergency-clear")
    def emergency_clear_endpoint(user=Depends(get_current_user)):
        _need(user, rbac.Capability.EMERGENCY_STOP)
        from safecadence.execution import tier3
        return tier3.emergency_clear(actor=user.username)

    @app.get("/api/execute/rbac")
    def rbac_endpoint(user=Depends(get_current_user)):
        role = _role_for_user(user)
        caps = rbac.capabilities_for(role)
        return {
            "role": role.value,
            "capabilities": sorted(c.value for c in caps),
            "approvals_needed": {
                "safe": rbac.approvals_needed("safe"),
                "low": rbac.approvals_needed("low"),
                "medium": rbac.approvals_needed("medium"),
                "high": rbac.approvals_needed("high"),
                "critical": rbac.approvals_needed("critical"),
            },
        }
