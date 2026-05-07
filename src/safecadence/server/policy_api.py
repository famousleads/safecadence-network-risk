"""
/api/policy/* REST surface.

Companion to platform_api.py. Same pattern: register() takes the
FastAPI app, get_current_user, require_writer dependencies.

Notable design choices:
  * All endpoints honor JWT auth from app.py
  * No execution endpoints — even "approve" is purely a state change
  * Generated configs are returned as text/plain or as a download
  * Cross-platform — uses pathlib + utf-8 throughout
"""

from __future__ import annotations

from typing import Optional

from safecadence.policy import (
    EnforcementMode, PolicyState, SecurityPolicy, Severity,
)
from safecadence.policy import audit, drift, exceptions, simulator, store, variants, webhooks
from safecadence.policy.attestation import build_attestation, attestation_markdown
from safecadence.policy.controls import all_controls
from safecadence.policy.cve_policies import policy_from_cves
from safecadence.policy.evaluator import evaluate
from safecadence.policy.exporters import export, list_exporters
from safecadence.policy.git_sync import sync as git_sync
from safecadence.policy.interpreter import interpret_offline
from safecadence.policy.remediation import generate_plan
from safecadence.policy.shadow_it import find_shadow_assets
from safecadence.policy.templates import list_templates, load_template
from safecadence.policy.testing import run_test_file, run_test_dict


def register(app, get_current_user, require_writer):
    from fastapi import Body, Depends, HTTPException, Query
    from fastapi.responses import PlainTextResponse, Response

    # ---- introspection -------------------------------------------- #
    @app.get("/api/policy/templates")
    def get_templates(_user=Depends(get_current_user)):
        return {"templates": list_templates()}

    @app.get("/api/policy/controls")
    def get_controls(_user=Depends(get_current_user)):
        return {"controls": [{
            "id": c.id, "description": c.description,
            "applies_to": c.applies_to, "severity": c.severity.value,
            "frameworks": c.frameworks,
        } for c in all_controls()]}

    @app.get("/api/policy/exporters")
    def get_exporters(_user=Depends(get_current_user)):
        return {"exporters": list_exporters()}

    # ---- IMPORTANT: every static `/api/policy/<verb>` route MUST be registered
    # ---- BEFORE `/api/policy/{pid}`, otherwise FastAPI will match the catch-all
    # ---- first and treat e.g. "audit" as a policy_id (returns 404).
    # ---- Block of static routes (must stay above the {pid} routes):

    # ---- v5.2: scheduler + ATT&CK + executive briefing (all static — register here)
    @app.post("/api/policy/schedule/run-once")
    def schedule_run_once(user=Depends(require_writer)):
        from safecadence.policy.scheduler import run_cycle
        return run_cycle(actor=user.username)

    @app.get("/api/policy/attack-coverage")
    def attack_coverage(_user=Depends(get_current_user)):
        from safecadence.policy.attack_mapping import coverage_report
        controls_in_use: set[str] = set()
        for meta in store.list_policies():
            p = store.get(meta["policy_id"])
            if p:
                for c in p.controls:
                    controls_in_use.add(c.control_id)
        return coverage_report(sorted(controls_in_use))

    # ---- v6.2: control suggestion + live preview (powers the Builder wizard)
    @app.get("/api/policy/suggest-controls")
    def suggest_controls_endpoint(asset_types: str = "", frameworks: str = "",
                                   strictness: str = "standard",
                                   _user=Depends(get_current_user)):
        from safecadence.policy.suggest import suggest_controls
        return suggest_controls(
            asset_types=[t for t in asset_types.split(",") if t],
            frameworks=[f for f in frameworks.split(",") if f],
            strictness=strictness,
        )

    @app.post("/api/policy/preview")
    def preview_policy_endpoint(body: dict = Body(...),
                                 _user=Depends(get_current_user)):
        from safecadence.policy.suggest import preview_impact
        from safecadence.server.platform_api import list_assets as _la
        return preview_impact(
            control_ids=body.get("control_ids") or [],
            parameters=body.get("parameters") or {},
            assets=_la(),
        )

    @app.get("/api/policy/{pid}/diff/{asset_id}")
    def per_device_diff_endpoint(pid: str, asset_id: str,
                                  _user=Depends(get_current_user)):
        """v6.5 — Per-device diff: what would change on this asset to
        satisfy this policy, in the device's native syntax."""
        from safecadence.policy.diff import compute_diff
        from safecadence.server.platform_api import get_asset
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        asset = get_asset(asset_id)
        if not asset:
            raise HTTPException(404, detail=f"asset not found: {asset_id}")
        return compute_diff(p, asset)

    # ---- v6.1: AI chat with fleet
    @app.post("/api/policy/chat")
    def chat_with_fleet(body: dict = Body(...), _user=Depends(get_current_user)):
        from safecadence.policy.chat_with_fleet import ask
        text = body.get("question") or body.get("text") or ""
        if not text.strip():
            raise HTTPException(400, detail="question is required")
        return ask(text, ai=bool(body.get("ai")),
                   provider=body.get("provider") or None,
                   api_key=body.get("api_key") or None,
                   model=body.get("model") or None)

    # ---- v6.1: CI/CD policy gate
    @app.get("/api/policy/ci-check")
    def ci_check(_user=Depends(get_current_user),
                 fail_on_regression: bool = True,
                 fail_on_critical: bool = False, fail_on_kev: bool = False):
        from safecadence.policy.ci_check import (
            decide_exit_code, evaluate_all, render_text,
        )
        s = evaluate_all()
        code, reasons = decide_exit_code(
            s, fail_on_regression=fail_on_regression,
            fail_on_critical=fail_on_critical, fail_on_kev=fail_on_kev,
        )
        s["exit_code"] = code
        s["reasons"] = reasons
        s["text"] = render_text(s, code, reasons)
        return s

    # ---- v6.1: top-N "fix the top risks" generator
    @app.get("/api/policy/top-risks")
    def top_risks_endpoint(top: int = 5, _user=Depends(get_current_user)):
        from safecadence.policy.top_risks import top_n_violations
        from safecadence.server.platform_api import list_assets as _la
        return top_n_violations(_la(), top_n=top)

    @app.get("/api/policy/fix-top-risks")
    def fix_top_risks_endpoint(top: int = 5, format: str = "ansible",
                                _user=Depends(get_current_user)):
        from safecadence.policy.top_risks import fix_top_risks_plan
        from safecadence.policy.exporters import export
        from safecadence.policy.schema import SecurityPolicy
        from safecadence.server.platform_api import list_assets as _la
        plan = fix_top_risks_plan(_la(), top_n=top)
        synthetic = SecurityPolicy(policy_id="(multi)",
                                    policy_name=f"Top {top} risk fixes")
        out = export(format, synthetic, plan)
        from fastapi.responses import PlainTextResponse, Response
        if isinstance(out, bytes):
            return Response(content=out, media_type="application/octet-stream")
        return PlainTextResponse(content=out)

    # ---- v6.0: Identity intelligence — cross-system drift detector
    @app.get("/api/policy/cross-system-drift")
    def cross_system_drift_endpoint(_user=Depends(get_current_user)):
        from safecadence.policy.cross_system_drift import detect_all
        from safecadence.server.platform_api import list_assets as _la
        return detect_all(_la())

    @app.get("/api/policy/executive-briefing")
    def exec_briefing(ai: bool = False, provider: str = "",
                      api_key: str = "", model: str = "",
                      _user=Depends(get_current_user)):
        from safecadence.policy.executive_briefing import build_briefing
        from safecadence.server.platform_api import list_assets as _la
        metas = store.list_policies()
        evals: dict = {}
        # Cache the asset list so we don't re-read disk per policy.
        assets = _la()
        for meta in metas:
            pid = meta["policy_id"]
            p = store.get(pid)
            if not p: continue
            ev = evaluate(p, assets)
            evals[pid] = {"pass": ev.pass_count, "fail": ev.fail_count,
                          "na": ev.na_count, "coverage_pct": ev.coverage_pct}
        return build_briefing(assets, metas, evals,
                              ai=ai, provider=provider or None,
                              api_key=api_key or None, model=model or None)

    @app.get("/api/policy/shadow")
    def shadow(_user=Depends(get_current_user)):
        return {"shadow_assets": find_shadow_assets(_load_assets())}

    @app.get("/api/policy/compliance")
    def compliance(_user=Depends(get_current_user)):
        assets = _load_assets()
        out = {"policies": []}
        for meta in store.list_policies():
            p = store.get(meta["policy_id"])
            if not p:
                continue
            ev = evaluate(p, assets)
            out["policies"].append({
                "policy_id": p.policy_id, "policy_name": p.policy_name,
                "state": p.state.value if hasattr(p.state, "value") else p.state,
                "pass": ev.pass_count, "fail": ev.fail_count,
                "na": ev.na_count, "coverage_pct": ev.coverage_pct,
            })
        return out

    @app.get("/api/policy/audit")
    def get_audit(limit: int = 100, _user=Depends(get_current_user)):
        return {"events": audit.read_recent(limit=limit)}

    @app.post("/api/policy/git/sync")
    def git_sync_endpoint(body: dict = Body(...), user=Depends(require_writer)):
        if not body.get("repo_url"):
            raise HTTPException(400, detail="repo_url required")
        return git_sync(body["repo_url"], branch=body.get("branch", "main"),
                        actor=user.username)

    @app.get("/api/policy/webhooks")
    def list_webhooks(_user=Depends(get_current_user)):
        return {"targets": webhooks.load_targets()}

    @app.post("/api/policy/cve/auto")
    def cve_auto(body: dict = Body(...), user=Depends(require_writer)):
        cves = body.get("cves") or []
        p = policy_from_cves(cves, name=body.get("name", ""),
                             target_asset_types=body.get("target_asset_types"))
        store.save(p, actor=user.username)
        return _serialize(p)

    @app.post("/api/policy/test")
    def run_test(body: dict = Body(...), _user=Depends(get_current_user)):
        return {"results": [run_test_dict(body)]}

    from fastapi.responses import HTMLResponse as _HTMLResponse
    @app.get("/api/policy/ui", response_class=_HTMLResponse)
    def policy_ui_page(user=Depends(get_current_user)):
        from safecadence.ui.policy_ui import render_policy_ui
        return _HTMLResponse(render_policy_ui(tenant=getattr(user, "tenant", "local")))

    # ---- AI / NL interpretation ----------------------------------- #
    @app.post("/api/policy/interpret")
    def interpret_nl(body: dict = Body(...), user=Depends(require_writer)):
        text = body.get("text") or ""
        if not text.strip():
            raise HTTPException(status_code=400, detail="text is required")
        from safecadence.policy.interpreter import interpret as _interpret_full
        p = _interpret_full(
            text, name=body.get("name") or "",
            ai=bool(body.get("ai")), provider=body.get("provider") or None,
            api_key=body.get("api_key") or None, model=body.get("model") or None,
        )
        if body.get("save"):
            store.save(p, actor=user.username)
        audit.log("interpret", actor=user.username, policy_id=p.policy_id,
                  detail={"chars": len(text), "controls": len(p.controls),
                          "source": p.source})
        return _serialize(p)

    # ---- CRUD ----------------------------------------------------- #
    @app.get("/api/policy/")
    def list_pol(_user=Depends(get_current_user)):
        return {"policies": store.list_policies()}

    @app.get("/api/policy/{pid}")
    def get_pol(pid: str, _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        return _serialize(p)

    @app.post("/api/policy/")
    def create_pol(body: dict = Body(...), user=Depends(require_writer)):
        # v9.53 — capability gate on top of role check.
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.WRITE_POLICY,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.WRITE_POLICY}")
        # Either from a template or a full policy spec
        tid = body.get("template_id")
        if tid:
            p = load_template(tid)
            if not p:
                raise HTTPException(400, detail=f"unknown template: {tid}")
        else:
            from safecadence.policy.templates import _to_policy
            p = _to_policy(body)
        if body.get("policy_name"):
            p.policy_name = body["policy_name"]
        if body.get("owner"):
            p.owner = body["owner"]
        store.save(p, actor=user.username)
        return _serialize(p)

    @app.put("/api/policy/{pid}")
    def update_pol(pid: str, body: dict = Body(...), user=Depends(require_writer)):
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.WRITE_POLICY,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.WRITE_POLICY}")
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        # Limited update — name, description, enforcement_mode, severity, scope
        if "policy_name" in body: p.policy_name = body["policy_name"]
        if "description" in body: p.description = body["description"]
        if "scope" in body: p.scope = body["scope"]
        if "enforcement_mode" in body:
            p.enforcement_mode = EnforcementMode(body["enforcement_mode"])
        if "severity" in body:
            p.severity = Severity(body["severity"])
        if "tags" in body: p.tags = body["tags"]
        p.version += 1
        store.save(p, actor=user.username)
        return _serialize(p)

    @app.delete("/api/policy/{pid}")
    def delete_pol(pid: str, user=Depends(require_writer)):
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.WRITE_POLICY,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.WRITE_POLICY}")
        ok = store.delete(pid, actor=user.username)
        if not ok:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        return {"ok": True}

    # ---- evaluation / simulation / drift -------------------------- #
    @app.post("/api/policy/{pid}/evaluate")
    def eval_pol(pid: str, _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        assets = _load_assets()
        ev = evaluate(p, assets)
        drift.persist_evaluation(ev)
        return _serialize_eval(ev)

    @app.post("/api/policy/{pid}/simulate")
    def sim_pol(pid: str, _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        return simulator.simulate(p, _load_assets())

    @app.get("/api/policy/{pid}/drift")
    def drift_pol(pid: str, _user=Depends(get_current_user)):
        return drift.detect_drift(pid)

    @app.get("/api/policy/{pid}/violations")
    def violations(pid: str, _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        ev = evaluate(p, _load_assets())
        return {"count": len(ev.violations),
                "violations": [v.serialize() for v in ev.violations]}

    @app.get("/api/policy/{pid}/remediation")
    def remediation(pid: str, vendor: Optional[str] = None,
                    _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        assets = _load_assets()
        ev = evaluate(p, assets)
        plan = generate_plan(p, ev, {(_aid(a)): a for a in assets},
                             vendor_target=vendor)
        return _serialize_plan(plan)

    @app.get("/api/policy/{pid}/export")
    def export_pol(pid: str, format: str = Query("markdown"),
                   vendor: Optional[str] = None,
                   _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        assets = _load_assets()
        ev = evaluate(p, assets)
        plan = generate_plan(p, ev, {_aid(a): a for a in assets},
                             vendor_target=vendor)
        try:
            data = export(format, p, plan)
        except KeyError as e:
            raise HTTPException(400, detail=str(e))
        if isinstance(data, bytes):
            return Response(content=data, media_type="application/octet-stream")
        return PlainTextResponse(content=data)

    # ---- workflow ------------------------------------------------- #
    @app.post("/api/policy/{pid}/transition")
    def trans(pid: str, body: dict = Body(...), user=Depends(require_writer)):
        from safecadence.policy.workflow import transition, WorkflowError
        try:
            p = transition(pid, PolicyState(body.get("target", "review")),
                           actor=user.username, approvers=body.get("approvers") or [])
        except WorkflowError as e:
            raise HTTPException(400, detail=str(e))
        return _serialize(p)

    # ---- exceptions ---------------------------------------------- #
    @app.get("/api/policy/{pid}/exceptions")
    def list_ex(pid: str, _user=Depends(get_current_user)):
        return {"exceptions": exceptions.list_exceptions(pid)}

    @app.post("/api/policy/{pid}/exceptions")
    def add_ex(pid: str, body: dict = Body(...), user=Depends(require_writer)):
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.WRITE_EXCEPTION,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.WRITE_EXCEPTION}")
        ex = exceptions.add_exception(
            pid, asset_id=body["asset_id"], control_id=body["control_id"],
            justification=body.get("justification", ""),
            approved_by=body.get("approved_by") or user.username,
            expires_at=body.get("expires_at", ""),
            actor=user.username,
        )
        return {"exception_id": ex.exception_id}

    @app.delete("/api/policy/{pid}/exceptions/{exception_id}")
    def revoke_ex(pid: str, exception_id: str, user=Depends(require_writer)):
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.WRITE_EXCEPTION,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.WRITE_EXCEPTION}")
        ok = exceptions.revoke_exception(pid, exception_id, actor=user.username)
        return {"ok": ok}

    # ---- variants ------------------------------------------------- #
    @app.post("/api/policy/{pid}/variants/{env}/{control_id}")
    def set_var(pid: str, env: str, control_id: str, body: dict = Body(...),
                user=Depends(require_writer)):
        p = variants.set_variant(pid, environment=env, control_id=control_id,
                                 parameters=body, actor=user.username)
        return _serialize(p)

    # ---- attestation --------------------------------------------- #
    @app.get("/api/policy/{pid}/gap-delta")
    def gap_delta(pid: str, _user=Depends(get_current_user)):
        """Compare the most recent two evaluations and surface regressions."""
        from safecadence.policy.drift import list_evaluations
        from safecadence.policy.executive_briefing import compliance_gap_delta
        history = list_evaluations(pid)
        if len(history) < 2:
            return {"policy_id": pid, "history_size": len(history),
                    "delta": None, "message": "need at least 2 evaluations"}
        history.sort(key=lambda h: h.get("evaluated_at", ""))
        return compliance_gap_delta(history[-2], history[-1])

    @app.get("/api/policy/{pid}/attestation")
    def attestation(pid: str, framework: str = "",
                    format: str = "json", _user=Depends(get_current_user)):
        p = store.get(pid)
        if not p:
            raise HTTPException(404, detail=f"policy not found: {pid}")
        att = build_attestation(p, _load_assets(), framework=framework)
        if format == "markdown":
            return PlainTextResponse(attestation_markdown(att))
        return att

    # NOTE: shadow / compliance / audit / git / webhooks / cve / test / ui are
    # registered ABOVE the /{pid} routes (see top of register()). Don't add
    # static /api/policy/<verb> routes down here — they'll be shadowed.

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _aid(a: dict) -> str:
    return (a.get("identity") or {}).get("asset_id", "")


def _load_assets() -> list[dict]:
    """Reuse the existing platform asset store from v4.0."""
    from safecadence.server.platform_api import list_assets
    return list_assets()


def _serialize(p: SecurityPolicy) -> dict:
    from safecadence.policy.store import _to_dict
    return _to_dict(p)


def _serialize_eval(ev) -> dict:
    return {
        "evaluation_id": ev.evaluation_id, "policy_id": ev.policy_id,
        "evaluated_at": ev.evaluated_at,
        "pass_count": ev.pass_count, "fail_count": ev.fail_count,
        "na_count": ev.na_count, "coverage_pct": ev.coverage_pct,
        "asset_results": ev.asset_results,
        "violations": [v.serialize() for v in ev.violations],
    }


def _serialize_plan(plan) -> dict:
    return {
        "plan_id": plan.plan_id, "policy_id": plan.policy_id,
        "generated_at": plan.generated_at, "summary": plan.summary,
        "steps": [{
            "asset_id": s.asset_id, "control_id": s.control_id,
            "vendor_target": s.vendor_target,
            "fix_commands": s.fix_commands, "rollback_commands": s.rollback_commands,
            "verify_commands": s.verify_commands, "notes": s.notes,
            "severity": s.severity.value if hasattr(s.severity, "value") else s.severity,
        } for s in plan.steps],
    }
