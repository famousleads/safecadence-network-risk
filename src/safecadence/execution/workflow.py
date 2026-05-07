"""Approval state machine — Draft → Review → Approve → Deploy.

This module owns every legal state transition for a CommandJob. The
REST API and CLI never poke ``job.status`` directly; they call
``submit()``, ``approve()``, ``reject()``, ``cancel()``,
``mark_running()``, ``mark_done()``, ``mark_failed()``, ``rollback()``.

The point: every transition writes an immutable audit row, computes
the new risk + lockout state with the latest commands, and refuses
illegal jumps (you cannot APPROVED → DRAFT, you cannot ROLLED_BACK →
RUNNING). That's how a privileged control plane stops surprising
people.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from safecadence.execution import store
from safecadence.execution.guardrails import preflight
from safecadence.execution.rbac import (
    Capability, Role, approvals_needed, can, role_can_approve,
)
from safecadence.execution.schema import (
    ApprovalRequest, CommandAuditLog, CommandExecution, CommandJob,
    JobStatus, RiskLevel, RollbackPlan,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(actor: str, action: str, *, job: CommandJob | None = None,
           detail: str = "", before: str = "", after: str = "",
           approval_id: str = "") -> None:
    store.write_audit(CommandAuditLog(
        actor=actor or "(unknown)",
        tenant=(job.tenant if job else "local"),
        action=action,
        job_id=(job.job_id if job else ""),
        risk=(job.risk.value if job else ""),
        detail=detail,
        before_state=before,
        after_state=after,
        approval_id=approval_id,
    ))


# --------------------------------------------------------------------------
# Authoring
# --------------------------------------------------------------------------

class WorkflowError(Exception):
    """Raised on illegal transitions or missing capabilities. Callers
    should turn into HTTP 403 / CLI exit 1."""


def create_job(job: CommandJob, *, actor: str, role: Role | str) -> CommandJob:
    """Save a brand-new DRAFT job. Authoring capability checks happen here."""
    cap_for_mode = {
        "read_only":   Capability.CREATE_READ_ONLY_JOB,
        "diagnostic":  Capability.CREATE_DIAGNOSTIC_JOB,
        "config":      Capability.CREATE_CONFIG_JOB,
        "remediation": Capability.CREATE_REMEDIATION_JOB,
        "verification": Capability.CREATE_DIAGNOSTIC_JOB,
        "rollback":    Capability.CREATE_REMEDIATION_JOB,
        "emergency":   Capability.CREATE_EMERGENCY_JOB,
    }.get(getattr(job.mode, "value", str(job.mode)),
          Capability.CREATE_CONFIG_JOB)
    if not can(role, cap_for_mode):
        raise WorkflowError(
            f"role '{role}' cannot create {job.mode} jobs"
        )
    job.status = JobStatus.DRAFT
    job.created_by = actor or job.created_by
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_created", job=job, after="draft")
    return job


def submit_for_review(job_id: str, *, actor: str) -> CommandJob:
    """DRAFT → REVIEW. Re-runs guardrails to set the real risk + block flags."""
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status != JobStatus.DRAFT:
        raise WorkflowError(
            f"only DRAFT jobs can be submitted (got {job.status})"
        )

    # Flatten commands across vendors and run preflight.
    flat: list[str] = []
    for cmds in (job.inline_commands or {}).values():
        flat.extend(cmds)
    pf = preflight(flat)
    job.risk = pf.risk
    if pf.blocked:
        job.status = JobStatus.BLOCKED
        store.save_job(job)
        _audit(actor, "job_blocked", job=job,
               detail="; ".join(pf.reasons)[:500],
               before="draft", after="blocked")
        raise WorkflowError("job blocked by guardrails: "
                             + "; ".join(pf.reasons))
    job.approvals_required = approvals_needed(job.risk.value)
    job.status = (JobStatus.APPROVED if job.approvals_required == 0
                  else JobStatus.REVIEW)
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_submitted", job=job,
           before="draft", after=job.status.value)
    return job


# --------------------------------------------------------------------------
# Approval
# --------------------------------------------------------------------------

def request_approval(job_id: str, *, requested_by: str) -> ApprovalRequest:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status != JobStatus.REVIEW:
        raise WorkflowError("can only request approval for REVIEW jobs")
    req = ApprovalRequest(job_id=job_id, requested_by=requested_by)
    store.save_approval(req)
    _audit(requested_by, "approval_requested", job=job, approval_id=req.approval_id)
    # v9.35 #4 — page the approver via the configured notifier (Slack /
    # Teams / PagerDuty / generic HMAC-signed webhook). Best-effort:
    # the workflow proceeds even if the notifier fails. Without this,
    # the approver had to poll /approvals to discover pending work.
    _notify_approval_requested(job, req, requested_by)
    return req


def _notify_approval_requested(job: CommandJob, req: ApprovalRequest,
                                  requested_by: str) -> None:
    """v9.35 #4 — fire-and-forget notification when a job enters REVIEW.

    Best-effort: failure here MUST NOT break the workflow. The audit
    log already records the approval-requested event so observability
    isn't lost when the webhook is down.
    """
    try:
        import os as _os
        # Legacy single-webhook env var is honoured as fallback so
        # operators who haven't migrated to the v9.44 registry still
        # see channel pings. Going forward, multi-provider webhooks
        # configured under /settings#webhooks fan out automatically.
        legacy_webhook = (_os.environ.get("SC_SLACK_WEBHOOK")
                            or _os.environ.get("SAFECADENCE_SLACK_WEBHOOK")
                            or _os.environ.get("SC_WEBHOOK_URL"))
        from safecadence.notifier.registry import dispatch_event
        target_count = (len(job.target_asset_ids) +
                          len(job.target_asset_group_ids))
        risk = job.risk.value if hasattr(job.risk, "value") else str(job.risk)
        approvals_required = getattr(job, "approvals_required", 1)
        title = f"Approval needed: {job.name or job.job_id}"
        summary = (
            f"{requested_by} requested approval for a {risk}-risk job "
            f"targeting {target_count} asset(s). Requires "
            f"{approvals_required} approver(s)."
        )
        sev = ("critical" if risk == "critical" else
                "high" if risk == "high" else
                "medium" if risk == "medium" else "info")
        dispatch_event(
            kind="approval_requested",
            title=title, summary=summary, severity=sev,
            invitees=list(getattr(job, "approvers_invited", []) or []),
            tenant=getattr(job, "tenant", "local"),
            extra={"job_id": job.job_id, "risk": risk,
                    "approval_id": req.approval_id,
                    "target_count": target_count},
            link=f"/approvals#{job.job_id}",
            requested_by=requested_by,
            channel_webhook=legacy_webhook,           # back-compat
            channel_signing_secret=_os.environ.get(
                "SC_WEBHOOK_SIGNING_SECRET"),
        )
    except Exception as exc:                                   # pragma: no cover
        # Audit log already has the approval-requested entry; not
        # being able to ping Slack is a degraded mode, not a failure.
        try:
            import sys
            sys.stderr.write(
                f"[workflow] approval notification failed: {exc}\n")
        except Exception:
            pass
    # v9.42 — email-DM each invited approver. v9.43 — go through the
    # generalized notification registry so the same fan-out machinery
    # serves every other event kind (findings, drift, watchlist, etc.).
    # This keeps approval invites always-on for invitees while letting
    # the operator opt out of the noisier categories per-channel.
    try:
        _notify_invited_approvers_via_email(job, req, requested_by)
    except Exception as exc:                                   # pragma: no cover
        try:
            import sys
            sys.stderr.write(
                f"[workflow] email-DM dispatch failed: {exc}\n")
        except Exception:
            pass


def _notify_invited_approvers_via_email(
    job: CommandJob, req: ApprovalRequest, requested_by: str,
) -> None:
    """v9.42 — Per-invitee email DM. Best-effort; never raises.

    Skipped when:
      - job.approvers_invited is empty (open queue, channel-only)
      - SMTP isn't configured (air-gap mode, channel-only)
      - the resolved invitee has no email on file

    Each DM is logged in the audit trail so SOX evidence shows who got
    pinged on which channel.
    """
    invited = list(getattr(job, "approvers_invited", []) or [])
    if not invited:
        return
    try:
        from safecadence.notifier.email_notifier import (
            is_configured, send_email, render_approval_email,
        )
        from safecadence.users.directory import lookup_invitees
    except Exception:                                          # pragma: no cover
        return
    if not is_configured():
        # Audit the skip so an admin can see why DMs didn't fire
        import json as _json
        _audit(requested_by, "email_dm_skipped",
                job=job, approval_id=req.approval_id,
                detail=_json.dumps({"reason": "smtp_not_configured",
                                       "invitees": invited}))
        return

    tenant = getattr(job, "tenant", "local") or "local"
    recs = lookup_invitees(invited, tenant=tenant)
    risk = job.risk.value if hasattr(job.risk, "value") else str(job.risk)
    target_count = (len(job.target_asset_ids) +
                      len(job.target_asset_group_ids))
    target_summary = (
        f"{len(job.target_asset_ids)} explicit asset(s)" if job.target_asset_ids
        else f"{len(job.target_asset_group_ids)} group(s)"
        if job.target_asset_group_ids
        else "all matching assets"
    )
    delivered: list[dict] = []
    for rec in recs:
        addr = rec.primary_email()
        if not addr:
            delivered.append({"username": rec.username,
                                "ok": False,
                                "reason": "no email on record"})
            continue
        subj, plain, html = render_approval_email(
            job_name=job.name or job.job_id,
            job_id=job.job_id,
            risk=risk,
            intent=(job.description or job.name or "")[:240],
            target_summary=target_summary,
            link=f"/approvals#{job.job_id}",
            requested_by=requested_by,
        )
        ok, err = send_email(to=addr, subject=subj,
                              body=plain, html_body=html)
        delivered.append({"username": rec.username,
                            "to": addr,
                            "ok": ok,
                            "reason": "" if ok else err})
    import json as _json
    _audit(requested_by, "email_dm_dispatched",
            job=job, approval_id=req.approval_id,
            detail=_json.dumps({"invitees": invited,
                                  "target_count": target_count,
                                  "delivered": delivered}))


def approve(job_id: str, *, approver: str, role: Role | str,
             note: str = "") -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status != JobStatus.REVIEW:
        raise WorkflowError(f"job is not in REVIEW (got {job.status})")
    if not role_can_approve(role, job.risk.value):
        raise WorkflowError(
            f"role '{role}' cannot approve {job.risk.value}-risk jobs"
        )
    if approver in job.approvers:
        raise WorkflowError("you have already approved this job")
    if approver == job.created_by:
        raise WorkflowError("authors cannot approve their own job")

    # Record the approval
    req = ApprovalRequest(job_id=job_id, requested_by="(self)",
                           decided_by=approver, decided_at=_now(),
                           decision="approved", note=note)
    store.save_approval(req)

    job.approvers.append(approver)
    if len(job.approvers) >= job.approvals_required:
        job.status = JobStatus.APPROVED
        # Generate the rollback plan at approval time
        plan = _generate_rollback_plan(job)
        store.save_rollback(plan)
        job.rollback_plan_id = plan.plan_id
    job.updated_at = _now()
    store.save_job(job)
    _audit(approver, "job_approved", job=job, approval_id=req.approval_id,
           before="review", after=job.status.value)
    return job


def reject(job_id: str, *, approver: str, reason: str = "") -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status not in (JobStatus.REVIEW, JobStatus.APPROVED):
        raise WorkflowError(f"cannot reject from {job.status}")
    job.status = JobStatus.REJECTED
    job.rejected_by = approver
    job.rejected_reason = reason
    job.updated_at = _now()
    store.save_job(job)
    req = ApprovalRequest(job_id=job_id, decided_by=approver,
                           decided_at=_now(), decision="rejected",
                           note=reason)
    store.save_approval(req)
    _audit(approver, "job_rejected", job=job, detail=reason,
           approval_id=req.approval_id, after="rejected")
    return job


def cancel(job_id: str, *, actor: str) -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status in (JobStatus.DONE, JobStatus.FAILED,
                       JobStatus.ROLLED_BACK, JobStatus.CANCELED):
        raise WorkflowError(f"cannot cancel job in terminal state {job.status}")
    job.status = JobStatus.CANCELED
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_canceled", job=job, after="canceled")
    return job


# --------------------------------------------------------------------------
# Execution lifecycle (mark_*) — driven by the executor module
# --------------------------------------------------------------------------

def mark_running(job_id: str, *, actor: str) -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if job.status != JobStatus.APPROVED:
        raise WorkflowError(
            f"only APPROVED jobs can start running (got {job.status})"
        )
    job.status = JobStatus.RUNNING
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_running", job=job, after="running")
    return job


def mark_done(job_id: str, *, actor: str) -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    job.status = JobStatus.DONE
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_done", job=job, after="done")
    return job


def mark_failed(job_id: str, *, actor: str, reason: str = "") -> CommandJob:
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    job.status = JobStatus.FAILED
    job.rejected_reason = reason
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_failed", job=job, detail=reason, after="failed")
    return job


def rollback(job_id: str, *, actor: str, role: Role | str) -> CommandJob:
    if not can(role, Capability.ROLLBACK_JOB):
        raise WorkflowError(f"role '{role}' cannot perform rollback")
    job = store.get_job(job_id)
    if not job:
        raise WorkflowError(f"job not found: {job_id}")
    if not job.rollback_plan_id:
        raise WorkflowError("no rollback plan for this job")
    job.status = JobStatus.ROLLED_BACK
    job.updated_at = _now()
    store.save_job(job)
    _audit(actor, "job_rolled_back", job=job, after="rolled_back")
    return job


# --------------------------------------------------------------------------
# Rollback plan generation
# --------------------------------------------------------------------------

# Per-vendor "undo" command patterns. When a command starts with a known
# verb we know how to invert, the rollback gets the inverted form.
# This is best-effort; an operator should review every rollback plan
# before relying on it for a production change.
_INVERT_PATTERNS: list[tuple[str, str]] = [
    # Generic prefix flip — handled specially in _generate_rollback_plan
    # so it preserves the rest of the line ("no foo bar" → "foo bar").
    ("no ", ""),

    # === Cisco IOS / IOS-XE / NX-OS ============================================
    ("shutdown", "no shutdown"),
    ("aaa new-model", "no aaa new-model"),
    ("aaa authentication", "no aaa authentication"),
    ("aaa authorization", "no aaa authorization"),
    ("aaa accounting", "no aaa accounting"),
    ("logging host ", "no logging host "),
    ("logging buffered", "no logging buffered"),
    ("ip http server", "no ip http server"),
    ("ip http secure-server", "no ip http secure-server"),
    ("snmp-server community", "no snmp-server community"),
    ("snmp-server host", "no snmp-server host"),
    ("snmp-server enable traps", "no snmp-server enable traps"),
    ("ntp server", "no ntp server"),
    ("ntp peer", "no ntp peer"),
    ("ip route ", "no ip route "),
    ("ipv6 route ", "no ipv6 route "),
    ("ip access-list", "no ip access-list"),
    ("access-list ", "no access-list "),
    ("ip nat inside source", "no ip nat inside source"),
    ("ip nat outside source", "no ip nat outside source"),
    ("ip dhcp pool", "no ip dhcp pool"),
    ("ip dhcp excluded-address", "no ip dhcp excluded-address"),
    ("router ospf", "no router ospf"),
    ("router bgp", "no router bgp"),
    ("router eigrp", "no router eigrp"),
    ("interface ", None),                  # unique — see __cmd_for_interface
    ("vlan ", "no vlan "),
    ("spanning-tree ", "no spanning-tree "),
    ("monitor session", "no monitor session"),
    ("transport input ssh", "transport input ssh telnet"),  # widen back
    ("transport input none", "transport input ssh"),
    ("line vty", "default line vty"),
    ("crypto isakmp", "no crypto isakmp"),
    ("crypto ipsec", "no crypto ipsec"),
    ("class-map", "no class-map"),
    ("policy-map", "no policy-map"),
    ("service-policy", "no service-policy"),
    ("login block-for", "no login block-for"),
    ("password ", "no password"),

    # === Arista EOS ===========================================================
    ("management api http-commands", "no management api http-commands"),
    ("management ssh", "no management ssh"),

    # === Juniper Junos (set/delete model) ====================================
    ("set ", "delete "),
    ("delete ", "set "),                   # symmetric

    # === Palo Alto / FortiGate (config-mode) ==================================
    ("set deviceconfig", "no set deviceconfig"),
    ("config system", "# REVIEW: invert FortiGate 'config system' block manually"),
    ("config firewall", "# REVIEW: invert FortiGate 'config firewall' block manually"),
]


def _generate_rollback_plan(job: CommandJob) -> RollbackPlan:
    """v9.35 #2 — invert each command in the job into an undo command,
    persisted alongside the job at approval time.

    Invert strategy:
      1. ``no <foo>``  → ``<foo>``                        (drop the negation)
      2. ``set <foo>`` → ``delete <foo>``                 (Junos-style)
      3. Known prefixes from ``_INVERT_PATTERNS``:
            * Static replacements (``shutdown`` → ``no shutdown``)
            * Negation prefixes — when the pattern's replacement
              already starts with ``no `` we PRESERVE the rest of
              the original line (e.g. ``ip route 10.0.0.0/24 1.1.1.1``
              → ``no ip route 10.0.0.0/24 1.1.1.1``).
            * ``interface <name>`` is special: an interface block
              shouldn't be rolled back as ``no interface eth0``
              (which deletes the interface). We emit a TODO marker
              so the operator reviews per-line edits manually.
      4. Comments (``#`` or ``!``) are dropped.
      5. Anything we can't invert becomes a ``# REVIEW`` line — the
         plan still surfaces, but the operator sees what needs
         hand-review.

    The plan is persisted reversed (last-in, first-out) so undo runs
    in the opposite order of the original job.
    """
    rollbacks: dict[str, list[str]] = {}
    for vendor, cmds in (job.inline_commands or {}).items():
        per: list[str] = []
        for c in cmds:
            cl = c.strip()
            if not cl or cl.startswith("#") or cl.startswith("!"):
                continue
            cl_low = cl.lower()
            inv: str | None = None
            # Special-case 1: ``no <whatever>`` → ``<whatever>``
            if cl_low.startswith("no "):
                inv = cl[3:].strip()
            # Special-case 2: interface block — don't auto-invert.
            elif cl_low.startswith("interface "):
                inv = (f"# REVIEW: do not auto-rollback interface "
                       f"block: {cl} — invert each line inside the "
                       f"block manually if needed")
            # Special-case 3: Junos set ↔ delete is symmetric (handled
            # by the pattern table below since both directions are listed).
            else:
                for needle, repl in _INVERT_PATTERNS:
                    if not cl_low.startswith(needle):
                        continue
                    # The "no " entry is handled above. Skip None replacements
                    # (interface placeholder) since interface is handled above.
                    if needle == "no " or repl is None:
                        continue
                    # If the replacement is a "no <prefix>" form of the
                    # needle, preserve the remainder of the line — most
                    # operationally correct (e.g. "ip route 10/8 1.1.1.1"
                    # → "no ip route 10/8 1.1.1.1").
                    repl_stripped = repl.rstrip()
                    needle_stripped = needle.rstrip()
                    if (repl_stripped.lower().startswith("no ")
                            and repl_stripped.endswith(needle_stripped)):
                        inv = repl + cl[len(needle):]
                    elif repl.lower().startswith("no "):
                        # e.g. needle="ip http server", repl="no ip http server"
                        # No remainder to preserve when the needle covers
                        # the whole line.
                        inv = repl
                    elif repl.startswith("# REVIEW"):
                        inv = f"{repl}: {cl}"
                    else:
                        inv = repl
                    break
            if inv is None:
                inv = f"# REVIEW: no automatic rollback for: {cl}"
            per.append(inv)
        # Reverse so we undo in opposite order
        rollbacks[vendor] = list(reversed(per))
    return RollbackPlan(job_id=job.job_id, asset_rollbacks=rollbacks)
