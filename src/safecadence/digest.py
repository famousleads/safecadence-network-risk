"""Daily / weekly summary email digest.

Combines the executive briefing + cross-system drift + recent execution
audit + license status into a single readable email an operator can
scan in 30 seconds. Sends via SMTP/STARTTLS or to stdout (for testing).

Used by:
  * `safecadence digest --once` from cron / systemd timer
  * a future v7.3 in-daemon scheduler

The digest is plain text + HTML multi-part. Plain text first so spam
filters and screen readers handle it nicely; HTML carries the visual
table.
"""

from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any


@dataclass
class DigestConfig:
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    from_addr: str = "safecadence@localhost"
    recipients: list[str] | None = None
    subject_prefix: str = "[SafeCadence]"

    @classmethod
    def from_env(cls) -> "DigestConfig":
        recips = os.environ.get("SC_DIGEST_RECIPIENTS", "")
        return cls(
            smtp_host=os.environ.get("SC_SMTP_HOST", ""),
            smtp_port=int(os.environ.get("SC_SMTP_PORT", "587")),
            smtp_user=os.environ.get("SC_SMTP_USER", ""),
            smtp_password=os.environ.get("SC_SMTP_PASSWORD", ""),
            smtp_use_tls=(os.environ.get("SC_SMTP_TLS", "1") != "0"),
            from_addr=os.environ.get("SC_DIGEST_FROM", "safecadence@localhost"),
            recipients=[r.strip() for r in recips.split(",") if r.strip()],
            subject_prefix=os.environ.get("SC_DIGEST_SUBJECT_PREFIX",
                                            "[SafeCadence]"),
        )


# --------------------------------------------------------------------------
# Content builder
# --------------------------------------------------------------------------

def build_digest() -> dict[str, Any]:
    """Pull the inputs from each subsystem. Returns a dict so we can
    render to text, HTML, or JSON without re-querying."""
    out: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        from safecadence.policy.executive_briefing import build_briefing_offline
        from safecadence.policy.evaluator import evaluate
        from safecadence.policy.store import list_policies, get as _g
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
        metas = list_policies()
        evals: dict[str, dict] = {}
        for m in metas:
            p = _g(m["policy_id"])
            if not p:
                continue
            ev = evaluate(p, assets)
            evals[p.policy_id] = {"pass": ev.pass_count, "fail": ev.fail_count,
                                   "na": ev.na_count,
                                   "coverage_pct": ev.coverage_pct}
        out["briefing"] = build_briefing_offline(assets, metas, evals)
    except Exception as e:                                  # pragma: no cover
        out["briefing_error"] = f"{type(e).__name__}: {e}"

    try:
        from safecadence.policy.cross_system_drift import detect_all
        from safecadence.server.platform_api import list_assets
        out["drift"] = detect_all(list_assets())
    except Exception:                                       # pragma: no cover
        out["drift"] = {"finding_count": 0, "by_severity": {}}

    try:
        from safecadence.execution import store as ex_store
        rows = ex_store.read_audit(limit=20)
        out["recent_audit"] = rows
        # Pending approvals (jobs in REVIEW)
        pending = [j for j in ex_store.list_jobs()
                   if (j.status if isinstance(j.status, str) else j.status.value) == "review"]
        out["pending_approvals"] = [
            {"job_id": j.job_id, "name": j.name, "risk": (j.risk if isinstance(j.risk, str) else j.risk.value),
             "approvers": list(j.approvers),
             "approvals_required": j.approvals_required}
            for j in pending
        ]
    except Exception:                                       # pragma: no cover
        out["recent_audit"] = []
        out["pending_approvals"] = []

    try:
        from safecadence.license import status as _lic
        from safecadence.server.platform_api import list_assets
        from dataclasses import asdict
        out["license"] = asdict(_lic(asset_count=len(list_assets())))
    except Exception:                                       # pragma: no cover
        out["license"] = {}
    return out


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_text(d: dict) -> str:
    lines: list[str] = []
    lines.append(f"SafeCadence digest — {d['generated_at']}")
    lines.append("=" * 60)
    b = d.get("briefing") or {}
    bs = b.get("asset_summary") or {}
    ps = b.get("policy_summary") or {}
    lines.append("")
    lines.append("FLEET")
    lines.append(f"  Assets:        {bs.get('asset_count', 0)}")
    lines.append(f"  Crown-jewels:  {bs.get('crown_jewels', 0)}")
    lines.append(f"  KEV CVEs:      {bs.get('kev_cves_total', 0)}")
    lines.append(f"  Critical CVEs: {bs.get('critical_cves_total', 0)}")
    lines.append("")
    lines.append("POLICY POSTURE")
    lines.append(f"  Active policies: {ps.get('policy_count', 0)}")
    lines.append(f"  Compliance:      {ps.get('overall_compliance_pct', 0)}%")
    lines.append(f"  Open failures:   {ps.get('total_failures', 0)}")
    drift = d.get("drift") or {}
    lines.append("")
    lines.append("CROSS-SYSTEM DRIFT")
    lines.append(f"  Total findings: {drift.get('finding_count', 0)} "
                  f"across {drift.get('detector_count', 0)} detectors")
    by_sev = drift.get("by_severity") or {}
    if by_sev:
        for sev, n in sorted(by_sev.items(),
                              key=lambda kv: -{'critical':4,'high':3,'medium':2,'low':1}.get(kv[0], 0)):
            lines.append(f"    {sev:<10} {n}")
    pending = d.get("pending_approvals") or []
    lines.append("")
    lines.append(f"PENDING APPROVALS: {len(pending)}")
    for p in pending[:10]:
        lines.append(f"  - {p['job_id']:<22} risk={p['risk']:<8} "
                      f"{len(p['approvers'])}/{p['approvals_required']} "
                      f"approvers · {p['name']}")
    audit = d.get("recent_audit") or []
    lines.append("")
    lines.append(f"RECENT EXECUTION AUDIT (last {len(audit)} events)")
    for r in audit[:10]:
        ts = (r.get('timestamp') or '')[:19]
        lines.append(f"  {ts}  {r.get('actor','?'):<12}  "
                      f"{r.get('action','?'):<22}  {(r.get('detail') or '')[:60]}")
    lic = d.get("license") or {}
    lines.append("")
    lines.append("LICENSE")
    lines.append(f"  Licensee:  {lic.get('licensee', 'unknown')}")
    lines.append(f"  Assets:    {lic.get('asset_count', 0)} of "
                  f"{lic.get('max_assets') or 'unlimited'}"
                  f"{' (OVER LIMIT)' if lic.get('over_limit') else ''}")
    lines.append(f"  Signature: {lic.get('signature_state', '?')}")
    return "\n".join(lines)


def render_html(d: dict) -> str:
    b = d.get("briefing") or {}
    bs = b.get("asset_summary") or {}
    ps = b.get("policy_summary") or {}
    drift = d.get("drift") or {}
    pending = d.get("pending_approvals") or []
    by_sev = drift.get("by_severity") or {}
    lic = d.get("license") or {}
    return f"""<html><body style="font:14px -apple-system,system-ui,sans-serif;color:#111;max-width:680px;margin:auto">
<h2 style="margin-bottom:4px">SafeCadence digest</h2>
<div style="color:#888;font-size:12px">{d['generated_at']}</div>
<table cellpadding="6" style="margin-top:18px;border-collapse:collapse;width:100%">
  <tr><td style="background:#f3f4f6;font-weight:bold">Fleet</td>
      <td>{bs.get('asset_count', 0)} assets · {bs.get('crown_jewels', 0)} crown-jewels</td></tr>
  <tr><td style="background:#f3f4f6;font-weight:bold">KEV / Critical CVEs</td>
      <td>{bs.get('kev_cves_total', 0)} KEV · {bs.get('critical_cves_total', 0)} critical</td></tr>
  <tr><td style="background:#f3f4f6;font-weight:bold">Policy compliance</td>
      <td>{ps.get('overall_compliance_pct', 0)}% across {ps.get('policy_count', 0)} policies
          ({ps.get('total_failures', 0)} failures)</td></tr>
  <tr><td style="background:#f3f4f6;font-weight:bold">Cross-system drift</td>
      <td>{drift.get('finding_count', 0)} findings across {drift.get('detector_count', 0)} detectors
          {('· '+', '.join(f"{k}: {v}" for k,v in by_sev.items())) if by_sev else ''}</td></tr>
  <tr><td style="background:#f3f4f6;font-weight:bold">Pending approvals</td>
      <td>{len(pending)} awaiting review</td></tr>
  <tr><td style="background:#f3f4f6;font-weight:bold">License</td>
      <td>{lic.get('licensee','?')} · {lic.get('asset_count',0)}/{lic.get('max_assets') or 'unlimited'}
          {('· OVER LIMIT' if lic.get('over_limit') else '')}</td></tr>
</table>
{'<h3 style="margin-top:24px">Pending approvals</h3><ul>' + ''.join(f'<li><code>{p["job_id"]}</code> — {p["name"]} (risk: <strong>{p["risk"]}</strong>)</li>' for p in pending[:10]) + '</ul>' if pending else ''}
<div style="color:#888;font-size:12px;margin-top:24px">
  Generated locally by SafeCadence — no telemetry leaves your environment.
</div>
</body></html>"""


# --------------------------------------------------------------------------
# Send
# --------------------------------------------------------------------------

def send(cfg: DigestConfig | None = None, *,
          digest: dict | None = None,
          subject: str = "Daily security digest") -> dict:
    cfg = cfg or DigestConfig.from_env()
    digest = digest or build_digest()
    if not cfg.recipients:
        return {"sent": False,
                "reason": "no recipients (set SC_DIGEST_RECIPIENTS=a@b,c@d)"}
    if not cfg.smtp_host:
        return {"sent": False,
                "reason": "no SC_SMTP_HOST configured"}
    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.recipients)
    msg["Subject"] = f"{cfg.subject_prefix} {subject}"
    msg.set_content(render_text(digest))
    msg.add_alternative(render_html(digest), subtype="html")
    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as s:
            s.ehlo()
            if cfg.smtp_use_tls:
                s.starttls()
                s.ehlo()
            if cfg.smtp_user:
                s.login(cfg.smtp_user, cfg.smtp_password)
            s.send_message(msg)
        # v9.45 — fan out via dispatch_event so the same digest also
        # reaches Slack/Teams/etc. for users who opted in. The SMTP
        # send above is the original DM channel; this is the team
        # echo. Best-effort — never fail digest send because of it.
        try:
            from safecadence.notifier.registry import dispatch_event
            b = (digest.get("briefing") or {}) if isinstance(digest, dict) else {}
            bs = b.get("asset_summary") or {}
            ps = b.get("policy_summary") or {}
            dr = (digest.get("drift") or {}) if isinstance(digest, dict) else {}
            pending = digest.get("pending_approvals") or []
            summary = (
                f"{bs.get('asset_count', 0)} assets · "
                f"{ps.get('overall_compliance_pct', 0)}% compliant · "
                f"{dr.get('finding_count', 0)} drift findings · "
                f"{len(pending)} pending approvals"
            )
            dispatch_event(
                kind="digest_daily",
                title=subject,
                summary=summary,
                severity="info",
                extra={"recipients_email": cfg.recipients,
                        "asset_count": bs.get("asset_count", 0),
                        "compliance_pct": ps.get("overall_compliance_pct", 0),
                        "drift_findings": dr.get("finding_count", 0),
                        "pending_approvals": len(pending)},
                link="/digest",
                requested_by="digest",
            )
        except Exception:           # pragma: no cover
            pass
        return {"sent": True, "recipients": cfg.recipients}
    except Exception as e:
        return {"sent": False, "reason": f"{type(e).__name__}: {e}"}
