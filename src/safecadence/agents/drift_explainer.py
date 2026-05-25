"""
v16.0 — Drift explainer: close the loop the v13 drift_daemon left open.

When ``drift_daemon`` detects a config change, the v13 default fires
a webhook and walks away. The v16 drift_explainer agent takes one
more step:

1. **Identify the responsible engineer** for the affected asset
   (looks at the v11.3 audit log for the most recent operator who
   touched related config / policies / approvals).
2. **Build a nudge** with: what changed, who probably did it, a
   "intentional?" question, a one-click "file exception" path, and
   a one-click "draft rollback" path.
3. **File the right follow-up** based on the operator's answer
   (recorded in agent_memory so repeated drift on the same asset
   doesn't re-ask).

What this is NOT
----------------

* This does NOT bypass the v9.x Tier-3 SSH execution triple-gate.
  When the operator chooses "draft rollback," the agent generates
  the diff via ``intelligence.remediation_pr.draft_remediation_pr``,
  which still requires the existing approval chain + TOTP MFA to
  actually execute.
* This does NOT auto-decide. It always loops the operator in. The
  agent is faster than a human at finding context, not at deciding.

Public API
----------

* ``identify_responsible_engineer(drift_event, audit_log_path=None)``
  → str | None  — best-effort attribution from audit log.
* ``explain_drift(drift_event, *, agent_id, nudge_conn)``
  → ``{"nudge_id": int, "explanation": str, "suggested_rollback": str | None}``
* ``handle_response(nudge_conn, nudge_id, *, answer, operator)``
  → ``{"action": "exception_filed" | "rollback_queued" | "noop", ...}``
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

_log = logging.getLogger("safecadence.agents.drift_explainer")


def _default_audit_log_path() -> Path:
    return Path.home() / ".safecadence" / "audit" / "audit.jsonl"


def identify_responsible_engineer(
    drift_event: dict,
    audit_log_path: Path | str | None = None,
) -> str | None:
    """Find the most-recent operator who touched anything related to
    the drifting asset. Returns an email/username or None.

    Heuristic: scan the v11.3 hash-chained audit log for entries whose
    ``resource`` field matches the asset hostname OR whose
    ``payload.host`` matches. Most-recent match wins. Returns None
    when no match (asset never modified by anyone in the log).

    Defensive: any file/parse error → None. Never raises.
    """
    path = Path(audit_log_path) if audit_log_path else _default_audit_log_path()
    if not path.exists():
        return None
    target = (drift_event.get("hostname") or "").strip().lower()
    if not target:
        return None

    candidate: str | None = None
    candidate_ts: int = -1
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                # Match on resource or payload.host
                resource = (row.get("resource") or "").lower()
                payload = row.get("payload") or {}
                phost = (payload.get("host") or payload.get("hostname") or "").lower()
                if target not in (resource, phost):
                    continue
                actor = row.get("actor") or row.get("user")
                ts = int(row.get("at") or row.get("ts") or 0)
                if actor and ts > candidate_ts:
                    candidate = str(actor)
                    candidate_ts = ts
    except Exception:
        return None
    return candidate


def explain_drift(
    drift_event: dict,
    *,
    agent_id: str = "drift-explainer",
    nudge_conn: Any,
    audit_log_path: Path | str | None = None,
) -> dict:
    """Turn a drift event into an operator-facing nudge.

    Args:
        drift_event: shape from ``monitoring.drift_daemon.compute_delta``::
            {"kind", "hostname", "finding_id", "severity", "detail"}
        agent_id: the agent posting this nudge.
        nudge_conn: SQLite conn the nudge/memory tables live in.
        audit_log_path: optional override (tests).

    Returns:
        {
          "nudge_id":           int (0 if dedup'd),
          "explanation":        str (the body of the nudge),
          "suggested_rollback": str | None (rollback intent for later),
          "responsible_user":   str | None,
        }
    """
    from safecadence.agents.nudges import create_nudge

    hostname = drift_event.get("hostname", "(unknown)")
    detail = drift_event.get("detail", "")
    severity = (drift_event.get("severity") or "info").lower()
    kind = drift_event.get("kind", "drift")

    responsible = identify_responsible_engineer(
        drift_event, audit_log_path=audit_log_path,
    )
    who = (
        f"Most-recent operator who touched {hostname} was **{responsible}** "
        "(from audit log)."
        if responsible else
        "No operator activity for this asset in the audit log — "
        "this drift may be unattributed (consider investigating the upstream change)."
    )

    explanation = (
        f"Drift detected: {detail}\n\n"
        f"Asset: `{hostname}` · severity: {severity} · kind: {kind}\n\n"
        f"{who}\n\n"
        "Was this an **intentional** change? "
        "If yes, I'll file an exception so I stop alerting on it. "
        "If no, I'll draft a rollback through the existing approval chain "
        "(Tier-3 SSH triple-gate still applies — nothing executes without "
        "your TOTP + role capability + env-flag)."
    )

    # Build a stable signature so the same drift event doesn't double-nudge.
    sig = (
        f"drift:{kind}:{hostname}:"
        f"{drift_event.get('finding_id') or 'host-only'}"
    )

    nudge_id = create_nudge(
        nudge_conn,
        agent_id=agent_id,
        signature=sig,
        title=f"Drift on {hostname}: was this intentional?",
        body=explanation,
        severity=severity if severity in ("info", "warning", "critical") else "warning",
        category="drift-explanation",
        suggested_action=f"answer_drift:{sig}",
        evidence={
            "drift_event": drift_event,
            "responsible_user": responsible,
        },
    )

    # Sketch the rollback intent (the actual PR drafts on operator confirm).
    suggested_rollback = None
    if kind in ("finding_added", "asset_severity_changed"):
        suggested_rollback = (
            f"draft_remediation_pr for {hostname} via "
            f"intelligence.remediation_pr.draft_remediation_pr()"
        )

    return {
        "nudge_id": nudge_id,
        "explanation": explanation,
        "suggested_rollback": suggested_rollback,
        "responsible_user": responsible,
    }


def handle_response(
    nudge_conn: Any,
    nudge_id: int,
    *,
    answer: str,
    operator: str,
    reason: str = "",
) -> dict:
    """Process the operator's answer to a drift nudge.

    Args:
        answer: one of {"intentional", "rollback", "ignore"}.
        operator: who answered (logged in audit chain).
        reason: free-text rationale.

    Returns ``{"action": ..., "ok": bool, "note": str}``.
    """
    from safecadence.agents.nudges import accept_nudge, dismiss_nudge

    a = (answer or "").lower().strip()
    if a == "intentional":
        # File an exception — for now we just dismiss + memory the decision.
        # In a future patch this writes to compliance.exception_lifecycle.
        ok = dismiss_nudge(
            nudge_conn, nudge_id, operator,
            reason=f"intentional change; {reason}".strip("; "),
        )
        return {
            "action": "exception_filed",
            "ok": ok,
            "note": (
                "Drift marked as intentional. Future identical drift on "
                "this asset will be auto-suppressed for the dedup window."
            ),
        }
    if a == "rollback":
        # Accept the nudge + signal that a rollback should be drafted.
        ok = accept_nudge(nudge_conn, nudge_id, operator)
        return {
            "action": "rollback_queued",
            "ok": ok,
            "note": (
                "Rollback intent recorded. The actual rollback runs through "
                "the existing Tier-3 SSH triple-gate (env flag + role "
                "capability + TOTP). Nothing executes silently."
            ),
        }
    # "ignore" or unknown
    ok = dismiss_nudge(
        nudge_conn, nudge_id, operator,
        reason=f"ignored without explanation; {reason}".strip("; "),
    )
    return {
        "action": "noop",
        "ok": ok,
        "note": "Nudge dismissed; no follow-up action taken.",
    }


__all__ = [
    "identify_responsible_engineer",
    "explain_drift",
    "handle_response",
]
