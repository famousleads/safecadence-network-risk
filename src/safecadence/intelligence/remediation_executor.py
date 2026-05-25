"""
v14.0 — Remediation executor bridge.

Glues ``intelligence.remediation_pr.draft_remediation_pr()`` (which
produces a vendor-specific config diff + rollback) into the existing
v9.x Tier-3 SSH execution pipeline.

Critically, this module does **not** weaken the existing triple-gate:

  1. ``SC_TIER3_ENABLED=1`` env flag must be set.
  2. The operator's role must carry the ``EXECUTE_REAL`` capability.
  3. The operator must submit an explicit acknowledge + TOTP MFA.

This module's job is purely to *queue* the draft as a real execution
plan; whether it actually runs is determined by the v9.x approval +
SSH execution path that already exists.

Public API
----------

* ``queue_remediation(finding, asset, *, vendor=None, operator,
                      approval_policy=None)`` → dict shaped:
  {
    "ok": bool,
    "draft_source": "recipe" | "llm" | "needs_operator_input",
    "queued": bool,
    "job_id": str | None,
    "needs_approval_chain": str | None,
    "warnings": [...]
  }

* ``preview_remediation(finding, asset, *, vendor=None)`` → just the
  draft PR (does NOT queue anything). Wraps ``draft_remediation_pr()``
  for symmetry.
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("safecadence.intelligence.remediation_executor")


def preview_remediation(
    finding: dict,
    asset: dict | None = None,
    *,
    vendor: str | None = None,
) -> dict:
    """Pure passthrough to ``draft_remediation_pr()``. Useful for the UI."""
    from safecadence.intelligence.remediation_pr import draft_remediation_pr
    return draft_remediation_pr(finding, asset=asset, vendor=vendor)


def queue_remediation(
    finding: dict,
    asset: dict | None = None,
    *,
    vendor: str | None = None,
    operator: str,
    approval_policy: Any = None,
) -> dict:
    """Draft a remediation PR and submit it to the existing execution
    queue as a *proposed* job. The job will not execute until the
    triple-gate + approval chain are satisfied.

    Returns a dict (never raises).
    """
    warnings: list[str] = []
    draft = preview_remediation(finding, asset=asset, vendor=vendor)

    if not draft.get("ok"):
        return {
            "ok": False,
            "draft_source": draft.get("source", "unknown"),
            "queued": False,
            "job_id": None,
            "needs_approval_chain": None,
            "warnings": draft.get("warnings", []) + ["draft_not_actionable"],
        }

    # Defensive: the v9.x execution module exists and has a queue helper.
    # If it doesn't import for any reason, we return a "ready-but-not-
    # queued" result so the UI can fall back to manual handling.
    try:
        from safecadence.execution.workflow import create_command_job
    except Exception:
        warnings.append("execution_module_unavailable")
        return {
            "ok": True,
            "draft_source": draft.get("source"),
            "queued": False,
            "job_id": None,
            "needs_approval_chain": None,
            "warnings": warnings,
            "draft": draft,
        }

    # Build the job request. We pass the forward commands as the
    # action and the rollback commands as the inverse, matching the
    # shape v9.x already understands.
    try:
        job = create_command_job(
            actor=operator,
            asset_id=(asset or {}).get("hostname", "") or "",
            vendor=vendor or (asset or {}).get("vendor", "") or "",
            intent=f"AI-drafted remediation: {finding.get('title', 'untitled')}",
            commands=list(draft.get("forward", []) or []),
            rollback_commands=list(draft.get("rollback", []) or []),
            risk=(finding.get("severity") or "high").lower(),
            source="ai-remediation",
            extra={"draft_source": draft.get("source"),
                   "finding_id": finding.get("id"),
                   "rationale": draft.get("rationale", "")},
        )
        job_id = getattr(job, "id", None) or (job.get("id") if isinstance(job, dict) else None)
    except TypeError:
        # v9.x signature mismatch — degrade to "ready but not queued"
        warnings.append("execution_signature_mismatch")
        return {
            "ok": True,
            "draft_source": draft.get("source"),
            "queued": False,
            "job_id": None,
            "needs_approval_chain": (
                approval_policy.name if approval_policy is not None else None
            ),
            "warnings": warnings,
            "draft": draft,
        }
    except Exception as exc:
        _log.exception("queue_remediation failed: %s", exc)
        return {
            "ok": False,
            "draft_source": draft.get("source"),
            "queued": False,
            "job_id": None,
            "needs_approval_chain": None,
            "warnings": warnings + [f"queue_failed: {type(exc).__name__}"],
        }

    return {
        "ok": True,
        "draft_source": draft.get("source"),
        "queued": True,
        "job_id": job_id,
        "needs_approval_chain": (
            approval_policy.name if approval_policy is not None else None
        ),
        "warnings": warnings,
        "draft": draft,
    }


__all__ = ["preview_remediation", "queue_remediation"]
