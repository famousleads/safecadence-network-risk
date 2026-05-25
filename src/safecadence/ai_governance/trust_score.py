"""
v14 — Machine identity trust scoring.

Pure-Python, no ML. Takes an API key (or AI agent) row and returns a
0–100 score plus the per-factor breakdown so the operator can see
*why* a key is low-trust. Higher = more trustworthy.

Factors (with weights)
----------------------

* **Age** (25)   — newer keys score higher; keys older than rotation
                   policy lose points.
* **Rotation cadence** (20) — keys that have been rotated within
                   `rotation_policy_days` get full credit.
* **Scope breadth** (20) — fewer scopes is better; the formula caps
                   credit at 5 scopes, then degrades.
* **Active use** (15) — keys seen within the last 30 days score higher
                   than keys that haven't been used in 6+ months.
* **Owner attribution** (10) — keys with a named owner_user_id score
                   higher than orphan keys.
* **Deprecation status** (10) — deprecated keys score 0 immediately
                   regardless of the other factors (a deprecated key
                   in active use is a finding, not a normal state).

The thresholds are public industry rules-of-thumb (NIST SP 800-57
rotation guidance + CIS Controls v8 6.5 + AWS IAM best practices).
Operators can override them via env vars; the defaults below match
the v11.x NHI module's defaults.

Public API
----------

* ``DEFAULTS`` — env-tunable thresholds (constants below).
* ``score_api_key(key, now_ts=None)`` → ``{score, factors, recommendation}``
* ``score_agent(agent, recent_invocations=None)`` → similar shape
* ``score_all_keys(conn, org_id=None)`` — bulk helper
"""
from __future__ import annotations

import os
import time
from typing import Any


# Default thresholds (days unless noted)
DEFAULTS = {
    "max_age_days":             int(os.getenv("SC_TRUST_MAX_AGE_DAYS", "365")),
    "rotation_policy_days":     int(os.getenv("SC_TRUST_ROTATION_DAYS", "90")),
    "active_use_window_days":   int(os.getenv("SC_TRUST_ACTIVE_DAYS", "30")),
    "stale_use_window_days":    int(os.getenv("SC_TRUST_STALE_DAYS", "180")),
    "max_scopes_for_full_credit": int(os.getenv("SC_TRUST_MAX_SCOPES", "5")),
}


def _age_score(age_days: int, max_age: int) -> tuple[float, str]:
    if age_days <= 0:
        return 25.0, "Brand new (no age penalty)"
    if age_days >= max_age:
        return 0.0, f"Older than max-age threshold ({max_age}d)"
    # Linear decay
    pct_remaining = 1.0 - (age_days / max_age)
    return round(25.0 * pct_remaining, 2), f"Age {age_days}d of {max_age}d max"


def _rotation_score(key: dict, policy: int) -> tuple[float, str]:
    rotated = key.get("rotated_at") or key.get("created_at") or 0
    created = key.get("created_at") or 0
    if not created:
        return 0.0, "Unknown creation date"
    days_since_rotation = max(
        0, (int(time.time()) - int(rotated)) // 86_400
    )
    if rotated == created:
        # Never explicitly rotated. Give credit if recent, none if old.
        if days_since_rotation <= policy:
            return 20.0, "Never rotated, but within policy window"
        return 0.0, f"Never rotated, {days_since_rotation}d old (policy: {policy}d)"
    if days_since_rotation <= policy:
        return 20.0, f"Rotated {days_since_rotation}d ago (≤ {policy}d policy)"
    overdue_ratio = days_since_rotation / policy
    return round(max(0.0, 20.0 - overdue_ratio * 5), 2), (
        f"Rotated {days_since_rotation}d ago, {overdue_ratio:.1f}× policy"
    )


def _scope_score(scopes: list[str], max_scopes: int) -> tuple[float, str]:
    n = len(scopes or [])
    if n == 0:
        return 5.0, "Zero scopes declared (unusual — investigate)"
    if n <= max_scopes:
        return 20.0, f"{n} scope(s) (within recommended ≤ {max_scopes})"
    # Each extra scope past the threshold drops 2 points.
    over = n - max_scopes
    return round(max(0.0, 20.0 - over * 2), 2), (
        f"{n} scopes (over {max_scopes} threshold by {over})"
    )


def _active_use_score(
    last_seen_at: int | None, active_win: int, stale_win: int,
) -> tuple[float, str]:
    if not last_seen_at:
        return 0.0, "Never observed in use"
    days_since = max(0, (int(time.time()) - int(last_seen_at)) // 86_400)
    if days_since <= active_win:
        return 15.0, f"Used {days_since}d ago (active)"
    if days_since >= stale_win:
        return 0.0, f"Not used in {days_since}d (stale ≥ {stale_win}d)"
    pct = 1.0 - (days_since - active_win) / max(1, stale_win - active_win)
    return round(15.0 * pct, 2), f"Used {days_since}d ago (between active+stale)"


def _owner_score(owner_user_id: str | None) -> tuple[float, str]:
    if owner_user_id:
        return 10.0, "Named owner"
    return 0.0, "ORPHAN — no owner_user_id"


def score_api_key(key: dict, *, now_ts: int | None = None) -> dict:
    """Compute the trust score for one API key row."""
    if not key:
        return {"score": 0.0, "factors": [], "recommendation": "Unknown key"}

    if key.get("is_deprecated"):
        return {
            "score": 0.0,
            "factors": [{"name": "deprecated", "value": 0,
                         "note": "Key is marked deprecated"}],
            "recommendation": "Investigate why a deprecated key is being scored.",
        }

    cfg = DEFAULTS
    now = now_ts if now_ts is not None else int(time.time())
    created = key.get("created_at") or 0
    age = max(0, (now - int(created)) // 86_400) if created else 0

    age_pts, age_note         = _age_score(age, cfg["max_age_days"])
    rot_pts, rot_note         = _rotation_score(key, cfg["rotation_policy_days"])
    scope_pts, scope_note     = _scope_score(
        key.get("scopes") or [], cfg["max_scopes_for_full_credit"],
    )
    use_pts, use_note         = _active_use_score(
        key.get("last_seen_at"),
        cfg["active_use_window_days"], cfg["stale_use_window_days"],
    )
    owner_pts, owner_note     = _owner_score(key.get("owner_user_id"))

    total = round(age_pts + rot_pts + scope_pts + use_pts + owner_pts, 2)
    # 10 points for "not deprecated" come for free.
    total += 10.0
    total = min(100.0, total)

    rec = _recommendation(total, age_pts, rot_pts, scope_pts, use_pts, owner_pts)

    return {
        "score": total,
        "factors": [
            {"name": "age",         "value": age_pts,   "note": age_note},
            {"name": "rotation",    "value": rot_pts,   "note": rot_note},
            {"name": "scope",       "value": scope_pts, "note": scope_note},
            {"name": "active_use",  "value": use_pts,   "note": use_note},
            {"name": "owner",       "value": owner_pts, "note": owner_note},
            {"name": "not_deprecated", "value": 10.0,
             "note": "Key is not deprecated"},
        ],
        "recommendation": rec,
    }


def _recommendation(
    total: float,
    age_pts: float, rot_pts: float, scope_pts: float,
    use_pts: float, owner_pts: float,
) -> str:
    if total >= 80:
        return "Healthy. No action required."
    weakest = min(
        ("age", age_pts), ("rotation", rot_pts), ("scope", scope_pts),
        ("active_use", use_pts), ("owner", owner_pts),
        key=lambda x: x[1],
    )
    name, pts = weakest
    if name == "rotation":
        return "Rotate the key now; consider tightening rotation policy."
    if name == "age":
        return "Key is old; rotate or replace."
    if name == "scope":
        return "Scope is broader than policy allows; split into per-purpose keys."
    if name == "active_use":
        return "Key hasn't been used; consider deprecating."
    if name == "owner":
        return "Orphan key; assign an owner or deprecate."
    return "Mixed health; review per-factor breakdown."


def score_agent(
    agent: dict,
    recent_invocations: int = 0,
    *,
    now_ts: int | None = None,
) -> dict:
    """Score an AI agent. Simpler than API key — agents don't rotate,
    but they do go stale and they should be paused when not in use."""
    if not agent:
        return {"score": 0.0, "factors": [], "recommendation": "Unknown agent"}

    status = (agent.get("status") or "").lower()
    if status == "deprecated":
        return {
            "score": 0.0,
            "factors": [{"name": "status", "value": 0,
                         "note": "Agent deprecated"}],
            "recommendation": "Deprecated agent should not be scored.",
        }

    now = now_ts if now_ts is not None else int(time.time())
    created = agent.get("created_at") or 0
    age = max(0, (now - int(created)) // 86_400) if created else 0

    factors: list[dict] = []
    score = 0.0

    # Status (40)
    if status == "active":
        score += 40.0
        factors.append({"name": "status", "value": 40,
                        "note": "Active and accountable"})
    elif status == "paused":
        score += 20.0
        factors.append({"name": "status", "value": 20,
                        "note": "Paused; consider deprecating if long-term"})
    else:
        factors.append({"name": "status", "value": 0,
                        "note": f"Unexpected status: {status!r}"})

    # Tool surface (30) — fewer tools is better.
    n_tools = len(agent.get("allowed_tools") or [])
    if n_tools == 0:
        tool_pts, tnote = 5.0, "Zero tools allowed (unusual)"
    elif n_tools <= 5:
        tool_pts, tnote = 30.0, f"{n_tools} tools (lean surface)"
    else:
        tool_pts, tnote = max(0.0, 30.0 - (n_tools - 5) * 3), (
            f"{n_tools} tools (broad surface, consider splitting)"
        )
    score += tool_pts
    factors.append({"name": "tool_surface", "value": tool_pts, "note": tnote})

    # Owner (15)
    if agent.get("owner_user_id"):
        score += 15.0
        factors.append({"name": "owner", "value": 15, "note": "Named owner"})
    else:
        factors.append({"name": "owner", "value": 0, "note": "ORPHAN — no owner"})

    # Recent activity (15)
    if recent_invocations > 0:
        score += 15.0
        factors.append({"name": "activity", "value": 15,
                        "note": f"{recent_invocations} recent invocation(s)"})
    elif age <= 7:
        score += 10.0
        factors.append({"name": "activity", "value": 10,
                        "note": "Brand new; activity not expected yet"})
    else:
        factors.append({"name": "activity", "value": 0,
                        "note": "No recent invocations"})

    score = min(100.0, round(score, 2))
    rec = (
        "Healthy." if score >= 75 else
        "Review owner + tool surface."
    )
    return {"score": score, "factors": factors, "recommendation": rec}


def score_all_keys(conn: Any, org_id: str | None = None) -> list[dict]:
    """Bulk score helper. Reads from ai_api_keys via api_keys.list_api_keys()."""
    from safecadence.ai_governance.api_keys import list_api_keys
    out: list[dict] = []
    for k in list_api_keys(conn, org_id=org_id):
        s = score_api_key(k)
        out.append({"key": k, **s})
    return out


__all__ = [
    "DEFAULTS", "score_api_key", "score_agent", "score_all_keys",
]
