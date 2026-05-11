"""
Configuration-drift forecasting (v11.0).

Predicts when an asset will next experience a "significant" config
change, defined as a change with at least medium severity or that
touches a control-relevant section (ACL, firewall, identity).

Inputs: per-asset change-log entries — either passed in via
``history`` or read from ``~/.safecadence/orgs/<org>/change_log.jsonl``
(v10.8 change-management) for the matching ``asset_id``.

The "model" is again stdlib + math: estimate mean inter-arrival time
between past significant changes, weight it by how long it's been
since the last one, and modulate by recent severity.
"""

from __future__ import annotations

import json
import math
import os
import datetime as _dt
from pathlib import Path


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _org_dir(org_id: str | None) -> Path:
    if org_id:
        try:
            from safecadence.storage.org_store import org_data_dir

            return org_data_dir(org_id)
        except Exception:
            pass
    root = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME")
    return Path(root) if root else Path.home() / ".safecadence"


def _coerce_ts(ts) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, _dt.datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            return _dt.datetime.fromisoformat(
                ts.replace("Z", "+00:00")
            ).timestamp()
        except Exception:
            return 0.0
    return 0.0


def _load_change_log(org_id: str | None, asset_id: str) -> list[dict]:
    """Read the v10.8 change_log.jsonl, filter to events for this asset."""
    path = _org_dir(org_id) / "change_log.jsonl"
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("asset_id") == asset_id:
            out.append(rec)
    return out


def _significance(ev: dict) -> int:
    """0 = noise; 1 = minor; 2 = significant."""
    sev = str(ev.get("severity") or "").lower()
    rank = _SEVERITY_RANK.get(sev, 1)
    if rank >= 2:
        return 2
    kind = str(ev.get("kind") or ev.get("type") or "").lower()
    if any(
        k in kind for k in ("acl", "firewall", "identity", "mfa", "policy", "auth")
    ):
        return 2
    return 1


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def forecast_drift(
    asset_id: str,
    history: list[dict] | None = None,
    *,
    org_id: str | None = None,
    now_ts: float | None = None,
) -> dict:
    """Return ``{days_until_drift, confidence, key_indicators}``.

    ``history`` is a list of change events for the asset. Each entry
    should carry a timestamp (``ts``/``timestamp``/``at``) plus an
    optional ``severity`` and ``kind``. When ``history`` is None, we
    read events from the org's v10.8 change log.

    Output
    ------
    days_until_drift:
        Predicted days until the next significant change. Capped to
        365 when no signal.
    confidence:
        0..1, higher when we have more events and the inter-arrival
        gaps are tight.
    key_indicators:
        Short human-readable hints — high cadence, recent critical
        change, control-sensitive churn, etc.
    """
    if history is None:
        history = _load_change_log(org_id, asset_id)
    events = []
    for ev in history or []:
        ts = ev.get("ts") or ev.get("timestamp") or ev.get("at") or ev.get(
            "occurred_at"
        )
        ts = _coerce_ts(ts)
        if ts <= 0:
            continue
        events.append((ts, ev))
    events.sort(key=lambda x: x[0])
    if now_ts is None:
        now_ts = _dt.datetime.utcnow().timestamp()

    indicators: list[str] = []
    if not events:
        return {
            "asset_id": asset_id,
            "days_until_drift": 365,
            "confidence": 0.0,
            "key_indicators": ["No change history available"],
            "events_seen": 0,
        }

    # Inter-arrival gaps between *significant* events (in days)
    sig_times = [ts for (ts, ev) in events if _significance(ev) >= 2]
    if len(sig_times) < 2:
        # Fall back to all events
        all_times = [ts for (ts, _) in events]
        gaps = [
            (all_times[i] - all_times[i - 1]) / 86400.0
            for i in range(1, len(all_times))
        ]
    else:
        gaps = [
            (sig_times[i] - sig_times[i - 1]) / 86400.0
            for i in range(1, len(sig_times))
        ]
    gaps = [g for g in gaps if g > 0]
    if not gaps:
        mean_gap = 30.0
    else:
        mean_gap = sum(gaps) / len(gaps)
    mean_gap = max(1.0, mean_gap)

    last_ts = events[-1][0]
    days_since_last = max(0.0, (now_ts - last_ts) / 86400.0)

    # Forecast: next event ~ mean_gap from the last one. If we're
    # already past mean_gap, we expect imminent drift (1-3 days).
    if days_since_last >= mean_gap:
        days_until = max(1.0, min(7.0, mean_gap * 0.1))
        indicators.append(
            "Currently overdue for change relative to history cadence"
        )
    else:
        days_until = mean_gap - days_since_last
    # Recent severity bumps shrink the window
    recent = events[-5:]
    max_recent_sev = max(
        (_SEVERITY_RANK.get(str(e.get("severity") or "").lower(), 0))
        for (_, e) in recent
    )
    if max_recent_sev >= 3:
        days_until *= 0.6
        indicators.append("Recent high/critical change — elevated drift risk")
    elif max_recent_sev >= 2:
        days_until *= 0.85

    # Cadence indicator
    if mean_gap < 7:
        indicators.append("High change cadence (mean < 1 week)")
    elif mean_gap < 30:
        indicators.append("Moderate change cadence (mean < 1 month)")
    else:
        indicators.append("Low change cadence")
    # Control-sensitive surfaces
    sensitive = sum(
        1
        for (_, e) in events
        if any(
            k in str(e.get("kind") or e.get("type") or "").lower()
            for k in ("acl", "firewall", "identity", "mfa", "policy", "auth")
        )
    )
    if sensitive:
        indicators.append(
            f"{sensitive} control-sensitive change(s) in history"
        )

    # Confidence: more events + tighter variance = more confident
    n = len(events)
    length_factor = min(0.6, n / 30.0)
    if gaps:
        mu = mean_gap
        var = sum((g - mu) ** 2 for g in gaps) / len(gaps)
        stab = max(0.0, 0.4 * (1.0 - min(1.0, math.sqrt(var) / max(1.0, mu))))
    else:
        stab = 0.1
    conf = round(max(0.0, min(1.0, length_factor + stab)), 3)

    days_until = max(1, int(round(min(365.0, days_until))))

    return {
        "asset_id": asset_id,
        "days_until_drift": days_until,
        "confidence": conf,
        "key_indicators": indicators,
        "events_seen": n,
        "mean_gap_days": round(mean_gap, 2),
        "days_since_last": round(days_since_last, 2),
    }


def assets_at_drift_risk(
    org_id: str | None,
    *,
    days: int = 14,
) -> list[dict]:
    """Return asset IDs predicted to drift within ``days``.

    Iterates every asset in the org's ``platform_assets`` store, runs
    :func:`forecast_drift`, and surfaces the ones where
    ``days_until_drift <= days``.
    """
    base = _org_dir(org_id) / "platform_assets"
    if not base.exists():
        return []
    out: list[dict] = []
    for f in base.glob("*.json"):
        try:
            asset = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        ident = asset.get("identity") or {}
        aid = (
            asset.get("id")
            or ident.get("id")
            or ident.get("hostname")
            or f.stem
        )
        fc = forecast_drift(aid, org_id=org_id)
        if fc["days_until_drift"] <= days:
            out.append(fc)
    out.sort(key=lambda r: r["days_until_drift"])
    return out


__all__ = ["forecast_drift", "assets_at_drift_risk"]
