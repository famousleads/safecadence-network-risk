"""
Predictive 30-day risk scoring (v11.0).

Heuristic, stdlib-only. Two layers:

* :func:`predict_risk_30d` — EWMA (exponential weighted moving average)
  + linear trend term over an asset's risk history. Returns a predicted
  score in 0..100, a 0..1 confidence (driven by history length +
  variance), and a short list of human-readable drivers.

* :func:`assets_trending_critical` — runs the per-asset prediction
  across every asset in the org store and surfaces the ones forecast
  to cross the ``risk_score >= 70`` line within ``horizon_days``.

The "model" is deliberately interpretable: a recruiter or a customer
can read the drivers and know why we flagged an asset. Real supervised
risk classifiers (gradient-boosted, trained on labelled drift events)
ship in v11.0.x point releases — this is the baseline.
"""

from __future__ import annotations

import json
import math
import os
import datetime as _dt
from pathlib import Path
from typing import Sequence


CRITICAL_RISK = 70.0
MAX_RISK = 100.0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _coerce_history(history) -> list[tuple[float, float]]:
    """Accept (ts, score) tuples, dicts with ts/value, or bare floats."""
    out: list[tuple[float, float]] = []
    if not history:
        return out
    now = _dt.datetime.utcnow().timestamp()
    for i, entry in enumerate(history):
        ts = None
        v = None
        if isinstance(entry, dict):
            ts = entry.get("ts") or entry.get("timestamp") or entry.get("date")
            v = entry.get("score") or entry.get("value") or entry.get("risk")
        elif isinstance(entry, (list, tuple)):
            if len(entry) >= 2:
                ts, v = entry[0], entry[1]
            elif len(entry) == 1:
                v = entry[0]
        else:
            v = entry
        # ts coercion
        if isinstance(ts, str):
            try:
                ts = _dt.datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                ts = None
        if isinstance(ts, _dt.datetime):
            ts = ts.timestamp()
        if not isinstance(ts, (int, float)):
            # default: 1 sample per day, oldest first
            ts = now - ((len(history) - 1 - i) * 86400)
        # value coercion
        try:
            v = float(v)
        except Exception:
            continue
        out.append((float(ts), v))
    out.sort(key=lambda x: x[0])
    return out


def _ewma(values: Sequence[float], alpha: float = 0.4) -> float:
    if not values:
        return 0.0
    s = float(values[0])
    for v in values[1:]:
        s = alpha * v + (1 - alpha) * s
    return s


def _linear_trend(values: Sequence[float]) -> float:
    """Slope per step from a simple least-squares fit. Empty/short → 0."""
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    mx = sum(xs) / n
    my = sum(values) / n
    num = sum((xs[i] - mx) * (values[i] - my) for i in range(n))
    den = sum((xs[i] - mx) ** 2 for i in range(n))
    if den == 0:
        return 0.0
    return num / den


def _variance(values: Sequence[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    mu = sum(values) / n
    return sum((v - mu) ** 2 for v in values) / (n - 1)


def _confidence(n: int, variance: float) -> float:
    """Confidence in 0..1.

    More history → more confidence. Higher variance → less confidence.
    Saturates at ~30 data points + low variance.
    """
    if n <= 0:
        return 0.0
    # Length factor: 0..0.6 saturating at n=30
    length = min(0.6, n / 50.0)
    # Stability factor: 0..0.4. Variance of 0 → 0.4; variance of
    # MAX_RISK^2/4 (huge swings) → ~0.
    norm_var = min(1.0, math.sqrt(variance) / 40.0)
    stability = 0.4 * (1.0 - norm_var)
    return round(max(0.0, min(1.0, length + stability)), 3)


# --------------------------------------------------------------------------
# Loading per-asset history
# --------------------------------------------------------------------------


def _org_dir(org_id: str | None) -> Path:
    if org_id:
        try:
            from safecadence.storage.org_store import org_data_dir

            return org_data_dir(org_id)
        except Exception:
            pass
    root = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME")
    return Path(root) if root else Path.home() / ".safecadence"


def _load_asset(org_id: str | None, asset_id: str) -> dict | None:
    base = _org_dir(org_id) / "platform_assets"
    if not base.exists():
        return None
    target = base / f"{asset_id}.json"
    if target.exists():
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            return None
    # Fallback: scan files looking for matching identity.id
    for f in base.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        ident = d.get("identity") or {}
        if (
            d.get("id") == asset_id
            or ident.get("id") == asset_id
            or ident.get("hostname") == asset_id
        ):
            return d
    return None


def _all_assets(org_id: str | None) -> list[dict]:
    base = _org_dir(org_id) / "platform_assets"
    if not base.exists():
        return []
    out = []
    for f in base.glob("*.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def _history_for_asset(asset: dict) -> list[tuple[float, float]]:
    """Pull whatever risk history is on the asset record."""
    if not asset:
        return []
    raw = (
        asset.get("risk_history")
        or asset.get("history")
        or asset.get("score_history")
        or []
    )
    return _coerce_history(raw)


def _current_score(asset: dict) -> float:
    if not asset:
        return 0.0
    try:
        return float(
            asset.get("risk_score")
            or asset.get("score")
            or (asset.get("risk") or {}).get("score")
            or 0.0
        )
    except Exception:
        return 0.0


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def predict_risk_30d(asset: dict, history=None) -> dict:
    """Predict an asset's risk score 30 days out.

    ``asset`` is a dict (from ``platform_assets/*.json`` or equivalent).
    ``history`` may be passed explicitly; otherwise we pull it off the
    asset record (``risk_history`` / ``history`` / ``score_history``).

    The model: ``predicted = clip(ewma(history) + 30 * slope, 0, 100)``
    with the slope estimated by least-squares on the trailing 60
    observations. Confidence is :func:`_confidence` over history
    length + variance.

    Drivers are human-readable strings — KEV CVEs, EOL flag, public
    exposure, missing MFA, recent severity spike. They help report
    sections explain *why* a number went up.
    """
    if history is None:
        history = _history_for_asset(asset or {})
    history = _coerce_history(history)
    values = [v for (_, v) in history[-60:]]
    current = _current_score(asset or {})
    if not values:
        values = [current]
    ewma = _ewma(values)
    slope = _linear_trend(values)
    predicted = ewma + 30.0 * slope
    # Floor at the asset's static "risk surface" score so a flat history
    # doesn't predict a lower number than today's reality warrants.
    predicted = max(predicted, ewma)
    predicted = max(0.0, min(MAX_RISK, predicted))
    variance = _variance(values)
    conf = _confidence(len(values), variance)

    # Drivers — interpretable risk surface factors
    drivers: list[str] = []
    cves = (asset or {}).get("cves") or (asset or {}).get("vulnerabilities") or []
    kev_cves = [c for c in cves if isinstance(c, dict) and c.get("kev")]
    if kev_cves:
        drivers.append(f"{len(kev_cves)} KEV-listed CVE(s) present")
    crit_cves = [
        c
        for c in cves
        if isinstance(c, dict)
        and (str(c.get("severity") or "").lower() == "critical")
    ]
    if crit_cves:
        drivers.append(f"{len(crit_cves)} critical CVE(s)")
    ident = (asset or {}).get("identity") or {}
    if (asset or {}).get("eol") or ident.get("eol"):
        drivers.append("End-of-life hardware/software")
    if (asset or {}).get("public_exposure") or ident.get("public_exposure"):
        drivers.append("Internet-facing exposure")
    if (asset or {}).get("mfa_missing") or ident.get("mfa_missing"):
        drivers.append("MFA not enforced")
    if slope > 0.5:
        drivers.append("Upward trend in recent history")
    elif slope < -0.5:
        drivers.append("Risk currently improving")
    if not drivers:
        drivers.append("No high-severity factors detected")

    return {
        "asset_id": (asset or {}).get("id")
        or ident.get("id")
        or ident.get("hostname")
        or "",
        "current_score": round(current, 2),
        "predicted_score": round(predicted, 2),
        "confidence": conf,
        "ewma": round(ewma, 2),
        "slope_per_day": round(slope, 4),
        "history_length": len(values),
        "drivers": drivers,
    }


def assets_trending_critical(
    org_id: str | None,
    *,
    horizon_days: int = 30,
    critical_threshold: float = CRITICAL_RISK,
) -> list[dict]:
    """Flag assets predicted to cross ``critical_threshold`` within ``horizon_days``.

    Returns ``{asset_id, current, predicted, days_to_critical, confidence}``.
    Assets already above the threshold are returned with
    ``days_to_critical = 0``. Assets where the slope is non-positive
    and the score is below the threshold are skipped (no projected
    crossing).
    """
    assets = _all_assets(org_id)
    out: list[dict] = []
    for asset in assets:
        pred = predict_risk_30d(asset)
        cur = pred["current_score"]
        slope = pred["slope_per_day"]
        if cur >= critical_threshold:
            out.append(
                {
                    "asset_id": pred["asset_id"],
                    "current": cur,
                    "predicted": pred["predicted_score"],
                    "days_to_critical": 0,
                    "confidence": pred["confidence"],
                    "drivers": pred["drivers"],
                }
            )
            continue
        if slope <= 0:
            continue
        # ETA in days = (threshold - ewma) / slope, clipped to horizon
        eta = (critical_threshold - pred["ewma"]) / slope if slope > 0 else 1e9
        if eta <= horizon_days:
            out.append(
                {
                    "asset_id": pred["asset_id"],
                    "current": cur,
                    "predicted": pred["predicted_score"],
                    "days_to_critical": int(max(1, round(eta))),
                    "confidence": pred["confidence"],
                    "drivers": pred["drivers"],
                }
            )
    out.sort(key=lambda r: r["days_to_critical"])
    return out


__all__ = [
    "predict_risk_30d",
    "assets_trending_critical",
    "CRITICAL_RISK",
]
