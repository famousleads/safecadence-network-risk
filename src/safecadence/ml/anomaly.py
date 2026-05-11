"""
Anomaly detection (v11.0).

Three detectors, all stdlib + math only.

* :func:`detect_anomalies` — sliding-window z-score over a numeric
  series. Returns the indexes where ``|z| > threshold``.
* :func:`detect_seasonal_anomaly` — compares each point to the median
  of the *same weekday* from prior weeks. Flags points outside ``2 *
  IQR``.
* :func:`detect_finding_anomaly` — convenience wrapper that runs the
  sliding z-score over the daily finding-count series for an org.

None of these read or write anywhere outside the safecadence data dir
when ``org_id`` is given. ``timeseries`` callers pass numbers directly
and get plain dicts back — no opinions about persistence layers.
"""

from __future__ import annotations

import math
import os
import json
import datetime as _dt
from pathlib import Path
from typing import Iterable, Sequence


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _mean(xs: Sequence[float]) -> float:
    xs = list(xs)
    if not xs:
        return 0.0
    return sum(xs) / len(xs)


def _stdev(xs: Sequence[float], mu: float | None = None) -> float:
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = mu if mu is not None else _mean(xs)
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var)


def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    if n % 2 == 1:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def _quartiles(xs: Sequence[float]) -> tuple[float, float, float]:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return (0.0, 0.0, 0.0)
    q2 = _median(s)
    lower = s[: n // 2]
    upper = s[(n + 1) // 2 :]
    q1 = _median(lower) if lower else q2
    q3 = _median(upper) if upper else q2
    return (q1, q2, q3)


def _severity(z: float) -> str:
    az = abs(z)
    if az >= 5.0:
        return "critical"
    if az >= 4.0:
        return "high"
    if az >= 3.0:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# 1. Sliding-window z-score
# --------------------------------------------------------------------------


def detect_anomalies(
    timeseries: list[float],
    *,
    window: int = 20,
    threshold: float = 3.0,
) -> list[dict]:
    """Return indexes where ``|z| > threshold``.

    Z-score is computed against the *trailing* window so each point is
    judged against the recent past, not the entire series. Points whose
    trailing window has zero variance are skipped (constant series →
    no anomaly).

    Parameters
    ----------
    timeseries:
        List of floats. Order is significant — index 0 is the earliest
        observation.
    window:
        Size of the trailing window. Minimum 3 to compute stdev.
    threshold:
        Absolute z-score above which a point is flagged.

    Returns
    -------
    list[dict]
        ``{index, value, z, mean, stdev, severity}`` for every flagged
        point, in ascending order by ``index``.
    """
    if window < 3:
        window = 3
    series = [float(x) for x in (timeseries or [])]
    out: list[dict] = []
    for i, v in enumerate(series):
        if i < window:
            # Not enough trailing data — don't claim an anomaly.
            continue
        win = series[i - window : i]
        mu = _mean(win)
        sigma = _stdev(win, mu)
        if sigma <= 0.0:
            continue
        z = (v - mu) / sigma
        if abs(z) >= threshold:
            out.append(
                {
                    "index": i,
                    "value": v,
                    "z": round(z, 3),
                    "mean": round(mu, 3),
                    "stdev": round(sigma, 3),
                    "severity": _severity(z),
                }
            )
    return out


# --------------------------------------------------------------------------
# 2. Seasonal (weekday) anomaly
# --------------------------------------------------------------------------


def _to_epoch(ts) -> float:
    """Coerce a timestamp argument (int/float/iso-string/datetime) to UNIX seconds."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, _dt.datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            try:
                return float(ts)
            except Exception:
                return 0.0
    return 0.0


def detect_seasonal_anomaly(
    series: list[tuple],
    *,
    period_days: int = 7,
) -> list[dict]:
    """Flag values that deviate from their same-weekday peers.

    ``series`` is a list of ``(ts, value)`` tuples. For each point we
    pull every other point whose weekday matches and that lies in a
    prior week (within roughly 8 weeks for stability), compute the
    IQR-based bounds (``q1 - 1.5*IQR`` / ``q3 + 1.5*IQR``, scaled out
    to ~2x IQR for "definite anomaly"), and flag points outside.

    ``period_days`` is the seasonality period in days; the default 7
    means weekly seasonality (most relevant to security telemetry).

    Returns
    -------
    list[dict]
        ``{index, ts, value, peer_median, peer_q1, peer_q3, deviation,
        severity}`` for every flagged point.
    """
    pts: list[tuple[float, float]] = []
    for entry in series or []:
        if not entry or len(entry) < 2:
            continue
        ts = _to_epoch(entry[0])
        try:
            v = float(entry[1])
        except Exception:
            continue
        pts.append((ts, v))
    out: list[dict] = []
    if not pts:
        return out
    for i, (ts, v) in enumerate(pts):
        wkd = _dt.datetime.utcfromtimestamp(ts).weekday()
        # peers: same weekday, strictly earlier, within the last 8 cycles
        cutoff = ts - (period_days * 8 * 86400)
        peers = [
            pv
            for (pts2, pv) in pts[:i]
            if pts2 >= cutoff
            and _dt.datetime.utcfromtimestamp(pts2).weekday() == wkd
        ]
        if len(peers) < 2:
            continue
        q1, q2, q3 = _quartiles(peers)
        iqr = q3 - q1
        if iqr <= 0.0:
            # Constant peer set — fall back to median + 1
            iqr = max(1.0, abs(q2) * 0.1)
        lo = q1 - 2.0 * iqr
        hi = q3 + 2.0 * iqr
        if v < lo or v > hi:
            dev = (v - q2) / iqr if iqr else 0.0
            out.append(
                {
                    "index": i,
                    "ts": ts,
                    "value": v,
                    "peer_median": q2,
                    "peer_q1": q1,
                    "peer_q3": q3,
                    "deviation": round(dev, 3),
                    "severity": _severity(dev),
                }
            )
    return out


# --------------------------------------------------------------------------
# 3. Finding-count anomaly (org-aware)
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


def _daily_finding_series(org_id: str | None) -> list[tuple[str, int]]:
    """Build a (date_iso, count) list from any available history source.

    Looks in three places, in order:
      1. ``<org_dir>/finding_history.jsonl`` — explicit daily snapshots.
      2. ``<org_dir>/scan_history/*.json`` — per-scan files; coerce
         scan timestamps to a date bucket.
      3. ``<org_dir>/platform_assets/*.json`` — count CVE+config
         findings per asset and bucket by ``last_scan`` date.

    Returns a list of ``(YYYY-MM-DD, count)`` sorted ascending.
    """
    base = _org_dir(org_id)
    counts: dict[str, int] = {}
    # 1) explicit history
    fh = base / "finding_history.jsonl"
    if fh.exists():
        for line in fh.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                rec = json.loads(line)
            except Exception:
                continue
            d = str(rec.get("date") or rec.get("day") or "")[:10]
            c = int(rec.get("count") or rec.get("findings") or 0)
            if d:
                counts[d] = counts.get(d, 0) + c
    # 2) scan_history
    sh = base / "scan_history"
    if not counts and sh.exists():
        for f in sh.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            ts = rec.get("timestamp") or rec.get("scanned_at") or rec.get("ts")
            d = None
            if isinstance(ts, str):
                d = ts[:10]
            elif isinstance(ts, (int, float)):
                d = _dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
            if not d:
                # Fall back to filename mtime
                d = _dt.datetime.utcfromtimestamp(f.stat().st_mtime).strftime(
                    "%Y-%m-%d"
                )
            findings = rec.get("findings") or rec.get("results") or []
            try:
                c = len(findings)
            except Exception:
                c = 0
            counts[d] = counts.get(d, 0) + c
    # 3) platform_assets fallback
    pa = base / "platform_assets"
    if not counts and pa.exists():
        for f in pa.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            last = (
                rec.get("last_scan")
                or rec.get("scanned_at")
                or rec.get("updated_at")
            )
            d = None
            if isinstance(last, str):
                d = last[:10]
            elif isinstance(last, (int, float)):
                d = _dt.datetime.utcfromtimestamp(last).strftime("%Y-%m-%d")
            else:
                d = _dt.datetime.utcfromtimestamp(f.stat().st_mtime).strftime(
                    "%Y-%m-%d"
                )
            cves = (rec.get("cves") or rec.get("vulnerabilities") or [])
            cfgs = (rec.get("findings") or rec.get("config_findings") or [])
            try:
                c = len(cves) + len(cfgs)
            except Exception:
                c = 0
            counts[d] = counts.get(d, 0) + c
    return sorted(counts.items(), key=lambda kv: kv[0])


def detect_finding_anomaly(
    org_id: str | None,
    *,
    window: int = 14,
    threshold: float = 3.0,
) -> list[dict]:
    """Run :func:`detect_anomalies` over the org's daily finding-count series.

    Returns the z-score dicts with an added ``date`` field so callers
    don't need to index back into the series.
    """
    series = _daily_finding_series(org_id)
    values = [float(c) for (_, c) in series]
    flagged = detect_anomalies(values, window=window, threshold=threshold)
    for f in flagged:
        idx = f.get("index", -1)
        if 0 <= idx < len(series):
            f["date"] = series[idx][0]
    return flagged


__all__ = [
    "detect_anomalies",
    "detect_seasonal_anomaly",
    "detect_finding_anomaly",
]
