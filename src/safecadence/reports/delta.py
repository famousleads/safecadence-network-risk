"""
Delta reports — snapshot the report payload to disk so we can diff
"now vs last week" and produce trend sparklines for KPI tiles.

A snapshot is a JSON file at:
    <data_dir>/reports/snapshots/<YYYY-MM-DD>__<id>.json

The contents are the full ``compose_report`` payload for the
``technical_deepdive`` preset (every section). One snapshot per day per
``snapshot_now`` call max — if a same-day file already exists it is
overwritten so trend series stay clean.

Public API:
  - snapshot_now(*, label=None)        -> dict        (raises in read-only)
  - list_snapshots(*, limit=50)        -> list[dict]
  - get_snapshot(snapshot_id)          -> dict | None
  - compute_delta(*, current=None, previous=None) -> dict
  - trend_series(metric, *, days=30)   -> list[float]
  - cleanup_old_snapshots(*, keep=90)  -> int

Read-only mode (``SC_READONLY=1``) makes ``snapshot_now`` and
``cleanup_old_snapshots`` raise :class:`PermissionError`. Read paths
(list/get/compute/trend) work in either mode and silently skip writes.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# data dir / path helpers (mirrors templates._data_dir)
# --------------------------------------------------------------------------


def _data_dir() -> Path:
    if os.environ.get("SC_DATA_DIR"):
        return Path(os.environ["SC_DATA_DIR"])
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "safecadence"


def _snapshots_dir() -> Path:
    d = _data_dir() / "reports" / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _today_str() -> str:
    return _now().strftime("%Y-%m-%d")


def _short_id() -> str:
    return secrets.token_hex(4)


_SAFE_ID = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}__[a-z0-9]+$")


# --------------------------------------------------------------------------
# Metric extraction
# --------------------------------------------------------------------------


def _kpi_from_report(report: dict | None) -> dict:
    """Pull the kpi_summary numbers out of a composed report dict."""
    if not isinstance(report, dict):
        return {}
    for s in report.get("sections", []) or []:
        if s.get("key") == "kpi_summary":
            d = s.get("data") or {}
            if isinstance(d, dict):
                return dict(d)
    return {}


def _findings_signature(report: dict) -> dict[str, dict]:
    """Build a stable map of finding_id -> {host, severity, title}.

    A "finding" is keyed by ``CVE-id|host`` for CVE rows and
    ``rule_id|host`` for rule findings; falls back to title if nothing
    else identifies it. This is the basis of new/fixed/regressed diffing.
    """
    out: dict[str, dict] = {}
    if not isinstance(report, dict):
        return out
    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    for s in report.get("sections", []) or []:
        key = s.get("key")
        data = s.get("data") or {}
        if key == "cve_exposure":
            for row in (data.get("cves") or []):
                cve_id = row.get("id") or row.get("cve_id") or ""
                host = row.get("host") or row.get("hostname") or ""
                if not cve_id:
                    continue
                fid = f"cve|{cve_id}|{host}".lower()
                sev = (row.get("severity") or "").lower()
                if not sev:
                    cvss = float(row.get("cvss") or 0)
                    if cvss >= 9: sev = "critical"
                    elif cvss >= 7: sev = "high"
                    elif cvss >= 4: sev = "medium"
                    else: sev = "low"
                out[fid] = {
                    "id": fid,
                    "kind": "cve",
                    "title": row.get("summary") or cve_id,
                    "host": host,
                    "severity": sev,
                    "rank": sev_rank.get(sev, 0),
                    "kev": bool(row.get("kev")),
                }
        elif key == "host_inventory":
            for row in (data.get("hosts") or []):
                host = row.get("hostname") or ""
                tf = row.get("top_finding") or ""
                if not host or not tf:
                    continue
                fid = f"host|{host}|{tf}".lower()
                # use risk score band as severity proxy
                risk = int(row.get("risk_score") or row.get("risk") or 0)
                if risk >= 80: sev = "critical"
                elif risk >= 50: sev = "high"
                elif risk >= 25: sev = "medium"
                else: sev = "low"
                out[fid] = {
                    "id": fid,
                    "kind": "host",
                    "title": tf,
                    "host": host,
                    "severity": sev,
                    "rank": sev_rank.get(sev, 0),
                }
    return out


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------


def _path_for(snapshot_id: str) -> Path:
    if not _SAFE_ID.match(snapshot_id or ""):
        raise ValueError(f"invalid snapshot id: {snapshot_id!r}")
    return _snapshots_dir() / f"{snapshot_id}.json"


def _build_compose_payload() -> dict:
    """Build the technical_deepdive report payload for snapshotting."""
    from safecadence.reports.builder import compose_report
    from safecadence.reports.presets import apply_preset
    preset = apply_preset("technical_deepdive")
    return compose_report(sections=preset["sections"], scope=preset["scope"],
                          title="Snapshot")


def snapshot_now(*, label: str | None = None) -> dict:
    """Persist a snapshot of the current technical_deepdive report.

    Raises :class:`PermissionError` when ``SC_READONLY=1`` is set.
    """
    if _is_readonly():
        raise PermissionError(
            "read_only: snapshots cannot be saved when SC_READONLY=1"
        )
    today = _today_str()
    # Same-day snapshot -> overwrite the most recent one for today.
    existing = sorted(_snapshots_dir().glob(f"{today}__*.json"))
    if existing:
        # Keep id, overwrite contents.
        snap_id = existing[-1].stem
    else:
        snap_id = f"{today}__{_short_id()}"
    payload = _build_compose_payload()
    snap = {
        "id": snap_id,
        "label": label or "",
        "created_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kpi": _kpi_from_report(payload),
        "report": payload,
    }
    path = _path_for(snap_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    return {k: v for k, v in snap.items() if k != "report"} | {"path": str(path)}


def list_snapshots(*, limit: int = 50) -> list[dict]:
    """Return snapshot summaries (no full report payload), newest first."""
    out: list[dict] = []
    for p in sorted(_snapshots_dir().glob("*.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        out.append({
            "id": d.get("id") or p.stem,
            "label": d.get("label") or "",
            "created_at": d.get("created_at") or "",
            "kpi": d.get("kpi") or {},
        })
        if len(out) >= limit:
            break
    return out


def get_snapshot(snapshot_id: str) -> dict | None:
    try:
        path = _path_for(snapshot_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Delta computation
# --------------------------------------------------------------------------


def _trend(now_v: float, prev_v: float) -> str:
    if now_v > prev_v: return "up"
    if now_v < prev_v: return "down"
    return "flat"


def compute_delta(*, current: dict | None = None,
                  previous: dict | None = None) -> dict:
    """Diff two snapshots. If either is None, auto-pick the last 2 from disk."""
    if current is None or previous is None:
        snaps = list_snapshots(limit=10)
        if current is None and snaps:
            current = get_snapshot(snaps[0]["id"])
        if previous is None and len(snaps) >= 2:
            previous = get_snapshot(snaps[1]["id"])

    cur_kpi = (current or {}).get("kpi") or _kpi_from_report((current or {}).get("report"))
    prv_kpi = (previous or {}).get("kpi") or _kpi_from_report((previous or {}).get("report"))

    metric_keys = ("hosts", "critical", "high", "medium", "low",
                   "cves", "kev", "eol", "eos_software")
    kpis: dict[str, dict] = {}
    for k in metric_keys:
        n = float(cur_kpi.get(k, 0) or 0)
        p = float(prv_kpi.get(k, 0) or 0)
        kpis[k] = {
            "now": int(n) if n.is_integer() else n,
            "prev": int(p) if p.is_integer() else p,
            "change": int(n - p) if (n - p).is_integer() else round(n - p, 2),
            "trend": _trend(n, p),
        }

    cur_findings = _findings_signature((current or {}).get("report") or {})
    prv_findings = _findings_signature((previous or {}).get("report") or {})

    new_findings = [v for k, v in cur_findings.items() if k not in prv_findings]
    fixed_findings = [v for k, v in prv_findings.items() if k not in cur_findings]
    regressed: list[dict] = []
    for k, v in cur_findings.items():
        prv = prv_findings.get(k)
        if prv and v.get("rank", 0) > prv.get("rank", 0):
            regressed.append({**v, "prev_severity": prv.get("severity")})

    # narrative
    crit = kpis["critical"]
    kev = kpis["kev"]
    bits = []
    if crit["change"]:
        verb = "rose" if crit["change"] > 0 else "fell"
        bits.append(f"critical findings {verb} by {abs(crit['change'])}")
    if kev["change"]:
        verb = "rose" if kev["change"] > 0 else "fell"
        bits.append(f"KEV-listed devices {verb} by {abs(kev['change'])}")
    if new_findings:
        bits.append(f"{len(new_findings)} new finding(s) appeared")
    if fixed_findings:
        bits.append(f"{len(fixed_findings)} finding(s) were resolved")
    if regressed:
        bits.append(f"{len(regressed)} finding(s) regressed in severity")
    summary_text = (
        ("Since the last snapshot, " + "; ".join(bits) + ".")
        if bits else
        "No material change in posture since the last snapshot."
    )

    return {
        "kpis": kpis,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "regressed": regressed,
        "summary_text": summary_text,
        "from_label": (previous or {}).get("label") or (previous or {}).get("created_at") or "previous",
        "to_label": (current or {}).get("label") or (current or {}).get("created_at") or "now",
        "available": bool(current and previous),
    }


def trend_series(metric: str, *, days: int = 30) -> list[float]:
    """Return numeric values for a KPI metric across the last N daily snapshots.

    Returns oldest-first so it can be passed straight to ``visuals.sparkline``.
    """
    cutoff = _now().date() - _dt.timedelta(days=days)
    rows: list[tuple[str, float]] = []
    for p in sorted(_snapshots_dir().glob("*.json")):
        stem = p.stem
        try:
            day = stem.split("__", 1)[0]
            day_d = _dt.date.fromisoformat(day)
        except ValueError:
            continue
        if day_d < cutoff:
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        kpi = d.get("kpi") or _kpi_from_report(d.get("report"))
        v = kpi.get(metric)
        if v is None:
            continue
        try:
            rows.append((day, float(v)))
        except (TypeError, ValueError):
            continue
    rows.sort(key=lambda x: x[0])
    return [v for _d, v in rows]


def cleanup_old_snapshots(*, keep: int = 90) -> int:
    """Delete snapshots older than ``keep`` days. Returns the count removed."""
    if _is_readonly():
        raise PermissionError(
            "read_only: cleanup_old_snapshots disabled when SC_READONLY=1"
        )
    cutoff = _now().date() - _dt.timedelta(days=keep)
    removed = 0
    for p in _snapshots_dir().glob("*.json"):
        try:
            day = p.stem.split("__", 1)[0]
            day_d = _dt.date.fromisoformat(day)
        except ValueError:
            continue
        if day_d < cutoff:
            try:
                p.unlink()
                removed += 1
            except OSError:
                continue
    return removed


# --------------------------------------------------------------------------
# Decorate KPI tiles with sparkline + delta indicators
# --------------------------------------------------------------------------


_KPI_LABEL_TO_METRIC = {
    "Hosts": "hosts",
    "Critical CVEs": "critical",
    "Critical findings": "critical",
    "High CVEs": "high",
    "High findings": "high",
    "Medium findings": "medium",
    "KEV-listed": "kev",
    "KEV-listed devices": "kev",
    "Total CVEs": "cves",
    "CVEs": "cves",
    "EOL hardware": "eol",
    "EOS software": "eos_software",
}


def _change_html(change: int | float, trend: str) -> str:
    if not change:
        return '<span class="sc-kpi-delta sc-flat" aria-label="no change">&middot;</span>'
    arrow = "&uarr;" if trend == "up" else "&darr;"
    cls = "sc-up" if trend == "up" else "sc-down"
    return (
        f'<span class="sc-kpi-delta {cls}" aria-label="change {trend} {abs(change)}">'
        f'{arrow} {abs(change)}</span>'
    )


def decorate_kpi_with_delta(kpi_html: str, *, delta: dict | None = None,
                            include_sparklines: bool = True) -> str:
    """Inject sparkline + change indicator into kpi_summary HTML.

    Best-effort: if delta is missing or no series available for a label,
    the original kpi card is returned unchanged.
    """
    if not delta or not delta.get("kpis"):
        return kpi_html
    try:
        from safecadence.reports.visuals import sparkline
    except Exception:
        sparkline = None  # type: ignore
    out = kpi_html
    for label, metric in _KPI_LABEL_TO_METRIC.items():
        kobj = (delta.get("kpis") or {}).get(metric)
        if not kobj:
            continue
        change_h = _change_html(kobj.get("change", 0), kobj.get("trend", "flat"))
        spark_h = ""
        if include_sparklines and sparkline:
            try:
                series = trend_series(metric, days=30)
                if len(series) >= 2:
                    spark_h = sparkline(series, width=80, height=22)
            except Exception:
                spark_h = ""
        # Match the rendered KPI card label, append change + sparkline
        marker = f'<div class="sc-kpi-lbl">{label}</div>'
        replacement = (
            f'<div class="sc-kpi-lbl">{label}'
            f'<span class="sc-kpi-extras">{change_h}'
            f'{spark_h}</span></div>'
        )
        out = out.replace(marker, replacement, 1)
    return out


__all__ = [
    "snapshot_now", "list_snapshots", "get_snapshot",
    "compute_delta", "trend_series", "cleanup_old_snapshots",
    "decorate_kpi_with_delta",
]
