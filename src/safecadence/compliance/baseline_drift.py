"""
v9.29 — Config-baseline drift.

Each asset can have a *declared baseline* (a snapshot of what good
looks like). We compare today's running config against the baseline
and report drift: lines added, lines removed, lines changed.

This is distinct from policy drift (where we check policy compliance)
and from cross-system drift (Okta vs AD, etc.). Baseline drift is the
"someone touched the prod firewall manually" signal.

Storage: baselines live at ``$SC_DATA_DIR/baselines/<asset_id>.txt``.
Comparison is line-level diff with a deterministic noise filter
(timestamps, dynamic counters) so ephemeral lines don't show up
as drift.

Source for baseline:
  * operator-supplied (uploaded via /api/compliance/baseline)
  * snapshot of running config when the asset is first adopted
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


# Lines we always strip before comparing — vendor-agnostic noise.
_NOISE_PATTERNS = [
    re.compile(r"^!.*$"),                                # comments
    re.compile(r"^\s*$"),                                  # blanks
    re.compile(r"!Last configuration change.*", re.I),
    re.compile(r"!NVRAM config last updated.*", re.I),
    re.compile(r"^Building configuration.*$", re.I),
    re.compile(r"^Current configuration\s*:.*$", re.I),
    re.compile(r"^uptime is.*$", re.I),
    re.compile(r"^\s*ntp clock-period \d+", re.I),
]


def _baselines_dir() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home) / "baselines"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe_id(asset_id: str) -> str:
    """Defang slashes / dots so the baseline path stays inside the dir."""
    if not asset_id or "/" in asset_id or ".." in asset_id:
        raise ValueError(f"invalid asset_id: {asset_id!r}")
    return re.sub(r"[^A-Za-z0-9_\-]", "_", asset_id)[:128]


def _normalize(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if any(p.search(stripped) for p in _NOISE_PATTERNS):
            continue
        out.append(stripped)
    return out


# ---------------------------------------------------------------- crud


def set_baseline(asset_id: str, config_text: str, *,
                   set_by: str = "operator") -> dict:
    safe = _safe_id(asset_id)
    p = _baselines_dir() / f"{safe}.txt"
    meta_p = _baselines_dir() / f"{safe}.meta.json"
    p.write_text(config_text or "", encoding="utf-8")
    meta = {
        "asset_id": asset_id,
        "set_by": set_by,
        "set_at": datetime.now(timezone.utc).isoformat(),
        "byte_size": len(config_text or ""),
        "line_count": len(_normalize(config_text or "")),
    }
    meta_p.write_text(json.dumps(meta), encoding="utf-8")
    return meta


def get_baseline(asset_id: str) -> Optional[str]:
    safe = _safe_id(asset_id)
    p = _baselines_dir() / f"{safe}.txt"
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8")


def get_baseline_meta(asset_id: str) -> Optional[dict]:
    safe = _safe_id(asset_id)
    p = _baselines_dir() / f"{safe}.meta.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def clear_baseline(asset_id: str) -> bool:
    safe = _safe_id(asset_id)
    p = _baselines_dir() / f"{safe}.txt"
    m = _baselines_dir() / f"{safe}.meta.json"
    removed = False
    if p.exists():
        p.unlink(); removed = True
    if m.exists():
        m.unlink()
    return removed


# ---------------------------------------------------------------- diff


@dataclass
class DriftReport:
    asset_id: str
    has_baseline: bool
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: int = 0

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "has_baseline": self.has_baseline,
            "added": list(self.added),
            "removed": list(self.removed),
            "added_count": len(self.added),
            "removed_count": len(self.removed),
            "changed_count": self.changed,
            "total_drift": len(self.added) + len(self.removed),
        }


def compute_drift(asset_id: str, current_config: str) -> DriftReport:
    """O(N+M) line-level diff between baseline and current config."""
    baseline = get_baseline(asset_id)
    if baseline is None:
        return DriftReport(asset_id=asset_id, has_baseline=False)

    base_lines = _normalize(baseline)
    cur_lines = _normalize(current_config)
    base_set = set(base_lines)
    cur_set = set(cur_lines)

    added = [l for l in cur_lines if l not in base_set]
    removed = [l for l in base_lines if l not in cur_set]
    return DriftReport(
        asset_id=asset_id, has_baseline=True,
        added=added, removed=removed,
        changed=0,
    )


# ---------------------------------------------------------------- helpers


def _running_config(asset: dict) -> str:
    raw = asset.get("raw_collection") or {}
    if isinstance(raw, dict):
        for k in ("running", "running_config", "config"):
            v = raw.get(k)
            if isinstance(v, str) and v:
                return v
    elif isinstance(raw, str):
        return raw
    return ""


def drift_for_asset(asset: dict) -> DriftReport:
    """Convenience wrapper: pull running config out of the asset and
    diff it against the stored baseline."""
    aid = (asset.get("identity") or {}).get("asset_id") or ""
    return compute_drift(aid, _running_config(asset))


def drift_findings_for_fleet(assets: Iterable[dict],
                                 *, max_per_asset: int = 5) -> list[dict]:
    """Generate findings for every asset whose running config has
    drifted from baseline. Daemon emits these so they flow through
    the same pipeline as everything else."""
    out: list[dict] = []
    for a in assets:
        rep = drift_for_asset(a)
        if not rep.has_baseline:
            continue
        if not rep.added and not rep.removed:
            continue
        aid = rep.asset_id or ""
        out.append({
            "id": f"baseline-drift::{aid}",
            "kind": "baseline_drift",
            "severity": "high" if (len(rep.added) + len(rep.removed) > 10)
                          else "medium",
            "asset_id": aid,
            "title": f"Config drift from baseline on {aid}",
            "message": (f"+{len(rep.added)}/-{len(rep.removed)} "
                          f"lines vs declared baseline. "
                          f"First few added: "
                          f"{'; '.join(rep.added[:max_per_asset])}"),
        })
    return out
