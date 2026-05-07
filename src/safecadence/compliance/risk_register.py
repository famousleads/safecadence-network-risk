"""
v9.29 — Risk register.

Every ISO 27001 / NIST RMF / SOX program needs a risk register: a
list of identified risks, their likelihood, their impact, the
controls in place, the residual risk, and the owner. This module is
the storage + math for that.

Storage: file-backed at ``$SC_DATA_DIR/risk_register.json``. Each
risk references one or more SafeCadence control IDs (from the
mapping pack) so we can link risk → control → finding → asset.

Severity model:
  inherent = likelihood × impact            (1..25, 5x5 matrix)
  residual = inherent × (1 - control_strength)   (control_strength
              comes from average pass-rate of the linked controls
              over the last 90 days; falls back to 0.0 if no data).
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# 1..5 each.
_LEVELS = (1, 2, 3, 4, 5)
_BAND_THRESHOLDS = [(20, "critical"), (12, "high"),
                      (6, "medium"), (3, "low"), (0, "info")]


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "risk_register.json"


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write_all(rows: list[dict]) -> None:
    _store_path().write_text(
        json.dumps(rows, separators=(",", ":")), encoding="utf-8")


@dataclass
class Risk:
    id: str
    title: str
    description: str
    owner: str
    domain: str            # network | server | identity | cloud | backup | storage | business
    likelihood: int        # 1..5
    impact: int            # 1..5
    control_ids: list[str] = field(default_factory=list)
    mitigation: str = ""
    status: str = "open"   # open | mitigating | accepted | closed
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _band(score: int) -> str:
    for thr, label in _BAND_THRESHOLDS:
        if score >= thr:
            return label
    return "info"


def _control_strength(control_ids: list[str], days: int = 90) -> float:
    """Average pass-rate of the linked controls in the last `days`
    days. Returns 0.0..1.0. No history → 0.0 (treat as unmitigated)."""
    if not control_ids:
        return 0.0
    try:
        from safecadence.compliance.control_history import (
            summary_for_evidence_pack,
        )
    except Exception:
        return 0.0
    rollup = {row["control_id"]: row
                for row in summary_for_evidence_pack(days=days)}
    total = 0.0
    n = 0
    for cid in control_ids:
        r = rollup.get(cid)
        if not r or not r.get("tests"):
            continue
        total += r["pass"] / r["tests"]
        n += 1
    return total / n if n else 0.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_level(name: str, v: int) -> int:
    if v not in _LEVELS:
        raise ValueError(f"{name} must be one of {_LEVELS}")
    return v


def create_risk(*, title: str, description: str, owner: str,
                  domain: str, likelihood: int, impact: int,
                  control_ids: Optional[list[str]] = None,
                  mitigation: str = "") -> Risk:
    title = (title or "").strip()
    if len(title) < 3:
        raise ValueError("title is required")
    _validate_level("likelihood", likelihood)
    _validate_level("impact", impact)
    rec = Risk(
        id=f"risk-{uuid.uuid4().hex[:12]}",
        title=title,
        description=(description or "").strip(),
        owner=(owner or "").strip(),
        domain=(domain or "general").strip().lower(),
        likelihood=int(likelihood), impact=int(impact),
        control_ids=list(control_ids or []),
        mitigation=(mitigation or "").strip(),
        status="open",
        created_at=_now(), updated_at=_now(),
    )
    rows = _read_all()
    rows.append(rec.to_dict())
    _write_all(rows)
    return rec


def list_risks(*, status: Optional[str] = None) -> list[dict]:
    rows = _read_all()
    if status:
        rows = [r for r in rows if r.get("status") == status]
    out = []
    for r in rows:
        out.append(_with_scores(r))
    return out


def _with_scores(r: dict) -> dict:
    """Compute inherent / residual + band on read."""
    L = int(r.get("likelihood", 1))
    I = int(r.get("impact", 1))
    inherent = L * I
    strength = _control_strength(r.get("control_ids") or [])
    residual = round(inherent * (1.0 - strength))
    return {
        **r,
        "inherent_score": inherent,
        "residual_score": residual,
        "control_strength": round(strength, 2),
        "band_inherent": _band(inherent),
        "band_residual": _band(residual),
    }


def get_risk(risk_id: str) -> Optional[dict]:
    for r in _read_all():
        if r.get("id") == risk_id:
            return _with_scores(r)
    return None


def update_risk(risk_id: str, **changes) -> Optional[dict]:
    rows = _read_all()
    for r in rows:
        if r.get("id") != risk_id:
            continue
        for k in ("title", "description", "owner", "domain",
                    "mitigation", "status"):
            if k in changes and changes[k] is not None:
                r[k] = str(changes[k])
        for k in ("likelihood", "impact"):
            if k in changes and changes[k] is not None:
                r[k] = _validate_level(k, int(changes[k]))
        if "control_ids" in changes and changes["control_ids"] is not None:
            r["control_ids"] = list(changes["control_ids"])
        r["updated_at"] = _now()
        _write_all(rows)
        return _with_scores(r)
    return None


def delete_risk(risk_id: str) -> bool:
    rows = _read_all()
    new = [r for r in rows if r.get("id") != risk_id]
    if len(new) == len(rows):
        return False
    _write_all(new)
    return True


def summary() -> dict:
    """Heatmap counts for the /risks page."""
    rows = list_risks()
    by_band: dict[str, int] = {}
    by_status: dict[str, int] = {}
    open_residual_max = 0
    for r in rows:
        by_band[r["band_residual"]] = by_band.get(r["band_residual"], 0) + 1
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        if r["status"] == "open":
            open_residual_max = max(open_residual_max,
                                       r["residual_score"])
    return {
        "total": len(rows),
        "by_band": by_band,
        "by_status": by_status,
        "max_open_residual": open_residual_max,
    }
