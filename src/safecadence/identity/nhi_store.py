"""
v9.34 #5 — Non-human identity store + lifecycle.

JSON-backed NHI registry. One file per NHI under
``$SC_DATA_DIR/nhi/<nhi_id>.json``. Mutations go through this module
so the daemon's stale-NHI hook and the /identity NHI tab read from a
single source of truth.

Lifecycle operations the operator drives from the UI:
  * register   — add an NHI manually (UI form) or via sync from a
                 connected system.
  * attest     — owner has reviewed scope + necessity ("yes, this
                 still needs to exist as configured").
  * rotate     — credential was rotated. Resets last_rotated_at and
                 the rotation-due clock.
  * mark_used  — bumps last_used_at. Sync is the typical caller.
  * deprecate  — flagged for removal but kept for the audit trail.

Stale-NHI detection (read by the daemon hook + /findings):
  * stale_unused_days — default 90 — last_used_at older than that
    triggers a "stale NHI" finding.
  * overdue_rotation — last_rotated_at + rotation_policy_days in the
    past triggers an "overdue rotation" finding.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# Match the safe-asset-id regex used elsewhere — same characters so
# we can reuse the platform store path resolver semantics.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._\-:@]+$")
_DEFAULT_STALE_DAYS = 90


def _store_dir() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(
        Path.home() / ".safecadence"
    )
    p = Path(base) / "nhi"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _path(nhi_id: str) -> Path:
    if not _SAFE_ID.match(nhi_id or ""):
        raise ValueError(f"invalid nhi_id {nhi_id!r}")
    return _store_dir() / f"{nhi_id}.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NHIRecord:
    """Operationally-focused NHI record. The full
    ``platform.schema.NonHumanIdentity`` dataclass has more fields
    but for v9.34 we persist the subset the lifecycle workflow uses."""
    nhi_id: str
    name: str
    subtype: str = "service_account"   # see platform.schema.NonHumanIdentity
    provider: str = ""                 # okta | aws | azure | ad | …
    owner: str = ""                    # email or principal id
    attested_at: str = ""
    attested_by: str = ""
    last_used_at: str = ""
    last_rotated_at: str = ""
    rotation_policy_days: int = 0
    notes: str = ""
    deprecated: bool = False
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)


# --------------------------------------------------------- CRUD


def register(*, name: str, subtype: str = "service_account",
              provider: str = "", owner: str = "",
              rotation_policy_days: int = 0,
              notes: str = "") -> NHIRecord:
    """Create a new NHI. Generates a stable id and persists. The id
    is uuid-derived rather than hostname-derived so renaming an NHI
    doesn't break audit-trail joins."""
    if not name or not isinstance(name, str):
        raise ValueError("name is required")
    nhi_id = "nhi-" + uuid.uuid4().hex[:12]
    rec = NHIRecord(
        nhi_id=nhi_id, name=name.strip(),
        subtype=subtype, provider=provider, owner=owner,
        rotation_policy_days=int(rotation_policy_days or 0),
        notes=notes,
    )
    _path(nhi_id).write_text(json.dumps(asdict(rec), indent=2),
                              encoding="utf-8")
    return rec


def get(nhi_id: str) -> Optional[NHIRecord]:
    p = _path(nhi_id)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return NHIRecord(**{k: d.get(k, getattr(NHIRecord, k, ""))
                              for k in NHIRecord.__dataclass_fields__})
    except Exception:
        return None


def list_all() -> list[NHIRecord]:
    out: list[NHIRecord] = []
    for f in sorted(_store_dir().glob("nhi-*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            out.append(NHIRecord(**{
                k: d.get(k, getattr(NHIRecord, k, ""))
                for k in NHIRecord.__dataclass_fields__
            }))
        except Exception:
            continue
    return out


def _save(rec: NHIRecord) -> NHIRecord:
    rec.updated_at = _now_iso()
    _path(rec.nhi_id).write_text(json.dumps(asdict(rec), indent=2),
                                   encoding="utf-8")
    return rec


def attest(nhi_id: str, *, by: str) -> NHIRecord:
    rec = get(nhi_id)
    if rec is None:
        raise KeyError(nhi_id)
    rec.attested_at = _now_iso()
    rec.attested_by = by
    return _save(rec)


def rotate(nhi_id: str) -> NHIRecord:
    rec = get(nhi_id)
    if rec is None:
        raise KeyError(nhi_id)
    rec.last_rotated_at = _now_iso()
    return _save(rec)


def mark_used(nhi_id: str, *, when: Optional[str] = None) -> NHIRecord:
    rec = get(nhi_id)
    if rec is None:
        raise KeyError(nhi_id)
    rec.last_used_at = when or _now_iso()
    return _save(rec)


def deprecate(nhi_id: str) -> NHIRecord:
    rec = get(nhi_id)
    if rec is None:
        raise KeyError(nhi_id)
    rec.deprecated = True
    return _save(rec)


# --------------------------------------------------------- stale-finder


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def stale_findings(*, stale_unused_days: int = _DEFAULT_STALE_DAYS,
                     now: Optional[datetime] = None) -> list[dict]:
    """Return a list of finding dicts for stale or rotation-overdue
    NHIs. The shape is compatible with the existing /findings surface."""
    now = now or datetime.now(timezone.utc)
    out: list[dict] = []
    for rec in list_all():
        if rec.deprecated:
            continue
        last_used = _parse_iso(rec.last_used_at)
        if last_used is None:
            # Never used.  A registered NHI that has never been used is
            # itself worth surfacing — operator should attest or
            # deprecate. We mark it stale at registration_age.
            ref = _parse_iso(rec.created_at) or now
            age_days = (now - ref).days
            if age_days >= stale_unused_days:
                out.append({
                    "finding_id": f"nhi-stale:{rec.nhi_id}",
                    "kind": "nhi_stale",
                    "severity": "medium" if age_days < 180 else "high",
                    "title": f"NHI {rec.name} unused for {age_days} days",
                    "principal": rec.nhi_id,
                    "evidence": {"last_used_at": rec.last_used_at,
                                  "created_at": rec.created_at,
                                  "age_days": age_days},
                    "suggested_ir": {},
                })
        else:
            age_days = (now - last_used).days
            if age_days >= stale_unused_days:
                out.append({
                    "finding_id": f"nhi-stale:{rec.nhi_id}",
                    "kind": "nhi_stale",
                    "severity": "medium" if age_days < 180 else "high",
                    "title": f"NHI {rec.name} unused for {age_days} days",
                    "principal": rec.nhi_id,
                    "evidence": {"last_used_at": rec.last_used_at,
                                  "age_days": age_days},
                    "suggested_ir": {},
                })
        # Rotation overdue.
        if rec.rotation_policy_days > 0 and rec.last_rotated_at:
            last_rot = _parse_iso(rec.last_rotated_at)
            if last_rot is not None:
                due_at = last_rot + timedelta(days=rec.rotation_policy_days)
                if now > due_at:
                    overdue_days = (now - due_at).days
                    out.append({
                        "finding_id": f"nhi-rotation:{rec.nhi_id}",
                        "kind": "nhi_rotation_overdue",
                        "severity": "medium" if overdue_days < 30 else "high",
                        "title": (f"NHI {rec.name} has not been rotated "
                                   f"({overdue_days} days overdue)"),
                        "principal": rec.nhi_id,
                        "evidence": {
                            "last_rotated_at": rec.last_rotated_at,
                            "rotation_policy_days": rec.rotation_policy_days,
                            "overdue_days": overdue_days,
                        },
                        "suggested_ir": {},
                    })
    return out
