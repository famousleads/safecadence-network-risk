"""
v9.32 — Vendor risk tracking.

Track third-party vendors (cloud providers, SaaS platforms, hardware
suppliers) and their security attestations. Auditors care about
fourth-party risk; SOC 2 CC9, ISO 27001 A.5.19/.20/.22 ask for it.

Schema per vendor:
  id, name, category, criticality, attestations[] (SOC2 / ISO27001 /
  PCI / HITRUST / FedRAMP / etc., each with type + status + expires_at),
  contact, residual_risk (low|medium|high|critical), notes.

Storage: file-backed JSON at $SC_DATA_DIR/vendor_risk.json.

The /vendors page reads + writes via the existing platform API. The
auditor portal already includes vendor risk in scope by default.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_VALID_CATEGORIES = ("cloud", "saas", "hardware", "msp",
                       "data_processor", "other")
_VALID_RISK = ("low", "medium", "high", "critical")
_VALID_ATTESTATION_TYPES = (
    "soc2_type1", "soc2_type2", "iso27001", "pci_dss",
    "hipaa", "fedramp_moderate", "fedramp_high", "hitrust",
    "iso27017", "iso27018", "csa_star", "other",
)
_VALID_ATTESTATION_STATUS = ("active", "expired", "in_progress",
                                "not_attested")


def _store() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "vendor_risk.json"


def _read_all() -> list[dict]:
    p = _store()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write_all(rows: list[dict]) -> None:
    _store().write_text(json.dumps(rows, indent=2), encoding="utf-8")


@dataclass
class Vendor:
    id: str
    name: str
    category: str
    criticality: str          # low | medium | high | critical
    contact: str = ""
    residual_risk: str = "medium"
    attestations: list[dict] = field(default_factory=list)
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_vendor(*, name: str, category: str, criticality: str,
                    contact: str = "", residual_risk: str = "medium",
                    notes: str = "") -> Vendor:
    name = (name or "").strip()
    if len(name) < 2:
        raise ValueError("name is required")
    if category not in _VALID_CATEGORIES:
        raise ValueError(f"category must be one of {_VALID_CATEGORIES}")
    if criticality not in _VALID_RISK:
        raise ValueError(f"criticality must be one of {_VALID_RISK}")
    if residual_risk not in _VALID_RISK:
        raise ValueError(f"residual_risk must be one of {_VALID_RISK}")
    rec = Vendor(
        id=f"ven-{uuid.uuid4().hex[:12]}",
        name=name, category=category, criticality=criticality,
        contact=contact.strip(), residual_risk=residual_risk,
        notes=notes.strip(),
        created_at=_now(), updated_at=_now(),
    )
    rows = _read_all()
    rows.append(rec.to_dict())
    _write_all(rows)
    return rec


def list_vendors() -> list[dict]:
    return _read_all()


def get_vendor(vendor_id: str) -> Optional[dict]:
    for r in _read_all():
        if r.get("id") == vendor_id:
            return r
    return None


def add_attestation(vendor_id: str, *, type: str,
                      status: str = "active",
                      expires_at: Optional[str] = None,
                      doc_url: str = "") -> Optional[dict]:
    if type not in _VALID_ATTESTATION_TYPES:
        raise ValueError(f"type must be one of {_VALID_ATTESTATION_TYPES}")
    if status not in _VALID_ATTESTATION_STATUS:
        raise ValueError(f"status must be one of {_VALID_ATTESTATION_STATUS}")
    rows = _read_all()
    for r in rows:
        if r.get("id") != vendor_id:
            continue
        rec = {"type": type, "status": status,
                "expires_at": expires_at or "",
                "doc_url": doc_url, "added_at": _now()}
        r.setdefault("attestations", []).append(rec)
        r["updated_at"] = _now()
        _write_all(rows)
        return rec
    return None


def delete_vendor(vendor_id: str) -> bool:
    rows = _read_all()
    new = [r for r in rows if r.get("id") != vendor_id]
    if len(new) == len(rows):
        return False
    _write_all(new)
    return True


def expiring_attestations(within_days: int = 60) -> list[dict]:
    """Find attestations whose expires_at falls within the window —
    feeds /home / morning briefing so renewals don't sneak up."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc)
                + timedelta(days=within_days)).isoformat()
    out: list[dict] = []
    for v in _read_all():
        for a in v.get("attestations") or []:
            exp = a.get("expires_at") or ""
            if exp and exp <= cutoff and a.get("status") == "active":
                out.append({
                    "vendor_id": v.get("id"),
                    "vendor_name": v.get("name"),
                    "type": a.get("type"),
                    "expires_at": exp,
                })
    out.sort(key=lambda r: r.get("expires_at", ""))
    return out


def summary() -> dict:
    vendors = _read_all()
    by_cat: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for v in vendors:
        by_cat[v.get("category", "other")] = by_cat.get(
            v.get("category", "other"), 0) + 1
        by_risk[v.get("residual_risk", "medium")] = by_risk.get(
            v.get("residual_risk", "medium"), 0) + 1
    return {
        "total": len(vendors),
        "by_category": by_cat,
        "by_residual_risk": by_risk,
        "expiring_60d": len(expiring_attestations(within_days=60)),
    }
