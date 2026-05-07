"""
v9.27 — control framework mapping loader + coverage math.

Reads ``data/control_mappings.yaml`` and answers:
  * which frameworks does SafeCadence map against?
  * for a given framework, which control IDs do we cover, via
    which SafeCadence controls?
  * for a given SafeCadence control, what does it satisfy?

Coverage is a SET — one SafeCadence control covers many framework
control IDs, and one framework ID may be covered by multiple
SafeCadence controls. We dedupe at the framework-ID level.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


_FRAMEWORKS = {
    "nist_800_53":     "NIST 800-53 r5",
    "cis_v8":          "CIS Controls v8",
    "pci_dss_4":       "PCI-DSS 4.0",
    "hipaa":           "HIPAA Security Rule",
    "iso_27001_2022":  "ISO 27001:2022",
    "soc2_tsc":        "SOC 2 Trust Services Criteria",
}


_CACHE: dict | None = None
_CACHE_PATH: Path | None = None


def _data_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / \
        "control_mappings.yaml"


def load_mappings(path: Path | None = None,
                    force_reload: bool = False) -> dict[str, dict]:
    """Load + cache the control mappings YAML. Returns
    ``{control_id: entry_dict, ...}``."""
    global _CACHE, _CACHE_PATH
    target = path or _data_path()
    if not force_reload and _CACHE is not None and _CACHE_PATH == target:
        return _CACHE
    try:
        import yaml
    except ImportError:                                  # pragma: no cover
        _CACHE, _CACHE_PATH = {}, target
        return _CACHE
    if not target.exists():
        _CACHE, _CACHE_PATH = {}, target
        return _CACHE
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raw = {}
    _CACHE, _CACHE_PATH = raw, target
    return _CACHE


def list_frameworks() -> list[dict]:
    """Return the list of frameworks we ship mappings for, with
    coverage counts so the UI can render the picker."""
    out: list[dict] = []
    mappings = load_mappings()
    for key, label in _FRAMEWORKS.items():
        ids: set[str] = set()
        sc_controls: set[str] = set()
        for sc_id, entry in mappings.items():
            for fid in entry.get(key, []) or []:
                ids.add(str(fid))
                sc_controls.add(sc_id)
        out.append({
            "key": key,
            "label": label,
            "covered_control_ids": sorted(ids),
            "safecadence_controls": sorted(sc_controls),
            "covered_count": len(ids),
            "safecadence_count": len(sc_controls),
        })
    return out


def coverage(framework_key: str) -> dict:
    """Return the mapping table for one framework, suitable for the
    coverage matrix page.

    Shape::

        {
          "framework": "NIST 800-53 r5",
          "key": "nist_800_53",
          "covered": [
            {"framework_id": "AC-2",
              "safecadence_controls": ["require_aaa","enforce_mfa",...]},
            ...
          ],
          "uncovered_hint": "Common framework IDs we don't yet cover"
        }
    """
    if framework_key not in _FRAMEWORKS:
        return {"framework": framework_key, "key": framework_key,
                "covered": [], "error": "unknown framework"}

    mappings = load_mappings()
    rev: dict[str, set[str]] = {}
    for sc_id, entry in mappings.items():
        for fid in entry.get(framework_key, []) or []:
            rev.setdefault(str(fid), set()).add(sc_id)

    covered = [
        {"framework_id": fid,
          "safecadence_controls": sorted(rev[fid])}
        for fid in sorted(rev)
    ]

    return {
        "framework": _FRAMEWORKS[framework_key],
        "key": framework_key,
        "covered": covered,
        "covered_count": len(covered),
    }


def control_detail(control_id: str) -> dict:
    """Return everything we know about one SafeCadence control."""
    mappings = load_mappings()
    entry = mappings.get(control_id)
    if not entry:
        return {"control_id": control_id, "error": "unknown control"}
    return {"control_id": control_id, **entry}


def framework_detail(framework_key: str) -> dict:
    """Top-level summary for one framework — label + coverage rollup."""
    if framework_key not in _FRAMEWORKS:
        return {"key": framework_key, "error": "unknown framework"}
    cov = coverage(framework_key)
    return {
        "key": framework_key,
        "framework": _FRAMEWORKS[framework_key],
        "covered_count": cov["covered_count"],
        "controls": cov["covered"],
    }


def all_metadata_for_control(control_id: str) -> dict:
    """Pull the metadata fields (owner, SLA, frequency, evidence type)
    a policy or evidence pack should display alongside the control."""
    entry = load_mappings().get(control_id) or {}
    return {
        "control_id": control_id,
        "description": entry.get("description", control_id),
        "domain": entry.get("domain", "general"),
        "owner_default": entry.get("owner_default", "secops"),
        "sla_severity_days": entry.get("sla_severity_days") or
            {"critical": 7, "high": 30, "medium": 90, "low": 180},
        "frequency": entry.get("frequency", "continuous"),
        "evidence_type": entry.get("evidence_type", "config_snapshot"),
    }
