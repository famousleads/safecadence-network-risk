"""Compliance framework mappings — load YAML, query control → framework refs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None


def _frameworks_dir() -> Path:
    return Path(__file__).resolve().parent


def load_mappings() -> dict[str, dict[str, list[str]]]:
    """Return {control_id: {framework_name: [refs]}}."""
    if not yaml:
        return {}
    f = _frameworks_dir() / "mappings.yaml"
    if not f.exists():
        return {}
    return yaml.safe_load(f.read_text(encoding="utf-8")) or {}


def control_framework_refs(control_id: str) -> list[str]:
    """Flat list like ['nist:AC-3', 'cis:5.2.1']."""
    out: list[str] = []
    for fw, refs in load_mappings().get(control_id, {}).items():
        prefix = fw.replace("-800-53", "").replace("-dss", "").split("-")[0]
        for r in refs:
            out.append(f"{prefix}:{r}")
    return out


def framework_coverage(framework: str, all_controls: list[str]) -> dict[str, list[str]]:
    """For a framework name, return {framework_ref: [control_ids covering it]}."""
    out: dict[str, list[str]] = {}
    mappings = load_mappings()
    for cid in all_controls:
        for fw, refs in mappings.get(cid, {}).items():
            if fw != framework:
                continue
            for r in refs:
                out.setdefault(r, []).append(cid)
    return out
