"""Template loader — converts YAML templates into SecurityPolicy objects."""

from __future__ import annotations

import uuid
from pathlib import Path

from safecadence.policy.schema import (
    EnforcementMode, PolicyControl, SecurityPolicy, Severity,
)

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None


def _templates_dir() -> Path:
    return Path(__file__).resolve().parent


def list_templates() -> list[dict]:
    """Return [{id, name, description, asset_types, framework_count}]."""
    out = []
    if not yaml:
        return out
    for f in sorted(_templates_dir().glob("*.yaml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        out.append({
            "id": d.get("policy_id") or f.stem,
            "name": d.get("policy_name") or f.stem,
            "description": (d.get("description") or "").strip(),
            "asset_types": d.get("target_asset_types") or [],
            "control_count": len(d.get("controls") or []),
            "frameworks": d.get("compliance_frameworks") or [],
        })
    return out


def load_template(template_id: str) -> SecurityPolicy | None:
    """Load a YAML template by id and return a SecurityPolicy."""
    if not yaml:
        raise RuntimeError("PyYAML required (pip install pyyaml)")
    for f in _templates_dir().glob("*.yaml"):
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if d.get("policy_id") == template_id or f.stem == template_id:
            return _to_policy(d)
    return None


def _to_policy(d: dict) -> SecurityPolicy:
    sev_map = {s.value: s for s in Severity}
    enf_map = {e.value: e for e in EnforcementMode}
    controls = []
    for c in (d.get("controls") or []):
        controls.append(PolicyControl(
            control_id=c.get("control_id") or "",
            description=c.get("description") or "",
            parameters=c.get("parameters") or {},
            severity=sev_map.get((c.get("severity") or "medium").lower(), Severity.MEDIUM),
            framework_refs=c.get("framework_refs") or [],
        ))
    return SecurityPolicy(
        policy_id=d.get("policy_id") or f"pol_{uuid.uuid4().hex[:8]}",
        policy_name=d.get("policy_name") or "untitled",
        description=(d.get("description") or "").strip(),
        scope=d.get("scope") or {},
        target_asset_types=d.get("target_asset_types") or [],
        # v6.4 — Builder wizard step 2 sends this list; empty = fleet-wide
        applies_to_groups=d.get("applies_to_groups") or [],
        required_state=d.get("required_state") or {},
        prohibited_state=d.get("prohibited_state") or {},
        controls=controls,
        severity=sev_map.get((d.get("severity") or "medium").lower(), Severity.MEDIUM),
        compliance_frameworks=d.get("compliance_frameworks") or [],
        enforcement_mode=enf_map.get((d.get("enforcement_mode") or "observe").lower(), EnforcementMode.OBSERVE),
        environment_variants=d.get("environment_variants") or {},
        tags=d.get("tags") or [],
        owner=d.get("owner") or "",
        source="template",
    )
