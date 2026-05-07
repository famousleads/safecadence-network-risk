"""
User-defined custom controls — loaded from YAML at
~/.safecadence/custom_controls/*.yaml so they survive package upgrades.

Each YAML file looks like:

    id: my_org_no_motd_password_hint
    description: MOTD must not include any password-like hint
    applies_to: [network]
    severity: medium
    pattern: '(?i)password\\s*(=|is|hint)'
    expected: absent          # 'absent' or 'present'
    frameworks: ['nist:AC-8']
    remediation:
      cisco_ios:
        fix: ['banner motd ^AUTHORIZED USE ONLY^']
        rollback: ['no banner motd']
        verify: ['show running-config | include banner']

The loader registers each into the central control registry so the
evaluator and translators see them just like built-in controls.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.controls.network import _config_text
from safecadence.policy.schema import EvaluationResult, Severity


def _custom_dir() -> Path:
    p = Path.home() / ".safecadence" / "custom_controls"
    p.mkdir(parents=True, exist_ok=True)
    return p


# Registry of (control_id → vendor_target → {fix, rollback, verify}) for
# the translator-side hooking of custom controls.
_CUSTOM_REMEDIATION: dict[str, dict[str, dict]] = {}


def custom_remediation(control_id: str, vendor_target: str) -> dict | None:
    return _CUSTOM_REMEDIATION.get(control_id, {}).get(vendor_target)


def _build_check(pattern: str, expected: str):
    rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE) if pattern else None

    def _check(asset: dict, params: dict):
        cfg = _config_text(asset)
        if not cfg:
            return EvaluationResult.UNKNOWN, "no config text collected"
        present = bool(rx and rx.search(cfg))
        if expected == "absent":
            return ((EvaluationResult.PASS, "pattern absent (good)") if not present
                    else (EvaluationResult.FAIL, "pattern present (forbidden)"))
        # expected = present
        return ((EvaluationResult.PASS, "pattern present (good)") if present
                else (EvaluationResult.FAIL, "pattern absent (required)"))
    return _check


def load_custom_controls() -> list[str]:
    """Load all custom-control YAMLs and register them. Returns the IDs."""
    if not yaml:
        return []
    loaded: list[str] = []
    for f in sorted(_custom_dir().glob("*.yaml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        cid = d.get("id")
        if not cid:
            continue
        sev = {s.value: s for s in Severity}.get(
            (d.get("severity") or "medium").lower(), Severity.MEDIUM)
        spec = ControlSpec(
            id=cid,
            description=d.get("description", "(custom control)"),
            applies_to=d.get("applies_to", ["network"]),
            severity=sev,
            frameworks=d.get("frameworks") or [],
            check_fn=_build_check(d.get("pattern", ""), d.get("expected", "absent")),
        )
        register_control(spec)
        if d.get("remediation"):
            _CUSTOM_REMEDIATION[cid] = d["remediation"]
        loaded.append(cid)
    return loaded


# auto-load any custom controls present at import time
load_custom_controls()
