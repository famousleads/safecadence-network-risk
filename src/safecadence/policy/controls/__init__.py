"""
Control library — atomic security requirements that policies compose.

Each control implements:
  - id          — stable string used in policy YAML
  - description — human-readable
  - applies_to  — which asset types it's relevant for
  - check       — given an asset + parameters, return PASS/FAIL/NA + evidence
  - frameworks  — default framework references

Controls are pure-Python and have no I/O. They run on already-collected
UnifiedAsset dicts, so they work identically on Windows, Linux, and Mac.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from safecadence.policy.schema import EvaluationResult, Severity


@dataclass
class ControlSpec:
    id: str
    description: str
    applies_to: list[str]                      # asset types
    severity: Severity = Severity.MEDIUM
    frameworks: list[str] = field(default_factory=list)
    check_fn: Callable[[dict, dict], tuple[EvaluationResult, str]] = lambda a, p: (EvaluationResult.UNKNOWN, "")


_REGISTRY: dict[str, ControlSpec] = {}


def register_control(spec: ControlSpec) -> ControlSpec:
    _REGISTRY[spec.id] = spec
    return spec


def get_control(control_id: str) -> ControlSpec | None:
    return _REGISTRY.get(control_id)


def all_controls() -> list[ControlSpec]:
    return sorted(_REGISTRY.values(), key=lambda c: c.id)


# Auto-load all built-in control modules.
from safecadence.policy.controls import network    # noqa: E402,F401
from safecadence.policy.controls import server     # noqa: E402,F401
from safecadence.policy.controls import cloud      # noqa: E402,F401
from safecadence.policy.controls import storage    # noqa: E402,F401
from safecadence.policy.controls import backup     # noqa: E402,F401
# v6.4.2 — identity controls (closes the v6.0 Identity Engine gap
# where the wizard listed Identity/NAC but suggested zero controls)
from safecadence.policy.controls import identity   # noqa: E402,F401
