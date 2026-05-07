"""
v7.5 — Unified Policy IR (intermediate representation).

One representation of intent that maps cleanly onto ISE authz rules,
ClearPass enforcement profiles, AD GPO settings, Entra Conditional
Access policies, and Okta group rules. Designed so the same IR can be:

  * authored by a human (typing JSON)
  * authored by AI (NL → IR via `ai_translator`)
  * evaluated against the live graph (`effective_permissions.decide`)
  * compiled to per-system changes (each adapter's `apply_policy`)

All dataclasses are JSON-stable: `dataclasses.asdict()` round-trips.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


VALID_EFFECTS = {"allow", "deny", "require_step_up"}
VALID_SEVERITIES = {"advisory", "warn", "enforce"}
VALID_TARGETS = {"okta", "ise", "clearpass", "ad", "entra", "all"}


@dataclass
class PrincipalSelector:
    """Who this policy applies to. Any of these match by union."""
    principals: list[str] = field(default_factory=list)        # explicit user IDs / NHI IDs
    groups: list[str] = field(default_factory=list)            # AD / Okta / ISE groups
    roles: list[str] = field(default_factory=list)             # Entra roles, Okta roles
    tags: list[str] = field(default_factory=list)              # SafeCadence asset tags
    nhi_subtypes: list[str] = field(default_factory=list)      # service_account, iam_role, ...
    exclude_principals: list[str] = field(default_factory=list)


@dataclass
class ResourceSelector:
    """What resources the policy targets. Matches against UnifiedAsset graph."""
    asset_ids: list[str] = field(default_factory=list)
    asset_types: list[str] = field(default_factory=list)       # network | server | identity | ...
    environments: list[str] = field(default_factory=list)      # prod | staging | dev
    criticalities: list[str] = field(default_factory=list)     # crown-jewel | high | ...
    tags: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)


@dataclass
class Condition:
    """A single conditional check. AND-composed with siblings."""
    kind: str                                                   # mfa_required | posture_compliant
                                                                # | time_window | device_trusted
                                                                # | session_age_max | risk_score_max
    value: Any = None                                           # condition-specific
    negate: bool = False


@dataclass
class UnifiedPolicyIR:
    """The portable intent. Validates, persists, evaluates, compiles."""
    intent: str = ""                                            # original NL, preserved
    subjects: PrincipalSelector = field(default_factory=PrincipalSelector)
    resources: ResourceSelector = field(default_factory=ResourceSelector)
    actions: list[str] = field(default_factory=list)            # ssh, http, rdp, read, ...
    conditions: list[Condition] = field(default_factory=list)
    effect: str = "deny"
    severity: str = "enforce"
    targets: list[str] = field(default_factory=lambda: ["all"])
    # Provenance
    author: str = ""                                            # 'ai' | 'human' | username
    ai_model: str = ""                                          # populated when author == 'ai'

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


@dataclass
class Rule:
    """A single rule in a Decision chain — what fired, where it came from."""
    system: str                                                 # ise | ad | entra | okta | clearpass
    rule_id: str
    rule_name: str
    effect: str                                                 # allow | deny | step_up
    matched_on: list[str] = field(default_factory=list)         # ['group:Contractors', 'mfa:false']


@dataclass
class Decision:
    """Effective-permission resolver output."""
    allowed: bool
    chain: list[Rule] = field(default_factory=list)
    systems_consulted: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)            # human-readable
    requires_step_up: bool = False
    principal: str = ""
    action: str = ""
    resource: str = ""


# ---------------------------------------------------------------- validation

class IRValidationError(ValueError):
    """Raised when an IR document fails schema or semantic validation."""


def validate_ir(doc: dict) -> UnifiedPolicyIR:
    """Validate a JSON-shaped IR dict, return a typed UnifiedPolicyIR.

    Strict by design — the AI's NL→IR step has to produce something we
    can confidently evaluate and compile. We refuse anything we don't
    fully recognize so a malformed IR cannot be applied.
    """
    if not isinstance(doc, dict):
        raise IRValidationError("IR must be a JSON object")

    effect = doc.get("effect", "deny")
    if effect not in VALID_EFFECTS:
        raise IRValidationError(
            f"effect={effect!r} not in {sorted(VALID_EFFECTS)}")

    severity = doc.get("severity", "enforce")
    if severity not in VALID_SEVERITIES:
        raise IRValidationError(
            f"severity={severity!r} not in {sorted(VALID_SEVERITIES)}")

    targets = doc.get("targets") or ["all"]
    if not isinstance(targets, list) or not targets:
        raise IRValidationError("targets must be a non-empty list")
    for t in targets:
        if t not in VALID_TARGETS:
            raise IRValidationError(
                f"target={t!r} not in {sorted(VALID_TARGETS)}")

    actions = doc.get("actions") or []
    if not isinstance(actions, list) or not actions:
        raise IRValidationError("actions must be a non-empty list")

    subjects_raw = doc.get("subjects") or {}
    if not isinstance(subjects_raw, dict):
        raise IRValidationError("subjects must be an object")
    subjects = PrincipalSelector(
        principals=list(subjects_raw.get("principals") or []),
        groups=list(subjects_raw.get("groups") or []),
        roles=list(subjects_raw.get("roles") or []),
        tags=list(subjects_raw.get("tags") or []),
        nhi_subtypes=list(subjects_raw.get("nhi_subtypes") or []),
        exclude_principals=list(subjects_raw.get("exclude_principals") or []),
    )
    # subjects must select someone or something
    if not any([subjects.principals, subjects.groups, subjects.roles,
                subjects.tags, subjects.nhi_subtypes]):
        raise IRValidationError(
            "subjects must select at least one of: principals, groups, "
            "roles, tags, nhi_subtypes")

    resources_raw = doc.get("resources") or {}
    if not isinstance(resources_raw, dict):
        raise IRValidationError("resources must be an object")
    resources = ResourceSelector(
        asset_ids=list(resources_raw.get("asset_ids") or []),
        asset_types=list(resources_raw.get("asset_types") or []),
        environments=list(resources_raw.get("environments") or []),
        criticalities=list(resources_raw.get("criticalities") or []),
        tags=list(resources_raw.get("tags") or []),
        sites=list(resources_raw.get("sites") or []),
    )

    conditions_raw = doc.get("conditions") or []
    if not isinstance(conditions_raw, list):
        raise IRValidationError("conditions must be a list")
    conditions: list[Condition] = []
    for c in conditions_raw:
        if not isinstance(c, dict) or "kind" not in c:
            raise IRValidationError(f"malformed condition: {c!r}")
        conditions.append(Condition(
            kind=str(c["kind"]),
            value=c.get("value"),
            negate=bool(c.get("negate", False)),
        ))

    return UnifiedPolicyIR(
        intent=str(doc.get("intent") or ""),
        subjects=subjects,
        resources=resources,
        actions=[str(a) for a in actions],
        conditions=conditions,
        effect=effect,
        severity=severity,
        targets=[str(t) for t in targets],
        author=str(doc.get("author") or ""),
        ai_model=str(doc.get("ai_model") or ""),
    )
