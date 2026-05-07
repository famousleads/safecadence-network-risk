"""
Universal Policy Model — vendor-neutral, JSON-serializable.

Mirrors the philosophy of platform/schema.py: every concept here is
generic across vendors. Translators handle the vendor specifics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementMode(str, Enum):
    """How a policy is treated when violations are found."""
    OBSERVE = "observe"           # report only
    WARN = "warn"                 # report + send webhook/digest
    REMEDIATE = "remediate"       # report + generate fix configs
    BLOCK = "block"               # report + open ticket + remediation


class EvaluationResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class PolicyState(str, Enum):
    """Approval-workflow state."""
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


# --------------------------------------------------------------------------
# Control — the atomic unit of a policy
# --------------------------------------------------------------------------

@dataclass
class PolicyControl:
    """
    One requirement within a policy.

    The `control_id` references a builtin or custom control implementation
    (see policy/controls/). `parameters` are inputs the control needs at
    evaluation/translation time (e.g. syslog target IP, allowed CIDR).
    """
    control_id: str = ""                       # e.g. "disable_telnet"
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.MEDIUM
    framework_refs: list[str] = field(default_factory=list)  # ["nist:AC-3", "cis:1.1"]


# --------------------------------------------------------------------------
# Exception / risk acceptance
# --------------------------------------------------------------------------

@dataclass
class PolicyException:
    """A formal exception: this asset is exempt from this control until X."""
    exception_id: str = ""
    asset_id: str = ""
    control_id: str = ""
    justification: str = ""
    approved_by: str = ""
    approved_at: str = ""
    expires_at: str = ""
    status: str = "active"                    # active | expired | revoked


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

@dataclass
class SecurityPolicy:
    policy_id: str = ""
    policy_name: str = ""
    description: str = ""
    version: int = 1
    scope: dict[str, Any] = field(default_factory=dict)        # filters: vendor, env, tags
    # v6.4 — explicit asset-group targeting. When set, only assets that
    # belong to one of these named groups are evaluated. When empty,
    # falls back to the legacy `scope` filter (whole-fleet evaluation).
    applies_to_groups: list[str] = field(default_factory=list)
    target_asset_types: list[str] = field(default_factory=list)
    required_state: dict[str, Any] = field(default_factory=dict)
    prohibited_state: dict[str, Any] = field(default_factory=dict)
    controls: list[PolicyControl] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    compliance_frameworks: list[str] = field(default_factory=list)  # ["nist-800-53", "cis", "pci"]
    enforcement_mode: EnforcementMode = EnforcementMode.OBSERVE
    state: PolicyState = PolicyState.DRAFT
    environment_variants: dict[str, dict[str, Any]] = field(default_factory=dict)
    exceptions: list[PolicyException] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    owner: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    source: str = "ui"                        # ui | git | nl | template | cve

    # ----- helpers -----
    def applies_to(self, asset: dict,
                   *, group_member_cache: set[str] | None = None) -> bool:
        """Decide whether this policy targets the given UnifiedAsset dict.

        v6.4: ``applies_to_groups`` (resolved into ``group_member_cache``
        by the evaluator) takes precedence — when populated, the asset
        must be a member of one of the named groups. The legacy
        ``scope`` filter still applies as an additional narrowing pass,
        so an operator can say "Cisco edge group AND environment=prod".
        """
        ident = asset.get("identity") or {}
        atype = ident.get("asset_type")
        if self.target_asset_types and atype not in self.target_asset_types:
            return False
        if self.applies_to_groups:
            # Caller is expected to pre-resolve group membership for
            # performance — see evaluate() in policy/evaluator.py.
            if group_member_cache is None:
                from safecadence.policy.asset_groups import asset_ids_in_groups
                # Slow path — used by ad-hoc CLI usage where we don't
                # have the full asset list to pre-resolve. Returns an
                # empty set if no asset list is available, which then
                # rejects every asset (safe fail).
                group_member_cache = set()
            if (ident.get("asset_id") or "") not in group_member_cache:
                return False
        scope = self.scope or {}
        if scope.get("vendor") and (ident.get("vendor", "").lower()
                                    not in [v.lower() for v in scope["vendor"]]):
            return False
        if scope.get("environment") and (ident.get("environment")
                                         not in scope["environment"]):
            return False
        if scope.get("asset_ids") and ident.get("asset_id") not in scope["asset_ids"]:
            return False
        if scope.get("tags"):
            atags = set(asset.get("tags", []) or [])
            if not (set(scope["tags"]) & atags):
                return False
        return True

    def control_for_asset(self, control_id: str, asset: dict) -> PolicyControl | None:
        """Resolve a control's effective parameters for an asset, applying env variants."""
        base = next((c for c in self.controls if c.control_id == control_id), None)
        if not base:
            return None
        env = ((asset.get("identity") or {}).get("environment") or "").lower()
        variant = (self.environment_variants or {}).get(env, {})
        if control_id in variant:
            merged = PolicyControl(
                control_id=base.control_id,
                description=base.description,
                parameters={**base.parameters, **variant[control_id]},
                severity=base.severity,
                framework_refs=list(base.framework_refs),
            )
            return merged
        return base


# --------------------------------------------------------------------------
# Violation + Evaluation + Remediation
# --------------------------------------------------------------------------

@dataclass
class PolicyViolation:
    violation_id: str = ""
    policy_id: str = ""
    control_id: str = ""
    asset_id: str = ""
    severity: Severity = Severity.MEDIUM
    message: str = ""
    evidence: str = ""                        # what we found / what's missing
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    framework_refs: list[str] = field(default_factory=list)
    exception_id: str = ""                    # populated if covered by an exception
    status: str = "open"                      # open | acknowledged | accepted | resolved

    def serialize(self) -> dict:
        return {
            "violation_id": self.violation_id, "policy_id": self.policy_id,
            "control_id": self.control_id, "asset_id": self.asset_id,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "message": self.message, "evidence": self.evidence,
            "detected_at": self.detected_at, "framework_refs": self.framework_refs,
            "exception_id": self.exception_id, "status": self.status,
        }


@dataclass
class PolicyEvaluation:
    evaluation_id: str = ""
    policy_id: str = ""
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    asset_results: list[dict] = field(default_factory=list)   # [{asset_id, result, controls:{cid:result}}]
    violations: list[PolicyViolation] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    coverage_pct: float = 0.0


@dataclass
class RemediationStep:
    """One concrete fix step for one (asset, control) pair."""
    asset_id: str = ""
    control_id: str = ""
    vendor_target: str = ""                    # "cisco_ios", "linux", etc.
    fix_commands: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    verify_commands: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    notes: str = ""


@dataclass
class RemediationPlan:
    plan_id: str = ""
    policy_id: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    steps: list[RemediationStep] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
