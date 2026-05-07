"""Role-based access control matrix for the execution engine.

Six tiers, exactly as specified in the v7 brief:

    Viewer        — no execution, can browse compliance + briefing
    Auditor       — read-only across the whole platform
    Operator      — can run diagnostic / read-only commands
    Engineer      — can submit limited config jobs (still need approval)
    Security Admin — can approve + run remediation, can manage policies
    Super Admin   — full control with multi-approver gates on critical

The matrix here is the single source of truth. Every endpoint that
touches the execution engine calls ``can(role, capability, ...)``
before doing anything privileged. New capabilities go in this file
and nowhere else, so an operator reviewing a PR can audit every
permission change on one page.
"""

from __future__ import annotations

import enum
from typing import Iterable


class Role(str, enum.Enum):
    VIEWER         = "viewer"
    AUDITOR        = "auditor"
    OPERATOR       = "operator"
    ENGINEER       = "engineer"
    SECURITY_ADMIN = "security_admin"
    SUPER_ADMIN    = "super_admin"


class Capability(str, enum.Enum):
    # Read paths — virtually everyone has these
    VIEW_DASHBOARD            = "view_dashboard"
    VIEW_POLICIES             = "view_policies"
    VIEW_AUDIT_LOG            = "view_audit_log"
    VIEW_EXECUTIONS           = "view_executions"

    # Job authoring
    CREATE_READ_ONLY_JOB      = "create_read_only_job"
    CREATE_DIAGNOSTIC_JOB     = "create_diagnostic_job"
    CREATE_CONFIG_JOB         = "create_config_job"
    CREATE_REMEDIATION_JOB    = "create_remediation_job"
    CREATE_EMERGENCY_JOB      = "create_emergency_job"

    # Approval — separate from authoring so Engineer can't approve own work
    APPROVE_LOW_RISK          = "approve_low_risk"
    APPROVE_MEDIUM_RISK       = "approve_medium_risk"
    APPROVE_HIGH_RISK         = "approve_high_risk"
    APPROVE_CRITICAL_RISK     = "approve_critical_risk"

    # Execution — push-the-button, even though we don't actually run
    EXECUTE_DRY_RUN           = "execute_dry_run"
    EXECUTE_REAL              = "execute_real"        # never granted by default
    CANCEL_JOB                = "cancel_job"
    EMERGENCY_STOP            = "emergency_stop"

    # Rollback
    ROLLBACK_JOB              = "rollback_job"

    # Policy management
    CREATE_POLICY             = "create_policy"
    APPROVE_POLICY            = "approve_policy"
    DELETE_POLICY             = "delete_policy"

    # Asset / inventory
    MANAGE_ASSET_GROUPS       = "manage_asset_groups"
    EDIT_ASSET_METADATA       = "edit_asset_metadata"

    # Platform
    MANAGE_USERS              = "manage_users"
    MANAGE_INTEGRATIONS       = "manage_integrations"


# --------------------------------------------------------------------------
# The matrix — the only place permissions live.
# Higher tiers inherit lower-tier capabilities at the bottom of the file.
# --------------------------------------------------------------------------

_BASE_VIEWER: set[Capability] = {
    Capability.VIEW_DASHBOARD,
    Capability.VIEW_POLICIES,
}

_BASE_AUDITOR: set[Capability] = _BASE_VIEWER | {
    Capability.VIEW_AUDIT_LOG,
    Capability.VIEW_EXECUTIONS,
}

_BASE_OPERATOR: set[Capability] = _BASE_AUDITOR | {
    Capability.CREATE_READ_ONLY_JOB,
    Capability.CREATE_DIAGNOSTIC_JOB,
    Capability.EXECUTE_DRY_RUN,
    Capability.APPROVE_LOW_RISK,        # ops can self-approve diagnostics
    Capability.CANCEL_JOB,
}

_BASE_ENGINEER: set[Capability] = _BASE_OPERATOR | {
    Capability.CREATE_CONFIG_JOB,
    # APPROVE_MEDIUM_RISK is intentionally NOT here — engineers can
    # author config jobs but a Security Admin must approve them.
    Capability.MANAGE_ASSET_GROUPS,
    Capability.EDIT_ASSET_METADATA,
    Capability.CREATE_POLICY,
}

_BASE_SECURITY_ADMIN: set[Capability] = _BASE_ENGINEER | {
    Capability.CREATE_REMEDIATION_JOB,
    Capability.APPROVE_MEDIUM_RISK,
    Capability.APPROVE_HIGH_RISK,
    Capability.APPROVE_POLICY,
    Capability.ROLLBACK_JOB,
    Capability.EMERGENCY_STOP,
}

_BASE_SUPER_ADMIN: set[Capability] = _BASE_SECURITY_ADMIN | {
    Capability.CREATE_EMERGENCY_JOB,
    Capability.APPROVE_CRITICAL_RISK,
    Capability.DELETE_POLICY,
    Capability.MANAGE_USERS,
    Capability.MANAGE_INTEGRATIONS,
    # Even Super Admin does NOT get EXECUTE_REAL by default — that's
    # an operational boundary we don't cross. To enable real SSH push,
    # an operator wires SafeCadence into Ansible Tower or NSO.
}


_MATRIX: dict[Role, set[Capability]] = {
    Role.VIEWER:         _BASE_VIEWER,
    Role.AUDITOR:        _BASE_AUDITOR,
    Role.OPERATOR:       _BASE_OPERATOR,
    Role.ENGINEER:       _BASE_ENGINEER,
    Role.SECURITY_ADMIN: _BASE_SECURITY_ADMIN,
    Role.SUPER_ADMIN:    _BASE_SUPER_ADMIN,
}


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------

def capabilities_for(role: Role | str) -> set[Capability]:
    """Return the full capability set for a role string or enum."""
    if isinstance(role, str):
        try:
            role = Role(role)
        except ValueError:
            return set()
    return set(_MATRIX.get(role, set()))


def can(role: Role | str, capability: Capability) -> bool:
    """Single source of truth for 'is this allowed?' checks."""
    return capability in capabilities_for(role)


def required_role_for(capability: Capability) -> Role:
    """Return the *lowest* role that has this capability — useful for
    error messages ('this requires Engineer or higher')."""
    order = [Role.VIEWER, Role.AUDITOR, Role.OPERATOR,
             Role.ENGINEER, Role.SECURITY_ADMIN, Role.SUPER_ADMIN]
    for r in order:
        if capability in capabilities_for(r):
            return r
    return Role.SUPER_ADMIN


def approvals_needed(risk: str) -> int:
    """How many distinct approvers must say yes for this risk level.

    safe / low → 0 (auto)
    medium     → 1
    high       → 1
    critical   → 2     # two-person rule for the dangerous stuff
    """
    risk = (risk or "safe").lower()
    if risk in ("safe", "low"):
        return 0
    if risk == "critical":
        return 2
    return 1


def role_can_approve(role: Role | str, risk: str) -> bool:
    """Convenience: does this role have the capability matching this risk?"""
    risk = (risk or "safe").lower()
    cap = {
        "safe":     Capability.APPROVE_LOW_RISK,
        "low":      Capability.APPROVE_LOW_RISK,
        "medium":   Capability.APPROVE_MEDIUM_RISK,
        "high":     Capability.APPROVE_HIGH_RISK,
        "critical": Capability.APPROVE_CRITICAL_RISK,
    }.get(risk, Capability.APPROVE_CRITICAL_RISK)
    return can(role, cap)
