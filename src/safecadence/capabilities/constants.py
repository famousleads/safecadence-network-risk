"""v9.48 — Capability constants + role floor.

Adding a new capability:
  1. Add the constant to ``Capability``.
  2. Add a sentence-long description to ``DESCRIPTIONS``.
  3. Decide which roles get it by default in ``ROLE_FLOOR``.
  4. Wire ``require_capability(Capability.X)`` on the route(s).

Removing a capability is a breaking change — leave the constant in
place and remove the role-floor entry instead, so existing per-user
grants keep round-tripping cleanly.
"""

from __future__ import annotations

from typing import Final


class Capability:
    """Namespace of capability string keys.

    Don't use a real Enum — capability names are stored as plain
    strings on disk and over the wire, and we want the YAML to
    round-trip without coercion."""

    # ---------- read paths ----------
    READ_ASSET: Final[str] = "read.asset"
    READ_FINDING: Final[str] = "read.finding"
    READ_POLICY: Final[str] = "read.policy"
    READ_AUDIT: Final[str] = "read.audit"
    READ_ACTIVITY: Final[str] = "read.activity"
    READ_IDENTITY: Final[str] = "read.identity"

    # ---------- write paths ----------
    WRITE_ASSET: Final[str] = "write.asset"
    WRITE_POLICY: Final[str] = "write.policy"
    WRITE_GROUP: Final[str] = "write.group"
    WRITE_TAG: Final[str] = "write.tag"
    WRITE_RISK: Final[str] = "write.risk"
    WRITE_EXCEPTION: Final[str] = "write.exception"
    WRITE_WATCHLIST: Final[str] = "write.watchlist"
    WRITE_AUTOMATION: Final[str] = "write.automation"

    # ---------- approval / execute ----------
    SUBMIT_JOB: Final[str] = "execute.submit"
    APPROVE_JOB: Final[str] = "execute.approve"
    EXECUTE_REAL: Final[str] = "execute.real"
    EXECUTE_ROLLBACK: Final[str] = "execute.rollback"
    GRANT_JIT: Final[str] = "execute.grant_jit"

    # ---------- identity write-back ----------
    APPLY_IDENTITY_DRY_RUN: Final[str] = "identity.apply.dry_run"
    APPLY_IDENTITY_COMMIT: Final[str] = "identity.apply.commit"
    MANAGE_IDENTITY_VAULT: Final[str] = "identity.vault"

    # ---------- admin ----------
    MANAGE_USERS: Final[str] = "admin.users"
    MANAGE_CAPABILITIES: Final[str] = "admin.capabilities"
    MANAGE_WEBHOOKS: Final[str] = "admin.webhooks"
    MANAGE_SETTINGS: Final[str] = "admin.settings"


# Human-readable descriptions for the /users#capabilities tab.
DESCRIPTIONS: dict[str, str] = {
    Capability.READ_ASSET: "View assets and inventory",
    Capability.READ_FINDING: "View findings and remediation suggestions",
    Capability.READ_POLICY: "View declared policies",
    Capability.READ_AUDIT: "View execution audit log",
    Capability.READ_ACTIVITY: "View the per-request activity log "
                                "(/audit page)",
    Capability.READ_IDENTITY: "View identity systems, principals, and "
                                "effective permissions",
    Capability.WRITE_ASSET: "Add, edit, or delete assets",
    Capability.WRITE_POLICY: "Author or modify policies",
    Capability.WRITE_GROUP: "Manage asset groups",
    Capability.WRITE_TAG: "Manage tags and saved searches",
    Capability.WRITE_RISK: "Add or edit risk register entries",
    Capability.WRITE_EXCEPTION: "Grant or revoke compliance exceptions",
    Capability.WRITE_WATCHLIST: "Add or remove watchlist entries",
    Capability.WRITE_AUTOMATION: "Author or edit automation rules",
    Capability.SUBMIT_JOB: "Submit execution jobs for approval",
    Capability.APPROVE_JOB: "Approve execution jobs (subject to "
                             "self-approve rules)",
    Capability.EXECUTE_REAL: "Run Tier-3 real SSH execution "
                              "(also gated by SC_TIER3_ENABLED + TOTP)",
    Capability.EXECUTE_ROLLBACK: "Apply a generated rollback plan",
    Capability.GRANT_JIT: "Issue Just-In-Time access grants",
    Capability.APPLY_IDENTITY_DRY_RUN: "Run identity write-back in dry-run mode",
    Capability.APPLY_IDENTITY_COMMIT: "Commit identity write-back to a "
                                        "real IdP (requires confirm token)",
    Capability.MANAGE_IDENTITY_VAULT: "Add/remove identity connectors and "
                                        "stored credentials",
    Capability.MANAGE_USERS: "Add, edit, delete users in the directory",
    Capability.MANAGE_CAPABILITIES: "Grant or revoke capabilities to "
                                      "other users",
    Capability.MANAGE_WEBHOOKS: "Add, edit, delete outbound webhook routes",
    Capability.MANAGE_SETTINGS: "Edit SMTP, tenant defaults, and system "
                                  "settings",
}


# Order matters here — used as the canonical list when rendering the
# /users#capabilities matrix and in tests that walk every capability.
ALL_CAPABILITIES: list[str] = [
    Capability.READ_ASSET, Capability.READ_FINDING, Capability.READ_POLICY,
    Capability.READ_AUDIT, Capability.READ_ACTIVITY,
    Capability.READ_IDENTITY,
    Capability.WRITE_ASSET, Capability.WRITE_POLICY,
    Capability.WRITE_GROUP, Capability.WRITE_TAG,
    Capability.WRITE_RISK, Capability.WRITE_EXCEPTION,
    Capability.WRITE_WATCHLIST, Capability.WRITE_AUTOMATION,
    Capability.SUBMIT_JOB, Capability.APPROVE_JOB,
    Capability.EXECUTE_REAL, Capability.EXECUTE_ROLLBACK,
    Capability.GRANT_JIT,
    Capability.APPLY_IDENTITY_DRY_RUN,
    Capability.APPLY_IDENTITY_COMMIT,
    Capability.MANAGE_IDENTITY_VAULT,
    Capability.MANAGE_USERS, Capability.MANAGE_CAPABILITIES,
    Capability.MANAGE_WEBHOOKS, Capability.MANAGE_SETTINGS,
]


# Role floor — what each built-in role gets without any explicit
# grant. Admins get everything (literally — the gate short-circuits
# on admin role); other roles get a sensible read-mostly baseline
# that an admin can extend per-user as needed.
_VIEWER_FLOOR = {
    Capability.READ_ASSET, Capability.READ_FINDING,
    Capability.READ_POLICY, Capability.READ_AUDIT,
    Capability.READ_ACTIVITY, Capability.READ_IDENTITY,
}

_ANALYST_FLOOR = _VIEWER_FLOOR | {
    Capability.WRITE_TAG,
    Capability.WRITE_WATCHLIST,
    Capability.WRITE_AUTOMATION,
    Capability.SUBMIT_JOB,
    Capability.APPLY_IDENTITY_DRY_RUN,
}

_APPROVER_FLOOR = _ANALYST_FLOOR | {
    Capability.WRITE_POLICY,
    Capability.WRITE_GROUP,
    Capability.WRITE_RISK,
    Capability.WRITE_EXCEPTION,
    Capability.APPROVE_JOB,
    Capability.GRANT_JIT,
}

_OPERATOR_FLOOR = _APPROVER_FLOOR | {
    Capability.WRITE_ASSET,
    Capability.EXECUTE_ROLLBACK,
}

ROLE_FLOOR: dict[str, set[str]] = {
    "viewer": _VIEWER_FLOOR,
    "analyst": _ANALYST_FLOOR,
    "approver": _APPROVER_FLOOR,
    "operator": _OPERATOR_FLOOR,
    # admin is special — handled by short-circuit in
    # store.has_capability(); listed here so callers can round-trip
    # the floor sets for documentation purposes.
    "admin": set(ALL_CAPABILITIES),
}
