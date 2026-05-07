"""v9.48 — Capability-based RBAC.

Roles answered "what kind of user are you" (admin / analyst / viewer).
Capabilities answer "what specifically can you do?". A capability is
a fine-grained permission like ``MANAGE_USERS`` or ``GRANT_JIT`` that
an admin can hand out individually without promoting someone to a
higher role.

Three layers, in priority order (highest wins):

  1. Per-user explicit grant or deny (``CapabilityRecord``)
  2. Tenant defaults (``capabilities.yaml`` per tenant)
  3. Role floor (each role has a baseline capability set)

The floor is hard-coded so a misconfigured YAML can never silently
strip a viewer of ``READ_ASSET``. Per-user grants are the only thing
admins typically touch.

Each grant/revoke writes a record to the v9.47 activity log so
``/audit`` shows who handed out what permission, when. The audit
trail is the whole point — a capability without provenance is just
a security promise nobody can verify.
"""

from .constants import (
    Capability,
    ALL_CAPABILITIES,
    ROLE_FLOOR,
)
from .store import (
    CapabilityRecord,
    list_grants,
    list_tenants,
    list_all_grants,
    grant,
    revoke,
    user_capabilities,
    has_capability,
    has_explicit_grant,
    reconcile_sso_grants,
)
from .gate import require_capability

__all__ = [
    "Capability",
    "ALL_CAPABILITIES",
    "ROLE_FLOOR",
    "CapabilityRecord",
    "list_grants",
    "list_tenants",
    "list_all_grants",
    "grant",
    "revoke",
    "user_capabilities",
    "has_capability",
    "has_explicit_grant",
    "reconcile_sso_grants",
    "require_capability",
]
