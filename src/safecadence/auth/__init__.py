"""SafeCadence NetRisk auth subsystem — magic links, sessions, RBAC.

Public surface::

    from safecadence.auth.magic_link import (
        request_login, verify_token, create_session,
        get_session, revoke_session,
    )
    from safecadence.auth.rbac import UserRole, assign_role, get_role
    from safecadence.auth.deps import require_session, require_role

Demo bypass: set ``SC_AUTH_DISABLED=1`` to short-circuit every helper
to a pseudo-session for ``demo@safecadence.com``. This is what keeps
the read-only `demo.safecadence.com` deployment working.
"""

from safecadence.auth.magic_link import (
    create_session,
    get_session,
    request_login,
    revoke_session,
    verify_token,
)
from safecadence.auth.rbac import UserRole, assign_role, get_role

__all__ = [
    "request_login",
    "verify_token",
    "create_session",
    "get_session",
    "revoke_session",
    "UserRole",
    "assign_role",
    "get_role",
]
