"""v9.48 — FastAPI dependency factory for capability checks.

Usage::

    from safecadence.capabilities import require_capability, Capability

    @app.post("/api/users")
    def create_user(
        body: dict,
        user: CurrentUser = Depends(
            require_capability(Capability.MANAGE_USERS)),
    ):
        ...

The decorator is intentionally additive on top of ``require_role``:
admins still have everything (short-circuit). Lower-tier roles get
the role floor + per-user grants. A 403 response includes the
required capability so the client can render a meaningful message.
"""

from __future__ import annotations

from typing import Any, Callable

try:                                                    # pragma: no cover
    from fastapi import HTTPException
except ImportError:                                     # pragma: no cover
    HTTPException = RuntimeError                # type: ignore[assignment]

from .store import has_capability


def require_capability(capability: str) -> Callable[[Any], Any]:
    """Return a FastAPI dependency that lets the request through only
    if the resolved user has ``capability``.

    The dependency is *parameter-name independent* — it expects the
    user object to be passed positionally by FastAPI's resolver. The
    user must expose ``username``, ``tenant``, and ``roles``
    attributes (CurrentUser does)."""

    def _dep(user: Any) -> Any:
        username = getattr(user, "username", "") or "anonymous"
        tenant = getattr(user, "tenant", "default")
        roles = list(getattr(user, "roles", []) or [])
        if not has_capability(username=username, roles=roles,
                                capability=capability, tenant=tenant):
            raise HTTPException(
                status_code=403,
                detail=(f"Missing capability: {capability}. "
                        "An admin can grant it via /users#capabilities."),
            )
        return user

    _dep.__name__ = f"require_capability_{capability.replace('.', '_')}"
    _dep.__doc__ = f"Require capability {capability!r}"
    return _dep
