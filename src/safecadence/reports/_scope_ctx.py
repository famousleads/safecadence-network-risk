"""
Process-wide org_id scope for report composition.

The section composer registry stores ``fn(store, scope) -> dict``
signatures. Threading a new ``org_id`` arg through 18 composers would
churn every call site, so v10.5 takes the smaller hammer: a contextvar
that ``compose_report()`` sets before dispatching to the composers and
clears after. ``_load_platform_assets()`` consults it to decide which
``platform_assets`` directory to read from.
"""

from __future__ import annotations

import contextvars

_org_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "sc_report_org_id", default=None
)


def push_org(org_id: str | None):
    """Set the current org id for this context. Returns a token caller
    must pass back to :func:`pop_org`."""
    return _org_id_var.set(org_id)


def pop_org(token) -> None:
    """Restore the prior value (paired with :func:`push_org`)."""
    try:
        _org_id_var.reset(token)
    except Exception:                              # pragma: no cover
        pass


def current_org() -> str | None:
    """Return the org id in effect for the current request/call, if any."""
    try:
        return _org_id_var.get()
    except Exception:                              # pragma: no cover
        return None


__all__ = ["push_org", "pop_org", "current_org"]
