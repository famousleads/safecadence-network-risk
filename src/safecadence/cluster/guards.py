"""
v12.1 — Active-only mutation guards.

Every code path that mutates shared state (writes findings, fires
webhooks, sends notifications, updates the audit log, etc.) must
short-circuit on the standby node. Otherwise two nodes pointing at
the same Postgres would each scan + write the same findings + fire
the same webhooks — silent double-everything.

This module provides three primitives:

* ``@active_only(default_return=None)`` — decorator. If we're not
  the active node, the function returns ``default_return`` (or
  raises ``IsStandbyError`` when ``raise_on_standby=True``).

* ``require_active()`` — imperative form. Raises ``IsStandbyError``
  when the local node is standby. Use at the top of a function when
  decorating it is awkward.

* ``IsStandbyError`` — exception type. Subclass of ``RuntimeError``
  so existing broad ``except RuntimeError`` clauses naturally swallow
  it instead of crashing the worker.

Single-node fallback
--------------------

When ``SC_REDIS_URL`` isn't set, ``am_i_active()`` returns ``True``
forever. Guards become no-ops. The v11.x single-node behavior is
preserved exactly.

Public API
----------

* ``IsStandbyError``
* ``active_only(default_return=None, raise_on_standby=False)``  — decorator
* ``require_active()``                                          — imperative
* ``is_standby()``                                              — inverse of am_i_active()
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable, TypeVar

_log = logging.getLogger("safecadence.cluster.guards")

F = TypeVar("F", bound=Callable[..., Any])


class IsStandbyError(RuntimeError):
    """Raised when a write was attempted on the standby node."""


def is_standby() -> bool:
    """True when this node is NOT the active one. Defensive: returns
    False (i.e. "act as active") if the lease check itself raises —
    we'd rather over-run by one cycle than crash the worker.
    """
    try:
        from safecadence.cluster.failover import am_i_active
        return not am_i_active()
    except Exception:
        return False


def require_active() -> None:
    """Raise IsStandbyError when called on the standby node."""
    if is_standby():
        raise IsStandbyError(
            "this operation is allowed only on the active cluster node"
        )


def active_only(
    default_return: Any = None,
    *,
    raise_on_standby: bool = False,
    log_label: str | None = None,
) -> Callable[[F], F]:
    """Decorator: short-circuit on the standby node.

    Usage::

        @active_only()
        def fire_webhook(event): ...

        @active_only(default_return={"skipped": "standby"})
        def schedule_scan(asset): ...

        @active_only(raise_on_standby=True)
        def commit_change(plan): ...

    The default behavior — return ``None`` and log at DEBUG level — is
    the right choice for fire-and-forget background work (webhook fire,
    notification send, scheduled scan). Callers that want a louder
    failure should pass ``raise_on_standby=True``.
    """
    def deco(fn: F) -> F:
        label = log_label or fn.__qualname__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if is_standby():
                if raise_on_standby:
                    raise IsStandbyError(
                        f"{label}() is allowed only on the active cluster node"
                    )
                _log.debug("cluster: skipping %s() on standby node", label)
                return default_return
            return fn(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return deco


__all__ = [
    "IsStandbyError",
    "is_standby",
    "require_active",
    "active_only",
]
