"""
Change management hooks (v10.8).

Every "tracked" config-change event lands here. The module is two things
at once:

1. **An append-only change log** persisted to
   ``~/.safecadence/orgs/<org_id>/change_log.jsonl``. Each entry is a
   ``ChangeEvent`` dict::

       {
         "id":      "chg_abcd1234",
         "ts":      "2026-05-10T01:02:03Z",
         "org_id":  "org_xyz",
         "kind":    "risk_accepted" | "template_saved" | ...,
         "before":  {...} | None,
         "after":   {...} | None,
         "actor":   "alice@acme.com" | None,
         "asset_id": "rtr1" | None
       }

2. **A pluggable hook system**. Callers register a hook by name; every
   :func:`record_change` invocation fires every hook. Built-in
   ``"jira"`` + ``"servicenow"`` hooks auto-create a ticket using the
   v10.6 + v10.7 integration modules. Hooks raise nothing — every
   failure is swallowed so a broken integration can't take down the
   recorder.

Wire-up
-------
The wired-in callers (added in v10.8) are:

* :func:`safecadence.reports.risk_acceptance.add_acceptance` →
  ``"risk_accepted"``.
* :func:`safecadence.reports.templates.save_template` →
  ``"template_saved"``.
* :func:`safecadence.reports.audit_trail.log_event` (when the event is
  a state transition) → ``"finding_transition"``.

Plus the v10.8 workflow modules:

* :func:`safecadence.workflow.approval_chains.start_approval` /
  ``sign_step`` / ``cancel_approval`` → ``"approval_*"`` events.
* :func:`safecadence.workflow.pentest.signoff` → ``"pentest_signoff"``.

Read-only mode is honoured — calls become no-ops, hooks are skipped.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Callable, Optional


# --------------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------------


@dataclasses.dataclass
class ChangeEvent:
    id: str
    ts: str
    org_id: str | None
    kind: str
    before: Any
    after: Any
    actor: str | None = None
    asset_id: str | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return d


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


HookCallback = Callable[[ChangeEvent], None]

_LOCK = threading.Lock()
_HOOKS: dict[str, HookCallback] = {}


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------


def _log_path(org_id: str | None) -> Path:
    if org_id:
        from safecadence.storage.org_store import org_data_dir
        return org_data_dir(org_id) / "change_log.jsonl"
    # Global / single-tenant fallback
    base = Path(
        os.environ.get("SAFECADENCE_HOME")
        or os.environ.get("SC_AUTH_HOME")
        or str(Path.home() / ".safecadence")
    )
    base.mkdir(parents=True, exist_ok=True)
    return base / "change_log.jsonl"


def _append_log(event: ChangeEvent) -> None:
    p = _log_path(event.org_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event.to_dict(), default=str) + "\n")


# --------------------------------------------------------------------------
# Hooks
# --------------------------------------------------------------------------


def register_hook(name: str, callback: HookCallback) -> None:
    """Register a callback that fires on every :func:`record_change`."""
    if not name or callback is None:
        raise ValueError("hook name + callback are required")
    with _LOCK:
        _HOOKS[name] = callback


def unregister_hook(name: str) -> bool:
    with _LOCK:
        return _HOOKS.pop(name, None) is not None


def list_hooks() -> list[str]:
    with _LOCK:
        return sorted(_HOOKS.keys())


def clear_hooks_for_tests() -> None:
    """Used by ``tests/test_v10_8.py`` to guarantee a clean hook table."""
    with _LOCK:
        _HOOKS.clear()


# Severity-aware filter for ticketing — only auto-create tickets when
# the change is a real-world risk change. Customise via env if needed.
_TICKETABLE_KINDS = {
    "risk_accepted",
    "acceptance_expired",
    "finding_transition",
    "pentest_signoff",
}


def _jira_hook(event: ChangeEvent) -> None:
    if event.kind not in _TICKETABLE_KINDS:
        return
    try:
        from safecadence.integrations.jira import create_jira_ticket, is_configured
        if not is_configured():
            return
        finding = {
            "title": f"[change] {event.kind}",
            "host": event.asset_id,
            "severity": "info",
            "description": json.dumps({
                "before": event.before,
                "after": event.after,
                "actor": event.actor,
            }, default=str),
            "labels": ["safecadence", "change-mgmt", event.kind],
        }
        create_jira_ticket(finding, org_id=event.org_id)
    except Exception:  # pragma: no cover
        return


def _servicenow_hook(event: ChangeEvent) -> None:
    if event.kind not in _TICKETABLE_KINDS:
        return
    try:
        from safecadence.integrations.servicenow import (
            create_servicenow_incident, is_configured,
        )
        if not is_configured():
            return
        create_servicenow_incident({
            "title": f"[change] {event.kind}",
            "severity": "info",
            "hostname": event.asset_id,
            "description": json.dumps({
                "before": event.before,
                "after": event.after,
                "actor": event.actor,
            }, default=str),
        })
    except Exception:  # pragma: no cover
        return


# Auto-enable the built-ins on import. They become real ticket-creates
# only when their respective integration's ``is_configured()`` returns
# True, so on a vanilla install they are effectively no-ops.
register_hook("jira", _jira_hook)
register_hook("servicenow", _servicenow_hook)


# --------------------------------------------------------------------------
# Public API — record + list
# --------------------------------------------------------------------------


def record_change(
    org_id: str | None,
    kind: str,
    *,
    before: Any = None,
    after: Any = None,
    actor: str | None = None,
    asset_id: str | None = None,
    extra: dict | None = None,
) -> ChangeEvent | None:
    """Record a change + fire every registered hook.

    Returns the persisted :class:`ChangeEvent` (or ``None`` if read-only).
    """
    if _is_readonly():
        return None
    kind = (kind or "").strip()
    if not kind:
        raise ValueError("kind is required")
    event = ChangeEvent(
        id="chg_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12],
        ts=_now_iso(),
        org_id=org_id,
        kind=kind,
        before=before,
        after=after,
        actor=actor,
        asset_id=asset_id,
        extra=extra,
    )
    try:
        _append_log(event)
    except Exception:  # pragma: no cover
        pass
    # Snapshot hooks under lock then fire outside.
    with _LOCK:
        hooks = list(_HOOKS.items())
    for name, cb in hooks:
        try:
            cb(event)
        except Exception:  # pragma: no cover
            # Hook failures must never propagate.
            pass
    return event


def list_changes(
    org_id: str | None,
    *,
    since: str | None = None,
    kind: str | None = None,
    limit: int = 500,
) -> list[ChangeEvent]:
    """Return change events oldest-first, optionally filtered."""
    p = _log_path(org_id)
    if not p.exists():
        return []
    out: list[ChangeEvent] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            if since and (obj.get("ts") or "") < since:
                continue
            if kind and obj.get("kind") != kind:
                continue
            out.append(ChangeEvent(
                id=str(obj.get("id") or ""),
                ts=str(obj.get("ts") or ""),
                org_id=obj.get("org_id"),
                kind=str(obj.get("kind") or ""),
                before=obj.get("before"),
                after=obj.get("after"),
                actor=obj.get("actor"),
                asset_id=obj.get("asset_id"),
                extra=obj.get("extra"),
            ))
    out.sort(key=lambda e: e.ts)
    if limit and len(out) > limit:
        out = out[-limit:]
    return out


__all__ = [
    "ChangeEvent",
    "register_hook",
    "unregister_hook",
    "list_hooks",
    "clear_hooks_for_tests",
    "record_change",
    "list_changes",
]
