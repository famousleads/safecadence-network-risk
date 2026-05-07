"""v9.48 — YAML-backed capability store.

File layout (``$SC_DATA_DIR/capabilities.yaml``):

    tenants:
      default:
        users:
          alice:
            grant: ["execute.real", "admin.webhooks"]
            deny:  ["execute.approve"]
            history:
              - {ts: "...", actor: "admin", action: "grant",
                 capability: "execute.real", reason: "incident-42"}

The history list lives next to the active grant set so a CRUD round
trip never erases provenance. Older entries can be pruned by ops
(e.g. ``yq 'del(.tenants.default.users.alice.history[:-50])'``);
the application never deletes them on its own.

Every grant/revoke also writes a row to the v9.47 activity log so
the same event is queryable from /audit alongside every other
mutation.
"""

from __future__ import annotations

import os
import time
from contextvars import ContextVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from .constants import ALL_CAPABILITIES, ROLE_FLOOR, Capability


# v9.50.1 — set to True by the HTTP route handlers right before they
# call grant()/revoke()/clear_deny(). The store-side _emit_activity()
# checks this flag and skips its synthetic write so we don't get two
# rows per change in the activity log (the middleware already logged
# the real request).
_http_in_flight: ContextVar[bool] = ContextVar(
    "sc_capabilities_http_in_flight", default=False,
)


def mark_http_in_flight(value: bool = True):
    """Set the contextvar so subsequent grant/revoke/clear_deny
    calls in this request don't double-log to the activity store.
    Returns a token; call ``_http_in_flight.reset(token)`` to undo
    if you need a finally clause. The route handlers don't bother
    resetting because the contextvar is per-request and dies with
    the response."""
    return _http_in_flight.set(value)


@dataclass
class CapabilityRecord:
    """One per-user record. ``grant`` adds, ``deny`` removes, both on
    top of the role floor."""
    username: str
    tenant: str = "default"
    grant: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)


def _store_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "capabilities.yaml"


def _load_raw() -> dict:
    p = _store_path()
    if not p.exists():
        return {"tenants": {}}
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {"tenants": {}}
    if not isinstance(d, dict):
        return {"tenants": {}}
    d.setdefault("tenants", {})
    return d


def _save_raw(data: dict) -> None:
    p = _store_path()
    p.write_text(yaml.safe_dump(data, sort_keys=True),
                  encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                                     # pragma: no cover
        pass


def _user_block(data: dict, *, tenant: str, username: str) -> dict:
    t = data.setdefault("tenants", {}).setdefault(tenant, {})
    users = t.setdefault("users", {})
    if not isinstance(users, dict):
        users = {}
        t["users"] = users
    rec = users.setdefault(username, {})
    rec.setdefault("grant", [])
    rec.setdefault("deny", [])
    rec.setdefault("history", [])
    return rec


# ---------------------------------------------------------------- public API


def list_tenants() -> list[str]:
    """v9.54 — return every tenant key present in the YAML store.

    Used by the cross-tenant capability admin view so MSP-style
    deployments (where one operator manages multiple customer
    tenants from the same install) can audit grants across the
    whole estate without making N round trips.
    """
    data = _load_raw()
    tenants = (data.get("tenants") or {})
    return sorted(t for t in tenants.keys() if isinstance(t, str))


def list_all_grants() -> list[CapabilityRecord]:
    """v9.54 — flat list of every CapabilityRecord across every
    tenant. Each record carries its tenant on the dataclass so the
    caller can group / filter without a second store round trip.
    """
    out: list[CapabilityRecord] = []
    for tenant in list_tenants():
        out.extend(list_grants(tenant=tenant))
    out.sort(key=lambda r: (r.tenant, r.username))
    return out


def list_grants(*, tenant: str = "default") -> list[CapabilityRecord]:
    data = _load_raw()
    out: list[CapabilityRecord] = []
    users = ((data.get("tenants") or {}).get(tenant) or {}).get("users") or {}
    for username, rec in users.items():
        if not isinstance(rec, dict):
            continue
        out.append(CapabilityRecord(
            username=username, tenant=tenant,
            grant=list(rec.get("grant") or []),
            deny=list(rec.get("deny") or []),
            history=list(rec.get("history") or []),
        ))
    out.sort(key=lambda r: r.username)
    return out


def get_grant(username: str, *, tenant: str = "default") -> CapabilityRecord:
    rows = list_grants(tenant=tenant)
    for r in rows:
        if r.username == username:
            return r
    return CapabilityRecord(username=username, tenant=tenant)


def grant(username: str, capability: str, *,
           tenant: str = "default", actor: str = "system",
           reason: str = "") -> CapabilityRecord:
    if capability not in ALL_CAPABILITIES:
        raise ValueError(f"unknown capability: {capability!r}")
    data = _load_raw()
    rec = _user_block(data, tenant=tenant, username=username)
    if capability not in rec["grant"]:
        rec["grant"].append(capability)
        rec["grant"].sort()
    # Granting also clears any explicit deny — otherwise the deny
    # would silently override the grant and the operator would be
    # confused.
    if capability in rec["deny"]:
        rec["deny"].remove(capability)
    rec["history"].append({
        "ts": _now_iso(),
        "actor": actor,
        "action": "grant",
        "capability": capability,
        "reason": reason,
    })
    _save_raw(data)
    _emit_activity(actor=actor, tenant=tenant, action="capability.grant",
                    target=username, capability=capability, reason=reason)
    return get_grant(username, tenant=tenant)


def revoke(username: str, capability: str, *,
            tenant: str = "default", actor: str = "system",
            reason: str = "") -> CapabilityRecord:
    if capability not in ALL_CAPABILITIES:
        raise ValueError(f"unknown capability: {capability!r}")
    data = _load_raw()
    rec = _user_block(data, tenant=tenant, username=username)
    changed = False
    if capability in rec["grant"]:
        rec["grant"].remove(capability)
        changed = True
    # Revoking ALSO sets a deny so the role-floor doesn't silently
    # restore the capability. The /users#capabilities tab labels
    # this case explicitly so admins know what they're doing.
    if capability not in rec["deny"]:
        rec["deny"].append(capability)
        rec["deny"].sort()
        changed = True
    if changed:
        rec["history"].append({
            "ts": _now_iso(),
            "actor": actor,
            "action": "revoke",
            "capability": capability,
            "reason": reason,
        })
        _save_raw(data)
        _emit_activity(actor=actor, tenant=tenant,
                        action="capability.revoke",
                        target=username, capability=capability,
                        reason=reason)
    return get_grant(username, tenant=tenant)


def clear_deny(username: str, capability: str, *,
                tenant: str = "default", actor: str = "system",
                reason: str = "") -> CapabilityRecord:
    """Remove an explicit deny without granting the capability —
    falls back to whatever the role floor says."""
    if capability not in ALL_CAPABILITIES:
        raise ValueError(f"unknown capability: {capability!r}")
    data = _load_raw()
    rec = _user_block(data, tenant=tenant, username=username)
    if capability in rec["deny"]:
        rec["deny"].remove(capability)
        rec["history"].append({
            "ts": _now_iso(),
            "actor": actor,
            "action": "clear_deny",
            "capability": capability,
            "reason": reason,
        })
        _save_raw(data)
        _emit_activity(actor=actor, tenant=tenant,
                        action="capability.clear_deny",
                        target=username, capability=capability,
                        reason=reason)
    return get_grant(username, tenant=tenant)


def user_capabilities(*, username: str, roles: list[str],
                       tenant: str = "default") -> set[str]:
    """Return the effective capability set for ``username``.

    Resolution order (highest priority first):
      1. Per-user explicit deny → never returned, regardless of role.
      2. Per-user explicit grant → always returned.
      3. Role floor union of every role the user holds.

    Admin role short-circuits to the full set.
    """
    if "admin" in roles:
        return set(ALL_CAPABILITIES)
    floor: set[str] = set()
    for r in roles:
        floor |= ROLE_FLOOR.get(r, set())
    rec = get_grant(username, tenant=tenant)
    eff = (floor | set(rec.grant)) - set(rec.deny)
    return eff


def has_capability(*, username: str, roles: list[str],
                    capability: str,
                    tenant: str = "default") -> bool:
    return capability in user_capabilities(
        username=username, roles=roles, tenant=tenant,
    )


def reconcile_sso_grants(*, username: str, wanted: list,
                          tenant: str = "default",
                          actor: str = "oidc:login",
                          reason: str = "") -> dict:
    """v9.54 — idempotent reconciliation of SSO-sourced grants.

    On every OIDC login, the IdP group claims plus the configured
    ``capability_map`` produce a fresh ``wanted`` list of capabilities.
    This function diff-applies the change so:

      * Capabilities in ``wanted`` that aren't currently SSO-managed
        for this user → granted (audit row + dispatch_event).
      * Capabilities currently SSO-managed but NOT in ``wanted`` →
        revoked (the user has left that group).
      * Capabilities granted by other paths (CLI, /users UI) →
        UNTOUCHED. We track the SSO-managed set in a separate field
        on the user record (``sso_managed``) so manual grants stay
        outside this loop.

    Returns a summary dict:
        {
          "granted":  ["read.audit"],
          "revoked":  ["execute.real"],
          "unchanged": ["admin.capabilities"],
          "wanted":   ["admin.capabilities", "read.audit"],
        }

    Raises ValueError on unknown capability names — fail loudly so
    a misconfigured capability_map can't silently grant nothing.
    """
    wanted_list = list(wanted or [])
    wanted_set = set(wanted_list)
    invalid = sorted(c for c in wanted_set if c not in ALL_CAPABILITIES)
    if invalid:
        raise ValueError(
            f"unknown capabilities in SSO capability_map: {invalid!r}"
        )
    data = _load_raw()
    rec = _user_block(data, tenant=tenant, username=username)
    rec.setdefault("sso_managed", [])
    current = set(rec["sso_managed"] or [])
    to_grant = sorted(wanted_set - current)
    to_revoke = sorted(current - wanted_set)
    unchanged = sorted(wanted_set & current)
    summary = {"granted": list(to_grant), "revoked": list(to_revoke),
                "unchanged": unchanged, "wanted": sorted(wanted_set)}
    if not to_grant and not to_revoke:
        # Idempotent fast-path — no audit noise on every login.
        return summary
    final_reason = reason or "sso reconcile"
    for cap in to_grant:
        grant(username, cap, tenant=tenant, actor=actor,
               reason=final_reason)
    for cap in to_revoke:
        revoke(username, cap, tenant=tenant, actor=actor,
                reason=(reason or "no longer in matching IdP group"))
    # Re-load and write the new sso_managed list (the grant/revoke
    # calls above rewrote the file each time, so we read fresh).
    data2 = _load_raw()
    rec2 = _user_block(data2, tenant=tenant, username=username)
    rec2["sso_managed"] = sorted(wanted_set)
    _save_raw(data2)
    return summary


def has_explicit_grant(*, username: str, capability: str,
                        tenant: str = "default") -> bool:
    """Stricter check: returns True only if ``capability`` appears in
    the user's per-user ``grant`` list AND is not in their ``deny``
    list. **Does not honor the admin role short-circuit.**

    Use this for highly destructive surfaces (Tier-3 SSH execution)
    where the admin role's universal-grant rule is too permissive —
    the security-team intent is "even admins don't get this without
    an explicit, audit-logged grant."
    """
    if capability not in ALL_CAPABILITIES:
        return False
    rec = get_grant(username, tenant=tenant)
    return capability in rec.grant and capability not in rec.deny


# ---------------------------------------------------------------- helpers


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _emit_activity(*, actor: str, tenant: str, action: str,
                    target: str, capability: str, reason: str) -> None:
    """Best-effort: route every grant/revoke through the v9.47
    activity log. If activity is disabled (e.g. tests), we silently
    skip — the YAML history is the load-bearing record.

    v9.50.1 — when this function is called from inside an HTTP
    request, the v9.47 middleware ALREADY logs the request as a
    /api/capabilities/{target} POST. Emitting another row here
    would create duplicate audit data. We use a contextvar set by
    the route handler to detect that case and skip the emit; the
    middleware row carries richer detail (real request_id, client
    IP, real duration_ms) so dropping the synthetic one is the
    right call.

    CLI / direct-Python callers (no HTTP middleware in flight) do
    NOT set the flag, so the synthetic emit fires for them — which
    is correct: those paths have no other audit record.

    v9.53 — every change ALSO fires dispatch_event(kind=
    "capability_changed") so the security team's configured
    channels (Slack / Teams / email DM) hear about privilege
    escalations in real-time. This fires regardless of the
    HTTP-vs-CLI dedup decision above — it's a separate notification
    channel, not an audit record.
    """
    # Notification fan-out — fire even when the activity-log emit is
    # skipped. Auditing and notifying are two different concerns.
    #
    # The `action` arg uses the long form ("capability.grant",
    # "capability.revoke", "capability.clear_deny") for activity-log
    # consistency. The notification feed wants the short verb so
    # consumers can branch on action == "grant" without parsing.
    try:
        from safecadence.notifier.registry import dispatch_event
        short_action = action.split(".", 1)[1] if "." in action else action
        severity = ("high" if short_action in ("grant", "revoke")
                     and capability in (
                         "execute.real", "admin.users",
                         "admin.capabilities", "admin.webhooks",
                         "admin.settings", "identity.apply.commit")
                     else "info")
        dispatch_event(
            kind="capability_changed",
            title=(f"Capability {short_action}: "
                    f"{capability} on {target}"),
            summary=(f"{actor!r} {short_action} {capability!r} for "
                      f"{target!r}. Reason: {reason or '—'}"),
            severity=severity,
            extra={"action": short_action,
                    "capability": capability,
                    "target": target,
                    "actor": actor,
                    "reason": reason},
            link="/audit?path=/api/capabilities/",
            requested_by=actor,
        )
    except Exception:                                   # pragma: no cover
        pass

    if _http_in_flight.get(False):
        return
    try:
        from safecadence.activity import append, ActivityRecord
        append(ActivityRecord(
            ts=_now_iso(),
            actor=actor,
            tenant=tenant,
            method="POST",
            path=f"/api/capabilities/{target}",
            status=200,
            ip="cli",
            duration_ms=0,
            request_id="cap_" + str(int(time.time() * 1000)),
            extra={"action": action, "capability": capability,
                    "reason": reason},
        ))
    except Exception:                                   # pragma: no cover
        pass
