"""
v9.43 — Generalized notification routing.

Before this module, only the approval workflow knew how to fan a
single event out to invitees via email. Every other place that
needed to ping the operator (findings, drift, daemon errors,
watchlist hits, automation fires, the morning digest) hit the
channel webhook directly and that was it.

This registry generalizes the v9.42 email-DM machinery so any event
kind can route to:

  - the channel webhook (Slack / Teams / PagerDuty / generic HMAC)
    — always fires, preserves v9.35 behaviour for backups
  - per-user email DM via the customer's SMTP (v9.42)
  - per-user Slack / Teams DM via @-mention in the channel payload

Routing rules:

  1. Approval invites are always-on for the named invitees — direct
     ask, the operator can't opt out.
  2. Other categories (finding_critical, watchlist_change, drift_detected,
     digest, automation_fired, jit_granted) are opt-in per user.
  3. A user can only enable channels they have contact info for —
     enabling email when they have no email on file is rejected
     server-side. The UI grays out unavailable cells.

Trust posture preserved:

  - Channel webhook fires regardless of per-user prefs. A muted user
    can't hide a critical alert from the team channel.
  - Each dispatch is audited with kind, channel, recipient, ok/error.
  - Empty config = silent skip, never raises. Air-gap-safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


# ---------------------------------------------------- categories

# Each category names one *kind of event*. Code that emits a notification
# picks the matching category; the operator's prefs decide which channels
# fire for that category. Adding a new event kind = add a row here.

NOTIFY_CATEGORIES: list[dict[str, str]] = [
    {"key": "approval_requested",
     "label": "Approval requests",
     "description": "When a job needs approval and you're invited.",
     "default_invitee_only": True,
     "default_channels": "email"},
    {"key": "finding_critical",
     "label": "Critical findings",
     "description": "When a CRITICAL finding lands on your fleet.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "watchlist_change",
     "label": "Watchlist changes",
     "description": "When an asset / NHI / principal you watch changes.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "drift_detected",
     "label": "Drift detected",
     "description": "Cross-system drift between AD/Entra/Okta/etc.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "digest_daily",
     "label": "Daily digest",
     "description": "Morning briefing — overnight changes + top actions.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "automation_fired",
     "label": "Automation fired",
     "description": "When an automation rule you authored fires.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "jit_granted",
     "label": "JIT access granted",
     "description": "When a JIT grant is issued or revoked.",
     "default_invitee_only": False,
     "default_channels": ""},
    {"key": "capability_changed",
     "label": "Capability changed",
     "description": ("When a privilege (capability) is granted or "
                       "revoked — security teams should hear about "
                       "privilege escalations in real-time."),
     "default_invitee_only": False,
     "default_channels": ""},
]


def category_keys() -> list[str]:
    return [c["key"] for c in NOTIFY_CATEGORIES]


# Channels a user can enable. Each channel maps to a specific
# contact-info field on the user record; a user can only enable a
# channel they have contact info for.

NOTIFY_CHANNELS: list[dict[str, str]] = [
    {"key": "email",
     "label": "Email",
     "user_field": "email",
     "description": "Direct email DM via the configured SMTP server."},
    {"key": "slack_dm",
     "label": "Slack",
     "user_field": "slack_user_id",
     "description": "@-mention in the configured Slack channel."},
    {"key": "teams_dm",
     "label": "Teams",
     "user_field": "teams_user_id",
     "description": "@-mention in the configured Teams channel."},
]


def channel_keys() -> list[str]:
    return [c["key"] for c in NOTIFY_CHANNELS]


# -------------------------------------------------- dispatch event


@dataclass
class DispatchResult:
    """One row of the audit trail for a single notification fan-out.

    The caller (workflow / daemon / etc.) gets this back so it can
    persist it; the registry doesn't reach into the audit store
    itself, keeping coupling low.
    """
    kind: str
    channel_webhook_fired: bool = False
    channel_webhook_error: str = ""
    deliveries: list[dict] = field(default_factory=list)
    # v9.44 — per-webhook fire results from the multi-provider registry
    webhook_fires: list[dict] = field(default_factory=list)

    def to_audit_dict(self) -> dict:
        return {
            "kind": self.kind,
            "channel_webhook_fired": self.channel_webhook_fired,
            "channel_webhook_error": self.channel_webhook_error,
            "deliveries": self.deliveries,
            "webhook_fires": self.webhook_fires,
        }


def dispatch_event(
    *,
    kind: str,
    title: str,
    summary: str,
    severity: str = "info",
    invitees: Optional[Iterable[str]] = None,
    tenant: str = "local",
    extra: Optional[dict] = None,
    link: str = "",
    requested_by: str = "",
    channel_webhook: Optional[str] = None,
    channel_signing_secret: Optional[str] = None,
) -> DispatchResult:
    """Fan a single event out to every channel that should hear about it.

    Args:
      kind: one of NOTIFY_CATEGORIES[*].key
      title / summary: human-readable description (channel rendering)
      severity: 'info' | 'warning' | 'high' | 'critical'
      invitees: usernames to DM directly. Approval requests fire to
                invitees regardless of opt-in (direct ask). Other
                categories check per-user prefs.
      tenant: tenant scope; controls which user records we resolve
              invitees against.
      extra: any extra structured fields the channel renderer wants
      link: deep-link the email/DM should expose (e.g. /approvals#JOB)
      requested_by: who triggered the event (audit + signature line)
      channel_webhook: override URL; defaults to env-configured webhook.
                       Empty / None = skip channel webhook.
      channel_signing_secret: HMAC secret for the channel webhook.

    Returns a DispatchResult the caller can persist in the audit log.
    """
    result = DispatchResult(kind=kind)
    invitees = list(invitees or [])

    # v9.49 — Phase B: expand @group:NAME entries against the
    # IdP-sourced group cache. This is the seam that lets approval
    # invites reference "eng-leads" instead of listing every
    # member by name. Best-effort — a missing cache or unknown
    # group degrades into "no DM goes out" rather than breaking.
    try:
        from safecadence.identity.groups import resolve_invitees
        if invitees and any(str(x).startswith("@group:") for x in invitees):
            invitees = resolve_invitees(invitees)
    except Exception:                               # pragma: no cover
        pass

    # Build the canonical event payload once; every channel renderer
    # downstream consumes the same shape.
    payload = {
        "kind": kind,
        "title": title,
        "summary": summary,
        "severity": severity,
        "link": link,
        "requested_by": requested_by,
    }
    if extra:
        payload.update({k: v for k, v in extra.items()
                          if k not in payload})
    # v9.43 — when invitees are set and have Slack/Teams ids,
    # enrich the payload with the @-mention tokens so the
    # channel webhook receiver can render them.
    if invitees:
        _enrich_with_dm_tags(payload, invitees, tenant=tenant)

    # ---------- 1a. Single-channel-webhook back-compat ----------
    # Pre-v9.44 callers passed a single `channel_webhook` URL. We
    # honour that path so existing wiring keeps working, but the
    # full v9.44 fan-out below is what new callers should use.
    try:
        if channel_webhook:
            from safecadence.notifier import notify
            notify(channel_webhook, [payload],
                     signing_secret=channel_signing_secret)
            result.channel_webhook_fired = True
    except Exception as e:                                       # pragma: no cover
        result.channel_webhook_error = f"{type(e).__name__}: {e}"

    # ---------- 1b. v9.44 multi-provider fan-out ----------
    # Iterate the registered webhooks; each one knows its own
    # provider, target URL, and category/severity filter. Failures
    # are isolated — one dead webhook doesn't block the others.
    try:
        from safecadence.notifier import webhook_registry
        for w in webhook_registry.matching(kind=kind, severity=severity):
            ok, err = webhook_registry.fire_one(w, payload)
            result.webhook_fires.append({
                "webhook_id": w.id,
                "provider": w.provider,
                "ok": ok,
                "error": err,
            })
    except Exception as e:                                       # pragma: no cover
        result.webhook_fires.append({
            "webhook_id": "_registry", "provider": "",
            "ok": False, "error": f"{type(e).__name__}: {e}"})

    # ---------- 2. Per-user direct delivery ----------
    if invitees:
        result.deliveries = _fan_out_to_invitees(
            kind=kind, invitees=invitees, tenant=tenant,
            title=title, summary=summary, severity=severity,
            link=link, requested_by=requested_by, extra=extra,
        )

    return result


def _enrich_with_dm_tags(payload: dict, invitees: list[str],
                          *, tenant: str) -> None:
    """v9.43 #4 — populate slack_user_ids + teams_user_ids on the
    payload so the channel webhook receiver can render @-mentions in
    the same message that fires for everyone.
    """
    try:
        from safecadence.users.directory import lookup_invitees
    except Exception:
        return
    recs = lookup_invitees(invitees, tenant=tenant)
    slack_ids = [r.notify.get("slack_user_id") for r in recs
                  if r.notify.get("slack_user_id")]
    teams_ids = [r.notify.get("teams_user_id") for r in recs
                  if r.notify.get("teams_user_id")]
    if slack_ids:
        payload["slack_user_ids"] = slack_ids
        # Slack-friendly mention string the receiver can drop into
        # the message body if it wants the simplest path
        payload["slack_mentions"] = " ".join(
            f"<@{uid}>" for uid in slack_ids)
    if teams_ids:
        payload["teams_user_ids"] = teams_ids


def _fan_out_to_invitees(*, kind: str, invitees: list[str], tenant: str,
                          title: str, summary: str, severity: str,
                          link: str, requested_by: str,
                          extra: Optional[dict]) -> list[dict]:
    """Per-recipient delivery loop. One row per recipient × channel.

    For ``approval_requested`` we ignore prefs (direct invite). For
    other categories we honour the user's notify_prefs.
    """
    out: list[dict] = []
    try:
        from safecadence.users.directory import lookup_invitees
        from safecadence.notifier.prefs import (
            user_channels_for_kind,
        )
    except Exception:                                            # pragma: no cover
        return out
    recs = lookup_invitees(invitees, tenant=tenant)
    always_on = (kind == "approval_requested")
    for rec in recs:
        # Decide which channels this user should be reached on for
        # this event kind. ``always_on`` means ignore prefs.
        if always_on:
            channels = _available_channels_for_user(rec)
        else:
            channels = user_channels_for_kind(rec, kind=kind,
                                                tenant=tenant)
        if not channels:
            out.append({"username": rec.username, "channel": "",
                          "ok": False, "reason": "no enabled channel"})
            continue
        for ch in channels:
            ok, err = _deliver(channel=ch, recipient=rec,
                                 kind=kind, title=title, summary=summary,
                                 severity=severity, link=link,
                                 requested_by=requested_by, extra=extra)
            out.append({"username": rec.username, "channel": ch,
                          "to": _addr_for(ch, rec),
                          "ok": ok, "reason": "" if ok else err})
    return out


def _available_channels_for_user(rec) -> list[str]:
    """Which channels does this user *have* contact info for?"""
    out = []
    if rec.primary_email():
        out.append("email")
    if rec.notify.get("slack_user_id"):
        out.append("slack_dm")
    if rec.notify.get("teams_user_id"):
        out.append("teams_dm")
    return out


def _addr_for(channel: str, rec) -> str:
    """Return the routable address for audit. We never log the
    encrypted password or anything secret here."""
    if channel == "email":
        return rec.primary_email()
    if channel == "slack_dm":
        return rec.notify.get("slack_user_id", "")
    if channel == "teams_dm":
        return rec.notify.get("teams_user_id", "")
    return ""


def _deliver(*, channel: str, recipient, kind: str, title: str,
              summary: str, severity: str, link: str,
              requested_by: str, extra: Optional[dict]) -> tuple[bool, str]:
    """Single channel × recipient delivery. Best-effort; never raises."""
    try:
        if channel == "email":
            return _deliver_email(rec=recipient, kind=kind, title=title,
                                    summary=summary, link=link,
                                    requested_by=requested_by, extra=extra)
        # Slack DM and Teams DM are delivered via the @-mention added
        # to the channel webhook payload; we don't open a separate
        # connection per user. Audit row records the user_id we
        # mentioned so the operator can prove who got pinged.
        if channel == "slack_dm":
            return True, ""
        if channel == "teams_dm":
            return True, ""
        return False, f"unknown channel {channel!r}"
    except Exception as e:                                       # pragma: no cover
        return False, f"{type(e).__name__}: {e}"


def _deliver_email(*, rec, kind: str, title: str, summary: str,
                     link: str, requested_by: str,
                     extra: Optional[dict]) -> tuple[bool, str]:
    from safecadence.notifier.email_notifier import (
        is_configured, send_email,
    )
    if not is_configured():
        return False, "smtp_not_configured"
    addr = rec.primary_email()
    if not addr:
        return False, "no email on record"
    subj = f"[SafeCadence] {title}"
    plain = (
        f"SafeCadence — {title}\n\n"
        f"  Severity: {severity_label(extra)}\n"
        f"  Summary:  {summary}\n"
        + (f"  Triggered by: {requested_by}\n" if requested_by else "")
        + (f"\n{link}\n" if link else "")
        + "\n"
        + ("This was sent because you opted in to "
           f"'{kind}' notifications. Manage preferences at "
           "/settings#notifications.\n")
    )
    return send_email(to=addr, subject=subj, body=plain)


def severity_label(extra: Optional[dict]) -> str:
    if not extra:
        return "info"
    return str(extra.get("severity") or "info")
