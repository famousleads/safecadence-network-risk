"""
v9.44 — Multi-provider webhook adapters.

Customer's messaging system → SafeCadence. Each provider takes the
generic event dict (``{kind, title, summary, severity, link, ...}``)
and renders it into the JSON shape that provider's incoming-webhook
endpoint accepts.

Provider list (auto-detected by URL pattern; can be overridden in the
webhook record):

  - slack          | hooks.slack.com/services/...
  - mattermost     | (Slack-API-compatible — uses slack renderer)
  - rocketchat     | (Slack-API-compatible — uses slack renderer)
  - teams          | outlook.office.com/webhook/... | webhook.office.com
  - discord        | discord.com/api/webhooks/...
  - pagerduty      | events.pagerduty.com/v2/enqueue
  - opsgenie       | api.opsgenie.com/v2/alerts
  - google_chat    | chat.googleapis.com/v1/spaces/...
  - webex          | webexapis.com/v1/messages | api.ciscospark.com
  - servicenow     | <instance>.service-now.com/api/...
  - generic_hmac   | (signed by SC_WEBHOOK_SIGNING_SECRET)
  - generic_webhook| (unsigned JSON POST)

Each adapter is small + dependency-free. They use stdlib `urllib`
instead of httpx so the notifier works in any deployment, including
the slim air-gap install. Failure is always (False, error_message);
the notifier swallows + audits — never crashes the workflow.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


# Severity → color mapping shared by every "rich" renderer that
# supports a colored sidebar (Slack, Discord, Teams, etc.).
_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "warning":  "#ca8a04",
    "low":      "#16a34a",
    "info":     "#2563eb",
}

_DISCORD_COLOR_INT = {
    "critical": 0xDC2626, "high": 0xEA580C, "medium": 0xCA8A04,
    "warning":  0xCA8A04, "low":  0x16A34A, "info":   0x2563EB,
}


# --------------------------------------------------- URL pattern detect


def detect_provider(url: str) -> str:
    """Best-effort provider detection. Operator can override in the
    webhook record but the auto-pick covers ~all common cases."""
    if not url:
        return "generic_webhook"
    u = url.lower()
    if "hooks.slack.com" in u:
        return "slack"
    if "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u:
        return "discord"
    if ("outlook.office.com/webhook" in u or
            "webhook.office.com" in u):
        return "teams"
    if "events.pagerduty.com" in u:
        return "pagerduty"
    if "api.opsgenie.com" in u or "api.eu.opsgenie.com" in u:
        return "opsgenie"
    if "chat.googleapis.com" in u:
        return "google_chat"
    if "webexapis.com" in u or "api.ciscospark.com" in u:
        return "webex"
    if ".service-now.com" in u:
        return "servicenow"
    return "generic_webhook"


SUPPORTED_PROVIDERS = (
    "slack", "mattermost", "rocketchat", "teams", "discord",
    "pagerduty", "opsgenie", "servicenow", "google_chat", "webex",
    "generic_hmac", "generic_webhook",
)


# ---------------------------------------------------- send (one webhook)


def send_webhook(
    *,
    provider: str,
    url: str,
    event: dict,
    signing_secret: Optional[str] = None,
    api_token: Optional[str] = None,
    timeout_s: float = 8.0,
) -> tuple[bool, str]:
    """Render ``event`` for the given provider and POST it.

    Returns ``(ok, error_message)``. Never raises — the caller's
    audit log captures (provider, ok, error).
    """
    # v12.1 — HA guard: only the active cluster node fires outbound
    # webhooks. Otherwise two nodes would each post the same alert.
    try:
        from safecadence.cluster.guards import is_standby
        if is_standby():
            return False, "skipped: standby cluster node"
    except Exception:
        pass

    # v12.2 — peer-sync: record the intent in the local event log so
    # the standby has a record of what was fired (best-effort; no-op
    # when peer-sync is disabled).
    try:
        from safecadence.cluster.peer_sync import record_replicated_event
        record_replicated_event("webhook_fire", {
            "provider": provider, "url": url,
            "event_title": (event or {}).get("title", ""),
        })
    except Exception:
        pass

    p = (provider or detect_provider(url) or "").lower()
    # Slack-API-compatible providers share the renderer
    if p in ("slack", "mattermost", "rocketchat"):
        body, headers = _render_slack(event), {"Content-Type": "application/json"}
    elif p == "teams":
        body, headers = _render_teams(event), {"Content-Type": "application/json"}
    elif p == "discord":
        body, headers = _render_discord(event), {"Content-Type": "application/json"}
    elif p == "pagerduty":
        body, headers = _render_pagerduty(event), {"Content-Type": "application/json"}
    elif p == "opsgenie":
        body, headers = _render_opsgenie(event), {
            "Content-Type": "application/json",
            "Authorization": f"GenieKey {api_token}" if api_token else "",
        }
    elif p == "google_chat":
        body, headers = _render_google_chat(event), {"Content-Type": "application/json"}
    elif p == "webex":
        body, headers = _render_webex(event), {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_token}" if api_token else "",
        }
    elif p == "servicenow":
        body, headers = _render_servicenow(event), {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_token}" if api_token else "",
        }
    elif p == "generic_hmac":
        body = json.dumps([event]).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if signing_secret:
            sig = hmac.new(signing_secret.encode("utf-8"),
                             body, hashlib.sha256).hexdigest()
            headers["X-SafeCadence-Signature"] = f"sha256={sig}"
        return _post(url, body, headers, timeout_s)
    elif p == "generic_webhook":
        body, headers = (json.dumps([event]).encode("utf-8"),
                          {"Content-Type": "application/json"})
    else:
        return False, f"unknown provider: {provider!r}"

    if isinstance(body, dict) or isinstance(body, list):
        body = json.dumps(body).encode("utf-8")
    return _post(url, body,
                  {k: v for k, v in headers.items() if v},
                  timeout_s)


def _post(url: str, body: bytes, headers: dict, timeout_s: float) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, data=body, headers=headers,
                                        method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if 200 <= resp.status < 300:
                return True, ""
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"URL error: {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ------------------------------------------------ provider renderers


def _ev_severity(event: dict) -> str:
    return str(event.get("severity") or "info").lower()


def _ev_link(event: dict) -> str:
    return str(event.get("link") or "")


def _ev_title(event: dict) -> str:
    return str(event.get("title") or "SafeCadence event")


def _ev_summary(event: dict) -> str:
    return str(event.get("summary") or "")


# ---- Slack / Mattermost / Rocket.Chat ----------------------------

def _render_slack(event: dict) -> dict:
    """Slack incoming-webhook (Block Kit). Mattermost + Rocket.Chat
    accept the same shape via their Slack-compat endpoints."""
    sev = _ev_severity(event)
    color = _SEVERITY_COLOR.get(sev, _SEVERITY_COLOR["info"])
    mentions = str(event.get("slack_mentions") or "")
    text_pieces = [f"*{_ev_title(event)}*"]
    if mentions:
        text_pieces.append(mentions)
    text_pieces.append(_ev_summary(event))
    text = "\n".join(p for p in text_pieces if p)
    fields = []
    for k in ("kind", "risk", "requested_by"):
        v = event.get(k)
        if v:
            fields.append({"title": k, "value": str(v), "short": True})
    attach = {"color": color, "text": text, "fields": fields,
              "footer": "SafeCadence",
              "mrkdwn_in": ["text"]}
    if _ev_link(event):
        attach["actions"] = [{"type": "button",
                                 "text": "Open in SafeCadence",
                                 "url": _ev_link(event)}]
    return {"attachments": [attach],
            "text": _ev_title(event) + (": " + _ev_summary(event)
                                          if _ev_summary(event) else "")}


# ---- Microsoft Teams (Adaptive Card via legacy MessageCard) -------

def _render_teams(event: dict) -> dict:
    sev = _ev_severity(event)
    color = _SEVERITY_COLOR.get(sev, _SEVERITY_COLOR["info"]).lstrip("#")
    facts = []
    for k in ("kind", "severity", "risk", "requested_by"):
        v = event.get(k)
        if v:
            facts.append({"name": k, "value": str(v)})
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": _ev_title(event),
        "title": _ev_title(event),
        "text": _ev_summary(event),
        "sections": [{"facts": facts}] if facts else [],
    }
    link = _ev_link(event)
    if link:
        payload["potentialAction"] = [{
            "@type": "OpenUri",
            "name": "Open in SafeCadence",
            "targets": [{"os": "default", "uri": link}],
        }]
    return payload


# ---- Discord ---------------------------------------------------------

def _render_discord(event: dict) -> dict:
    sev = _ev_severity(event)
    color = _DISCORD_COLOR_INT.get(sev, _DISCORD_COLOR_INT["info"])
    fields = []
    for k in ("kind", "severity", "risk", "requested_by"):
        v = event.get(k)
        if v:
            fields.append({"name": k, "value": str(v), "inline": True})
    embed = {
        "title": _ev_title(event)[:256],
        "description": _ev_summary(event)[:4000],
        "color": color,
        "fields": fields[:25],
        "footer": {"text": "SafeCadence"},
    }
    link = _ev_link(event)
    if link.startswith(("http://", "https://")):
        embed["url"] = link
    payload = {"embeds": [embed]}
    # Discord doesn't need leading content; embed alone renders well
    return payload


# ---- PagerDuty Events v2 ---------------------------------------------

def _render_pagerduty(event: dict) -> dict:
    sev = _ev_severity(event)
    pd_sev = ("critical" if sev == "critical"
                else "error" if sev == "high"
                else "warning" if sev in ("medium", "warning")
                else "info")
    return {
        # routing_key MUST be in the URL (events.pagerduty.com sample
        # uses POST with body containing routing_key). Operators store
        # the integration key in a query string or pass via api_token.
        "event_action": "trigger",
        "payload": {
            "summary": _ev_title(event),
            "source": "safecadence",
            "severity": pd_sev,
            "custom_details": {
                "summary": _ev_summary(event),
                "kind": event.get("kind", ""),
                "risk": event.get("risk", ""),
                "link": _ev_link(event),
                "requested_by": event.get("requested_by", ""),
            },
        },
        "links": ([{"href": _ev_link(event), "text": "Open in SafeCadence"}]
                    if _ev_link(event) else []),
    }


# ---- Opsgenie alerts API ---------------------------------------------

def _render_opsgenie(event: dict) -> dict:
    sev = _ev_severity(event)
    pri = ("P1" if sev == "critical" else
            "P2" if sev == "high" else
            "P3" if sev == "medium" else
            "P4" if sev == "low" else "P5")
    payload = {
        "message": _ev_title(event)[:130],
        "description": _ev_summary(event)[:15000],
        "priority": pri,
        "source": "safecadence",
        "details": {
            "kind": event.get("kind", ""),
            "severity": sev,
            "risk": event.get("risk", ""),
            "requested_by": event.get("requested_by", ""),
            "link": _ev_link(event),
        },
    }
    return payload


# ---- Google Chat -----------------------------------------------------

def _render_google_chat(event: dict) -> dict:
    """Google Chat incoming webhook with a card v2 layout."""
    sev = _ev_severity(event)
    text = f"*{_ev_title(event)}*\n{_ev_summary(event)}"
    card = {
        "header": {"title": _ev_title(event),
                     "subtitle": f"severity: {sev}"},
        "sections": [{
            "widgets": [
                {"textParagraph": {"text": _ev_summary(event)}},
            ],
        }],
    }
    link = _ev_link(event)
    if link:
        card["sections"][0]["widgets"].append({
            "buttonList": {"buttons": [{
                "text": "Open in SafeCadence",
                "onClick": {"openLink": {"url": link}},
            }]},
        })
    return {"text": text, "cardsV2": [{"cardId": "sc-event",
                                          "card": card}]}


# ---- Cisco Webex -----------------------------------------------------

def _render_webex(event: dict) -> dict:
    """Webex Messages API. Markdown body. Caller must supply the
    target ``roomId`` via the URL (?roomId=...) or the per-webhook
    record's metadata; the renderer only assembles the message body."""
    md = (f"**{_ev_title(event)}**\n\n"
            f"{_ev_summary(event)}\n\n"
            f"_severity:_ `{_ev_severity(event)}` · "
            f"_kind:_ `{event.get('kind', '')}`")
    if _ev_link(event):
        md += f"\n\n[Open in SafeCadence]({_ev_link(event)})"
    out: dict = {"markdown": md}
    # If the caller stuffed roomId into URL query, parse and copy.
    return out


# ---- ServiceNow -----------------------------------------------------

def _render_servicenow(event: dict) -> dict:
    """ServiceNow Table API record (incident or sn_si_incident).

    The customer points the webhook URL at the right table, e.g.
    ``https://acme.service-now.com/api/now/table/incident``. We render
    a minimal incident shape; customers with SOAR or Security Incident
    Response can swap the table.
    """
    sev = _ev_severity(event)
    impact = ("1" if sev == "critical" else
                "2" if sev == "high" else
                "3" if sev in ("medium", "warning") else "4")
    return {
        "short_description": _ev_title(event)[:160],
        "description": (
            f"{_ev_summary(event)}\n\n"
            f"Kind: {event.get('kind', '')}\n"
            f"Severity: {sev}\n"
            f"Risk: {event.get('risk', '')}\n"
            f"Link: {_ev_link(event)}\n"
        ),
        "urgency": impact,
        "impact": impact,
        "category": "security",
        "u_source": "safecadence",
    }
