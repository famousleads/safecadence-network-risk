"""
Webhook delivery — Slack, Microsoft Teams, generic JSON endpoints.

Lazy-imports httpx (already in [server] extras).
Pure stdlib otherwise. No third-party Slack/Teams SDK needed.

Designed for use by `safecadence watch` (continuous monitoring) and the UI
"Send to Slack/Teams" buttons.
"""

from __future__ import annotations

from typing import Any


def _import_httpx():
    try:
        import httpx
        return httpx
    except ImportError:
        return None


def post_slack(webhook_url: str, *, summary: str, detail_blocks: list[dict] | None = None,
               color: str = "warning") -> dict:
    """
    Post a Slack-formatted message via incoming-webhook URL.
    color: 'good' (green), 'warning' (yellow), 'danger' (red), or hex.
    """
    httpx = _import_httpx()
    if not httpx:
        return {"error": "httpx required for webhooks"}

    attachments = [{
        "color": color,
        "title": "SafeCadence Network Risk",
        "text": summary,
        "fields": [{"title": b.get("title", ""), "value": b.get("value", ""), "short": b.get("short", False)} for b in (detail_blocks or [])],
        "footer": "safecadence-netrisk · MIT · 100% local",
    }]
    payload = {"attachments": attachments}

    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(webhook_url, json=payload)
            return {"ok": r.status_code < 400, "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def post_teams(webhook_url: str, *, title: str, summary: str,
               facts: list[dict] | None = None, color: str = "FFA500") -> dict:
    """Microsoft Teams via incoming-webhook URL (uses MessageCard format)."""
    httpx = _import_httpx()
    if not httpx:
        return {"error": "httpx required for webhooks"}

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": summary,
        "title": title,
        "text": summary,
        "sections": [{
            "facts": [{"name": f.get("title", ""), "value": str(f.get("value", ""))} for f in (facts or [])],
        }],
    }

    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(webhook_url, json=payload)
            return {"ok": r.status_code < 400, "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def post_generic(webhook_url: str, payload: dict) -> dict:
    """POST raw JSON to any endpoint (for custom integrations / Zapier / n8n)."""
    httpx = _import_httpx()
    if not httpx:
        return {"error": "httpx required for webhooks"}
    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(webhook_url, json=payload)
            return {"ok": r.status_code < 400, "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def format_diff_alert(diff_payload: dict, *, cidr: str) -> tuple[str, list[dict]]:
    """Format a diff result into (summary, detail_blocks) for webhook delivery."""
    summary = diff_payload.get("summary", {})
    added = summary.get("added_count", 0)
    removed = summary.get("removed_count", 0)
    changed = summary.get("changed_count", 0)

    if added == 0 and removed == 0 and changed == 0:
        return f"Network audit on `{cidr}`: no changes since last scan ✓", []

    headline = f"⚠ Network changes detected on `{cidr}` — {added} added, {removed} removed, {changed} changed"

    blocks = []
    if added:
        added_list = ", ".join(f"`{a.get('ip','?')}`" for a in (diff_payload.get("added") or [])[:8])
        blocks.append({"title": f"➕ {added} new device(s)", "value": added_list, "short": False})
    if removed:
        removed_list = ", ".join(f"`{r.get('ip','?')}`" for r in (diff_payload.get("removed") or [])[:8])
        blocks.append({"title": f"➖ {removed} device(s) gone", "value": removed_list, "short": False})
    if changed:
        changed_list = ", ".join(f"`{c.get('ip','?')}`" for c in (diff_payload.get("changed") or [])[:8])
        blocks.append({"title": f"🔄 {changed} device(s) changed", "value": changed_list, "short": False})

    return headline, blocks


def format_critical_alert(fleet: dict) -> tuple[str, list[dict]]:
    """Format a critical-finding alert for a discovery scan."""
    summary = fleet.get("summary", {})
    bands = summary.get("by_risk_band", {})
    cves = summary.get("cves", {})
    crit = bands.get("critical", 0)
    high = bands.get("high", 0)
    kev = cves.get("kev_cves", 0)

    headline = (
        f"🚨 SafeCadence audit on `{fleet.get('cidr','?')}`: "
        f"{crit} critical, {high} high, {kev} KEV CVE{'s' if kev != 1 else ''}"
    )

    blocks = [
        {"title": "Devices in scope", "value": str(fleet.get("count", 0)), "short": True},
        {"title": "Subnet", "value": fleet.get("cidr", "?"), "short": True},
        {"title": "Critical risk", "value": str(crit), "short": True},
        {"title": "KEV CVEs", "value": str(kev), "short": True},
    ]

    # Top 3 critical devices
    crits = [r for r in (fleet.get("results") or []) if r.get("risk_band") == "critical"][:3]
    if crits:
        crit_list = "\n".join(f"• `{r.get('ip','?')}` ({r.get('vendor','?')}) — risk {r.get('risk_score', 0)}" for r in crits)
        blocks.append({"title": "Top critical devices", "value": crit_list, "short": False})

    return headline, blocks
