"""
v12.0 — Customer-facing read-only portal scaffold.

The v10.9 portal at ``safecadence.portal.customer`` was built around the
internal admin operator console. This v12 scaffold is the **external**
customer view: when an MSP runs SafeCadence on behalf of a client, the
client logs in here, sees their (and only their) posture, and can't
change anything.

Design choices made on the user's behalf
----------------------------------------

* **Read-only by hard constraint.** Every route handler refuses any
  non-GET request with HTTP 405. No "are you sure?" flows, no edit
  forms — if a customer needs a change, they file a support ticket.

* **Magic-link auth only.** No password fields, no SSO config in the
  customer-facing UI. Reuses ``safecadence.notifier.email_notifier``
  (or the Postmark scaffold when configured) to send a signed token.

* **Three tabs, no more.** Posture / Reports / Help. Customers don't
  need a sidebar of 20 items. This forces every future addition to
  justify itself against the existing three.

* **Branded shell.** The customer's org `display_name` and brand color
  drive the chrome, so the MSP can hand the URL to their client without
  the SafeCadence wordmark dominating.

* **No JavaScript framework.** Pure server-rendered HTML + a single
  ``<details>`` widget for expandable rows. The portal works in any
  browser without a build step.

This module exposes the **HTML renderers** and **route plan** — wiring
into the FastAPI ``ui.app`` router happens in a follow-up commit when
the ``app.py`` route table next gets touched. Renderers are pure
functions returning ``str``, so they're trivially testable.

Public API
----------

* ``render_shell(org, brand_color, active_tab, body_html)`` → str
* ``render_posture_tab(org, posture)``                       → str
* ``render_reports_tab(org, reports)``                       → str
* ``render_help_tab(org, support_email)``                    → str
* ``CUSTOMER_PORTAL_ROUTES``                                 → list[dict]
"""
from __future__ import annotations

import html as _h
from typing import Any


# --------------------------------------------------------------------------
# Route plan (consumed by ui.app wiring)
# --------------------------------------------------------------------------


CUSTOMER_PORTAL_ROUTES: list[dict] = [
    {"path": "/customer",          "tab": "posture", "method": "GET"},
    {"path": "/customer/posture",  "tab": "posture", "method": "GET"},
    {"path": "/customer/reports",  "tab": "reports", "method": "GET"},
    {"path": "/customer/help",     "tab": "help",    "method": "GET"},
    {"path": "/customer/login",    "tab": None,      "method": "GET"},
    {"path": "/customer/login",    "tab": None,      "method": "POST"},  # magic-link request
    {"path": "/customer/auth",     "tab": None,      "method": "GET"},   # callback w/ token
    {"path": "/customer/logout",   "tab": None,      "method": "POST"},
]


# --------------------------------------------------------------------------
# Shell + tab renderers
# --------------------------------------------------------------------------


_TABS = [
    ("posture", "Posture", "/customer/posture"),
    ("reports", "Reports", "/customer/reports"),
    ("help",    "Help",    "/customer/help"),
]


def render_shell(
    *,
    org: dict,
    brand_color: str = "#3b82f6",
    active_tab: str = "posture",
    body_html: str = "",
) -> str:
    """Wrap a tab body in the branded customer-portal chrome."""
    org_name = _h.escape(org.get("display_name") or "Customer")
    safe_color = _h.escape(brand_color)

    tab_links = []
    for key, label, href in _TABS:
        cls = "tab tab-active" if key == active_tab else "tab"
        tab_links.append(
            f'<a class="{cls}" href="{_h.escape(href)}">{_h.escape(label)}</a>'
        )

    css = (
        ":root{--brand:" + safe_color + ";}"
        "*{box-sizing:border-box}"
        "body{margin:0;font-family:system-ui,sans-serif;color:#0f172a;"
        "background:#f8fafc;}"
        ".bar{background:var(--brand);color:#fff;padding:14px 22px;"
        "display:flex;align-items:center;justify-content:space-between;}"
        ".bar h1{margin:0;font-size:18px;font-weight:600}"
        ".bar .who{font-size:13px;opacity:.85}"
        "nav.tabs{background:#fff;border-bottom:1px solid #e5e7eb;"
        "padding:0 22px;display:flex;gap:4px}"
        ".tab{padding:12px 14px;text-decoration:none;color:#475569;"
        "border-bottom:2px solid transparent;font-size:14px}"
        ".tab-active{color:var(--brand);border-bottom-color:var(--brand);"
        "font-weight:600}"
        "main{max-width:980px;margin:24px auto;padding:0 22px}"
        ".card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;"
        "padding:18px 20px;margin-bottom:16px}"
        ".kpi{display:flex;gap:18px;flex-wrap:wrap}"
        ".kpi .item{flex:1 1 160px;border:1px solid #e5e7eb;border-radius:10px;"
        "padding:14px;background:#fff}"
        ".kpi .item .v{font-size:26px;font-weight:700;color:var(--brand)}"
        ".kpi .item .l{font-size:12px;text-transform:uppercase;color:#64748b;"
        "letter-spacing:.04em;margin-top:4px}"
        "footer{text-align:center;color:#94a3b8;font-size:12px;"
        "padding:24px 0}"
    )

    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{org_name} — Posture portal</title>"
        f"<style>{css}</style></head><body>"
        f"<div class=\"bar\"><h1>{org_name}</h1>"
        "<div class=\"who\">Read-only customer view</div></div>"
        f"<nav class=\"tabs\">{''.join(tab_links)}</nav>"
        f"<main>{body_html}</main>"
        "<footer>Powered by SafeCadence · "
        "Read-only — for changes, contact your service provider.</footer>"
        "</body></html>"
    )


def render_posture_tab(org: dict, posture: dict | None = None) -> str:
    """Render the Posture tab body. Pure function — no I/O."""
    p = posture or {}
    safe_score = p.get("safe_score")
    score_str = f"{safe_score:.0f}" if isinstance(safe_score, (int, float)) else "—"
    crit = int(p.get("critical_open", 0) or 0)
    high = int(p.get("high_open", 0) or 0)
    assets = int(p.get("asset_count", 0) or 0)
    last_scan = _h.escape(str(p.get("last_scan_at") or "no scans yet"))

    return (
        "<div class=\"card\">"
        "<h2 style=\"margin-top:0\">Current posture</h2>"
        "<div class=\"kpi\">"
        f"<div class=\"item\"><div class=\"v\">{score_str}</div>"
        "<div class=\"l\">Safe Score</div></div>"
        f"<div class=\"item\"><div class=\"v\">{crit}</div>"
        "<div class=\"l\">Open critical</div></div>"
        f"<div class=\"item\"><div class=\"v\">{high}</div>"
        "<div class=\"l\">Open high</div></div>"
        f"<div class=\"item\"><div class=\"v\">{assets}</div>"
        "<div class=\"l\">Assets monitored</div></div>"
        "</div>"
        f"<p style=\"color:#64748b;font-size:13px;margin-top:14px\">"
        f"Last scan: {last_scan}.</p>"
        "</div>"
    )


def render_reports_tab(org: dict, reports: list[dict] | None = None) -> str:
    """Render the Reports tab body. `reports` items: {title, generated_at, link}."""
    items = reports or []
    if not items:
        body = (
            "<p style=\"color:#64748b\">No reports have been published yet.</p>"
        )
    else:
        rows = []
        for r in items:
            t = _h.escape(r.get("title") or "Untitled report")
            ts = _h.escape(str(r.get("generated_at") or ""))
            link = _h.escape(r.get("link") or "#")
            rows.append(
                f"<li><a href=\"{link}\">{t}</a>"
                f" <span style=\"color:#94a3b8;font-size:12px\">{ts}</span></li>"
            )
        body = "<ul>" + "".join(rows) + "</ul>"
    return f"<div class=\"card\"><h2 style=\"margin-top:0\">Reports</h2>{body}</div>"


def render_help_tab(org: dict, support_email: str = "support@example.com") -> str:
    """Render the Help tab body. No outbound links — keeps the portal local-feeling."""
    se = _h.escape(support_email)
    return (
        "<div class=\"card\">"
        "<h2 style=\"margin-top:0\">Need help?</h2>"
        f"<p>For changes or questions, email "
        f"<a href=\"mailto:{se}\">{se}</a>.</p>"
        "<p style=\"color:#64748b;font-size:13px\">"
        "This view is read-only. Your service provider runs SafeCadence on "
        "your behalf and will action any requested changes.</p>"
        "</div>"
    )


__all__ = [
    "CUSTOMER_PORTAL_ROUTES",
    "render_shell",
    "render_posture_tab",
    "render_reports_tab",
    "render_help_tab",
]
