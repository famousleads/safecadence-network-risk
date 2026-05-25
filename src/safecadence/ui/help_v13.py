"""
v13.0 — In-app contextual help surfacing.

Builds on the v9.1 ``help_registry.HELP`` dict by adding entries for
every v12/v13/v14 feature that didn't exist when the original
registry was written, and adds a topic-directory page at
``/help/topics`` so users can browse the full list.

The original popover-on-hover behavior is unchanged; this module
just adds discoverability for the entries that already exist.

Public API
----------

* ``V13_HELP`` — supplemental help dict merged into the registry at
                 module-import time.
* ``router``    — FastAPI router exposing GET /help/topics.
"""
from __future__ import annotations

import html as _h

try:
    from fastapi import APIRouter
    from fastapi.responses import HTMLResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False


# --------------------------------------------------------------------------
# v12 / v13 / v14 help entries
# --------------------------------------------------------------------------


V13_HELP: dict[str, dict] = {
    # ----- v12 themes ------------------------------------------------------
    "mcp-server": {
        "title": "MCP server",
        "body": "Exposes SafeCadence as an Anthropic MCP server over JSON-RPC stdio "
                "with 7 tools: query_topology, retrieve_findings, query_compliance, "
                "fetch_evidence, inspect_identities, generate_report, evaluate_posture. "
                "RBAC + audit-log integration; never crashes the client.",
        "example": "safecadence mcp-server --org-id customer-a",
        "docs_href": "/help",
    },
    "multi-dim-safe-score": {
        "title": "Multi-dim Safe Score",
        "body": "Six dimensions instead of one number: compliance health, identity "
                "health, drift stability, patch freshness, attack-path risk, and "
                "AI governance readiness. Each carries a confidence band and the "
                "top 1–3 findings driving it.",
        "docs_href": "/scores",
    },
    "risk-economics": {
        "title": "Risk Economics",
        "body": "Translates technical findings into business numbers: estimated audit-"
                "failure exposure, remediation cost in $ + engineer-hours, risk-"
                "reduction ROI ranking, technical-debt score. Disclaimer: figures are "
                "order-of-magnitude estimates from public industry data.",
        "docs_href": "/reports",
    },
    "exec-risk-brief": {
        "title": "Executive Risk Brief preset",
        "body": "v12 flagship 5-minute board-ready report. Composes KPI summary, "
                "executive narrative, multi-dim Safe Score radar, weakest-link "
                "analysis, attack-path summary, compliance roll-up, risk economics, "
                "top-5 executive actions, and remediation roadmap.",
        "docs_href": "/reports",
    },

    # ----- v12.1 / v12.2 high availability ---------------------------------
    "ha-architecture-a": {
        "title": "HA — shared stores (Architecture A)",
        "body": "Two SafeCadence nodes against shared Postgres + S3 + Redis. The "
                "active node holds the Redis lease and writes; the standby reads. "
                "Best for enterprise installs that already operate a Postgres "
                "cluster. Failover in ~60s on active death.",
        "docs_href": "/help",
    },
    "ha-architecture-b": {
        "title": "HA — peer-to-peer (Architecture B)",
        "body": "Two SafeCadence nodes talk to each other over a single TCP socket. "
                "No Postgres, no Redis, no S3. Best for MSP pair-of-boxes "
                "deployments and air-gapped installs.",
        "docs_href": "/cluster-status",
    },

    # ----- v13 operational excellence --------------------------------------
    "drift-daemon": {
        "title": "Drift monitor daemon",
        "body": "Polls the fleet on a schedule (default 5 minutes), computes the "
                "delta against the last-known-good baseline, and fires webhooks / "
                "tickets only when something changed and the severity is above "
                "the configured threshold. Honors maintenance windows.",
    },
    "bidirectional-ticketing": {
        "title": "Bidirectional ticketing",
        "body": "Tickets are no longer one-way: when Jira / ServiceNow / GitHub / "
                "Linear closes a ticket, the linked finding flips to resolved. "
                "Deduplicates by the upstream event ID so webhook replays are safe.",
        "docs_href": "/help",
    },
    "approval-v2": {
        "title": "Approval workflow v2",
        "body": "Multi-approver chains (N-of-M quorums), delegation rules for OOO, "
                "per-asset-class policies (firewall vs. switch vs. identity), and "
                "time-bound approval validity. Approvals expire after 24h by default.",
    },
    "sse-dashboards": {
        "title": "Live SSE dashboards",
        "body": "Server-Sent Events stream from the active node to every open "
                "dashboard tab. Drift detected on fw-01 shows up in every operator "
                "browser within seconds — no page refresh.",
    },

    # ----- v14 intelligence ------------------------------------------------
    "intelligence-corpus": {
        "title": "Reference corpus",
        "body": "Blends the customer's own local history with per-vertical "
                "published industry baselines (NVD, KEV, DBIR, IBM Cost of a Data "
                "Breach, Mandiant M-Trends, Microsoft DDR, CyberArk, Qualys). The "
                "data_source_breakdown field shows exactly what fed each answer.",
        "docs_href": "/help",
    },
    "intelligence-forecasting": {
        "title": "Predictive forecasting",
        "body": "OLS regression on the customer's own series with honest 90% "
                "confidence bands. Higher-is-better metrics (Safe Score, MFA "
                "coverage) interpret positive slope as 'improving'; lower-is-"
                "better metrics (open critical, patch lag) interpret it as "
                "'worsening' — never mis-reports the direction.",
    },
    "intelligence-anomaly": {
        "title": "Anomaly detection",
        "body": "EWMA + z-score against each entity's own history. Requires at "
                "least 5 observations before flagging, to avoid thin-sample "
                "false positives. Cold-start cases seed from the relevant corpus "
                "baseline.",
    },
    "ai-governance-agents": {
        "title": "AI agent registry",
        "body": "Every AI agent that holds platform credentials gets registered "
                "with an owner, allowed tools, and model + prompt version. Every "
                "MCP tool call ties back to the agent in the audit log.",
        "docs_href": "/ai-agents",
    },
    "ai-governance-keys": {
        "title": "API key inventory",
        "body": "Tracks every API key with provider, owner, scopes, last-rotated, "
                "and last-seen. Never stores the secret — only the last four "
                "characters. A trust score from 0–100 surfaces orphans + stale keys.",
        "docs_href": "/api-keys",
    },
    "remediation-pr": {
        "title": "AI-drafted remediation PRs",
        "body": "Given a finding + a vendor, drafts a config snippet with the "
                "inverse rollback pre-attached. Refuses to hallucinate: if "
                "neither the recipe table nor the BYO-AI provider can produce a "
                "valid snippet, returns 'needs_operator_input' instead.",
    },
}


# Merge into the existing registry so popovers find these too.
def _merge_into_registry() -> None:
    try:
        from safecadence.ui import help_registry as _hr
        for k, v in V13_HELP.items():
            _hr.HELP.setdefault(k, v)
    except Exception:
        pass


_merge_into_registry()


# --------------------------------------------------------------------------
# /help/topics page
# --------------------------------------------------------------------------


_PAGE_CSS = (
    "body{font:14px/1.5 system-ui,sans-serif;background:#0b1020;color:#e7ecf5;margin:0;padding:24px}"
    "h1{margin:0 0 4px;font-size:22px}"
    "p.sub{color:#94a3b8;margin:0 0 24px}"
    "input[type=search]{width:100%;max-width:560px;padding:10px 14px;background:#0a1029;"
    "color:#e7ecf5;border:1px solid #26315b;border-radius:8px;font:inherit;margin-bottom:18px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}"
    ".card{background:#121a33;border:1px solid #26315b;border-radius:10px;padding:14px 16px}"
    ".card h3{margin:0 0 6px;font-size:14px;color:#a5b4fc}"
    ".card p{margin:0;font-size:13px;color:#cbd5e1;line-height:1.45}"
    ".card .ex{margin-top:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#94a3b8;background:#0a1029;padding:6px 8px;border-radius:6px}"
    ".card a{color:#7c5cff;font-size:12px;text-decoration:none}"
    ".card a:hover{text-decoration:underline}"
    ".kicker{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-right:6px}"
)


def _render_topics_page() -> str:
    try:
        from safecadence.ui.help_registry import HELP
        registry = HELP
    except Exception:
        registry = {}

    cards = []
    for k in sorted(registry.keys()):
        entry = registry[k] or {}
        title = _h.escape(entry.get("title") or k)
        body = _h.escape(entry.get("body") or "")
        example = entry.get("example")
        docs_href = entry.get("docs_href")
        ex_html = (
            f"<div class='ex'>{_h.escape(example)}</div>"
            if example else ""
        )
        link_html = (
            f"<a href='{_h.escape(docs_href)}'>Open related page →</a>"
            if docs_href else ""
        )
        cards.append(
            f"<div class='card' data-key='{_h.escape(k)}'>"
            f"<span class='kicker'>{_h.escape(k)}</span>"
            f"<h3>{title}</h3>"
            f"<p>{body}</p>"
            f"{ex_html}{link_html}"
            "</div>"
        )

    js = (
        "<script>"
        "const inp=document.querySelector('#topic-search');"
        "const cards=Array.from(document.querySelectorAll('.card'));"
        "inp.addEventListener('input',function(e){"
          "const q=e.target.value.toLowerCase();"
          "cards.forEach(c=>{"
            "c.style.display=c.textContent.toLowerCase().includes(q)?'':'none';"
          "});"
        "});"
        "</script>"
    )

    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Help — All topics</title>"
        f"<style>{_PAGE_CSS}</style></head><body>"
        "<h1>All help topics</h1>"
        f"<p class='sub'>{len(registry)} entries. Every tooltip in the UI "
        "pulls from this registry.</p>"
        "<input id='topic-search' type='search' placeholder='Filter topics — try drift, mfa, ha…'>"
        f"<div class='grid'>{''.join(cards)}</div>"
        f"{js}"
        "</body></html>"
    )


def _make_router():
    if not _FASTAPI_OK:                                 # pragma: no cover
        return None
    r = APIRouter()

    @r.get("/help/topics", response_class=HTMLResponse)
    def _topics():
        return HTMLResponse(_render_topics_page())

    return r


router = _make_router() if _FASTAPI_OK else None


__all__ = ["V13_HELP", "router"]
