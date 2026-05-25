"""
v12.0.0a6 — Lightweight UI page wrappers for v12 / v14 surfaces.

Three pages, each a thin server-rendered shell over the existing
JSON APIs:

* ``/cluster-status``  — wraps GET /api/v1/cluster/status
* ``/ai-agents``       — lists rows from ai_agents table + trust scores
* ``/api-keys``        — lists rows from ai_api_keys table + trust scores

All three are read-only, so they're safe to show on the standby node
too. The cluster status page works in single-node mode (just shows
"single-node" badge).

Public API
----------

* ``router`` — FastAPI APIRouter mounting all three GET routes
"""
from __future__ import annotations

import html as _h
from typing import Any

try:
    from fastapi import APIRouter, Request
    from fastapi.responses import HTMLResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------


def _shell(title: str, body: str) -> str:
    """Tiny page shell. Real chrome is wrapped by the v9 _chrome module
    when these routes are accessed through the live app; this fallback
    is here so the pages render correctly in tests + when chrome
    isn't available."""
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{_h.escape(title)}</title>"
        "<style>body{font:14px/1.5 system-ui,sans-serif;background:#0b1020;color:#e7ecf5;margin:0;padding:24px}"
        "h1{margin:0 0 16px;font-size:20px}h2{margin:24px 0 8px;font-size:16px;color:#94a3b8;font-weight:600}"
        ".card{background:#121a33;border:1px solid #26315b;border-radius:12px;padding:18px 20px;margin-bottom:14px}"
        "table{width:100%;border-collapse:collapse;margin-top:8px}"
        "th,td{padding:8px 10px;border-bottom:1px solid #26315b;text-align:left;font-size:13px}"
        "th{color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}"
        ".pill-active{background:rgba(16,185,129,.16);color:#10b981}"
        ".pill-standby{background:rgba(245,158,11,.16);color:#f59e0b}"
        ".pill-error{background:rgba(220,38,38,.16);color:#dc2626}"
        ".pill-ok{background:rgba(16,185,129,.16);color:#10b981}"
        ".muted{color:#64748b;font-size:12px}"
        ".kpi{display:flex;gap:16px;flex-wrap:wrap}"
        ".kpi-item{flex:1 1 140px;background:#0a1029;border:1px solid #26315b;border-radius:10px;padding:12px 14px}"
        ".kpi-v{font-size:24px;font-weight:700;color:#7c5cff}"
        ".kpi-l{font-size:11px;text-transform:uppercase;color:#94a3b8;margin-top:4px}"
        "</style></head><body>"
        f"<h1>{_h.escape(title)}</h1>"
        f"{body}"
        "</body></html>"
    )


# --------------------------------------------------------------------------
# /cluster-status — wraps the cluster/status API
# --------------------------------------------------------------------------


def _render_cluster_status(state: dict) -> str:
    local = state.get("local") or {}
    repl = state.get("replication_lag") or {}

    is_active = bool(local.get("is_active_node"))
    role_pill = (
        f"<span class='pill pill-active'>ACTIVE</span>" if is_active
        else f"<span class='pill pill-standby'>STANDBY</span>"
    )
    node_name = _h.escape(str(local.get("node") or "?"))
    peer_count = int(state.get("peer_count", 0) or 0)
    reachable = int(state.get("reachable_peers", 0) or 0)

    kpi = (
        "<div class='kpi'>"
        f"<div class='kpi-item'><div class='kpi-v'>{role_pill}</div>"
        f"<div class='kpi-l'>this node ({node_name})</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{reachable}/{peer_count}</div>"
        "<div class='kpi-l'>peers reachable</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{_h.escape(str(repl.get('role','?')))}</div>"
        "<div class='kpi-l'>db replication role</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{repl.get('lag_seconds') if repl.get('lag_seconds') is not None else '—'}</div>"
        "<div class='kpi-l'>repl lag (s)</div></div>"
        "</div>"
    )

    health = local.get("ok", True)
    health_note = (
        "<div class='card'>"
        f"<strong>Local health:</strong> "
        f"db_status={_h.escape(str(local.get('db_status','?')))} · "
        f"redis_status={_h.escape(str(local.get('redis_status','?')))} · "
        f"s3_status={_h.escape(str(local.get('s3_status','?')))} · "
        f"last_scan_age_s={_h.escape(str(local.get('last_scan_age_s','?')))}"
        "</div>"
    )

    _ok_pill = '<span class="pill pill-ok">ok</span>'
    _err_pill = '<span class="pill pill-error">unreachable</span>'
    peers_rows = "".join(
        f"<tr><td>{_h.escape(str(p.get('peer','?')))}</td>"
        f"<td>{_ok_pill if p.get('reachable') else _err_pill}</td>"
        f"<td class='muted'>{_h.escape(str(p.get('error') or ''))}</td></tr>"
        for p in (state.get("peers") or [])
    )
    peers_table = (
        "<div class='card'><h2 style='margin:0 0 8px'>Peers</h2>"
        + ("<table><thead><tr><th>Peer</th><th>Reachable</th><th>Note</th></tr></thead>"
           f"<tbody>{peers_rows}</tbody></table>" if peers_rows else
           "<div class='muted'>No peers configured — running single-node.</div>")
        + "</div>"
    )

    repl_note = ""
    if repl.get("note"):
        repl_note = f"<div class='card'><strong>Replication:</strong> {_h.escape(str(repl.get('note','')))}</div>"

    actions = (
        "<div class='card'>"
        "<h2 style='margin:0 0 8px'>Manual actions</h2>"
        "<form method='post' action='/api/v1/cluster/transfer' style='display:inline'>"
        "<button type='submit' style='padding:6px 12px;border:1px solid #26315b;background:#0a1029;color:#e7ecf5;border-radius:8px;cursor:pointer'>"
        "Drain (release lease)</button></form>"
        "<div class='muted' style='margin-top:6px'>"
        "Use before maintenance. The peer node grabs the lease within ~LEASE_TTL_S seconds.</div>"
        "</div>"
    )

    return kpi + health_note + repl_note + peers_table + actions


# --------------------------------------------------------------------------
# /ai-agents — lists registered v14 AI agents
# --------------------------------------------------------------------------


def _render_ai_agents(agents: list[dict], scores_by_id: dict[str, dict]) -> str:
    if not agents:
        return (
            "<div class='card'>"
            "<strong>No AI agents registered.</strong><br>"
            "<span class='muted'>"
            "Register agents via <code>safecadence.ai_governance.register_agent()</code>. "
            "Once an agent is registered, every MCP tool call it makes is "
            "attributed to it in the audit log.</span>"
            "</div>"
        )

    rows = []
    for a in agents:
        s = scores_by_id.get(a["agent_id"]) or {}
        score = s.get("score", "—")
        status = a.get("status", "")
        status_pill = (
            f"<span class='pill pill-ok'>{_h.escape(status)}</span>"
            if status == "active" else
            f"<span class='pill pill-standby'>{_h.escape(status)}</span>"
        )
        rows.append(
            f"<tr><td><strong>{_h.escape(a.get('name',''))}</strong>"
            f"<div class='muted'>{_h.escape(a.get('agent_id',''))}</div></td>"
            f"<td>{status_pill}</td>"
            f"<td>{_h.escape(a.get('model',''))}</td>"
            f"<td>{_h.escape(a.get('owner_user_id','') or '<orphan>')}</td>"
            f"<td>{len(a.get('allowed_tools') or [])}</td>"
            f"<td><strong>{score}</strong></td></tr>"
        )

    table = (
        "<div class='card'>"
        "<table><thead><tr><th>Agent</th><th>Status</th><th>Model</th>"
        "<th>Owner</th><th># tools</th><th>Trust</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</div>"
    )
    return table


# --------------------------------------------------------------------------
# /api-keys — lists v14 API key inventory
# --------------------------------------------------------------------------


def _render_api_keys(keys: list[dict], scores_by_id: dict[str, dict]) -> str:
    if not keys:
        return (
            "<div class='card'>"
            "<strong>No API keys tracked.</strong><br>"
            "<span class='muted'>"
            "Add keys via <code>safecadence.ai_governance.register_api_key()</code>. "
            "The platform stores only the last-four — never the secret itself."
            "</span></div>"
        )

    rows = []
    for k in keys:
        s = scores_by_id.get(k["key_id"]) or {}
        score = s.get("score", "—")
        last_seen = k.get("last_seen_at")
        last_seen_str = "never" if not last_seen else "active"
        rows.append(
            f"<tr><td><strong>{_h.escape(k.get('label',''))}</strong>"
            f"<div class='muted'>{_h.escape(k.get('key_id',''))}</div></td>"
            f"<td>{_h.escape(k.get('provider',''))}</td>"
            f"<td>****{_h.escape(k.get('last_four','') or '')}</td>"
            f"<td>{_h.escape(k.get('owner_user_id','') or '<orphan>')}</td>"
            f"<td>{len(k.get('scopes') or [])}</td>"
            f"<td>{last_seen_str}</td>"
            f"<td><strong>{score}</strong></td></tr>"
        )

    return (
        "<div class='card'>"
        "<table><thead><tr><th>Label</th><th>Provider</th><th>Key</th>"
        "<th>Owner</th><th># scopes</th><th>Last seen</th><th>Trust</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</div>"
    )


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------


def _make_router():
    if not _FASTAPI_OK:                                 # pragma: no cover
        return None
    router = APIRouter()

    @router.get("/cluster-status", response_class=HTMLResponse)
    def _cluster_status_page(request: Request):
        try:
            from safecadence.cluster.health import cluster_state
            from safecadence.cluster.replication_lag import probe_lag
            state = cluster_state()
            state["replication_lag"] = probe_lag()
        except Exception as exc:
            return HTMLResponse(_shell(
                "Cluster status",
                f"<div class='card'>Error: {_h.escape(str(exc))}</div>"
            ), status_code=200)
        return HTMLResponse(_shell("Cluster status", _render_cluster_status(state)))

    @router.get("/ai-agents", response_class=HTMLResponse)
    def _ai_agents_page(request: Request):
        agents: list[dict] = []
        scores_by_id: dict[str, dict] = {}
        try:
            import sqlite3
            from pathlib import Path
            from safecadence.ai_governance import (
                ensure_agent_schema, list_agents, score_agent,
            )
            db = Path.home() / ".safecadence" / "ai_governance.db"
            db.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db))
            ensure_agent_schema(conn)
            agents = list_agents(conn)
            for a in agents:
                scores_by_id[a["agent_id"]] = score_agent(a)
        except Exception:
            pass
        body = _render_ai_agents(agents, scores_by_id)
        return HTMLResponse(_shell("AI agents", body))

    @router.get("/api-keys", response_class=HTMLResponse)
    def _api_keys_page(request: Request):
        keys: list[dict] = []
        scores_by_id: dict[str, dict] = {}
        try:
            import sqlite3
            from pathlib import Path
            from safecadence.ai_governance import (
                ensure_api_key_schema, list_api_keys, score_api_key,
            )
            db = Path.home() / ".safecadence" / "ai_governance.db"
            db.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db))
            ensure_api_key_schema(conn)
            keys = list_api_keys(conn)
            for k in keys:
                scores_by_id[k["key_id"]] = score_api_key(k)
        except Exception:
            pass
        body = _render_api_keys(keys, scores_by_id)
        return HTMLResponse(_shell("API key inventory", body))

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
