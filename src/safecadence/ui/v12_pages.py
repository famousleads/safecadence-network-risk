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
    from fastapi import APIRouter, Form, Request
    from fastapi.responses import HTMLResponse, RedirectResponse
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
           "<div class='muted'>No peers configured — running single-node. "
           "<a href='/cluster-status/configure' style='color:#7c5cff'>"
           "Configure peers →</a></div>")
        + "</div>"
    )

    repl_note = ""
    if repl.get("note"):
        repl_note = f"<div class='card'><strong>Replication:</strong> {_h.escape(str(repl.get('note','')))}</div>"

    actions = (
        "<div class='card'>"
        "<h2 style='margin:0 0 8px'>Manual actions</h2>"
        "<a href='/cluster-status/configure' "
        "style='display:inline-block;padding:6px 12px;border:1px solid #7c5cff;background:#1a1640;color:#a78bfa;border-radius:8px;text-decoration:none;margin-right:8px'>"
        "⚙️ Configure peers</a>"
        "<form method='post' action='/api/v1/cluster/transfer' style='display:inline'>"
        "<button type='submit' style='padding:6px 12px;border:1px solid #26315b;background:#0a1029;color:#e7ecf5;border-radius:8px;cursor:pointer'>"
        "Drain (release lease)</button></form>"
        "<div class='muted' style='margin-top:6px'>"
        "Use before maintenance. The peer node grabs the lease within ~LEASE_TTL_S seconds.</div>"
        "</div>"
    )

    return kpi + health_note + repl_note + peers_table + actions


# --------------------------------------------------------------------------
# /cluster-status/configure — form to set HA env vars
# --------------------------------------------------------------------------


def _render_configure_form(
    cfg: dict, errors: list[str] | None = None,
    saved: bool = False, warnings: list[str] | None = None,
) -> str:
    from safecadence.cluster.config_persistence import is_readonly, SECRET_KEYS

    readonly = is_readonly()
    masked = cfg.get("masked", {})
    has_secrets = cfg.get("has_secrets", {})

    banner_html = ""
    if readonly:
        banner_html = (
            "<div class='card' style='background:#1a1640;border-color:#7c5cff'>"
            "<strong>Preview only — this is a demo install (SC_READONLY=1).</strong>"
            "<br><span class='muted'>The form below shows the configuration "
            "surface a real operator would use. Submissions are blocked. "
            "On your own install, the form persists to "
            "<code>~/.safecadence/cluster.env</code>.</span></div>"
        )
    if saved:
        banner_html += (
            "<div class='card' style='background:rgba(16,185,129,.08);border-color:#10b981'>"
            "<strong>✓ Saved.</strong> "
            + " ".join(f"<span class='muted'>{_h.escape(w)}</span>"
                        for w in (warnings or []))
            + "</div>"
        )
    if errors:
        banner_html += (
            "<div class='card' style='background:rgba(220,38,38,.08);border-color:#dc2626'>"
            "<strong>Cannot save</strong><ul style='margin:6px 0 0 18px'>"
            + "".join(f"<li>{_h.escape(e)}</li>" for e in errors)
            + "</ul></div>"
        )

    def field(name: str, label: str, hint: str = "",
              placeholder: str = "") -> str:
        is_secret = name in SECRET_KEYS
        val = masked.get(name, "")
        current_hint = ""
        if is_secret and has_secrets.get(name):
            current_hint = (
                "<div class='muted' style='margin-top:4px'>"
                "Secret currently set; leave blank to keep it. "
                f"Last 4: <code>{_h.escape(val[-4:] if len(val) >= 4 else val)}</code>"
                "</div>"
            )
            val = ""   # don't pre-fill secret fields
        return (
            f"<label style='display:block;margin:10px 0'>"
            f"<div style='font-weight:600;color:#cbd5e1'>{_h.escape(label)}</div>"
            f"<div class='muted' style='margin:2px 0 6px'>{_h.escape(hint)}</div>"
            f"<input type='{'password' if is_secret else 'text'}' "
            f"name='{_h.escape(name)}' "
            f"value='{_h.escape(val)}' "
            f"placeholder='{_h.escape(placeholder)}' "
            f"{'disabled' if readonly else ''} "
            f"style='width:100%;max-width:480px;padding:8px 10px;background:#0a1029;color:#e7ecf5;border:1px solid #26315b;border-radius:6px;font-family:ui-monospace,Menlo,monospace;font-size:13px'>"
            f"{current_hint}"
            f"</label>"
        )

    # Mode selector renders as a select; rest are text fields
    current_mode = masked.get("SC_HA_MODE", "") or ""
    mode_options = []
    for m in ("", "shared-stores", "peer-sync"):
        label = "(single-node default)" if m == "" else m
        sel = " selected" if m == current_mode else ""
        mode_options.append(
            f"<option value='{m}'{sel}>{label}</option>"
        )
    mode_select = (
        "<label style='display:block;margin:10px 0'>"
        "<div style='font-weight:600;color:#cbd5e1'>SC_HA_MODE</div>"
        "<div class='muted' style='margin:2px 0 6px'>"
        "Which HA architecture this node participates in.</div>"
        f"<select name='SC_HA_MODE' {'disabled' if readonly else ''} "
        "style='padding:8px 10px;background:#0a1029;color:#e7ecf5;border:1px solid #26315b;border-radius:6px'>"
        f"{''.join(mode_options)}</select></label>"
    )

    form = (
        "<form method='post' action='/api/v1/cluster/configure'>"
        + mode_select
        + field("SC_NODE_NAME", "Node name",
                "Unique identifier for this host in cluster status output.",
                "node-1")
        + "<h3 style='margin:18px 0 4px;color:#94a3b8;font-size:13px;text-transform:uppercase;letter-spacing:.04em'>Architecture A — shared stores</h3>"
        + field("SC_REDIS_URL", "Redis URL",
                "Coordinates the active-node lease. redis:// or rediss://.",
                "redis://redis.internal:6379/0")
        + field("SC_CLUSTER_PEERS", "Cluster peers",
                "Comma-separated host[:port] list of OTHER nodes for healthz aggregation.",
                "node-2.internal:8003,node-3.internal:8003")
        + field("DATABASE_URL", "Database URL",
                "Postgres connection string. Required for true HA (SQLite can't replicate).",
                "postgres://safecadence:secret@primary/safecadence")
        + field("SC_S3_BUCKET", "S3 bucket",
                "Shared bucket for reports/evidence/attachments.",
                "safecadence-shared")
        + field("SC_S3_ENDPOINT", "S3 endpoint",
                "Leave blank for AWS S3; set for MinIO / Wasabi / Backblaze.",
                "https://minio.internal:9000")
        + "<h3 style='margin:18px 0 4px;color:#94a3b8;font-size:13px;text-transform:uppercase;letter-spacing:.04em'>Architecture B — peer-to-peer sync</h3>"
        + field("SC_PEER_HOST", "Peer host",
                "Hostname / IP of the OTHER node. Required when SC_HA_MODE=peer-sync.",
                "10.0.0.20")
        + field("SC_PEER_PORT", "Peer port",
                "Port the OTHER node listens on for incoming events.",
                "8767")
        + field("SC_PEER_LISTEN_HOST", "Local listen host",
                "Interface this node binds for incoming peer events. Default 0.0.0.0.",
                "0.0.0.0")
        + field("SC_PEER_LISTEN_PORT", "Local listen port",
                "Port this node binds for incoming peer events. Default 8767.",
                "8767")
        + field("SC_PEER_SECRET", "Shared HMAC secret",
                "≥ 24 chars; same value on both nodes. Generate via "
                "`openssl rand -hex 32`.",
                "(paste a long random string)")
        + (
            ""
            if readonly else
            "<button type='submit' "
            "style='margin-top:14px;padding:10px 22px;background:#7c5cff;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer'>"
            "Save configuration</button>"
        )
        + "</form>"
    )

    help_card = (
        "<div class='card' style='margin-top:18px'>"
        "<h2 style='margin:0 0 8px'>How this works</h2>"
        "<ul style='margin:0 0 0 18px;font-size:13px;line-height:1.55'>"
        "<li>Settings persist to <code>~/.safecadence/cluster.env</code> "
        "(mode 0600, owner-only). No root required.</li>"
        "<li>The systemd unit sources that file via "
        "<code>EnvironmentFile=-~/.safecadence/cluster.env</code> "
        "(the leading <code>-</code> means 'ignore if missing').</li>"
        "<li>Changes take effect on the next service restart: "
        "<code>systemctl restart safecadence</code>.</li>"
        "<li>Secrets are stored encrypted at rest on disk; the form "
        "displays only the last 4 characters and accepts blank as 'keep current'.</li>"
        "<li>Full HA deployment guide: "
        "<a href='https://github.com/famousleads/safecadence-network-risk/blob/main/docs/HA_DEPLOYMENT.md' "
        "style='color:#7c5cff'>docs/HA_DEPLOYMENT.md</a></li>"
        "</ul></div>"
    )

    return banner_html + form + help_card


# --------------------------------------------------------------------------
# /ai-agents — lists registered v14 AI agents
# --------------------------------------------------------------------------


def _render_ai_agents(agents: list[dict], scores_by_id: dict[str, dict]) -> str:
    # v16 — top-of-page action: register a new agent via the form.
    actions = (
        "<div class='card' style='display:flex;justify-content:space-between;align-items:center;background:#0a1029;border-color:#7c5cff'>"
        "<div><strong>Registered agents</strong> are tracked in the v14 "
        "governance registry. Every MCP tool call by a registered agent "
        "ties back to it in the audit log.</div>"
        "<a href='/ai-agents/new' style='padding:6px 14px;background:#7c5cff;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px'>"
        "+ Register agent</a></div>"
    )

    if not agents:
        return actions + (
            "<div class='card'>"
            "<strong>No AI agents registered yet.</strong><br>"
            "<span class='muted'>"
            "Click <strong>Register agent</strong> above to add one via the form, "
            "or call <code>safecadence.ai_governance.register_agent()</code> directly."
            "</span></div>"
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
    # v15.1.2 — disambiguating banner.
    # This page is for the GOVERNANCE inventory of API keys that exist
    # in the customer's environment (last-four only, never the secret).
    # The operator's own BYO-AI / LLM provider keys live in
    # Settings → AI / LLM. Cross-link both ways so users can't conflate them.
    banner = (
        "<div class='card' style='background:#0a1029;border-color:#7c5cff'>"
        "<strong>This page tracks third-party API keys for posture + "
        "governance.</strong><br>"
        "<span class='muted'>Last-four characters only; the secret is "
        "never stored. Use this to track an OAuth / API key issued to a "
        "service account or AI agent in your environment.</span>"
        "<div style='margin-top:10px;font-size:13px'>"
        "<strong>Looking for your own BYO-AI / LLM provider key</strong> "
        "(OpenAI / Anthropic / Gemini / etc.)? That's a different setting → "
        "<a href='/settings/llm' style='color:#7c5cff'>Settings → AI / LLM</a>."
        "</div></div>"
    )

    if not keys:
        return banner + (
            "<div class='card'>"
            "<strong>No API keys tracked yet.</strong><br>"
            "<span class='muted'>"
            "Register a key via <code>safecadence.ai_governance.register_api_key()</code> "
            "or through the upcoming /api-keys/add UI."
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

    return banner + (
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
        return HTMLResponse(_shell(
            "Machine identity & API key governance", body,
        ))

    @router.get("/cluster-status/configure", response_class=HTMLResponse)
    def _cluster_configure_page(
        request: Request,
        saved: str = "",
        err: str = "",
    ):
        from safecadence.cluster.config_persistence import read_config
        cfg = read_config()
        errors = [err] if err else []
        body = _render_configure_form(
            cfg, errors=errors, saved=(saved == "1"),
        )
        return HTMLResponse(_shell(
            "Configure cluster peers", body,
        ))

    @router.post("/api/v1/cluster/configure", response_class=HTMLResponse)
    async def _cluster_configure_save(request: Request):
        from safecadence.cluster.config_persistence import (
            KNOWN_KEYS, write_config,
        )
        form = await request.form()
        values = {k: str(form.get(k, "")) for k in KNOWN_KEYS}
        result = write_config(values)
        if result["ok"]:
            return RedirectResponse(
                url="/cluster-status/configure?saved=1",
                status_code=303,
            )
        # Re-render the form with errors inline
        from safecadence.cluster.config_persistence import read_config
        cfg = read_config()
        body = _render_configure_form(
            cfg,
            errors=result["errors"],
            warnings=result.get("warnings"),
        )
        return HTMLResponse(
            _shell("Configure cluster peers", body),
            status_code=400,
        )

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
