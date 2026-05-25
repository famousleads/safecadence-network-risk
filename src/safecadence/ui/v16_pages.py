"""
v16.0 — UI pages for the agents layer.

Four new routes:

* ``GET  /nudges``                 — operator inbox of pending nudges
* ``POST /api/v1/nudges/{id}/{verb}`` — accept | dismiss | snooze
* ``GET  /red-vs-blue``            — continuous adversarial-pair findings
* ``GET  /agents/{agent_id}``      — per-agent detail + action timeline
* ``POST /api/v1/agents/create``   — closes the v15 "no create form" gap
"""
from __future__ import annotations

import html as _h
import sqlite3
import time
from pathlib import Path

try:
    from fastapi import APIRouter, Form, Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False


def _shell(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{_h.escape(title)}</title>"
        "<style>body{font:14px/1.5 system-ui,sans-serif;background:#0b1020;color:#e7ecf5;margin:0;padding:24px}"
        "h1{margin:0 0 16px;font-size:20px}h2{margin:24px 0 8px;font-size:16px;color:#94a3b8;font-weight:600}"
        ".card{background:#121a33;border:1px solid #26315b;border-radius:12px;padding:18px 20px;margin-bottom:14px}"
        "table{width:100%;border-collapse:collapse;margin-top:8px}"
        "th,td{padding:8px 10px;border-bottom:1px solid #26315b;text-align:left;font-size:13px;vertical-align:top}"
        "th{color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}"
        ".pill-info{background:rgba(59,130,246,.16);color:#3b82f6}"
        ".pill-warn{background:rgba(245,158,11,.16);color:#f59e0b}"
        ".pill-crit{background:rgba(220,38,38,.16);color:#dc2626}"
        ".pill-ok{background:rgba(16,185,129,.16);color:#10b981}"
        ".muted{color:#64748b;font-size:12px}"
        "button,.btn{padding:6px 12px;border:1px solid #26315b;background:#0a1029;color:#e7ecf5;border-radius:6px;cursor:pointer;font-size:13px}"
        "button.primary{background:#7c5cff;color:#fff;border-color:#7c5cff}"
        "button:hover{border-color:#7c5cff}"
        "input,select,textarea{background:#0a1029;color:#e7ecf5;border:1px solid #26315b;border-radius:6px;padding:6px 10px;font:inherit}"
        ".empty{padding:30px;text-align:center;color:#64748b;font-style:italic}"
        ".kpi{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}"
        ".kpi-item{flex:1 1 140px;background:#0a1029;border:1px solid #26315b;border-radius:8px;padding:10px 12px}"
        ".kpi-v{font-size:22px;font-weight:700;color:#7c5cff}"
        ".kpi-l{font-size:11px;text-transform:uppercase;color:#94a3b8}"
        "</style></head><body>"
        f"<h1>{_h.escape(title)}</h1>{body}</body></html>"
    )


def _readonly() -> bool:
    import os
    return (os.getenv("SC_READONLY") or "").strip() in ("1", "true", "yes")


def _agents_db_path() -> Path:
    return Path.home() / ".safecadence" / "agents.db"


def _open_agents_db() -> sqlite3.Connection:
    p = _agents_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p))
    from safecadence.agents.memory import ensure_memory_schema
    from safecadence.agents.nudges import ensure_nudge_schema
    ensure_memory_schema(c)
    ensure_nudge_schema(c)
    return c


def _ai_governance_db_path() -> Path:
    return Path.home() / ".safecadence" / "ai_governance.db"


def _open_governance_db() -> sqlite3.Connection:
    p = _ai_governance_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p))
    from safecadence.ai_governance import ensure_agent_schema
    ensure_agent_schema(c)
    return c


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------


def _render_nudge_card(n: dict) -> str:
    sev_pill = {
        "info": "pill-info", "warning": "pill-warn", "critical": "pill-crit",
    }.get(n["severity"], "pill-info")
    readonly_attr = "disabled" if _readonly() else ""
    actions = (
        "<div style='margin-top:10px;display:flex;gap:6px'>"
        f"<form method='post' action='/api/v1/nudges/{n['id']}/accept' style='display:inline'>"
        f"<button {readonly_attr} class='primary' type='submit'>Accept</button></form>"
        f"<form method='post' action='/api/v1/nudges/{n['id']}/snooze' style='display:inline'>"
        f"<button {readonly_attr} type='submit'>Snooze 7d</button></form>"
        f"<form method='post' action='/api/v1/nudges/{n['id']}/dismiss' style='display:inline'>"
        f"<button {readonly_attr} type='submit'>Dismiss</button></form>"
        "</div>"
    )
    body_safe = _h.escape(n["body"]).replace("\n", "<br>")
    return (
        "<div class='card'>"
        f"<div><span class='pill {sev_pill}'>{_h.escape(n['severity'])}</span>"
        f" <strong style='font-size:15px'>{_h.escape(n['title'])}</strong></div>"
        f"<div class='muted' style='margin:4px 0 10px'>"
        f"by <strong>{_h.escape(n['agent_id'])}</strong> · "
        f"category {_h.escape(n['category'])}</div>"
        f"<div style='font-size:13px;line-height:1.55'>{body_safe}</div>"
        f"{actions}</div>"
    )


def _render_nudges_inbox(nudges: list[dict], summary: dict) -> str:
    if _readonly():
        banner = (
            "<div class='card' style='background:#1a1640;border-color:#7c5cff'>"
            "<strong>Demo preview only.</strong> Buttons are disabled. "
            "On a real install, accepted / snoozed / dismissed nudges drive "
            "follow-up workflows (file exception, draft rollback, etc.).</div>"
        )
    else:
        banner = ""
    kpi = (
        "<div class='kpi'>"
        + "".join(
            f"<div class='kpi-item'><div class='kpi-v'>{summary.get(k, 0)}</div>"
            f"<div class='kpi-l'>{k}</div></div>"
            for k in ("pending", "accepted", "dismissed", "snoozed")
        )
        + "</div>"
    )
    if not nudges:
        return banner + kpi + (
            "<div class='card empty'>No pending nudges. "
            "The agents will queue items here as they observe things "
            "worth your attention.</div>"
        )
    return banner + kpi + "".join(_render_nudge_card(n) for n in nudges)


def _render_red_blue(summary: dict) -> str:
    verdicts = summary.get("verdicts") or []
    if _readonly():
        banner = (
            "<div class='card' style='background:#1a1640;border-color:#7c5cff'>"
            "<strong>Demo preview.</strong> Red walks the Knowledge Graph for "
            "attack paths; Blue checks compensating controls. Only "
            "<strong>disagreements</strong> become operator-visible nudges. "
            "Both agents respect the v12.1 active-only guards.</div>"
        )
    else:
        banner = ""
    kpi = (
        "<div class='kpi'>"
        f"<div class='kpi-item'><div class='kpi-v'>{summary.get('candidates', 0)}</div><div class='kpi-l'>candidate paths</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{summary.get('agreements_exposed', 0)}</div><div class='kpi-l'>agree exposed</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{summary.get('disagreements', 0)}</div><div class='kpi-l'>disagreements</div></div>"
        f"<div class='kpi-item'><div class='kpi-v'>{summary.get('agreements_safe', 0)}</div><div class='kpi-l'>agree safe</div></div>"
        "</div>"
    )
    if not verdicts:
        return banner + kpi + (
            "<div class='card empty'>No attack-path candidates yet. "
            "Either the Knowledge Graph has no edge-tagged assets "
            "(`exposure: public` attribute), or no crown_jewel nodes. "
            "Add at least one of each to see the red-vs-blue pair in action.</div>"
        )
    rows = []
    for v in verdicts[:25]:
        path_str = " → ".join(f"{t}:{i}" for t, i in v["path"])
        ag_pill = {
            "agree_exposed": "pill-crit",
            "disagreement":  "pill-warn",
            "agree_safe":    "pill-ok",
        }.get(v["agreement"], "pill-info")
        rows.append(
            "<tr>"
            f"<td style='font-family:ui-monospace,Menlo,monospace;font-size:12px'>{_h.escape(path_str)}</td>"
            f"<td><span class='pill {ag_pill}'>{_h.escape(v['agreement'])}</span></td>"
            f"<td>red: <strong>{_h.escape(v['red_says'])}</strong> "
            f"({v['red_confidence']})</td>"
            f"<td>blue: <strong>{_h.escape(v['blue_says'])}</strong>"
            f"<div class='muted'>{_h.escape(v['blue_reason'])}</div></td>"
            "</tr>"
        )
    return banner + kpi + (
        "<div class='card'><table><thead><tr>"
        "<th>Path</th><th>Verdict</th><th>Red</th><th>Blue</th>"
        "</tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def _render_agent_create_form() -> str:
    banner = ""
    if _readonly():
        banner = (
            "<div class='card' style='background:#1a1640;border-color:#7c5cff'>"
            "<strong>Demo preview only — form is disabled.</strong> "
            "On a real install, this creates an entry in the v14 agent "
            "registry; every subsequent MCP tool call by this agent ties "
            "back to it in the v11.3 hash-chained audit log.</div>"
        )
    ro_attr = "disabled" if _readonly() else ""
    return banner + (
        "<form method='post' action='/api/v1/agents/create' class='card'>"
        "<h2 style='margin:0 0 10px'>Register a new agent</h2>"
        "<label style='display:block;margin:8px 0'>Name<br>"
        f"<input name='name' required {ro_attr} placeholder='QA bot' style='width:100%;max-width:400px'></label>"
        "<label style='display:block;margin:8px 0'>Owner (user_id)<br>"
        f"<input name='owner_user_id' required {ro_attr} placeholder='alice@acme.example' style='width:100%;max-width:400px'></label>"
        "<label style='display:block;margin:8px 0'>Model<br>"
        f"<input name='model' {ro_attr} placeholder='claude-opus-4 / gpt-4o-mini / ollama:llama3' style='width:100%;max-width:400px'></label>"
        "<label style='display:block;margin:8px 0'>Allowed MCP tools (comma-separated)<br>"
        f"<input name='allowed_tools' {ro_attr} placeholder='query_topology, retrieve_findings' style='width:100%;max-width:400px'></label>"
        f"<button class='primary' type='submit' {ro_attr}>Register</button>"
        "</form>"
    )


def _render_agent_detail(agent: dict, memory_rows: list[dict],
                          recent_nudges: list[dict]) -> str:
    if not agent:
        return "<div class='card empty'>Agent not found.</div>"
    rows = "".join(
        f"<tr><td>{_h.escape(m.get('kind', ''))}</td>"
        f"<td style='font-family:ui-monospace,Menlo,monospace;font-size:12px'>{_h.escape(m.get('signature', ''))}</td>"
        f"<td class='muted'>{_h.escape(str(m.get('recorded_at', '')))}</td></tr>"
        for m in memory_rows[:50]
    )
    nudge_html = "".join(_render_nudge_card(n) for n in recent_nudges[:10])
    return (
        f"<div class='card'><h2 style='margin:0 0 8px'>{_h.escape(agent.get('name', ''))}</h2>"
        f"<div class='muted'>ID: <code>{_h.escape(agent.get('agent_id', ''))}</code> · "
        f"Status: {_h.escape(agent.get('status', ''))} · "
        f"Owner: {_h.escape(agent.get('owner_user_id', '') or '(orphan)')} · "
        f"Model: {_h.escape(agent.get('model', '') or '(unspecified)')}</div>"
        f"<div style='margin-top:8px'>Allowed tools: "
        + ", ".join(f"<code>{_h.escape(t)}</code>" for t in (agent.get('allowed_tools') or []))
        + "</div></div>"
        f"<h2>Recent action timeline</h2>"
        + (f"<div class='card'><table><thead><tr><th>Kind</th><th>Signature</th><th>When (unix)</th></tr></thead><tbody>{rows}</tbody></table></div>"
           if rows else "<div class='card empty'>No recorded actions yet.</div>")
        + f"<h2>Recent nudges from this agent</h2>"
        + (nudge_html or "<div class='card empty'>No nudges from this agent yet.</div>")
    )


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------


def _make_router():
    if not _FASTAPI_OK:                                 # pragma: no cover
        return None
    router = APIRouter()

    @router.get("/nudges", response_class=HTMLResponse)
    def _nudges_page(request: Request):
        from safecadence.agents.nudges import list_nudges, nudge_summary
        try:
            c = _open_agents_db()
            nudges = list_nudges(c)
            summary = nudge_summary(c)
        except Exception as exc:
            return HTMLResponse(_shell("Nudge inbox",
                f"<div class='card'>Error: {_h.escape(str(exc))}</div>"))
        return HTMLResponse(_shell("AI agent nudge inbox",
            _render_nudges_inbox(nudges, summary)))

    @router.post("/api/v1/nudges/{nudge_id}/{verb}", response_class=HTMLResponse)
    async def _nudge_action(nudge_id: int, verb: str, request: Request):
        from safecadence.agents.nudges import (
            accept_nudge, dismiss_nudge, snooze_nudge,
        )
        if _readonly():
            return HTMLResponse(
                "<div class='card'>Demo is read-only.</div>",
                status_code=403,
            )
        c = _open_agents_db()
        operator = request.headers.get("X-SafeCadence-User") or "operator"
        if verb == "accept":
            accept_nudge(c, nudge_id, operator)
        elif verb == "dismiss":
            dismiss_nudge(c, nudge_id, operator)
        elif verb == "snooze":
            snooze_nudge(c, nudge_id, operator, days=7)
        else:
            return HTMLResponse(
                f"<div class='card'>Unknown verb: {_h.escape(verb)}</div>",
                status_code=400,
            )
        return RedirectResponse(url="/nudges", status_code=303)

    @router.get("/red-vs-blue", response_class=HTMLResponse)
    def _red_blue_page(request: Request):
        from safecadence.agents.adversarial import run_round
        try:
            from safecadence.graph import GraphStore, rebuild
            g = GraphStore()
            rebuild(g)
            nc = _open_agents_db()
            summary = run_round(g, nudge_conn=nc)
        except Exception as exc:
            return HTMLResponse(_shell("Red vs Blue",
                f"<div class='card'>Error: {_h.escape(str(exc))}</div>"))
        return HTMLResponse(_shell(
            "Red vs Blue (continuous adversarial pair)",
            _render_red_blue(summary),
        ))

    @router.get("/ai-agents/new", response_class=HTMLResponse)
    def _agent_new_page(request: Request):
        return HTMLResponse(_shell(
            "Register a new AI agent",
            _render_agent_create_form(),
        ))

    @router.post("/api/v1/agents/create", response_class=HTMLResponse)
    async def _agent_create(request: Request):
        from safecadence.ai_governance import register_agent
        if _readonly():
            return HTMLResponse(
                "<div class='card'>Demo is read-only.</div>",
                status_code=403,
            )
        form = await request.form()
        name = (form.get("name") or "").strip()
        owner = (form.get("owner_user_id") or "").strip()
        model = (form.get("model") or "").strip()
        tools_raw = (form.get("allowed_tools") or "").strip()
        tools = [t.strip() for t in tools_raw.split(",") if t.strip()]
        if not name or not owner:
            return HTMLResponse(
                _shell("Register a new AI agent",
                "<div class='card'>name and owner are required</div>"
                + _render_agent_create_form()),
                status_code=400,
            )
        c = _open_governance_db()
        register_agent(c, name=name, owner_user_id=owner,
                        model=model, allowed_tools=tools)
        return RedirectResponse(url="/ai-agents", status_code=303)

    @router.get("/agents/{agent_id}", response_class=HTMLResponse)
    def _agent_detail_page(agent_id: str, request: Request):
        from safecadence.agents.memory import recall
        from safecadence.agents.nudges import list_nudges
        from safecadence.ai_governance import get_agent
        try:
            gc = _open_governance_db()
            ac = _open_agents_db()
            agent = get_agent(gc, agent_id)
            mem = recall(ac, agent_id, since_days=90)
            nudges = list_nudges(ac, status=None, agent_id=agent_id)
        except Exception as exc:
            return HTMLResponse(_shell("Agent detail",
                f"<div class='card'>Error: {_h.escape(str(exc))}</div>"))
        return HTMLResponse(_shell(
            f"Agent: {agent.get('name', agent_id) if agent else agent_id}",
            _render_agent_detail(agent, mem, nudges),
        ))

    return router


router = _make_router() if _FASTAPI_OK else None


__all__ = ["router"]
