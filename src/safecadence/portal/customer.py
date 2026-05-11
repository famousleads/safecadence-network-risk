"""
Customer portal routes (v10.9).

Server-rendered HTML at ``/portal/*``. Sections:

  GET  /portal              — dashboard (plan, usage bars, action items)
  GET  /portal/billing      — subscription + invoices + plan change
  GET  /portal/team         — team roster + invite
  POST /portal/team/invite  — send magic-link invite (admin only)
  POST /portal/team/remove  — remove member (admin only; uses POST for HTML form)
  GET  /portal/usage        — usage charts (monthly history)
  GET  /portal/support      — contact form + recent tickets

Org id is read from the ``sc_org`` cookie (set on signup), fallback to
``?org_id=`` query for shareable links. If no org id resolves, the user
gets a "Select org" stub. Admin-gated routes verify the caller is an
ADMIN of the chosen org via :func:`safecadence.auth.rbac.get_role`.
"""

from __future__ import annotations

import html
import os
from typing import Any

try:
    from fastapi import APIRouter, Body, Form, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    _FASTAPI_OK = True
except Exception:                                      # pragma: no cover
    _FASTAPI_OK = False

from safecadence.auth.deps import optional_session, require_session


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _resolve_org_id(request) -> str:
    return (
        (request.cookies.get("sc_org") or "")
        or (request.query_params.get("org_id") or "")
        or (request.headers.get("X-SafeCadence-Org") or "")
    ).strip()


def _is_admin(org_id: str, email: str) -> bool:
    if os.environ.get("SC_AUTH_DISABLED", "") == "1":
        return True
    from safecadence.auth.rbac import get_role, UserRole
    return get_role(org_id, email) == UserRole.ADMIN


def _page(title: str, body: str, *,
          active: str = "dashboard",
          org_id: str = "",
          email: str = "") -> str:
    nav_items = [
        ("dashboard", "/portal", "Overview"),
        ("billing", "/portal/billing", "Billing"),
        ("team", "/portal/team", "Team"),
        ("usage", "/portal/usage", "Usage"),
        ("support", "/portal/support", "Support"),
    ]
    nav_html = "".join(
        f'<a href="{href}" class="{"active" if key == active else ""}">{name}</a>'
        for key, href, name in nav_items
    )
    org_chip = (
        f'<span class="orgchip">{html.escape(org_id or "no org")}</span>'
        if org_id else ""
    )
    email_chip = (
        f'<span class="emailchip">{html.escape(email)}</span>'
        if email else ""
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)} — SafeCadence Portal</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 :root{{--bg:#0b1020;--card:#121a33;--bd:#26315b;--fg:#e7ecf5;--muted:#8b95b1;
        --pri:#7c5cff;--ok:#10b981;--warn:#f59e0b;--err:#ef4444;}}
 body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;}}
 header{{background:var(--card);border-bottom:1px solid var(--bd);
         display:flex;align-items:center;gap:18px;padding:14px 28px;}}
 header h1{{font-size:18px;margin:0;color:#fff;flex:1;}}
 header a{{color:var(--muted);text-decoration:none;font-size:13px;}}
 header a.active,header a:hover{{color:#fff;}}
 .nav{{display:flex;gap:18px;}}
 .orgchip,.emailchip{{font-size:12px;padding:4px 10px;border-radius:999px;
                       background:#1d2645;color:var(--muted);}}
 main{{max-width:1080px;margin:0 auto;padding:32px 28px;}}
 h2{{margin:0 0 18px;font-size:22px;color:#fff;}}
 .grid{{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));}}
 .card{{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;}}
 .kpi{{font-size:28px;font-weight:700;color:#fff;}}
 .label{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}}
 .bar{{height:8px;background:#0a1029;border-radius:4px;overflow:hidden;margin-top:8px;}}
 .bar > span{{display:block;height:100%;background:var(--pri);}}
 .bar.warn > span{{background:var(--warn);}}
 .bar.err > span{{background:var(--err);}}
 table{{width:100%;border-collapse:collapse;}}
 th,td{{padding:10px 12px;border-bottom:1px solid var(--bd);text-align:left;font-size:13px;}}
 th{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}}
 .pill{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;}}
 .pill.ok{{background:#053723;color:#86efac;}}
 .pill.warn{{background:#78350f;color:#fcd34d;}}
 .pill.err{{background:#7f1d1d;color:#fca5a5;}}
 button,.btn{{background:var(--pri);color:#fff;border:0;border-radius:8px;
               padding:9px 14px;font-weight:600;cursor:pointer;font-size:13px;
               text-decoration:none;display:inline-block;}}
 button:hover,.btn:hover{{background:#6648f0;}}
 .btn.secondary{{background:#26315b;color:var(--fg);}}
 .btn.secondary:hover{{background:#334172;}}
 input,select,textarea{{background:#0a1029;color:var(--fg);border:1px solid var(--bd);
                          border-radius:8px;padding:9px 12px;font:inherit;width:100%;
                          box-sizing:border-box;}}
 form .row{{margin:10px 0;}}
 .actions{{margin:14px 0 0;display:flex;gap:10px;}}
 .muted{{color:var(--muted);}}
 .empty{{padding:36px 20px;text-align:center;color:var(--muted);}}
 .bars{{display:grid;gap:6px;}}
 .barrow{{display:grid;grid-template-columns:80px 1fr 60px;align-items:center;gap:10px;font-size:12px;}}
 .miniBar{{height:8px;background:#0a1029;border-radius:4px;overflow:hidden;}}
 .miniBar > span{{display:block;height:100%;background:var(--pri);}}
</style></head><body>
<header>
  <h1>SafeCadence Portal</h1>
  <nav class="nav">{nav_html}</nav>
  {org_chip}{email_chip}
  <form method="post" action="/logout" style="display:inline;margin-left:6px;">
    <button class="btn secondary" type="submit">Sign out</button>
  </form>
</header>
<main>{body}</main>
</body></html>"""


def _bar_class(used: int, limit: int) -> str:
    if limit < 0 or limit == 0:
        return ""
    pct = used / limit
    if pct >= 0.95:
        return "err"
    if pct >= 0.75:
        return "warn"
    return ""


def _bar_pct(used: int, limit: int) -> int:
    if limit < 0:
        return 10
    if limit == 0:
        return 0
    return max(0, min(100, int(round(100 * used / limit))))


def _limit_label(limit: int) -> str:
    return "∞" if limit == -1 else (str(limit) if limit > 0 else "—")


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


def _make_router():
    if not _FASTAPI_OK:                                # pragma: no cover
        return None
    router = APIRouter(prefix="/portal")

    # ---------------- dashboard ---------------------------------------
    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> str:
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        if not org_id:
            body = (
                '<div class="card empty">'
                '<h2>No org selected</h2>'
                '<p>Visit <a href="/signup">signup</a> to create one, or set '
                'the <code>sc_org</code> cookie / <code>?org_id=</code> param.</p>'
                '</div>'
            )
            return _page("Overview", body, email=email)

        from safecadence.billing.plans import get_org_billing, check_quota, get_plan
        from safecadence.billing.usage import get_usage

        rec = get_org_billing(org_id)
        plan = get_plan(rec.get("plan_id") or "Free")
        usage = get_usage(org_id, period="month")
        quotas = {r: check_quota(org_id, r) for r in
                  ("assets", "reports", "api_calls")}

        # Action items: trial ending, past_due, near-quota.
        actions: list[str] = []
        if rec.get("status") == "past_due":
            actions.append(
                '<div class="card" style="border-color:#7f1d1d;">'
                '<span class="pill err">Past due</span> '
                'Update your payment method to keep your subscription active. '
                '<a href="/portal/billing" class="btn">Update billing</a></div>'
            )
        if rec.get("status") == "trialing":
            actions.append(
                '<div class="card" style="border-color:#78350f;">'
                '<span class="pill warn">Trial</span> '
                'You\'re on a 14-day Pro trial. '
                '<a href="/portal/billing" class="btn">Add card</a></div>'
            )
        for r, q in quotas.items():
            if q["limit"] == -1 or q["limit"] == 0:
                continue
            if q["used"] / max(1, q["limit"]) >= 0.8:
                actions.append(
                    f'<div class="card" style="border-color:#78350f;">'
                    f'<span class="pill warn">{r}</span> '
                    f'You\'ve used {q["used"]} of {q["limit"]}. '
                    f'<a href="/portal/billing" class="btn">Upgrade</a></div>'
                )

        actions_html = "".join(actions) or '<div class="card muted empty">All clear.</div>'

        kpi_html = ""
        for resource, label in (("assets", "Assets"),
                                  ("reports", "Reports this month"),
                                  ("api_calls", "API calls this month")):
            q = quotas[resource]
            cls = _bar_class(q["used"], q["limit"])
            pct = _bar_pct(q["used"], q["limit"])
            kpi_html += (
                f'<div class="card">'
                f'<div class="label">{label}</div>'
                f'<div class="kpi">{q["used"]} <span class="muted" '
                f'style="font-size:14px;">/ {_limit_label(q["limit"])}</span></div>'
                f'<div class="bar {cls}"><span style="width:{pct}%"></span></div>'
                '</div>'
            )

        body = f"""<h2>Overview</h2>
<div class="grid">
  <div class="card">
    <div class="label">Current plan</div>
    <div class="kpi">{html.escape(plan.id)}</div>
    <div class="muted">${plan.price_cents/100:.0f}/mo
      <span class="pill ok">{html.escape(rec.get("status") or "active")}</span></div>
    <div class="actions"><a class="btn" href="/portal/billing">Manage</a></div>
  </div>
  {kpi_html}
</div>
<h2 style="margin-top:32px;">Action items</h2>
<div class="grid">{actions_html}</div>
"""
        return _page("Overview", body, active="dashboard",
                      org_id=org_id, email=email)

    # ---------------- billing -----------------------------------------
    @router.get("/billing", response_class=HTMLResponse)
    def billing(request: Request) -> str:
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        from safecadence.billing.plans import (
            get_org_billing, list_plans,
        )
        from safecadence.billing import stripe_client

        rec = get_org_billing(org_id) if org_id else {"plan_id": "Free",
                                                       "status": "active"}
        plan_id = rec.get("plan_id") or "Free"

        # Invoices — only fetched if Stripe is configured + a customer id exists.
        invoices: list[dict] = []
        if (stripe_client.is_configured()
                and rec.get("stripe_customer_id")):
            try:
                invoices = stripe_client.list_invoices(
                    rec["stripe_customer_id"], limit=10
                )
            except Exception:                          # pragma: no cover
                invoices = []

        inv_html = ""
        if invoices:
            rows = ""
            for inv in invoices:
                amt = (inv.get("amount_paid") or 0) / 100
                cur = (inv.get("currency") or "usd").upper()
                status = inv.get("status") or "?"
                hosted = inv.get("hosted_invoice_url") or "#"
                rows += (
                    f'<tr><td>{html.escape(str(inv.get("number") or inv.get("id") or ""))}</td>'
                    f'<td>{amt:.2f} {cur}</td>'
                    f'<td><span class="pill ok">{html.escape(status)}</span></td>'
                    f'<td><a href="{html.escape(hosted)}" target="_blank">View</a></td></tr>'
                )
            inv_html = f'<table><tr><th>Invoice</th><th>Amount</th><th>Status</th><th></th></tr>{rows}</table>'
        else:
            inv_html = '<div class="empty">No invoices yet.</div>'

        # Plan cards
        plan_cards = ""
        for p in list_plans():
            current = (p.id == plan_id)
            feat = "".join(f'<li>{html.escape(f)}</li>' for f in p.features)
            cta = ('<button disabled style="opacity:.4;cursor:default;">Current plan</button>'
                   if current else
                   f'<form method="post" action="/portal/billing/change" style="margin:0;">'
                   f'<input type="hidden" name="plan" value="{html.escape(p.id)}">'
                   f'<button type="submit">Switch to {html.escape(p.id)}</button></form>')
            plan_cards += f"""<div class="card">
  <div class="label">{html.escape(p.name)}</div>
  <div class="kpi">${p.price_cents/100:.0f}<span class="muted" style="font-size:14px;">/mo</span></div>
  <ul style="font-size:12px;color:var(--muted);padding-left:18px;">{feat}</ul>
  <div class="actions">{cta}</div>
</div>"""

        portal_btn = ""
        if rec.get("stripe_customer_id") and stripe_client.is_configured():
            portal_btn = (
                '<form method="post" action="/portal/billing/manage" style="display:inline;">'
                '<button class="btn">Manage in Stripe</button></form>'
            )

        body = f"""<h2>Billing</h2>
<div class="card">
  <div class="label">Current plan</div>
  <div class="kpi">{html.escape(plan_id)}</div>
  <div class="muted">Status: <span class="pill ok">{html.escape(rec.get("status") or "active")}</span></div>
  <div class="actions">{portal_btn}</div>
</div>
<h2 style="margin-top:32px;">Change plan</h2>
<div class="grid">{plan_cards}</div>
<h2 style="margin-top:32px;">Invoices</h2>
<div class="card">{inv_html}</div>"""
        return _page("Billing", body, active="billing",
                      org_id=org_id, email=email)

    @router.post("/billing/change")
    def billing_change(request: Request, plan: str = Form(...)):
        session = require_session(request)
        org_id = _resolve_org_id(request)
        if not org_id:
            raise HTTPException(400, "no org selected")
        plan = (plan or "").strip()
        email = session.get("email") or ""
        if plan.lower() == "free":
            from safecadence.billing.plans import set_org_plan
            set_org_plan(org_id, "Free", source="manual", status="active")
            return RedirectResponse("/portal/billing?changed=1",
                                     status_code=303)
        # Paid plans → checkout.
        from safecadence.billing import stripe_client
        if not stripe_client.is_configured():
            return RedirectResponse(
                "/portal/billing?error=Stripe+not+configured",
                status_code=303,
            )
        base = (os.environ.get("SC_PUBLIC_URL") or
                "https://app.safecadence.com").rstrip("/")
        try:
            out = stripe_client.create_checkout_session(
                plan=plan,
                customer_email=email,
                success_url=f"{base}/portal/billing?ok=1",
                cancel_url=f"{base}/portal/billing?cancelled=1",
                metadata={"org_id": org_id, "plan": plan},
            )
        except Exception as exc:
            return RedirectResponse(
                f"/portal/billing?error={html.escape(str(exc))[:120]}",
                status_code=303,
            )
        target = out.get("url") or "/portal/billing"
        return RedirectResponse(target, status_code=303)

    @router.post("/billing/manage")
    def billing_manage(request: Request):
        require_session(request)
        org_id = _resolve_org_id(request)
        from safecadence.billing import stripe_client
        from safecadence.billing.plans import get_org_billing
        rec = get_org_billing(org_id)
        cid = rec.get("stripe_customer_id")
        if not cid or not stripe_client.is_configured():
            return RedirectResponse("/portal/billing?error=Stripe+not+available",
                                     status_code=303)
        base = (os.environ.get("SC_PUBLIC_URL") or
                "https://app.safecadence.com").rstrip("/")
        try:
            out = stripe_client.create_billing_portal_session(
                cid, f"{base}/portal/billing"
            )
        except Exception as exc:
            return RedirectResponse(
                f"/portal/billing?error={html.escape(str(exc))[:120]}",
                status_code=303,
            )
        return RedirectResponse(out.get("url") or "/portal/billing",
                                 status_code=303)

    # ---------------- team --------------------------------------------
    @router.get("/team", response_class=HTMLResponse)
    def team(request: Request) -> str:
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        from safecadence.auth.rbac import list_members
        members = list_members(org_id) if org_id else []
        is_admin = _is_admin(org_id, email) if org_id else False

        rows = ""
        for m in members:
            remove_form = ""
            if is_admin and m["email"] != email:
                remove_form = (
                    f'<form method="post" action="/portal/team/remove" '
                    f'style="display:inline;margin:0;">'
                    f'<input type="hidden" name="email" value="{html.escape(m["email"])}">'
                    f'<button class="btn secondary" type="submit">Remove</button>'
                    f'</form>'
                )
            rows += (
                f'<tr><td>{html.escape(m["email"])}</td>'
                f'<td><span class="pill ok">{html.escape(m["role"])}</span></td>'
                f'<td>{remove_form}</td></tr>'
            )
        if not rows:
            rows = '<tr><td colspan="3" class="muted empty">No members yet.</td></tr>'

        invite_form = ""
        if is_admin:
            invite_form = """<h2 style="margin-top:32px;">Invite teammate</h2>
<div class="card">
<form method="post" action="/portal/team/invite">
  <div class="row"><label>Email</label><input name="email" type="email" required></div>
  <div class="row"><label>Role</label>
    <select name="role">
      <option value="viewer">Viewer (read-only)</option>
      <option value="editor">Editor</option>
      <option value="admin">Admin</option>
    </select></div>
  <button type="submit">Send invite</button>
</form>
</div>"""

        body = f"""<h2>Team</h2>
<div class="card">
  <table><tr><th>Email</th><th>Role</th><th></th></tr>{rows}</table>
</div>
{invite_form}"""
        return _page("Team", body, active="team",
                      org_id=org_id, email=email)

    @router.post("/team/invite")
    def team_invite(request: Request,
                      email: str = Form(...),
                      role: str = Form("viewer")):
        session = require_session(request)
        org_id = _resolve_org_id(request)
        caller = session.get("email") or ""
        if not org_id:
            raise HTTPException(400, "no org selected")
        if not _is_admin(org_id, caller):
            raise HTTPException(403, "admin only")
        # Assign role immediately (single-tenant convention) AND send a
        # magic-link sign-in so the invitee can land in the portal.
        from safecadence.auth.rbac import assign_role, UserRole
        role_enum = UserRole.from_str(role) or UserRole.VIEWER
        try:
            assign_role(org_id, email, role_enum)
        except ValueError as exc:
            return RedirectResponse(
                f"/portal/team?error={html.escape(str(exc))[:120]}",
                status_code=303,
            )
        try:
            from safecadence.auth.magic_link import request_login
            request_login(email)
        except Exception:                              # pragma: no cover
            pass
        return RedirectResponse("/portal/team?invited=1", status_code=303)

    @router.post("/team/remove")
    def team_remove(request: Request, email: str = Form(...)):
        session = require_session(request)
        org_id = _resolve_org_id(request)
        caller = session.get("email") or ""
        if not org_id:
            raise HTTPException(400, "no org selected")
        if not _is_admin(org_id, caller):
            raise HTTPException(403, "admin only")
        from safecadence.auth.rbac import remove_role
        remove_role(org_id, email)
        return RedirectResponse("/portal/team?removed=1", status_code=303)

    # Provide DELETE alias for the spec.
    @router.delete("/team/{user_id}")
    def team_delete(request: Request, user_id: str):
        # ``user_id`` here is interpreted as the user's email per RBAC.
        session = require_session(request)
        org_id = _resolve_org_id(request)
        caller = session.get("email") or ""
        if not org_id:
            raise HTTPException(400, "no org selected")
        if not _is_admin(org_id, caller):
            raise HTTPException(403, "admin only")
        from safecadence.auth.rbac import remove_role
        ok = remove_role(org_id, user_id)
        return {"ok": ok}

    # ---------------- usage -------------------------------------------
    @router.get("/usage", response_class=HTMLResponse)
    def usage(request: Request) -> str:
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        from safecadence.billing.usage import get_usage_history
        from safecadence.billing.plans import check_quota

        sections = ""
        for resource, label in (("assets", "Assets added"),
                                  ("reports", "Reports generated"),
                                  ("api_calls", "API calls")):
            history = get_usage_history(org_id, resource, months=6) if org_id else []
            cap = max((row["count"] for row in history), default=1) or 1
            rows = ""
            for row in history:
                pct = int(round(100 * row["count"] / cap))
                rows += (
                    f'<div class="barrow">'
                    f'<span class="muted">{html.escape(row["period"])}</span>'
                    f'<div class="miniBar"><span style="width:{pct}%"></span></div>'
                    f'<span>{row["count"]}</span></div>'
                )
            q = check_quota(org_id, resource) if org_id else {"used": 0, "limit": 0}
            sections += f"""<div class="card">
  <div class="label">{html.escape(label)}</div>
  <div class="muted" style="margin-bottom:10px;">This month: {q.get("used", 0)} / {_limit_label(q.get("limit", 0))}</div>
  <div class="bars">{rows or '<div class="empty">No data yet.</div>'}</div>
</div>"""

        body = f'<h2>Usage</h2><div class="grid">{sections}</div>'
        return _page("Usage", body, active="usage",
                      org_id=org_id, email=email)

    # ---------------- support -----------------------------------------
    @router.get("/support", response_class=HTMLResponse)
    def support(request: Request) -> str:
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        from safecadence.portal.support_tickets import list_tickets
        tickets = list_tickets(org_id) if org_id else []
        rows = ""
        for t in tickets[:20]:
            rows += (
                f'<tr><td>{html.escape(t.get("subject") or "")}</td>'
                f'<td><span class="pill ok">{html.escape(t.get("status") or "open")}</span></td>'
                f'<td class="muted">{html.escape(t.get("created_at") or "")}</td></tr>'
            )
        if not rows:
            rows = '<tr><td colspan="3" class="muted empty">No tickets yet.</td></tr>'
        body = f"""<h2>Support</h2>
<div class="card">
<form method="post" action="/portal/support">
  <div class="row"><label>Subject</label><input name="subject" required></div>
  <div class="row"><label>Message</label><textarea name="message" rows="5" required></textarea></div>
  <button type="submit">Submit ticket</button>
</form>
</div>
<h2 style="margin-top:32px;">Recent tickets</h2>
<div class="card"><table>
<tr><th>Subject</th><th>Status</th><th>Created</th></tr>{rows}
</table></div>"""
        return _page("Support", body, active="support",
                      org_id=org_id, email=email)

    @router.post("/support")
    def support_submit(request: Request,
                        subject: str = Form(...),
                        message: str = Form(...)):
        session = require_session(request)
        org_id = _resolve_org_id(request)
        email = session.get("email") or ""
        if not org_id:
            raise HTTPException(400, "no org selected")
        from safecadence.portal.support_tickets import create_ticket
        create_ticket(org_id, email, subject, message)
        return RedirectResponse("/portal/support?sent=1", status_code=303)

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
