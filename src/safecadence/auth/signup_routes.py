"""
FastAPI routes for self-service signup (v10.9).

Mounts:

  GET  /signup           — HTML form
  POST /signup           — accept email + org + plan, send verification
  GET  /signup/verify    — consume token, set cookie, redirect to portal
                           (or to Stripe checkout for paid plans)
"""

from __future__ import annotations

import html
import os

try:
    from fastapi import APIRouter, Form, Request
    from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
    _FASTAPI_OK = True
except Exception:                                      # pragma: no cover
    _FASTAPI_OK = False

from safecadence.auth.deps import SESSION_COOKIE
from safecadence.auth.signup import request_signup, verify_signup


def _signup_form_html(plan_default: str = "Free",
                       message: str = "", error: str = "") -> str:
    msg_html = ""
    if message:
        msg_html = (
            '<div class="ok">' + html.escape(message) + '</div>'
        )
    err_html = ""
    if error:
        err_html = (
            '<div class="err">' + html.escape(error) + '</div>'
        )
    plan_default = (plan_default or "Free").strip()
    sel = lambda p: 'selected' if p.lower() == plan_default.lower() else ''
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Create your SafeCadence account</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{{margin:0;background:#0f172a;color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;}}
 .card{{max-width:440px;width:90%;background:#1e293b;border:1px solid #334155;
        border-radius:14px;padding:28px;box-shadow:0 20px 40px rgba(0,0,0,.3);}}
 h1{{margin:0 0 6px;font-size:22px;color:#fff;}}
 p.sub{{margin:0 0 18px;color:#94a3b8;font-size:13px;}}
 label{{display:block;margin:14px 0 6px;color:#cbd5e1;font-size:12px;}}
 input,select{{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;
        border:1px solid #475569;background:#0f172a;color:#fff;font-size:14px;}}
 button{{width:100%;margin-top:18px;padding:11px 14px;border:0;border-radius:8px;
         background:#2563eb;color:#fff;font-weight:600;font-size:14px;cursor:pointer;}}
 button:hover{{background:#1d4ed8;}}
 .ft{{margin-top:18px;font-size:12px;color:#64748b;text-align:center;}}
 .ft a{{color:#94a3b8;}}
 .ok{{margin:12px 0;padding:10px 14px;border-radius:8px;background:#0a6b3d;color:#e6f4ea;font-size:13px;}}
 .err{{margin:12px 0;padding:10px 14px;border-radius:8px;background:#7f1d1d;color:#fee2e2;font-size:13px;}}
</style></head><body>
<div class="card">
  <h1>Create your SafeCadence account</h1>
  <p class="sub">14-day free Pro trial. No credit card for Free.</p>
  {msg_html}{err_html}
  <form method="post" action="/signup">
    <label for="email">Work email</label>
    <input id="email" name="email" type="email" required autocomplete="email" autofocus>
    <label for="org_name">Organization name</label>
    <input id="org_name" name="org_name" type="text" required>
    <label for="plan">Plan</label>
    <select id="plan" name="plan">
      <option value="Free" {sel('Free')}>Free — $0/mo, 25 assets</option>
      <option value="Pro" {sel('Pro')}>Pro — $49/mo, 250 assets (14-day trial)</option>
      <option value="Enterprise" {sel('Enterprise')}>Enterprise — $499/mo, unlimited</option>
    </select>
    <button type="submit">Create account</button>
  </form>
  <div class="ft">Already have an account? <a href="/login">Sign in</a></div>
</div></body></html>"""


def _make_router():
    if not _FASTAPI_OK:                                # pragma: no cover
        return None
    router = APIRouter()

    @router.get("/signup", response_class=HTMLResponse)
    def signup_form(request: Request) -> str:
        plan = request.query_params.get("plan") or "Free"
        sent = request.query_params.get("sent") or ""
        err = request.query_params.get("error") or ""
        msg = "Check your inbox for a verification link." if sent else ""
        return _signup_form_html(plan_default=plan, message=msg, error=err)

    @router.post("/signup")
    def signup_submit(
        request: Request,
        email: str = Form(...),
        org_name: str = Form(...),
        plan: str = Form("Free"),
    ):
        try:
            result = request_signup(email, org_name, plan)
        except PermissionError as exc:
            return RedirectResponse(
                f"/signup?error={str(exc) or 'signups disabled'}",
                status_code=303,
            )
        if not result.get("sent"):
            err = result.get("error") or "Could not send verification."
            return RedirectResponse(
                f"/signup?plan={plan}&error={err}", status_code=303,
            )
        # In demo / SC_AUTH_DISABLED mode, deep-link the user directly so
        # the flow can be exercised without SMTP. Production users get
        # the email link and a confirmation page.
        if os.environ.get("SC_AUTH_DISABLED"):
            verify_url = result.get("verify_url") or "/portal"
            return RedirectResponse(verify_url, status_code=303)
        return RedirectResponse(f"/signup?plan={plan}&sent=1",
                                status_code=303)

    @router.get("/signup/verify")
    def signup_verify(request: Request, token: str = ""):
        result = verify_signup(token)
        if not result.get("ok"):
            err = result.get("error") or "Invalid token."
            return RedirectResponse(f"/signup?error={err}", status_code=303)
        # Set the session cookie + redirect.
        target = result.get("checkout_url") or result.get("return_url") or "/portal"
        is_https = request.url.scheme == "https"
        resp = RedirectResponse(target, status_code=303)
        if result.get("session_token"):
            resp.set_cookie(
                key=SESSION_COOKIE,
                value=result["session_token"],
                max_age=30 * 86400,
                httponly=True,
                secure=is_https,
                samesite="lax",
                path="/",
            )
        # Surface org id in a cookie so the customer portal can pick it up
        # without an extra round-trip.
        resp.set_cookie(
            key="sc_org",
            value=result.get("org_id") or "",
            max_age=30 * 86400,
            httponly=False,
            secure=is_https,
            samesite="lax",
            path="/",
        )
        return resp

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
