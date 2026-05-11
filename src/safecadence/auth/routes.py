"""
FastAPI routes for magic-link auth.

Mounts:
  GET  /login                 → email-entry form
  POST /login/request         → email a magic link
  GET  /auth/callback?token=  → consume token, set session cookie, redirect
  POST /logout                → clear cookie and revoke session
  GET  /me                    → current session as JSON

The router is opt-in: ``server.app.create_app`` already wraps its
import in try/except so installs without [server] extras keep working.
"""

from __future__ import annotations

import html
import os

try:
    from fastapi import APIRouter, Form, Request, Response
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    _FASTAPI_OK = True
except Exception:                                  # pragma: no cover
    _FASTAPI_OK = False

from safecadence.auth.deps import SESSION_COOKIE, optional_session
from safecadence.auth.magic_link import (
    create_session,
    request_login,
    revoke_session,
    verify_token,
)


def _login_form_html(message: str = "", error: str = "") -> str:
    msg_html = ""
    if message:
        msg_html = (
            '<div style="margin:12px 0;padding:10px 14px;border-radius:8px;'
            'background:#e6f4ea;color:#0a6b3d;font-size:13px;">'
            f'{html.escape(message)}</div>'
        )
    err_html = ""
    if error:
        err_html = (
            '<div style="margin:12px 0;padding:10px 14px;border-radius:8px;'
            'background:#fdecea;color:#9b1c1c;font-size:13px;">'
            f'{html.escape(error)}</div>'
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Sign in — SafeCadence</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{{margin:0;background:#0f172a;color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;}}
 .card{{max-width:380px;width:90%;background:#1e293b;border:1px solid #334155;
        border-radius:14px;padding:28px;box-shadow:0 20px 40px rgba(0,0,0,.3);}}
 h1{{margin:0 0 6px;font-size:20px;color:#fff;}}
 p.sub{{margin:0 0 18px;color:#94a3b8;font-size:13px;}}
 label{{display:block;margin:14px 0 6px;color:#cbd5e1;font-size:12px;}}
 input{{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;
        border:1px solid #475569;background:#0f172a;color:#fff;font-size:14px;}}
 button{{width:100%;margin-top:14px;padding:11px 14px;border:0;border-radius:8px;
         background:#2563eb;color:#fff;font-weight:600;font-size:14px;cursor:pointer;}}
 button:hover{{background:#1d4ed8;}}
 .ft{{margin-top:18px;font-size:12px;color:#64748b;text-align:center;}}
</style></head>
<body><div class="card">
 <h1>Sign in to SafeCadence</h1>
 <p class="sub">We'll email you a one-time link. No password required.</p>
 {msg_html}{err_html}
 <form method="post" action="/login/request">
   <label for="email">Email address</label>
   <input id="email" name="email" type="email" required autocomplete="email" autofocus>
   <button type="submit">Send magic link</button>
 </form>
 <div class="ft">By signing in you agree to our terms of service.</div>
</div></body></html>"""


def _make_router():
    if not _FASTAPI_OK:                            # pragma: no cover
        return None
    router = APIRouter()

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request) -> str:
        msg = request.query_params.get("sent")
        err = request.query_params.get("error")
        message = "Link sent — check your inbox." if msg else ""
        error = err or ""
        return _login_form_html(message=message, error=error)

    @router.post("/login/request")
    def login_request(request: Request, email: str = Form(...)):
        result = request_login(email)
        if result.get("sent"):
            return RedirectResponse(url="/login?sent=1", status_code=303)
        err = result.get("error") or "Could not send the link. Try again."
        return RedirectResponse(
            url=f"/login?error={err}", status_code=303
        )

    @router.get("/auth/callback")
    def auth_callback(request: Request, token: str = ""):
        result = verify_token(token)
        if not result:
            return RedirectResponse(
                url="/login?error=That+link+is+expired+or+invalid.",
                status_code=303,
            )
        user_id, email = result
        sess_token = create_session(user_id, email)
        resp = RedirectResponse(url="/home", status_code=303)
        is_https = request.url.scheme == "https"
        resp.set_cookie(
            key=SESSION_COOKIE,
            value=sess_token,
            max_age=30 * 86400,
            httponly=True,
            secure=is_https,
            samesite="lax",
            path="/",
        )
        return resp

    @router.post("/logout")
    def logout(request: Request) -> Response:
        tok = request.cookies.get(SESSION_COOKIE)
        if tok:
            revoke_session(tok)
        resp = RedirectResponse(url="/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @router.get("/me")
    def me(request: Request):
        sess = optional_session(request)
        if not sess:
            return JSONResponse({"authenticated": False}, status_code=200)
        return {
            "authenticated": True,
            "user_id": sess.get("user_id"),
            "email": sess.get("email"),
            "demo": bool(sess.get("demo")),
        }

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
