"""
FastAPI app factory.

Endpoints (all JWT-bearer auth except /api/login + /api/health):

    POST /api/login                  → JWT
    GET  /api/health                 → liveness
    GET  /api/me                     → current user info

    GET  /api/devices                → fleet list (latest scan per host)
    GET  /api/devices/{hostname}     → full latest scan
    GET  /api/scans                  → recent scans (history)
    GET  /api/scans/{id}             → one scan payload

    POST /api/scan                   → upload + scan one config (admin/analyst)
    POST /api/scan/bulk              → upload many configs (admin/analyst)

    GET  /api/cves                   → bundled CVE DB
    GET  /api/eol                    → bundled EOL DB
    GET  /api/vendors                → registered adapters
    GET  /api/rules                  → all audit rules

    GET  /api/dashboard.html         → live single-file dashboard
"""

import json
import os
import secrets as _secrets
from typing import List, Optional

# IMPORTANT: import FastAPI at MODULE level (not inside create_app) so its
# annotation classes resolve cleanly when FastAPI inspects the route handlers.
# Wrapped in try/except so the module imports cleanly without [server] extras —
# create_app() raises a friendly error instead.
try:
    from fastapi import Body, Depends, FastAPI, File, HTTPException, Query, UploadFile
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.security import (
        HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm,
    )
    _SERVER_AVAILABLE = True
except ImportError:
    _SERVER_AVAILABLE = False

from safecadence.server.auth import (
    CurrentUser, authenticate, decode_jwt, load_users, make_jwt, require_role,
)


def create_app(*, db_url: Optional[str] = None, jwt_secret: Optional[str] = None,
               users_file: Optional[str] = None):
    if not _SERVER_AVAILABLE:
        raise RuntimeError(
            "API server requires the [server] extras: "
            "pip install 'safecadence-network-risk[server]'"
        )
    from safecadence.bulk import bulk_scan, _scan_one
    from safecadence.core.registry import AdapterRegistry
    from safecadence.dashboard import build_dashboard_data, render_dashboard
    from safecadence.engines.config_audit import load_rules
    from safecadence.enrichment import load_cve_db, load_eol_db
    from safecadence.storage import open_store

    # JWT secret persistence — auto-generating a random secret on every restart
    # silently invalidates every issued token (everyone gets logged out, with no
    # error message). Persist a generated secret to ~/.safecadence/jwt_secret so
    # tokens survive restarts; explicit jwt_secret arg or SC_JWT_SECRET env var
    # always takes precedence.
    secret = jwt_secret or os.environ.get("SC_JWT_SECRET")
    if not secret:
        from pathlib import Path
        _sec_dir = Path.home() / ".safecadence"
        _sec_dir.mkdir(parents=True, exist_ok=True)
        _sec_file = _sec_dir / "jwt_secret"
        if _sec_file.exists():
            secret = _sec_file.read_text(encoding="utf-8").strip()
        if not secret:
            secret = _secrets.token_urlsafe(48)
            _sec_file.write_text(secret, encoding="utf-8")
            try:
                os.chmod(_sec_file, 0o600)
            except OSError:
                pass
    load_users(users_file)              # bootstrap on first run
    store  = open_store(db_url or os.environ.get("DATABASE_URL"))
    bearer = HTTPBearer(auto_error=False)

    app = FastAPI(
        title="SafeCadence Network Risk API",
        version="2.0",
        description="Open-source enterprise network risk auditing — local-first, BYO-AI.",
    )

    # v9.47 — activity tracking. The middleware decodes the bearer
    # token to learn the actor, then writes one JSONL row per
    # authenticated mutation. Set SC_ACTIVITY_DISABLED=1 to skip
    # (useful for tests that don't want temp files everywhere).
    if os.environ.get("SC_ACTIVITY_DISABLED", "") != "1":
        try:
            from safecadence.activity import ActivityMiddleware
            app.add_middleware(ActivityMiddleware, jwt_secret=secret)
        except Exception:                       # pragma: no cover
            pass

    # ---- helpers ------------------------------------------------ #
    def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> CurrentUser:
        if not creds or not creds.credentials:
            raise HTTPException(status_code=401, detail="Bearer token required")
        return decode_jwt(creds.credentials, secret=secret)

    def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        return require_role("admin")(user)

    def require_writer(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        return require_role("admin", "analyst")(user)

    def audit(user: CurrentUser, action: str, resource: str = "", detail: str = ""):
        if hasattr(store, "audit"):
            try:
                store.audit(tenant_id=user.tenant, actor=user.username,
                            action=action, resource=resource, detail=detail)
            except Exception:
                pass

    # ---- public --------------------------------------------------- #
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "2.0"}

    @app.post("/api/login")
    def login(form: OAuth2PasswordRequestForm = Depends()):
        # Re-read users.yaml on every login so admins can edit it without restart
        users_now = load_users(users_file)
        user = authenticate(users_now, username=form.username, password=form.password)
        if not user:
            raise HTTPException(status_code=401, detail="Bad username or password")
        token = make_jwt(user, secret=secret, ttl_minutes=60)
        return {"access_token": token, "token_type": "bearer",
                "tenant": user.tenant, "roles": user.roles}

    # ---- introspection ------------------------------------------- #
    @app.get("/api/me")
    def me(user: CurrentUser = Depends(get_current_user)):
        return {"username": user.username, "tenant": user.tenant, "roles": user.roles}

    @app.get("/api/vendors")
    def vendors(_user: CurrentUser = Depends(get_current_user)):
        return [a.info() for a in AdapterRegistry.all()]

    @app.get("/api/rules")
    def rules(vendor: Optional[str] = None, _user: CurrentUser = Depends(get_current_user)):
        return [{
            "id": r.id, "title": r.title, "severity": r.severity.value,
            "vendor": r.vendor, "domain": r.domain,
        } for r in load_rules(vendor=vendor)]

    @app.get("/api/cves")
    def cves(_user: CurrentUser = Depends(get_current_user)):
        db = load_cve_db()
        return {v: items for v, items in db.items()}

    @app.get("/api/eol")
    def eol(_user: CurrentUser = Depends(get_current_user)):
        return [r.to_dict() for r in load_eol_db()]

    # ---- fleet --------------------------------------------------- #
    @app.get("/api/devices")
    def devices(user: CurrentUser = Depends(get_current_user)):
        return store.latest_per_host(tenant_id=user.tenant)

    @app.get("/api/devices/{hostname}")
    def device(hostname: str, user: CurrentUser = Depends(get_current_user)):
        rows = store.latest_per_host(tenant_id=user.tenant)
        match = next((r for r in rows if r["hostname"] == hostname), None)
        if not match:
            raise HTTPException(status_code=404, detail="Device not found")
        full = store.get(match["id"], tenant_id=user.tenant)
        return full or match

    @app.get("/api/scans")
    def scans(limit: int = Query(50, le=500),
              user: CurrentUser = Depends(get_current_user)):
        return store.list(limit=limit, tenant_id=user.tenant)

    @app.get("/api/scans/{scan_id}")
    def scan_detail(scan_id: int, user: CurrentUser = Depends(get_current_user)):
        d = store.get(scan_id, tenant_id=user.tenant)
        if d is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return d

    # ---- mutation ------------------------------------------------ #
    # Config files almost never exceed a couple hundred KB. Cap at 10MB to
    # prevent a memory-exhaustion DoS via huge uploads.
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024
    MAX_BULK_TOTAL_BYTES = 50 * 1024 * 1024
    MAX_BULK_FILE_COUNT = 500

    async def _read_capped(upload: UploadFile, cap: int) -> bytes:
        """Stream the upload into memory but bail if it exceeds `cap`."""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await upload.read(1024 * 1024)  # 1MB at a time
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise HTTPException(
                    status_code=413,
                    detail=f"upload exceeds {cap // (1024*1024)}MB cap",
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @app.post("/api/scan")
    async def post_scan(file: UploadFile = File(...),
                        vendor: Optional[str] = Query(None),
                        criticality: str = Query("medium"),
                        user: CurrentUser = Depends(require_writer)):
        from pathlib import Path
        import tempfile
        body = await _read_capped(file, MAX_UPLOAD_BYTES)
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        try:
            tmp.write(body)
            tmp.close()
            result, summary = _scan_one(Path(tmp.name), vendor_override=vendor,
                                        criticality=criticality)
            if result is None:
                raise HTTPException(status_code=400, detail=summary.error or "scan failed")
            scan_id = store.save(result.to_dict(), tenant_id=user.tenant)
            audit(user, "scan", resource=summary.hostname,
                  detail=f"risk={summary.risk}")
            return {"scan_id": scan_id, "summary": {
                "hostname": summary.hostname, "vendor": summary.vendor,
                "health": summary.health, "risk": summary.risk,
                "findings": summary.findings, "cves": summary.cves,
                "eol_status": summary.eol_status,
            }}
        finally:
            try: os.unlink(tmp.name)
            except OSError: pass

    @app.post("/api/scan/bulk")
    async def post_bulk(files: List[UploadFile] = File(...),
                        criticality: str = Query("medium"),
                        user: CurrentUser = Depends(require_writer)):
        import tempfile
        from pathlib import Path
        if len(files) > MAX_BULK_FILE_COUNT:
            raise HTTPException(
                status_code=413,
                detail=f"too many files (max {MAX_BULK_FILE_COUNT})",
            )
        running_total = 0
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            for f in files:
                # Reject path-traversal in supplied filename.
                safe_name = os.path.basename(f.filename or "upload.txt")
                if not safe_name or safe_name in (".", ".."):
                    raise HTTPException(status_code=400, detail="bad filename")
                body = await _read_capped(f, MAX_UPLOAD_BYTES)
                running_total += len(body)
                if running_total > MAX_BULK_TOTAL_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"bulk total exceeds {MAX_BULK_TOTAL_BYTES // (1024*1024)}MB cap",
                    )
                (td_path / safe_name).write_bytes(body)
            results = bulk_scan(td_path, criticality=criticality)
            saved = []
            for r in results:
                if r.error:
                    continue
                # re-scan to get full ScanResult dict (bulk_scan returns summaries only)
                full, _ = _scan_one(Path(r.source), criticality=criticality)
                if full:
                    sid = store.save(full.to_dict(), tenant_id=user.tenant)
                    saved.append({"scan_id": sid, "hostname": r.hostname,
                                  "vendor": r.vendor, "risk": r.risk})
            audit(user, "scan_bulk", detail=f"{len(saved)} devices")
            return {"saved": saved, "total": len(results)}

    # ---- live dashboard (HTML) ----------------------------------- #
    @app.get("/api/dashboard.html", response_class=HTMLResponse)
    def dashboard_live(user: CurrentUser = Depends(get_current_user)):
        rows = store.latest_per_host(tenant_id=user.tenant)
        scans_full = []
        for r in rows:
            full = store.get(r["id"], tenant_id=user.tenant)
            if full: scans_full.append(full)
        data = build_dashboard_data(scans_full)
        return HTMLResponse(render_dashboard(
            data, title=f"SafeCadence — {user.tenant}"
        ))

    # ---- platform REST surface (/api/platform/* incl. /ui) ------- #
    from safecadence.server.platform_api import register as _register_platform
    _register_platform(app, get_current_user, require_writer)

    # ---- policy intelligence REST surface (/api/policy/*) -------- #
    from safecadence.server.policy_api import register as _register_policy
    _register_policy(app, get_current_user, require_writer)

    # ---- v7.0: secure command execution engine (/api/execute/*) -- #
    from safecadence.server.execution_api import register_execution_routes
    register_execution_routes(
        app,
        get_current_user=get_current_user,
        require_writer=require_writer,
        require_admin=require_admin,
    )

    # ---- v7.7: identity REST API (/api/identity/*) ---------------- #
    from safecadence.server.identity_api import register as _register_identity
    _register_identity(app, get_current_user, require_writer)

    # ---- v7.7: identity UI page (/identity) ----------------------- #
    from safecadence.ui.identity_ui import register as _register_identity_ui
    _register_identity_ui(app)

    # ---- v7.7.1: Tool Hub (/hub) — index of every capability ----- #
    from safecadence.ui.tool_hub import register as _register_hub
    _register_hub(app)

    # ---- v7.8: smart home page (/home) ---------------------------- #
    from safecadence.ui.smart_home import register as _register_home
    _register_home(app)

    # ---- v7.9: intel REST API (/api/intel/*) ---------------------- #
    from safecadence.server.intel_api import register as _register_intel
    _register_intel(app, get_current_user, require_writer)

    # ---- v7.9: intel UI pages (/ask, /timeline, /onboarding, /briefing) #
    from safecadence.ui.intel_ui import register as _register_intel_ui
    _register_intel_ui(app)

    # ---- v8.0: asset detail + simulate + share pages ----------- #
    from safecadence.ui.asset_detail import register as _register_asset_detail
    _register_asset_detail(app)
    from safecadence.ui.v8_pages import register as _register_v8
    _register_v8(app)

    # ---- v9.0: list pages + sidebar stubs ---------------------- #
    from safecadence.ui.v9_pages import register as _register_v9
    _register_v9(app)

    # ---- v9.1: interactive tour of killer features ------------- #
    from safecadence.ui.tour import register as _register_tour
    _register_tour(app)

    # ---- v9.1: contextual help index --------------------------- #
    from safecadence.ui.help_page import register as _register_help
    _register_help(app)

    # ---- v10.1: Reports wizard (/reports + /api/reports/*) ----- #
    # Same mount as the standalone UI app. Wiring it here means the
    # link audit and other tests that bring up server.create_app see
    # /reports resolve instead of 404.
    try:
        from safecadence.reports.ui_routes import router as _reports_router
        if _reports_router is not None:
            app.include_router(_reports_router)
    except Exception:                              # pragma: no cover
        pass

    # ---- v11.1: PWA manifest + service worker + responsive.css --- #
    # /manifest.webmanifest, /sw.js, /static/responsive.css. Mounted
    # here so the link-audit suite (which uses server.create_app) sees
    # the manifest link target resolve instead of 404.
    try:
        from safecadence.ui.pwa import register as _pwa_register
        _pwa_register(app)
    except Exception:                              # pragma: no cover
        pass

    # ---- v10.5: auth + observability + multi-tenant scaffolding - #
    try:
        from safecadence.auth.routes import router as _auth_router
        if _auth_router is not None:
            app.include_router(_auth_router)
    except Exception:                              # pragma: no cover
        pass
    try:
        from safecadence.observability.metrics import (
            router as _obs_router, MetricsMiddleware,
        )
        if _obs_router is not None:
            app.include_router(_obs_router)
            app.add_middleware(MetricsMiddleware)
    except Exception:                              # pragma: no cover
        pass

    # ---- v10.6: Slack + Jira + dashboard widgets routers ----------- #
    try:
        from safecadence.integrations.slack import build_router as _slack_router
        _r = _slack_router()
        if _r is not None:
            app.include_router(_r)
    except Exception:                              # pragma: no cover
        pass
    try:
        from safecadence.integrations.jira import build_router as _jira_router
        _r = _jira_router()
        if _r is not None:
            app.include_router(_r)
    except Exception:                              # pragma: no cover
        pass
    try:
        from safecadence.dashboard.widgets import build_router as _widgets_router
        _r = _widgets_router()
        if _r is not None:
            app.include_router(_r)
    except Exception:                              # pragma: no cover
        pass

    # ---- v10.8: workflow + governance routers --------------------- #
    try:
        from safecadence.workflow.api_v1 import build_router as _wf_router
        _r = _wf_router()
        if _r is not None:
            app.include_router(_r)
    except Exception:                              # pragma: no cover
        pass
    try:
        from safecadence.auth.saml import build_router as _saml_router
        _r = _saml_router()
        if _r is not None:
            app.include_router(_r)
    except Exception:                              # pragma: no cover
        pass

    return app
