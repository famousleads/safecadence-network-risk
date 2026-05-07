"""
FastAPI app for the local UI.

Differs from `safecadence.server.app` in two important ways:
  1. No authentication — assumes single-user local mode.
  2. Adds UI-specific endpoints (file uploads from drag-drop, discover proxy,
     enrichment refresh, BYOK AI proxy) that don't make sense in the
     production multi-tenant API.

Designed to run on localhost only. If you need network-accessible auth,
use `safecadence api` instead.
"""

from __future__ import annotations

import dataclasses
import os
import socket
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Optional

# Lazy import — the [server] extras are required to actually run the UI.
try:
    from fastapi import Body, FastAPI, File, HTTPException, Query, UploadFile
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False


def _check_extras() -> None:
    if not _FASTAPI_OK:
        sys.stderr.write(
            "\n  The local UI requires the [server] extras. Install with:\n"
            "    pip install 'safecadence-netrisk[server]'\n\n"
        )
        sys.exit(1)


def _to_jsonable(obj: Any) -> Any:
    """Convert dataclasses, sets, paths, etc. to JSON-friendly forms."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _to_jsonable(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


def create_app(*, password: str | None = None):
    _check_extras()

    # Late imports so import-time failures show friendly messages, not stack traces.
    from safecadence.bulk import _scan_one
    from safecadence.core.registry import AdapterRegistry
    from safecadence.dashboard import build_dashboard_data, render_dashboard
    from safecadence.engines.config_audit import load_rules
    from safecadence.storage import open_store

    from safecadence import __version__ as _sc_ver
    app = FastAPI(
        title="SafeCadence Device Intelligence Platform — Local UI",
        description=("Single-user local web UI: v2 audit dashboard, "
                     "v4 platform inventory, v5 policy intelligence."),
        version=_sc_ver,
        docs_url="/api/docs",
        redoc_url=None,
    )

    # v9.47 — activity tracking. Every authenticated mutation
    # (POST/PUT/PATCH/DELETE) lands in $SC_DATA_DIR/activity/YYYY-MM-DD.jsonl
    # so /audit can answer "who did what, when?" without trawling
    # systemd logs. Best-effort — disk-full never breaks a request.
    # Set SC_ACTIVITY_DISABLED=1 to skip the middleware (e.g. in tests).
    if os.environ.get("SC_ACTIVITY_DISABLED", "") != "1":
        try:
            from safecadence.activity import ActivityMiddleware
            app.add_middleware(ActivityMiddleware, jwt_secret=None)
        except Exception:                       # pragma: no cover
            # Activity log is a nice-to-have, not load-bearing.
            pass

    # ---------------------------------------------------------------- v5.2: optional password gate
    # When `password=` is set (via `safecadence ui --password ...`), every
    # request except /healthz and /login must carry a valid cookie.
    # Cross-platform: pure middleware, no JWT machinery.
    if password:
        import secrets, hmac
        from fastapi import Request
        # NOTE: HTMLResponse / JSONResponse / Response come from the module-level
        # try-import at the top — DON'T re-import them inside this conditional
        # or Python flags them as locals throughout create_app() and breaks the
        # other handlers that reference them above (e.g. @app.get("/")).
        from fastapi.responses import RedirectResponse
        from starlette.middleware.base import BaseHTTPMiddleware

        _COOKIE_NAME = "sc_local_session"
        _SESSION_TOKEN = secrets.token_urlsafe(32)

        class _PasswordMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                path = request.url.path
                # Always allow these
                if path in ("/login", "/healthz", "/favicon.ico") or path.startswith("/static"):
                    return await call_next(request)
                cookie = request.cookies.get(_COOKIE_NAME, "")
                if hmac.compare_digest(cookie, _SESSION_TOKEN):
                    return await call_next(request)
                # Not authenticated — show the login page (or 401 for API calls)
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "password required"}, status_code=401)
                return RedirectResponse("/login", status_code=302)

        app.add_middleware(_PasswordMiddleware)

        @app.get("/login", response_class=HTMLResponse)
        def _login_form(error: str = ""):
            err_html = (f'<div style="color:#dc2626;margin:10px 0">{error}</div>'
                        if error else "")
            return HTMLResponse(f"""<!doctype html><html><head>
<meta charset="utf-8"><title>SafeCadence — sign in</title>
<style>body{{font:14px/1.5 -apple-system,Segoe UI,Inter,sans-serif;background:#0b1020;color:#e7ecf5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.card{{background:#121a33;border:1px solid #26315b;border-radius:12px;padding:32px 36px;width:340px}}
input{{width:100%;padding:10px 12px;background:#0a1029;color:#e7ecf5;border:1px solid #26315b;border-radius:8px;font:inherit;margin-top:6px}}
button{{margin-top:14px;width:100%;padding:10px 12px;background:#7c5cff;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer}}
h1{{margin:0 0 6px;font-size:18px}}small{{color:#8b95b1}}</style></head><body>
<form method="POST" action="/login" class="card">
  <h1>SafeCadence</h1>
  <small>Local UI is password-protected. Enter the password set with <code>--password</code>.</small>
  {err_html}
  <input type="password" name="password" autofocus required />
  <button type="submit">Sign in</button>
</form></body></html>""")

        from fastapi import Form
        from fastapi.responses import RedirectResponse as _RR

        @app.post("/login")
        def _login_submit(password: str = Form(...)):
            given = (password or "").strip()
            if hmac.compare_digest(given, globals().get("__SC_UI_PASSWORD__", "") or ""):
                # fall through to set cookie
                pass
            return _login_check(given)

        # Stash password in a closure so the handler can see it
        _ui_password = password
        def _login_check(given: str):
            if hmac.compare_digest(given, _ui_password):
                resp = _RR("/", status_code=302)
                resp.set_cookie(_COOKIE_NAME, _SESSION_TOKEN,
                                httponly=True, samesite="lax",
                                max_age=8 * 60 * 60)  # 8 hours
                return resp
            return _RR("/login?error=Invalid+password", status_code=302)

        @app.get("/healthz")
        def _healthz():
            return {"ok": True}

    # Persistent local store — same SQLite the CLI uses
    db_path = Path.home() / ".safecadence" / "ui.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = open_store(sqlite_path=str(db_path))

    # UI-specific discover history store (separate DB, separate table)
    from safecadence.ui.discover_store import get_discover_store
    discover_store = get_discover_store()

    INDEX_PATH = Path(__file__).parent / "templates" / "index.html"

    # ---------------------------------------------------------------- index
    # v9.0: `/` now redirects to `/home` (the redesigned dashboard).
    # The legacy single-page UI is preserved at `/legacy` for anyone
    # who needs the old fleet/scan workflow during the transition.
    @app.get("/", response_class=HTMLResponse)
    def index_redirect():
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/home", status_code=302)

    @app.get("/legacy", response_class=HTMLResponse)
    def legacy_index() -> str:
        return INDEX_PATH.read_text(encoding="utf-8")

    @app.get("/favicon.ico")
    def favicon() -> Response:
        return Response(content=b"", media_type="image/x-icon")

    # ---------------------------------------------------------------- core read
    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": _sc_ver, "mode": "local-ui"}

    @app.get("/api/vendors")
    def list_vendors() -> list:
        # AdapterRegistry exposes adapter classes; expose the registered ids.
        out = []
        try:
            adapters = AdapterRegistry.list_adapters()  # may not exist
        except AttributeError:
            adapters = []
            try:
                # Probe the registry's internal map if available
                for vid in getattr(AdapterRegistry, "_adapters", {}).keys():
                    adapters.append({"id": vid})
            except Exception:
                pass
        for a in adapters:
            if isinstance(a, dict):
                out.append(a)
            else:
                out.append({
                    "id": getattr(a, "id", str(a)),
                    "name": getattr(a, "display_name", getattr(a, "id", str(a))),
                    "vendor": getattr(a, "vendor", ""),
                    "os": getattr(a, "os_name", ""),
                })
        return out

    @app.get("/api/rules")
    def list_rules(vendor: Optional[str] = None) -> list:
        rules = load_rules(vendor=vendor)
        out = []
        for r in rules:
            d = _to_jsonable(r)
            # Ensure these fields exist for the UI even if Rule doesn't carry them
            d.setdefault("id", getattr(r, "id", "?"))
            d.setdefault("title", getattr(r, "title", ""))
            d.setdefault("severity", getattr(r, "severity", "info"))
            d.setdefault("vendor", getattr(r, "vendor", ""))
            d.setdefault("tags", getattr(r, "tags", []) or [])
            out.append(d)
        return out

    @app.get("/api/cves")
    def list_cves(kev_only: bool = False) -> list:
        from safecadence.enrichment.cve import load_cve_db
        db = load_cve_db()  # dict[vendor -> list[dict]]
        rows = []
        for vendor, items in (db or {}).items():
            for item in items:
                d = dict(item)
                d.setdefault("vendor", vendor)
                rows.append(d)
        if kev_only:
            rows = [r for r in rows if r.get("kev")]
        return rows

    @app.get("/api/eol")
    def list_eol() -> list:
        from safecadence.enrichment.eol import load_eol_db
        records = load_eol_db()  # list[EOLRecord]
        return [_to_jsonable(r) for r in records]

    @app.get("/api/devices")
    def list_devices() -> list:
        return _to_jsonable(store.latest_per_host())

    @app.get("/api/devices/{hostname}")
    def get_device(hostname: str) -> dict:
        for d in store.latest_per_host():
            if (d.get("source") == hostname or d.get("hostname") == hostname
                or d.get("parsed_summary", {}).get("hostname") == hostname):
                return _to_jsonable(d)
        raise HTTPException(404, f"device '{hostname}' not found")

    @app.get("/api/scans")
    def list_scans(limit: int = 50) -> list:
        return _to_jsonable(store.list(limit=limit))

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: int) -> dict:
        s = store.get(scan_id)
        if not s:
            raise HTTPException(404, f"scan #{scan_id} not found")
        return _to_jsonable(s)

    @app.get("/api/dashboard.json")
    def dashboard_json() -> dict:
        scans = store.list(limit=500)
        # store.list returns summary rows; build_dashboard_data expects full scan dicts
        full = [store.get(s["id"]) for s in scans if s.get("id") is not None]
        full = [s for s in full if s]
        data = build_dashboard_data(full, topology=None)
        return _to_jsonable(data.to_dict())

    @app.get("/api/dashboard.html", response_class=HTMLResponse)
    def dashboard_html() -> str:
        scans = store.list(limit=500)
        full = [store.get(s["id"]) for s in scans if s.get("id") is not None]
        full = [s for s in full if s]
        data = build_dashboard_data(full, topology=None)
        return render_dashboard(data, title="SafeCadence Local Dashboard")

    # ---------------------------------------------------------------- scan
    async def _scan_upload(upload: UploadFile) -> dict:
        content = await upload.read()
        suffix = Path(upload.filename or "config.txt").suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
            tf.write(content)
            tmp_path = Path(tf.name)
        try:
            scan_result, _ = _scan_one(tmp_path)
            if scan_result is None:
                return {"error": "no adapter matched", "filename": upload.filename}
            d = scan_result.to_dict()
            store.save(d)
            return d
        finally:
            try:
                tmp_path.unlink()
            except Exception:
                pass

    @app.post("/api/scan")
    async def scan_one(file: UploadFile = File(...)) -> dict:
        return await _scan_upload(file)

    @app.post("/api/scan/bulk")
    async def scan_bulk(files: list[UploadFile] = File(...)) -> dict:
        results = []
        for f in files:
            try:
                results.append(await _scan_upload(f))
            except Exception as e:
                results.append({"error": str(e), "filename": f.filename})
        return {"count": len(results), "results": results}

    # ---------------------------------------------------------------- discover
    @app.post("/api/discover")
    def discover(payload: dict = Body(...)) -> dict:
        cidr = (payload or {}).get("cidr", "").strip()
        mode = (payload or {}).get("mode", "lan_deep")
        if not cidr:
            raise HTTPException(400, "cidr required (e.g. 192.168.1.0/24)")
        if mode not in ("quick", "extended", "lan_deep"):
            raise HTTPException(400, f"mode must be quick/extended/lan_deep (got {mode})")

        # Pick the implementation based on mode.
        # - quick     : original discover_subnet, DEFAULT_PORTS
        # - extended  : original discover_subnet, EXTENDED_PORTS
        # - lan_deep  : new deep_scan with ARP cache + mDNS + TLS cert + HTTP title
        try:
            if mode == "lan_deep":
                from safecadence.discovery.lan_scan import deep_scan
                result = deep_scan(cidr, mode="lan_deep", workers=64, timeout=1.0)
            elif mode == "extended":
                from safecadence.discovery.lan_scan import deep_scan
                result = deep_scan(cidr, mode="extended", workers=64, timeout=0.8)
            else:  # quick
                from safecadence.discovery import discover_subnet
                result = discover_subnet(cidr, workers=64, timeout=0.6)
        except Exception as e:
            raise HTTPException(400, f"discover failed: {e}")

        from safecadence.discovery.cve_match import cves_for_device, cve_summary_for_fleet
        from safecadence.discovery.toxic_combinations import enrich_device_with_toxic_combos, fleet_toxic_summary

        hosts = getattr(result, "hosts", []) or []
        results = []
        for h in hosts:
            d = _to_jsonable(h)
            d.setdefault("ip", getattr(h, "ip", ""))
            d.setdefault("hostname", getattr(h, "hostname", "") or "")
            d["mac"] = getattr(h, "mac", "") or ""
            d["vendor"] = getattr(h, "vendor_guess", "") or d.get("vendor", "")
            d["os"] = getattr(h, "os_guess", "") or d.get("os", "")
            d["device_type"] = getattr(h, "device_type_guess", "") or ""
            d["snmp_sysdescr"] = getattr(h, "snmp_sysdescr", "") or ""
            banners = dict(getattr(h, "banners", {}) or {})

            d["category"] = banners.pop("__category__", d["device_type"])
            d["risk_score"] = int(banners.pop("__risk_score__", "0") or 0)
            d["risk_band"] = banners.pop("__risk_band__", "safe")
            findings_str = banners.pop("__risk_findings__", "")
            actions_str = banners.pop("__risk_actions__", "")
            d["findings"] = [f for f in findings_str.split("␟") if f] if findings_str else []
            d["recommended_actions"] = [a for a in actions_str.split("␟") if a] if actions_str else []

            d["banners"] = banners
            d.setdefault("open_ports", list(getattr(h, "open_ports", []) or []))

            # CVE matching — per device, deterministic based on vendor + version
            try:
                d["cves"] = cves_for_device(d)
            except Exception:
                d["cves"] = []
            # Boost risk score if KEV CVE matched
            kev_count = sum(1 for c in d["cves"] if c.get("kev"))
            if kev_count:
                d["risk_score"] = min(100, d["risk_score"] + kev_count * 15)
                if d["risk_score"] >= 75:
                    d["risk_band"] = "critical"
                elif d["risk_score"] >= 50:
                    d["risk_band"] = "high"
                d["findings"].insert(0, f"{kev_count} CVE{'s' if kev_count != 1 else ''} on CISA Known Exploited Vulnerabilities catalog — patch immediately.")
                d["recommended_actions"].insert(0, "Patch identified CVEs immediately; KEV-listed CVEs are actively exploited in the wild.")

            # Apply toxic-combination enrichment (compound findings + boosted score)
            d = enrich_device_with_toxic_combos(d)

            results.append(d)

        results.sort(key=lambda r: -r.get("risk_score", 0))

        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
        categories: dict[str, int] = {}
        for r in results:
            bands[r.get("risk_band", "safe")] = bands.get(r.get("risk_band", "safe"), 0) + 1
            cat = r.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1

        # v2.7.0: merge in user-provided asset tags + owner + criticality
        try:
            from safecadence.ui.asset_tags import annotate_results
            results = annotate_results(results)
            # Re-sort if criticality boost changed any scores
            results.sort(key=lambda r: -r.get("risk_score", 0))
        except Exception:
            pass

        cve_summary = cve_summary_for_fleet(results)
        toxic_summary = fleet_toxic_summary(results)

        payload = {
            "cidr": cidr,
            "mode": mode,
            "count": len(results),
            "scanned": getattr(result, "hosts_scanned", 0),
            "duration_ms": getattr(result, "duration_ms", 0),
            "summary": {
                "by_risk_band": bands,
                "by_category": categories,
                "highest_risk_count": bands["critical"] + bands["high"],
                "cves": cve_summary,
                "toxic": toxic_summary,
            },
            "results": results,
        }

        # Auto-save to server-side discover history (survives browser + server restarts)
        try:
            run_id = discover_store.save_run(payload)
            payload["saved_id"] = run_id
        except Exception as e:
            sys.stderr.write(f"  WARN: failed to persist discover run: {e}\n")

        return payload

    # ----------------------------- v9.3 streaming discovery (SSE) ----
    @app.get("/api/discover/stream")
    def discover_stream(cidr: str, mode: str = "lan_deep"):
        """Server-Sent Events: emits one event per host as it's discovered,
        plus periodic 'progress' events. Browser opens this with EventSource.

        Event types:
          progress  → {scanned, total, percent, current_ip}
          host      → DiscoveredHost JSON (same shape as /api/discover results)
          done      → {count, duration_ms, scanned}
          error     → {message}
        """
        import queue
        import threading
        import json as _json
        from fastapi.responses import StreamingResponse

        if not cidr.strip():
            raise HTTPException(400, "cidr required (e.g. 192.168.1.0/24)")
        if mode not in ("quick", "extended", "lan_deep"):
            raise HTTPException(400, f"mode must be quick/extended/lan_deep")

        q: "queue.Queue[tuple[str, dict]]" = queue.Queue()

        def on_host(h):
            try:
                d = _to_jsonable(h)
                d["mac"] = getattr(h, "mac", "") or ""
                d["vendor"] = getattr(h, "vendor_guess", "") or d.get("vendor", "")
                d["os"] = getattr(h, "os_guess", "") or d.get("os", "")
                d["device_type"] = getattr(h, "device_type_guess", "") or ""
                banners = dict(getattr(h, "banners", {}) or {})
                d["category"] = banners.pop("__category__", d.get("device_type", ""))
                d["risk_score"] = int(banners.pop("__risk_score__", "0") or 0)
                d["risk_band"] = banners.pop("__risk_band__", "safe")
                d["banners"] = banners
                q.put(("host", d))
            except Exception as e:
                q.put(("error", {"message": str(e)}))

        def on_progress(scanned, total):
            q.put(("progress", {"scanned": scanned, "total": total,
                                "percent": int(scanned * 100 / max(total, 1))}))

        def runner():
            from datetime import datetime as _dt
            t0 = _dt.utcnow()
            try:
                if mode == "lan_deep":
                    from safecadence.discovery.lan_scan import deep_scan
                    result = deep_scan(cidr, mode="lan_deep", workers=64,
                                       timeout=1.0, on_host=on_host,
                                       on_progress=on_progress)
                elif mode == "extended":
                    from safecadence.discovery.lan_scan import deep_scan
                    result = deep_scan(cidr, mode="extended", workers=64,
                                       timeout=0.8, on_host=on_host,
                                       on_progress=on_progress)
                else:
                    from safecadence.discovery import discover_subnet
                    # discover_subnet doesn't support callbacks; just run
                    # and emit hosts after the fact.
                    result = discover_subnet(cidr, workers=64, timeout=0.6)
                    for h in getattr(result, "hosts", []) or []:
                        on_host(h)
                dur = int((_dt.utcnow() - t0).total_seconds() * 1000)
                q.put(("done", {"count": len(getattr(result, "hosts", []) or []),
                                "duration_ms": dur,
                                "scanned": getattr(result, "hosts_scanned", 0)}))
            except Exception as e:
                q.put(("error", {"message": str(e)}))
            finally:
                q.put(("__close__", {}))

        threading.Thread(target=runner, daemon=True).start()

        def gen():
            # Send initial event so browsers see the stream is live.
            yield f": connected\n\n"
            while True:
                try:
                    ev, data = q.get(timeout=120)
                except Exception:
                    yield f"event: error\ndata: {_json.dumps({'message': 'timeout'})}\n\n"
                    return
                if ev == "__close__":
                    return
                yield f"event: {ev}\ndata: {_json.dumps(data, default=str)}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream",
                                  headers={"Cache-Control": "no-cache",
                                           "X-Accel-Buffering": "no"})

    # ----------------------------- v9.4 SNMP/LLDP/CDP harvest --------
    @app.post("/api/discover/snmp-harvest")
    def snmp_harvest_endpoint(payload: dict = Body(...)) -> dict:
        """Harvest LLDP/CDP neighbors + MAC table from one router/switch.

        Body: {host, community, version}  (version: "1" | "2c" | default 2c)
        Returns: HarvestResult as a dict + DiscoveredHost-shaped list ready
                 for /api/platform/adopt-discovered.

        v9.9: Also persists the full harvest on the source router's asset
        record under raw_collection.snmp_harvest, so /topology can rebuild
        the physical L2 graph across multiple routers later.
        """
        from safecadence.discovery.snmp_harvest import (
            harvest_from_router, neighbors_as_discovered_hosts,
        )
        host = (payload or {}).get("host", "").strip()
        community = (payload or {}).get("community", "public").strip()
        version = (payload or {}).get("version", "2c").strip()
        if not host:
            raise HTTPException(400, "host required (e.g. 10.0.0.1)")
        if version not in ("1", "2c"):
            raise HTTPException(400, "version must be '1' or '2c'")
        try:
            result = harvest_from_router(host, community, version=version)
        except RuntimeError as e:
            raise HTTPException(503, detail=str(e))
        hosts = neighbors_as_discovered_hosts(result)

        # v9.9 — persist harvest on the source router's asset record so
        # /topology can rebuild physical L2 graph across multiple routers.
        try:
            from safecadence.server.platform_api import (
                get_asset, save_asset, list_assets,
            )
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            # Find an existing asset for this router (by mgmt_ip or hostname)
            target = None
            for a in list_assets():
                ident = a.get("identity") or {}
                if ident.get("mgmt_ip") == host or ident.get("hostname") == host:
                    target = a; break
                cf = ident.get("custom_fields") or {}
                if cf.get("mgmt_ip") == host:
                    target = a; break
            if target is None:
                # Create a placeholder asset for the router so the harvest
                # has somewhere to live. User can re-enrich via /asset/{id}.
                aid = host.replace("/", "-").replace(":", "-")
                target = {"identity": {
                    "asset_id": aid, "hostname": result.sys_name or host,
                    "asset_type": "network", "vendor": "unknown",
                    "mgmt_ip": host, "discovery_source": "snmp-harvest",
                    "first_seen": now, "last_seen": now,
                    "custom_fields": {}, "tags": [],
                }}
            raw = target.setdefault("raw_collection", {})
            raw["snmp_harvest"] = {
                "via_router": result.via_router,
                "sys_name": result.sys_name,
                "sys_descr": result.sys_descr,
                "snmp_version": result.snmp_version,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "neighbors": [
                    {"source_protocol": n.source_protocol,
                     "hostname": n.hostname, "ip_address": n.ip_address,
                     "chassis_id": n.chassis_id, "port_id": n.port_id,
                     "port_description": n.port_description,
                     "sys_description": n.sys_description,
                     "platform": n.platform,
                     "capabilities": n.capabilities}
                    for n in result.neighbors],
                "macs": [{"mac": m.mac, "port": m.port, "vlan": m.vlan}
                         for m in result.macs],
            }
            target.setdefault("identity", {})["last_collected_at"] = now
            save_asset(target)
        except Exception as e:                          # pragma: no cover
            sys.stderr.write(f"  WARN: failed to persist snmp harvest: {e}\n")
        # JSON-able shape
        return {
            "via_router": result.via_router,
            "sys_name": result.sys_name,
            "sys_descr": result.sys_descr,
            "snmp_version": result.snmp_version,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "neighbor_count": result.neighbor_count,
            "mac_count": result.mac_count,
            "error": result.error,
            "neighbors": [
                {"source_protocol": n.source_protocol,
                 "hostname": n.hostname, "ip_address": n.ip_address,
                 "chassis_id": n.chassis_id, "port_id": n.port_id,
                 "port_description": n.port_description,
                 "sys_description": n.sys_description,
                 "platform": n.platform,
                 "capabilities": n.capabilities}
                for n in result.neighbors
            ],
            "macs": [{"mac": m.mac, "port": m.port, "vlan": m.vlan}
                     for m in result.macs],
            "hosts": hosts,
        }

    # ----------------------------- v9.5 AD / LDAP ---------------------
    @app.post("/api/discover/ad-harvest")
    def ad_harvest_endpoint(payload: dict = Body(...)) -> dict:
        from safecadence.discovery.ad_harvest import (
            harvest_ad, computers_as_discovered_hosts,
        )
        b = payload or {}
        server = (b.get("server") or "").strip()
        if not server:
            raise HTTPException(400, "server required (DC hostname or IP)")
        try:
            r = harvest_ad(
                server=server,
                bind_dn=b.get("bind_dn", ""),
                password=b.get("password", ""),
                base_dn=b.get("base_dn", ""),
                ldap_filter=b.get("ldap_filter") or "(objectClass=computer)",
                use_ssl=bool(b.get("use_ssl", True)),
            )
        except RuntimeError as e:
            raise HTTPException(503, detail=str(e))
        return {
            "server": r.server, "base_dn": r.base_dn,
            "started_at": r.started_at, "finished_at": r.finished_at,
            "count": r.count, "error": r.error,
            "computers": [
                {"name": c.name, "dns_hostname": c.dns_hostname,
                 "os": c.os, "os_version": c.os_version,
                 "last_logon": c.last_logon, "ou": c.ou,
                 "enabled": c.enabled} for c in r.computers],
            "hosts": computers_as_discovered_hosts(r),
        }

    # ----------------------------- v9.5 Entra (Azure AD) --------------
    @app.post("/api/discover/entra-harvest")
    def entra_harvest_endpoint(payload: dict = Body(...)) -> dict:
        from safecadence.discovery.entra_harvest import (
            harvest_entra, devices_as_discovered_hosts,
        )
        b = payload or {}
        tenant = (b.get("tenant_id") or "").strip()
        cid = (b.get("client_id") or "").strip()
        sec = (b.get("client_secret") or "").strip()
        if not (tenant and cid and sec):
            raise HTTPException(400, "tenant_id, client_id, client_secret required")
        r = harvest_entra(tenant, cid, sec)
        return {
            "tenant_id": r.tenant_id,
            "started_at": r.started_at, "finished_at": r.finished_at,
            "count": r.count, "error": r.error,
            "devices": [
                {"name": d.display_name, "os": d.os, "os_version": d.os_version,
                 "ownership": d.ownership, "compliant": d.compliant,
                 "managed": d.managed, "last_signin": d.last_signin,
                 "enabled": d.enabled} for d in r.devices],
            "hosts": devices_as_discovered_hosts(r),
        }

    # ----------------------------- v9.5 DHCP --------------------------
    @app.post("/api/discover/dhcp-harvest")
    def dhcp_harvest_endpoint(payload: dict = Body(...)) -> dict:
        from safecadence.discovery.dhcp_harvest import (
            harvest_isc, harvest_windows, leases_as_discovered_hosts,
        )
        b = payload or {}
        kind = (b.get("kind") or "isc").strip()
        if kind == "isc":
            lease_file = b.get("lease_file") or "/var/lib/dhcp/dhcpd.leases"
            r = harvest_isc(lease_file=lease_file)
        elif kind == "windows":
            r = harvest_windows(csv_text=b.get("csv_text"))
        elif kind == "paste":
            # Paste-mode: user pastes ISC lease text directly (no file read)
            from safecadence.discovery.dhcp_harvest import (
                DhcpHarvestResult, parse_isc_leases_text,
            )
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            r = DhcpHarvestResult(source="isc-dhcpd-paste",
                                   started_at=now, finished_at=now)
            r.leases = parse_isc_leases_text(b.get("text") or "")
        else:
            raise HTTPException(400, "kind must be isc|windows|paste")
        return {
            "source": r.source, "started_at": r.started_at,
            "finished_at": r.finished_at, "count": r.count,
            "error": r.error,
            "leases": [
                {"ip": L.ip, "mac": L.mac, "hostname": L.hostname,
                 "state": L.state, "ends": L.ends,
                 "vendor_class": L.vendor_class}
                for L in r.leases],
            "hosts": leases_as_discovered_hosts(r),
        }

    # ----------------------------- v9.8.1 cloud CLI status ------------
    @app.get("/api/discover/cloud-status")
    def cloud_status_endpoint() -> dict:
        """Probe whether aws/az/gcloud CLIs are installed + authenticated
        on this SafeCadence host. The slide-over uses this to render
        status badges + setup commands inline."""
        from safecadence.discovery.cloud_harvest import cli_status
        return cli_status()

    # ----------------------------- v9.6 cloud (AWS/Azure/GCP) ---------
    @app.post("/api/discover/cloud-harvest")
    def cloud_harvest_endpoint(payload: dict = Body(...)) -> dict:
        from safecadence.discovery.cloud_harvest import (
            harvest_aws, harvest_azure, harvest_gcp,
            instances_as_discovered_hosts,
        )
        b = payload or {}
        cloud = (b.get("cloud") or "").strip().lower()
        json_text = b.get("json_text")    # optional paste-mode
        if cloud == "aws":
            r = harvest_aws(profile=b.get("profile", ""),
                            region=b.get("region", ""),
                            json_text=json_text)
        elif cloud == "azure":
            r = harvest_azure(subscription=b.get("subscription", ""),
                              json_text=json_text)
        elif cloud == "gcp":
            r = harvest_gcp(project=b.get("project", ""),
                            json_text=json_text)
        else:
            raise HTTPException(400, "cloud must be aws|azure|gcp")
        return {
            "cloud": r.cloud, "count": r.count,
            "started_at": r.started_at, "finished_at": r.finished_at,
            "error": r.error,
            "instances": [
                {"name": i.name, "instance_id": i.instance_id,
                 "region": i.region, "state": i.state,
                 "instance_type": i.instance_type,
                 "public_ip": i.public_ip, "private_ip": i.private_ip,
                 "os": i.os, "tags": i.tags}
                for i in r.instances],
            "hosts": instances_as_discovered_hosts(r),
        }

    # ---------------------------------------------------------------- saved discover history
    @app.get("/api/discover/saved")
    def list_saved_runs(limit: int = 50, cidr: Optional[str] = None) -> list:
        return discover_store.list_runs(limit=limit, cidr=cidr)

    @app.get("/api/discover/saved/{run_id}")
    def get_saved_run(run_id: int) -> dict:
        run = discover_store.get_run(run_id)
        if not run:
            raise HTTPException(404, f"run {run_id} not found")
        return run

    @app.delete("/api/discover/saved/{run_id}")
    def delete_saved_run(run_id: int) -> dict:
        discover_store.delete_run(run_id)
        return {"ok": True, "deleted": run_id}

    @app.get("/api/discover/subnets")
    def list_subnets() -> list:
        """List every subnet that's ever been scanned, with the latest run summary."""
        return discover_store.list_subnets()

    @app.get("/api/discover/diff")
    def diff_runs(old_id: int, new_id: int) -> dict:
        """Diff two discovery runs of the same subnet."""
        return discover_store.diff_runs(old_id, new_id)

    # ---------------------------------------------------------------- simple inventory report
    @app.post("/api/discover/report")
    def discover_report(payload: dict = Body(...)) -> dict:
        from safecadence.discovery.inventory_report import render_inventory_report
        try:
            html = render_inventory_report(payload)
        except Exception as e:
            raise HTTPException(500, f"report failed: {e}")
        return {"html": html, "size": len(html)}

    # ---------------------------------------------------------------- management report
    @app.post("/api/discover/management-report")
    def management_report(payload: dict = Body(...)) -> dict:
        """Multi-section, exec-grade HTML report. Beats commercial output."""
        from safecadence.discovery.management_report import render_management_report
        try:
            cve_summary = (payload.get("summary") or {}).get("cves", {})
            html = render_management_report(
                payload,
                cve_summary=cve_summary,
                organization=payload.get("organization") or "Your Organization",
            )
        except Exception as e:
            raise HTTPException(500, f"management report failed: {e}")
        return {"html": html, "size": len(html)}

    # ---------------------------------------------------------------- AI deep-analyze
    @app.post("/api/discover/ai-analyze")
    def ai_analyze_device(payload: dict = Body(...)) -> dict:
        """Per-device AI analysis. BYOK. Returns structured JSON."""
        from safecadence.discovery.ai_analyze import analyze_device
        host = payload.get("host", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        if not host:
            raise HTTPException(400, "host required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required for openai/anthropic")
        result = analyze_device(host, provider=provider, api_key=api_key, model=model)
        return result

    # ---------------------------------------------------------------- AI chat ("chat with your fleet")
    @app.post("/api/ai/chat")
    def ai_chat(payload: dict = Body(...)) -> dict:
        """Conversational AI grounded in actual fleet data."""
        from safecadence.discovery.ai_chat import chat
        message = payload.get("message", "")
        fleet = payload.get("fleet", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        history = payload.get("history", [])
        if not message:
            raise HTTPException(400, "message required")
        if not fleet or not fleet.get("results"):
            raise HTTPException(400, "fleet data required (run a scan first)")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required")
        return chat(message, fleet, provider=provider, api_key=api_key,
                    model=model, conversation_history=history)

    # ---------------------------------------------------------------- v2.7.0: compliance pack
    @app.post("/api/discover/compliance-pack")
    def compliance_pack(payload: dict = Body(...)) -> dict:
        """Generate a framework-specific compliance audit pack (HTML)."""
        from safecadence.discovery.compliance_pack import render_compliance_pack
        framework = payload.get("framework", "soc2")
        organization = payload.get("organization", "Your Organization")
        auditor_name = payload.get("auditor_name", "")
        audit_period = payload.get("audit_period", "")
        try:
            html = render_compliance_pack(
                payload, framework=framework,
                organization=organization,
                auditor_name=auditor_name,
                audit_period=audit_period,
            )
        except Exception as e:
            raise HTTPException(500, f"compliance pack failed: {e}")
        return {"html": html, "framework": framework, "size": len(html)}

    # ---------------------------------------------------------------- v2.7.0: AI architect
    @app.post("/api/ai/architect")
    def ai_architect(payload: dict = Body(...)) -> dict:
        """AI Network Architect — analyzes network architecture as a system."""
        from safecadence.discovery.ai_architect import analyze_architecture
        fleet = payload.get("fleet", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        if not fleet or not fleet.get("results"):
            raise HTTPException(400, "fleet data required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required")
        return analyze_architecture(fleet, provider=provider, api_key=api_key, model=model)

    # ---------------------------------------------------------------- v2.7.0: threat hunting
    @app.get("/api/discover/threat-hunt-feed")
    def threat_feed(days: int = 30) -> dict:
        """Pull the recent CISA KEV catalog (last N days)."""
        from safecadence.discovery.threat_hunt import fetch_recent_kev
        return fetch_recent_kev(days=days)

    @app.post("/api/discover/threat-hunt")
    def threat_hunt_endpoint(payload: dict = Body(...)) -> dict:
        """Match recent CISA KEV against the fleet."""
        from safecadence.discovery.threat_hunt import hunt_fleet
        fleet = payload.get("fleet", {})
        days = payload.get("days", 30)
        if not fleet:
            raise HTTPException(400, "fleet required")
        return hunt_fleet(fleet, days=days)

    # ---------------------------------------------------------------- v2.7.0: asset tags
    from safecadence.ui.asset_tags import get_asset_store
    asset_store = get_asset_store()

    @app.get("/api/assets/tags")
    def list_asset_tags() -> dict:
        """List all tagged assets + the universe of tags in use."""
        return {
            "assets": asset_store.list_all(),
            "all_tags": asset_store.all_tags(),
        }

    @app.get("/api/assets/tags/{ip}")
    def get_asset_tags(ip: str) -> dict:
        t = asset_store.get(ip)
        if not t:
            return {"ip": ip, "tags": [], "owner": "", "criticality": "medium", "notes": ""}
        return t

    @app.post("/api/assets/tags")
    def upsert_asset_tags(payload: dict = Body(...)) -> dict:
        ip = payload.get("ip", "").strip()
        if not ip:
            raise HTTPException(400, "ip required")
        rid = asset_store.upsert(
            ip,
            mac=payload.get("mac", ""),
            tags=payload.get("tags", []),
            owner=payload.get("owner", ""),
            criticality=payload.get("criticality", "medium"),
            notes=payload.get("notes", ""),
        )
        return {"ok": True, "id": rid, "ip": ip}

    @app.delete("/api/assets/tags/{ip}")
    def delete_asset_tags(ip: str) -> dict:
        asset_store.delete(ip)
        return {"ok": True, "ip": ip}

    # ---------------------------------------------------------------- AI attack path analysis
    @app.post("/api/ai/attack-paths")
    def ai_attack_paths(payload: dict = Body(...)) -> dict:
        """AI-powered attack path analysis grounded in actual fleet data."""
        from safecadence.discovery.attack_paths import analyze_attack_paths
        fleet = payload.get("fleet", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        if not fleet or not fleet.get("results"):
            raise HTTPException(400, "fleet data required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required")
        return analyze_attack_paths(fleet, provider=provider, api_key=api_key, model=model)

    @app.post("/api/ai/consensus-attack-paths")
    def ai_consensus(payload: dict = Body(...)) -> dict:
        """Multi-LLM consensus — query both OpenAI + Anthropic for the same analysis."""
        from safecadence.discovery.attack_paths import consensus_analyze
        fleet = payload.get("fleet", {})
        openai_key = payload.get("openai_key", "")
        anthropic_key = payload.get("anthropic_key", "")
        if not fleet:
            raise HTTPException(400, "fleet required")
        if not openai_key and not anthropic_key:
            raise HTTPException(400, "at least one provider key required")
        return consensus_analyze(fleet, openai_key=openai_key, anthropic_key=anthropic_key)

    # ---------------------------------------------------------------- webhook test/send
    @app.post("/api/webhook/test")
    def webhook_test(payload: dict = Body(...)) -> dict:
        """Test a Slack/Teams/generic webhook by sending a hello message."""
        from safecadence.discovery.webhooks import post_slack, post_teams, post_generic
        kind = payload.get("kind", "slack")
        url = payload.get("url", "")
        if not url:
            raise HTTPException(400, "url required")
        if kind == "slack":
            return post_slack(url, summary="✓ SafeCadence test message — your Slack webhook works!", color="good")
        elif kind == "teams":
            return post_teams(url, title="SafeCadence test", summary="✓ Webhook works.")
        else:
            return post_generic(url, {"message": "test", "from": "safecadence-netrisk"})

    @app.post("/api/webhook/send-fleet-alert")
    def webhook_send_fleet(payload: dict = Body(...)) -> dict:
        """Send the current fleet's critical findings to a configured webhook."""
        from safecadence.discovery.webhooks import post_slack, post_teams, format_critical_alert
        kind = payload.get("kind", "slack")
        url = payload.get("url", "")
        fleet = payload.get("fleet", {})
        if not url or not fleet:
            raise HTTPException(400, "url + fleet required")
        summary, blocks = format_critical_alert(fleet)
        if kind == "slack":
            return post_slack(url, summary=summary, detail_blocks=blocks, color="danger")
        else:
            return post_teams(url, title="SafeCadence fleet alert", summary=summary,
                              facts=[{"title": b.get("title"), "value": b.get("value")} for b in blocks])

    # ---------------------------------------------------------------- AI bulk fleet analysis
    @app.post("/api/ai/bulk-analyze")
    def ai_bulk_analyze(payload: dict = Body(...)) -> dict:
        """One-shot fleet-wide AI analysis with cross-device pattern recognition."""
        from safecadence.discovery.ai_chat import bulk_analyze_fleet
        fleet = payload.get("fleet", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        if not fleet or not fleet.get("results"):
            raise HTTPException(400, "fleet data required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required")
        return bulk_analyze_fleet(fleet, provider=provider, api_key=api_key, model=model)

    # ---------------------------------------------------------------- AI playbook
    @app.post("/api/discover/playbook")
    def ai_playbook(payload: dict = Body(...)) -> dict:
        """Per-device remediation playbook. BYOK. Returns markdown."""
        from safecadence.discovery.ai_analyze import generate_remediation_playbook
        host = payload.get("host", {})
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        if not host:
            raise HTTPException(400, "host required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required")
        markdown = generate_remediation_playbook(host, provider=provider, api_key=api_key, model=model)
        return {"markdown": markdown}

    # ---------------------------------------------------------------- enrichment refresh
    @app.post("/api/enrichment/refresh")
    def refresh_enrichment(source: str = Query("all", pattern="^(all|cve|eol|kev)$")) -> dict:
        from safecadence.enrichment import refresh as refresh_mod
        try:
            if source in ("all", "cve", "kev"):
                refresh_mod.refresh_kev(online=True)
            if source in ("all", "eol"):
                refresh_mod.refresh_eol(online=True)
        except Exception as e:
            raise HTTPException(500, f"refresh failed: {e}")
        return {"ok": True, "source": source,
                "refreshed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # ---------------------------------------------------------------- AI explain
    @app.post("/api/ai/explain")
    def ai_explain(payload: dict = Body(...)) -> dict:
        from safecadence.ai.client import explain_findings
        from safecadence.core.schema import ScanResult

        scan_id = payload.get("scan_id")
        provider = payload.get("provider", "openai")
        api_key = payload.get("api_key", "")
        model = payload.get("model")
        if not scan_id:
            raise HTTPException(400, "scan_id required")
        if not api_key and provider != "ollama":
            raise HTTPException(400, "api_key required for openai/anthropic")

        try:
            sid = int(scan_id)
        except (TypeError, ValueError):
            raise HTTPException(400, f"invalid scan_id: {scan_id}")

        scan_dict = store.get(sid)
        if not scan_dict:
            raise HTTPException(404, f"scan #{sid} not found")

        # explain_findings expects a ScanResult dataclass, but reconstructing
        # one from a dict is fragile (nested dataclasses). Easier path: write
        # a small shim that reads the dict directly.
        try:
            text = explain_findings(
                _DictShim(scan_dict),
                provider=provider,
                api_key=api_key,
                model=model,
            )
        except Exception as e:
            raise HTTPException(502, f"AI provider error: {e}")
        return {"scan_id": sid, "explanation": text, "provider": provider}

    # ---------------------------------------------------------------- vault (read-only stub)
    @app.get("/api/vault/list")
    def vault_list() -> list:
        # The vault requires a key. Until we add a UI flow for unlocking it,
        # the vault tab is a status/info view only. Use `safecadence vault`
        # CLI to manage credentials.
        vault_path = Path.home() / ".safecadence" / "vault.json"
        return [{"name": "(vault unlocked via CLI only)", "created_at": ""}] if vault_path.exists() else []

    @app.post("/api/vault/add")
    def vault_add(payload: dict = Body(...)) -> dict:
        raise HTTPException(
            501,
            "Vault writes require a master key — use `safecadence vault set NAME` "
            "from the CLI for now. UI-side vault unlock arrives in v2.4.x.",
        )

    # ---------------------------------------------------------------- v4 + v5 mount
    # The local UI is single-user / unauthenticated, but platform_api and
    # policy_api expect JWT bearer auth. We pass stub deps that always return
    # a fake "local" user so the same endpoints work in this context.
    class _LocalUser:
        username = "local"
        tenant = "local"
        roles = ["admin"]

    def _local_user():
        return _LocalUser()

    try:
        from safecadence.server.platform_api import register as _reg_platform
        _reg_platform(app, _local_user, _local_user)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.server.policy_api import register as _reg_policy
        _reg_policy(app, _local_user, _local_user)
    except Exception:                          # pragma: no cover
        pass

    # v7.7: identity REST API + UI page. Cookie-gated like the rest of
    # `safecadence ui` — _local_user shim provides any-authenticated and
    # writer roles without the JWT machinery the JSON-API server uses.
    try:
        from safecadence.server.identity_api import register as _reg_identity
        _reg_identity(app, _local_user, _local_user)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.identity_ui import register as _reg_identity_ui
        _reg_identity_ui(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.tool_hub import register as _reg_hub
        _reg_hub(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.smart_home import register as _reg_home
        _reg_home(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.server.intel_api import register as _reg_intel_api
        _reg_intel_api(app, _local_user, _local_user)
    except Exception:                          # pragma: no cover
        pass

    # v9.11 — execution engine on the local UI (Command Center page).
    # Without this, /execute renders but /api/execute/* returns 404.
    try:
        from safecadence.server.execution_api import register_execution_routes
        register_execution_routes(
            app,
            require_writer=_local_user, require_admin=_local_user,
            get_current_user=_local_user,
        )
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.intel_ui import register as _reg_intel_ui
        _reg_intel_ui(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.asset_detail import register as _reg_asset_detail
        _reg_asset_detail(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.v8_pages import register as _reg_v8
        _reg_v8(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.v9_pages import register as _reg_v9
        _reg_v9(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.tour import register as _reg_tour
        _reg_tour(app)
    except Exception:                          # pragma: no cover
        pass
    try:
        from safecadence.ui.help_page import register as _reg_help
        _reg_help(app)
    except Exception:                          # pragma: no cover
        pass

    return app


class _DictShim:
    """Adapt a stored scan dict to look enough like ScanResult for AI client.

    The AI client reads a handful of fields off the ScanResult dataclass
    (findings, summary, hostname/source). A dict shim is simpler than
    reconstructing the nested dataclasses.
    """

    def __init__(self, d: dict):
        self._d = d
        # Expose top-level fields as attributes for attribute access
        for k, v in d.items():
            try:
                setattr(self, k, v)
            except Exception:
                pass
        # Common derived fields the AI prompt references
        if "hostname" not in d:
            self.hostname = (d.get("parsed_summary") or {}).get("hostname") or d.get("source") or "unknown"
        self.findings = d.get("findings", [])
        self.summary = d.get("summary", "")
        self.health_score = d.get("health_score", 0)
        self.risk_score = d.get("risk_score", 0)

    def to_dict(self) -> dict:
        return self._d


def _is_port_free(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
        return True
    except OSError:
        return False


def _open_browser_when_ready(url: str, delay: float = 1.0) -> None:
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def run(*, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
        password: str | None = None) -> None:
    _check_extras()
    import uvicorn

    if not _is_port_free(host, port):
        for candidate in range(port + 1, port + 21):
            if _is_port_free(host, candidate):
                port = candidate
                break
        else:
            sys.stderr.write(f"No free port near {port}; specify --port.\n")
            sys.exit(1)

    url = f"http://{host}:{port}/"
    auth_note = " (password-protected)" if password else ""
    sys.stdout.write(f"\n  SafeCadence Local UI starting at {url}{auth_note}\n  Press Ctrl-C to stop.\n\n")

    if open_browser:
        _open_browser_when_ready(url)

    app = create_app(password=password)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
