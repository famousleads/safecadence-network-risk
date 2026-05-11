"""
Platform REST surface — /api/platform/*

Companion endpoints to the network-audit surface in app.py. These power
the multi-vendor Device Intelligence Platform UI.

All endpoints are protected by the same JWT bearer auth as the rest of
/api/*. Data is read from the platform asset store; if the store is
empty (no platform collections run yet) the endpoints return empty
collections rather than errors so the UI renders gracefully.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

# v9.31 — Request needs to be at module-level so FastAPI's annotation
# resolver finds it under `from __future__ import annotations`.
# Without this, every async POST handler with `req: Request` mis-parses
# as having `req` be a required query parameter.
try:
    from fastapi import Request as _FastAPIRequest    # type: ignore
    Request = _FastAPIRequest
except ImportError:                                       # pragma: no cover
    Request = Any        # type: ignore[misc,assignment]


# --------------------------------------------------------------------------
# Asset store — JSON-backed, no external DB dependency.
# --------------------------------------------------------------------------

def _store_dir() -> Path:
    """Directory the platform writes per-asset JSON snapshots into."""
    base = os.environ.get("SC_PLATFORM_STORE") or str(
        Path.home() / ".safecadence" / "platform_assets"
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


# Allow only safe filename characters in asset_id. Anything outside this set —
# slashes, dots-dots, null bytes, control chars — could be path traversal or
# allow reading/writing arbitrary files on the server. asset_ids in practice
# are short slugs (hostname, MAC, ARN-derived) so the restriction is safe.
_SAFE_ASSET_ID = __import__("re").compile(r"^[A-Za-z0-9._\-:@]+$")


def _safe_asset_path(asset_id: str) -> Path:
    """Resolve asset_id → on-disk path while rejecting path traversal."""
    if not asset_id or not isinstance(asset_id, str):
        raise ValueError("asset_id required")
    if len(asset_id) > 256:
        raise ValueError("asset_id too long")
    if any(c in asset_id for c in ("/", "\\", "\x00")) or ".." in asset_id:
        raise ValueError("asset_id contains illegal characters")
    if not _SAFE_ASSET_ID.match(asset_id):
        raise ValueError("asset_id contains illegal characters")
    base = _store_dir().resolve()
    target = (base / f"{asset_id}.json").resolve()
    # Belt-and-braces: ensure resolved path is still inside the store dir
    # (defends against any clever Unicode/symlink escape).
    try:
        target.relative_to(base)
    except ValueError as e:
        raise ValueError("asset_id escapes store directory") from e
    return target


def list_assets(asset_type: Optional[str] = None,
                vendor: Optional[str] = None) -> list[dict]:
    """Return all asset snapshots, optionally filtered by type or vendor.

    v7.3 — when ``DATABASE_URL`` is set and SQLAlchemy is installed, the
    Postgres-backed adapter is used. Otherwise the original file-backed
    JSON path. Exact same shape either way.
    """
    try:
        from safecadence import storage_pg
        if storage_pg.is_enabled():
            assets = storage_pg.list_assets()
            if asset_type or vendor:
                out = []
                for a in assets:
                    ident = (a.get("identity") or {})
                    if asset_type and ident.get("asset_type") != asset_type:
                        continue
                    if vendor and (ident.get("vendor") or "").lower() != vendor.lower():
                        continue
                    out.append(a)
                return out
            return assets
    except Exception:                                # pragma: no cover
        pass
    out = []
    for f in _store_dir().glob("*.json"):
        try:
            asset = json.loads(f.read_text())
        except Exception:
            continue
        ident = (asset.get("identity") or {})
        if asset_type and ident.get("asset_type") != asset_type:
            continue
        if vendor and (ident.get("vendor") or "").lower() != vendor.lower():
            continue
        out.append(asset)
    return out


def get_asset(asset_id: str) -> Optional[dict]:
    try:
        from safecadence import storage_pg
        if storage_pg.is_enabled():
            return storage_pg.get_asset(asset_id)
    except Exception:                                # pragma: no cover
        pass
    try:
        f = _safe_asset_path(asset_id)
    except ValueError:
        return None
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return None


def save_asset(asset: Any) -> str:
    """Save a UnifiedAsset (dataclass or dict) to the store. Returns asset_id.

    Routes to Postgres when DATABASE_URL is set, otherwise file-backed JSON.
    """
    if hasattr(asset, "__dataclass_fields__"):
        try:
            d = asdict(asset)
        except Exception:
            d = dict(asset.__dict__)
    else:
        d = dict(asset)
    aid = (d.get("identity") or {}).get("asset_id") or d.get("asset_id") or ""
    if not aid:
        raise ValueError("asset has no asset_id")
    try:
        from safecadence import storage_pg
        if storage_pg.is_enabled():
            return storage_pg.save_asset(d)
    except Exception:                                # pragma: no cover
        pass
    target = _safe_asset_path(aid)  # validates aid; raises on traversal
    target.write_text(json.dumps(d, default=str, indent=2))
    return aid


# --------------------------------------------------------------------------
# Aggregation helpers — used by the dashboard endpoints.
# --------------------------------------------------------------------------

def _summarize(assets: list[dict]) -> dict:
    """Generic per-domain summary — counts, vendor breakdown, health buckets."""
    by_vendor: dict[str, int] = {}
    by_grade = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0, "?": 0}
    eos_at_risk = 0
    crit_cves = 0
    for a in assets:
        v = ((a.get("identity") or {}).get("vendor") or "unknown").lower()
        by_vendor[v] = by_vendor.get(v, 0) + 1
        grade = (a.get("health") or {}).get("grade", "?") or "?"
        by_grade[grade if grade in by_grade else "?"] += 1
        if (a.get("lifecycle") or {}).get("days_until_eos", 99999) <= 365:
            eos_at_risk += 1
        crit_cves += (a.get("security") or {}).get("critical_cves", 0)
    return {
        "count": len(assets),
        "by_vendor": dict(sorted(by_vendor.items(), key=lambda kv: -kv[1])),
        "by_grade": by_grade,
        "eos_at_risk_12mo": eos_at_risk,
        "critical_cves_total": crit_cves,
    }


# --------------------------------------------------------------------------
# Endpoint registration — called from server/app.py.
# --------------------------------------------------------------------------

def register(app, get_current_user, require_writer):
    """Register all /api/platform/* endpoints onto the FastAPI app."""
    from fastapi import Body, Depends, HTTPException, Query, Request
    from fastapi.responses import HTMLResponse, PlainTextResponse

    # ---- v5.2 STATIC routes — must come before any /{asset_id} catch-all
    @app.get("/api/platform/search")
    def fleet_search(q: str = "", limit: int = 200,
                     _user=Depends(get_current_user)):
        from safecadence.platform.search import search
        return search(list_assets(), q, limit=limit)

    @app.post("/api/platform/cve/refresh-epss")
    def refresh_epss_endpoint(user=Depends(require_writer)):
        from safecadence.platform.cve_enrichment import refresh_epss
        return refresh_epss()

    @app.post("/api/platform/cve/enrich")
    def enrich_cves_endpoint(user=Depends(require_writer)):
        from safecadence.platform.cve_enrichment import enrich_fleet
        from safecadence.server.platform_api import save_asset as _save
        assets = list_assets()
        summary = enrich_fleet(assets)
        for a in assets:
            _save(a)
        return summary

    @app.post("/api/platform/adopt-discovered")
    def adopt_discovered_endpoint(body: dict = Body(...),
                                   user=Depends(require_writer)):
        from safecadence.platform.bridge import adopt_discovered
        return adopt_discovered(body)

    # v9.7 — asset dedup + shadow-IT detection across all sources
    @app.post("/api/platform/dedup")
    def dedup_endpoint(payload: dict = Body(...),
                       _user=Depends(get_current_user)):
        """Reconcile asset records across N sources.

        Body: {sources: {<name>: [<records>]}}
        Returns: {canonical: [...], shadow_it: [...], summary: "..."}
        """
        from safecadence.intel.asset_dedup import (
            merge_asset_groups, find_shadow_it, describe_dedup_result,
        )
        sources = (payload or {}).get("sources") or {}
        if not isinstance(sources, dict):
            raise HTTPException(400, "sources must be a dict of source_name → records[]")
        result = merge_asset_groups(sources)
        shadow = find_shadow_it(result)
        result.summary_text = describe_dedup_result(result)
        return {
            "summary": result.summary_text,
            "counts_by_source": result.counts_by_source,
            "canonical_count": len(result.canonical),
            "shadow_it_count": len(shadow),
            "canonical": [
                {"asset_id": c.asset_id, "hostname": c.hostname,
                 "mac": c.mac, "primary_ip": c.primary_ip,
                 "asset_type": c.asset_type, "vendor": c.vendor,
                 "sources": c.sources, "match_reasons": c.match_reasons}
                for c in result.canonical],
            "shadow_it": [
                {"asset_id": c.asset_id, "hostname": c.hostname,
                 "primary_ip": c.primary_ip, "sources": c.sources}
                for c in shadow],
        }

    # v9.19 — discovery scheduling
    @app.get("/api/platform/discovery-jobs")
    def discovery_jobs_list(_user=Depends(get_current_user)):
        from safecadence.intel.discovery_jobs import list_jobs
        from dataclasses import asdict
        return {"jobs": [asdict(j) for j in list_jobs()]}

    @app.post("/api/platform/discovery-jobs")
    def discovery_jobs_create(body: dict = Body(...),
                               user=Depends(require_writer)):
        from safecadence.intel.discovery_jobs import create_job
        from dataclasses import asdict
        try:
            j = create_job(
                name=body.get("name", ""),
                source=body.get("source", ""),
                params=body.get("params") or {},
                interval_hours=int(body.get("interval_hours", 24)),
                tenant=getattr(user, "tenant", "local"),
            )
        except ValueError as e:
            raise HTTPException(400, detail=str(e))
        return asdict(j)

    @app.delete("/api/platform/discovery-jobs/{job_id}")
    def discovery_jobs_delete(job_id: str,
                               user=Depends(require_writer)):
        from safecadence.intel.discovery_jobs import delete_job
        if not delete_job(job_id):
            raise HTTPException(404, detail="job not found")
        return {"deleted": True}

    @app.post("/api/platform/discovery-jobs/{job_id}/run-now")
    def discovery_jobs_run_now(job_id: str,
                                user=Depends(require_writer)):
        """v9.36 — Manual fire actually runs the job now.

        Before v9.36 this endpoint stamped `mark_run(ok=True)` without
        firing anything and redirected the operator to /inventory. That
        was a fake-success — exactly the trust violation v9.33/v9.35
        audited out elsewhere. Now we call the same `fire_job` dispatcher
        the daemon uses, persist the real outcome via mark_run, and
        return ok/error so the UI shows truth.
        """
        from safecadence.intel.discovery_jobs import (
            get_job, mark_run, fire_job,
        )
        j = get_job(job_id)
        if not j:
            raise HTTPException(404, detail="job not found")
        ok, err = fire_job(j)
        mark_run(job_id, ok=ok, error=err)
        return {"status": "ok" if ok else "error",
                "ok": ok,
                "error": err,
                "job_id": job_id,
                "source": j.source}

    # v9.36 — single source-of-truth list of supported discovery sources
    # so the UI doesn't drift from the runner. Public read; no writer
    # privilege needed.
    @app.get("/api/platform/discovery-jobs/sources")
    def discovery_jobs_sources(_user=Depends(get_current_user)):
        from safecadence.intel.discovery_jobs import (
            SUPPORTED_SOURCES, REQUIRED_PARAMS, SOURCE_DESCRIPTIONS,
        )
        return {
            "sources": [
                {
                    "source": s,
                    "label": SOURCE_DESCRIPTIONS.get(s, {}).get("label", s),
                    "required_params": list(REQUIRED_PARAMS.get(s, ())),
                    "needs": SOURCE_DESCRIPTIONS.get(s, {}).get("needs", ""),
                }
                for s in SUPPORTED_SOURCES
            ]
        }

    @app.get("/api/platform/changes")
    def changes_endpoint(since_days: int = 7,
                          _user=Depends(get_current_user)):
        """v9.18 — Fleet change report: added/removed/modified vs N days ago."""
        from safecadence.intel.fleet_changes import compute_changes
        return compute_changes(list_assets(), since_days=since_days)

    @app.get("/api/platform/tags")
    def tags_endpoint(_user=Depends(get_current_user)):
        """v9.20 — Aggregate every tag in use across the fleet."""
        from collections import Counter
        c = Counter()
        for a in list_assets():
            ident = a.get("identity") or {}
            for t in (ident.get("tags") or []):
                if t and isinstance(t, str):
                    c[t] += 1
        return {
            "tags": [{"tag": t, "count": n}
                      for t, n in sorted(c.items(),
                                          key=lambda kv: (-kv[1], kv[0]))],
            "total_unique": len(c),
        }

    @app.post("/api/platform/tags/rename")
    def tag_rename_endpoint(body: dict = Body(...),
                             user=Depends(require_writer)):
        """Rename a tag globally across every asset that has it.
        Body: {old_tag, new_tag}.  Use empty new_tag to delete."""
        old = (body.get("old_tag") or "").strip()
        new = (body.get("new_tag") or "").strip()
        if not old:
            raise HTTPException(400, "old_tag required")
        renamed = 0
        for a in list_assets():
            ident = a.setdefault("identity", {})
            tags = ident.get("tags") or []
            if old not in tags:
                continue
            new_tags = [t for t in tags if t != old]
            if new and new not in new_tags:
                new_tags.append(new)
            ident["tags"] = new_tags
            save_asset(a)
            renamed += 1
        return {"renamed": renamed,
                "action": "delete" if not new else "rename"}

    @app.get("/api/platform/scope")
    def scope_endpoint(_user=Depends(get_current_user)):
        """v9.20 — Compliance scope visualizer: assets grouped by
        compliance:* tag (e.g. compliance:pci → list of assets in PCI scope)."""
        from collections import defaultdict
        scopes: dict[str, list[dict]] = defaultdict(list)
        for a in list_assets():
            ident = a.get("identity") or {}
            for t in (ident.get("tags") or []):
                if isinstance(t, str) and t.lower().startswith("compliance:"):
                    framework = t.split(":", 1)[1].strip().lower()
                    if framework:
                        scopes[framework].append({
                            "asset_id": ident.get("asset_id"),
                            "hostname": ident.get("hostname"),
                            "asset_type": ident.get("asset_type"),
                            "site": ident.get("site"),
                            "criticality": ident.get("criticality"),
                        })
        return {
            "frameworks": [
                {"framework": k, "count": len(v), "members": v}
                for k, v in sorted(scopes.items(), key=lambda kv: -len(kv[1]))
            ],
        }

    @app.get("/api/platform/coverage")
    def coverage_endpoint(_user=Depends(get_current_user)):
        """v9.17 — Discovery coverage health: which sources are connected,
        when each last ran, and what's most worth connecting next."""
        from safecadence.intel.coverage import compute_coverage
        return compute_coverage(list_assets())

    # ---- v9.24: Safe Score ------------------------------------------ #

    def _gather_score_inputs():
        """Collect findings, paths, CVEs from existing data sources for
        the score functions. Each lookup is best-effort — a missing
        signal degrades to "no deduction" rather than a bad score."""
        assets = list_assets()
        findings: list[dict] = []
        paths: list[dict] = []
        cves: list[dict] = []
        try:
            from safecadence.platform.attack_paths import \
                top_k_paths_to_crown_jewels
            paths = top_k_paths_to_crown_jewels(assets, k=50) or []
        except Exception:
            paths = []
        try:
            from safecadence.platform.cve_enrichment import enrich_fleet
            enriched = enrich_fleet(assets) or {}
            for a in assets:
                aid = (a.get("identity") or {}).get("asset_id")
                row = (enriched.get("assets") or {}).get(aid) or {}
                if row.get("cves"):
                    cves.append({"asset_id": aid, "cves": row["cves"]})
        except Exception:
            cves = []
        try:
            from safecadence.intel._store import read as _read
            findings = _read("findings", []) or []
        except Exception:
            findings = []
        return assets, findings, paths, cves

    @app.get("/api/scores/safe")
    def safe_score_endpoint(_user=Depends(get_current_user)):
        """v9.24 — Fleet Safe Score (0-100, higher = safer).

        Composes findings + attack paths + CVE data (KEV+EPSS+CVSS) +
        drift + missing controls into a single number per asset and
        a criticality-weighted fleet aggregate. The reasoning behind
        each per-asset score is included in the response so the UI
        can show a "why this number" tooltip.
        """
        from safecadence.scores import score_fleet_safe
        assets, findings, paths, cves = _gather_score_inputs()
        return score_fleet_safe(
            assets, findings=findings, paths=paths, cves=cves,
        )

    @app.get("/api/scores/safe/{asset_id}")
    def safe_score_asset_endpoint(asset_id: str,
                                    _user=Depends(get_current_user)):
        """v9.24 — Per-asset Safe Score with contributing reasons."""
        from safecadence.scores import score_asset_safe
        assets, findings, paths, cves = _gather_score_inputs()
        target = next(
            (a for a in assets
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        if not target:
            from fastapi import HTTPException
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return score_asset_safe(
            target, findings=findings, paths=paths, cves=cves,
        ).to_dict()

    @app.get("/api/scores/weak-link")
    def weak_link_endpoint(_user=Depends(get_current_user)):
        """v9.24 — The single asset whose remediation kills the most
        attack paths. Returns projected fleet-score lift so the UI can
        render the 'Fix X and N paths collapse — fleet 64 → 78'
        sentence on /home."""
        from safecadence.scores import weak_link
        assets, findings, paths, cves = _gather_score_inputs()
        wl = weak_link(assets, paths, findings=findings, cves=cves)
        if wl is None:
            return {"weak_link": None,
                    "message": "No attack paths computed yet — connect "
                                "more sources or run discovery."}
        return {"weak_link": wl}

    # ---- v9.25: Settings (Splunk HEC) ------------------------------- #

    @app.get("/api/settings/splunk")
    def settings_splunk_get(_user=Depends(get_current_user)):
        """v9.25 — Read Splunk HEC config (token returned masked)."""
        from safecadence.settings import get_splunk_config
        return get_splunk_config(masked=True)

    @app.post("/api/settings/splunk")
    async def settings_splunk_set(req: Request,
                                    _user=Depends(get_current_user)):
        """v9.25 — Update Splunk HEC config. Token field is preserved
        if the submitted value looks like the mask (i.e. user didn't
        actually change it). Returns the masked, persisted view."""
        from safecadence.settings import set_splunk_config
        body = await req.json()
        return set_splunk_config(
            hec_url=body.get("hec_url"),
            hec_token=body.get("hec_token"),
            index=body.get("index"),
            source=body.get("source"),
            sourcetype=body.get("sourcetype"),
            enabled=body.get("enabled"),
        )

    # ---- v9.42: Approver directory + email settings -------------- #

    @app.get("/api/users")
    def users_list(user=Depends(get_current_user)):
        """List users in the caller's tenant — directory view, no
        password hashes. Powers the /builder invite-typeahead and the
        /users admin page."""
        from safecadence.users.directory import list_users
        from dataclasses import asdict as _ad
        tenant = getattr(user, "tenant", "local")
        recs = list_users(tenant=tenant)
        return {"users": [_ad(r) for r in recs]}

    @app.post("/api/users")
    async def users_create(req: Request,
                            user=Depends(get_current_user)):
        """Create or update a user. Requires MANAGE_USERS capability.

        Trust property: an admin can edit contact info (email,
        notify channels), display name, and roles. They cannot set or
        change another user's password through this endpoint — that
        path keeps living in the dedicated admin-set-password
        command + auth.py to avoid mixing the two concerns.

        v9.49.1 — gate switched from raw "admin role" to the
        MANAGE_USERS capability so a non-admin user with an explicit
        grant can also manage users.
        """
        from fastapi import HTTPException
        from dataclasses import asdict as _ad
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_USERS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_USERS}")
        body = await req.json()
        from safecadence.users.directory import upsert_user
        try:
            rec = upsert_user(body, tenant=getattr(user, "tenant", "local"))
        except ValueError as e:
            raise HTTPException(400, detail=str(e))
        return {"saved": True, "user": _ad(rec)}

    @app.delete("/api/users/{username}")
    def users_delete(username: str, user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_USERS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_USERS}")
        if username == user.username:
            raise HTTPException(400,
                "cannot delete yourself; use another admin account")
        from safecadence.users.directory import delete_user
        ok = delete_user(username,
                          tenant=getattr(user, "tenant", "local"))
        if not ok:
            raise HTTPException(404, "user not found")
        return {"deleted": True, "username": username}

    @app.get("/api/settings/email")
    def settings_email_get(user=Depends(get_current_user)):
        """v9.42 — Email (customer SMTP) settings. The password is
        never returned — only the boolean ``has_password`` flag."""
        from safecadence.notifier.email_notifier import load_email_config
        return load_email_config().to_public_dict()

    @app.post("/api/settings/email")
    async def settings_email_set(req: Request,
                                  user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_SETTINGS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_SETTINGS}")
        body = await req.json()
        from safecadence.notifier.email_notifier import (
            EmailConfig, load_email_config, save_email_config,
        )
        # Preserve the existing encrypted password when the operator
        # leaves the field blank (UI sends "" or omits the key).
        prior = load_email_config()
        cfg = EmailConfig(
            enabled=bool(body.get("enabled", prior.enabled)),
            host=str(body.get("host", prior.host) or ""),
            port=int(body.get("port", prior.port) or 587),
            use_tls=bool(body.get("use_tls", prior.use_tls)),
            use_ssl=bool(body.get("use_ssl", prior.use_ssl)),
            username=str(body.get("username", prior.username) or ""),
            password=str(body.get("password") or ""),
            password_encrypted=("" if body.get("password")
                                  else prior.password_encrypted),
            from_addr=str(body.get("from_addr", prior.from_addr) or ""),
            timeout_s=int(body.get("timeout_s", prior.timeout_s) or 15),
        )
        save_email_config(cfg)
        return load_email_config().to_public_dict()

    @app.post("/api/settings/email/test")
    async def settings_email_test(req: Request,
                                    user=Depends(get_current_user)):
        """Send a test email to the configured admin or to a body-
        supplied recipient. Used by the Settings → Email "Send test"
        button to verify the customer's SMTP config end-to-end before
        relying on it for real approval notifications."""
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_SETTINGS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_SETTINGS}")
        try:
            body = await req.json()
        except Exception:
            body = {}
        to = (body.get("to") or "").strip()
        if not to:
            from safecadence.users.directory import get_user
            rec = get_user(user.username,
                            tenant=getattr(user, "tenant", "local"))
            to = rec.primary_email() if rec else ""
        if not to:
            raise HTTPException(400, "no recipient — set body.to or "
                                       "configure your own email address")
        from safecadence.notifier.email_notifier import send_email
        ok, err = send_email(
            to=to,
            subject="[SafeCadence] SMTP test message",
            body=("This is a SafeCadence SMTP test message.\n\n"
                   "If you got this email, your SMTP config is working "
                   "and approval notifications will route via this same "
                   "server. No further action required."),
        )
        if not ok:
            raise HTTPException(502, detail=f"SMTP send failed: {err}")
        return {"sent": True, "to": to}

    # ---- v9.43: Notification preferences ------------------------- #

    @app.get("/api/notify/categories")
    def notify_categories(_user=Depends(get_current_user)):
        """List the categories + channels the directory supports.
        Drives the /settings notifications matrix."""
        from safecadence.notifier.registry import (
            NOTIFY_CATEGORIES, NOTIFY_CHANNELS,
        )
        return {"categories": NOTIFY_CATEGORIES,
                "channels": NOTIFY_CHANNELS}

    @app.get("/api/settings/notify-defaults")
    def notify_defaults_get(user=Depends(get_current_user)):
        """Tenant-default category × channel matrix used when a user
        has no override for a category."""
        from safecadence.notifier.prefs import load_tenant_defaults
        return {"defaults": load_tenant_defaults()}

    @app.post("/api/settings/notify-defaults")
    async def notify_defaults_set(req: Request,
                                    user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_SETTINGS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_SETTINGS}")
        body = await req.json()
        from safecadence.notifier.prefs import save_tenant_defaults
        return {"defaults": save_tenant_defaults(
            body.get("defaults") or body)}

    @app.get("/api/users/me/notify-prefs")
    def me_notify_prefs_get(user=Depends(get_current_user)):
        """Self-service: return the caller's effective prefs +
        availability matrix so the UI can gray out cells the user
        can't toggle on (no contact info on that channel)."""
        from fastapi import HTTPException
        from safecadence.users.directory import get_user
        from safecadence.notifier.prefs import (
            load_tenant_defaults, user_prefs,
        )
        rec = get_user(user.username, tenant=getattr(user, "tenant", "local"))
        if rec is None:
            raise HTTPException(404, "no user record")
        avail = []
        if rec.primary_email():
            avail.append("email")
        if rec.notify.get("slack_user_id"):
            avail.append("slack_dm")
        if rec.notify.get("teams_user_id"):
            avail.append("teams_dm")
        return {
            "username": rec.username,
            "available_channels": avail,
            "tenant_defaults": load_tenant_defaults(),
            "overrides": user_prefs(rec),
        }

    @app.post("/api/users/me/notify-prefs")
    async def me_notify_prefs_set(req: Request,
                                    user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.users.directory import get_user, upsert_user
        from safecadence.notifier.prefs import validate_prefs
        body = await req.json()
        prefs = body.get("notify_prefs") or body or {}
        rec = get_user(user.username, tenant=getattr(user, "tenant", "local"))
        if rec is None:
            raise HTTPException(404, "no user record")
        errs = validate_prefs(rec, prefs)
        if errs:
            raise HTTPException(400, detail="; ".join(errs))
        # Round-trip into upsert with the existing record's other fields
        from dataclasses import asdict as _ad
        upsert_user({**_ad(rec), "notify_prefs": prefs},
                     tenant=getattr(user, "tenant", "local"))
        return {"saved": True, "notify_prefs": prefs}

    @app.get("/api/users/{username}/notify-prefs")
    def admin_notify_prefs_get(username: str,
                                 user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if (username != user.username and
                not has_capability(username=user.username,
                                      roles=list(user.roles or []),
                                      capability=Capability.MANAGE_USERS,
                                      tenant=getattr(user, "tenant", "local"))):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_USERS} "
                "(or operate on your own prefs)")
        from safecadence.users.directory import get_user
        from safecadence.notifier.prefs import user_prefs
        rec = get_user(username, tenant=getattr(user, "tenant", "local"))
        if rec is None:
            raise HTTPException(404, "user not found")
        return {"username": username, "overrides": user_prefs(rec)}

    @app.post("/api/users/{username}/notify-prefs")
    async def admin_notify_prefs_set(username: str, req: Request,
                                       user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_USERS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_USERS}")
        from safecadence.users.directory import get_user, upsert_user
        from safecadence.notifier.prefs import validate_prefs
        from dataclasses import asdict as _ad
        body = await req.json()
        prefs = body.get("notify_prefs") or body or {}
        rec = get_user(username, tenant=getattr(user, "tenant", "local"))
        if rec is None:
            raise HTTPException(404, "user not found")
        errs = validate_prefs(rec, prefs)
        if errs:
            raise HTTPException(400, detail="; ".join(errs))
        upsert_user({**_ad(rec), "notify_prefs": prefs},
                     tenant=getattr(user, "tenant", "local"))
        return {"saved": True, "username": username,
                "notify_prefs": prefs}

    # ---- v9.44: Multi-provider webhooks -------------------------- #

    @app.get("/api/webhooks")
    def webhooks_list(_user=Depends(get_current_user)):
        """List configured webhooks. URLs are NEVER returned —
        only the redacted preview + has_url boolean."""
        from safecadence.notifier import webhook_registry
        return {"webhooks": [w.to_public_dict()
                              for w in webhook_registry.list_webhooks()],
                "providers": list(
                    __import__("safecadence.notifier.providers",
                                  fromlist=["SUPPORTED_PROVIDERS"])
                    .SUPPORTED_PROVIDERS),
                }

    @app.post("/api/webhooks")
    async def webhooks_upsert(req: Request,
                                user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_WEBHOOKS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_WEBHOOKS}")
        body = await req.json()
        from safecadence.notifier import webhook_registry
        try:
            w = webhook_registry.upsert(body)
        except ValueError as e:
            raise HTTPException(400, detail=str(e))
        return {"saved": True, "webhook": w.to_public_dict()}

    @app.delete("/api/webhooks/{webhook_id}")
    def webhooks_delete(webhook_id: str,
                          user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_WEBHOOKS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_WEBHOOKS}")
        from safecadence.notifier import webhook_registry
        if not webhook_registry.delete(webhook_id):
            raise HTTPException(404, "webhook not found")
        return {"deleted": True, "id": webhook_id}

    @app.post("/api/webhooks/{webhook_id}/test")
    def webhooks_test(webhook_id: str,
                        user=Depends(get_current_user)):
        from fastapi import HTTPException
        from safecadence.capabilities import has_capability, Capability
        if not has_capability(username=user.username,
                                roles=list(user.roles or []),
                                capability=Capability.MANAGE_WEBHOOKS,
                                tenant=getattr(user, "tenant", "local")):
            raise HTTPException(403,
                f"Missing capability: {Capability.MANAGE_WEBHOOKS}")
        from safecadence.notifier import webhook_registry
        w = webhook_registry.get(webhook_id)
        if not w:
            raise HTTPException(404, "webhook not found")
        ok, err = webhook_registry.fire_one(w, {
            "kind": "_test",
            "title": "SafeCadence webhook test",
            "summary": ("This is a SafeCadence webhook test. If you see "
                          "this, the URL + provider are wired correctly."),
            "severity": "info",
            "link": "",
            "requested_by": user.username,
        })
        if not ok:
            raise HTTPException(502, detail=f"send failed: {err}")
        return {"sent": True, "provider": w.provider,
                "id": webhook_id}

    # ---- v9.32.1: unified drift roll-up -------------------------- #

    @app.get("/api/drift/all")
    def drift_all(_user=Depends(get_current_user)):
        """v9.32.1 — unified roll-up across the three drift sources:

          1. Policy drift     (declared policy ↔ running config)
          2. Baseline drift   (declared baseline ↔ running config)
          3. Cross-system     (Okta vs AD vs Entra disagreement)

        Each row carries a `kind`, `asset_id`, `severity`, and a
        deep-link the UI can follow. The /drift page reads this and
        renders three tabs with per-row remediate buttons.
        """
        out: dict = {"policy": [], "baseline": [], "cross_system": [],
                       "summary": {"total": 0,
                                     "policy": 0, "baseline": 0,
                                     "cross_system": 0,
                                     "by_severity": {"critical": 0,
                                                      "high": 0,
                                                      "medium": 0,
                                                      "low": 0}}}
        # 1) Policy drift across all known policies.
        # Bug fixed v9.32.2: was importing from policy.persistence
        # (doesn't exist) and reading the wrong keys. detect_drift()
        # returns {regressions, improvements, ...} — regressions are
        # the ones we want to surface (pass→fail since last cycle).
        try:
            from safecadence.policy.drift import detect_drift
            from safecadence.policy.store import list_policies
            for p in list_policies() or []:
                pid = p.get("id") or p.get("policy_id") or ""
                if not pid:
                    continue
                d = detect_drift(pid) or {}
                # Regressions = controls that were passing and now fail.
                # That's the actionable "config drifted away from policy"
                # signal. Severity comes from the policy's metadata if
                # set, otherwise default to high (a passing control
                # going red is rarely low-severity).
                policy_sev = (p.get("severity")
                                or p.get("default_severity")
                                or "high").lower()
                for row in (d.get("regressions") or []):
                    out["policy"].append({
                        "kind": "policy",
                        "policy_id": pid,
                        "asset_id": row.get("asset_id", ""),
                        "control_id": row.get("control_id", ""),
                        "severity": policy_sev,
                        "message": (
                            f"Control {row.get('control_id','?')} regressed "
                            f"from {row.get('from','?')} → {row.get('to','?')} "
                            f"on {row.get('asset_id','?')}"
                        ),
                        "first_seen": d.get("current_evaluated_at", ""),
                    })
        except Exception:
            pass

        # 2) Baseline drift across the fleet.
        try:
            from safecadence.compliance.baseline_drift import (
                drift_findings_for_fleet,
            )
            assets = list_assets()
            for f in drift_findings_for_fleet(assets) or []:
                out["baseline"].append({
                    "kind": "baseline",
                    "asset_id": f.get("asset_id", ""),
                    "severity": (f.get("severity")
                                    or "medium").lower(),
                    "message": f.get("message", ""),
                    "title": f.get("title", ""),
                })
        except Exception:
            pass

        # 3) Cross-system drift.
        try:
            from safecadence.policy.cross_system_drift import compute_drift
            divs = compute_drift() or []
            for d in (divs.get("divergences") if isinstance(divs, dict) else divs) or []:
                out["cross_system"].append({
                    "kind": "cross_system",
                    "principal": d.get("principal") or d.get("subject") or "",
                    "resource":  d.get("resource") or d.get("policy") or "",
                    "system_a":  d.get("system_a") or d.get("source_a") or "",
                    "system_b":  d.get("system_b") or d.get("source_b") or "",
                    "severity": (d.get("severity")
                                    or "medium").lower(),
                    "message": d.get("message", ""),
                })
        except Exception:
            pass

        # Summary
        out["summary"]["policy"] = len(out["policy"])
        out["summary"]["baseline"] = len(out["baseline"])
        out["summary"]["cross_system"] = len(out["cross_system"])
        out["summary"]["total"] = (out["summary"]["policy"]
                                       + out["summary"]["baseline"]
                                       + out["summary"]["cross_system"])
        for bucket in ("policy", "baseline", "cross_system"):
            for r in out[bucket]:
                sev = r.get("severity", "medium")
                if sev in out["summary"]["by_severity"]:
                    out["summary"]["by_severity"][sev] += 1
        return out

    # ---- v9.32: trust artifacts (security.txt, SBOM) -------------- #

    @app.get("/.well-known/security.txt", include_in_schema=False)
    def well_known_security_txt():
        """v9.32 — RFC 9116 security disclosure pointer.

        Trust artifact: every prospect can `curl <host>/.well-known/
        security.txt` and see exactly how to report a vulnerability.
        Static — no info leakage."""
        from fastapi.responses import PlainTextResponse
        body = (
            "Contact: mailto:security@safecadence.com\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
            "Encryption: https://safecadence.com/.well-known/pgp-key.txt\n"
            "Preferred-Languages: en\n"
            "Policy: https://github.com/safecadence/network-risk/blob/main/SECURITY.md\n"
            "Acknowledgments: https://github.com/safecadence/network-risk/blob/main/docs/SECURITY-CREDITS.md\n"
        )
        return PlainTextResponse(body)

    @app.get("/api/trust/posture")
    def trust_posture(_user=Depends(get_current_user)):
        """v9.32 — Live trust-posture report. Surfaces every property
        a prospect's security team would otherwise have to grep for:
        is telemetry off, is AI air-gapped, is the JWT secret persisted,
        is the evidence chain intact, is the audit log rotating, etc.
        """
        import os as _os
        try:
            from safecadence.compliance.evidence_chain import verify_chain
            chain = verify_chain()
        except Exception:
            chain = {"ok": None, "checked": 0,
                       "reason": "module unavailable"}
        ai_disabled = (_os.environ.get("SC_AI_DISABLED") or "").lower() \
                          not in ("", "0", "false", "no", "off")
        return {
            "telemetry": "none",
            "phone_home": False,
            "auto_update": False,
            "ai": {
                "byo_keys": True,
                "disabled": ai_disabled,
                "providers_supported": ["anthropic", "openai", "ollama"],
                "fallback": "offline rule-based",
            },
            "storage": {
                "default": "file-backed JSON",
                "postgres_when": "DATABASE_URL set",
                "encrypted_vault": True,
            },
            "outbound_calls_gated_on": [
                "SC_SLACK_WEBHOOK", "SC_TEAMS_WEBHOOK",
                "SC_PAGERDUTY_URL", "SC_SPLUNK_HEC_URL",
                "SC_SMTP_HOST", "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OLLAMA_HOST",
            ],
            "evidence_chain": chain,
            "version": __import__("safecadence").__version__,
        }

    # ---- v9.32: vendor risk + data classification ----------------- #

    @app.get("/api/compliance/vendors")
    def vendor_risk_list(_user=Depends(get_current_user)):
        from safecadence.compliance.vendor_risk import (
            list_vendors, summary, expiring_attestations,
        )
        return {"vendors": list_vendors(),
                "summary": summary(),
                "expiring": expiring_attestations(within_days=60)}

    @app.post("/api/compliance/vendors")
    async def vendor_risk_create(req: Request,
                                    _user=Depends(require_writer)):
        from safecadence.compliance.vendor_risk import create_vendor
        body = await req.json()
        try:
            return create_vendor(
                name=body.get("name", ""),
                category=body.get("category", "saas"),
                criticality=body.get("criticality", "medium"),
                contact=body.get("contact", ""),
                residual_risk=body.get("residual_risk", "medium"),
                notes=body.get("notes", ""),
            ).to_dict()
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.post("/api/compliance/vendors/{vendor_id}/attestations")
    async def vendor_risk_attestation(vendor_id: str, req: Request,
                                          _user=Depends(require_writer)):
        from safecadence.compliance.vendor_risk import add_attestation
        body = await req.json()
        try:
            rec = add_attestation(
                vendor_id,
                type=body.get("type", "soc2_type2"),
                status=body.get("status", "active"),
                expires_at=body.get("expires_at"),
                doc_url=body.get("doc_url", ""),
            )
            if not rec:
                from fastapi import HTTPException
                raise HTTPException(404, "vendor not found")
            return rec
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/compliance/vendors/{vendor_id}")
    def vendor_risk_delete(vendor_id: str,
                              _user=Depends(require_writer)):
        from safecadence.compliance.vendor_risk import delete_vendor
        return {"ok": delete_vendor(vendor_id)}

    @app.get("/api/compliance/data-classification/catalog")
    def data_classification_catalog(_user=Depends(get_current_user)):
        from safecadence.compliance.data_classification import classes
        return {"classes": classes()}

    @app.get("/api/compliance/data-classification/summary")
    def data_classification_summary(_user=Depends(get_current_user)):
        from safecadence.compliance.data_classification import fleet_summary
        return fleet_summary(list_assets())

    # ---- v9.32: brownfield import + cross-vendor migration ------- #

    @app.post("/api/policy/import-from-config")
    async def policy_import_one(req: Request,
                                   _user=Depends(get_current_user)):
        """v9.32 — point at one config text, get back the implicit
        SafeCadence policy (controls already enforced)."""
        from safecadence.policy.import_from_configs import import_one_config
        body = await req.json()
        return import_one_config(
            body.get("config_text", ""),
            asset_id=body.get("asset_id", "imported"),
        ).to_dict()

    @app.post("/api/policy/import-from-fleet")
    async def policy_import_fleet(req: Request,
                                     _user=Depends(get_current_user)):
        """v9.32 — aggregate import across multiple configs."""
        from safecadence.policy.import_from_configs import import_fleet
        body = await req.json()
        configs = [(c.get("asset_id", ""), c.get("config_text", ""))
                     for c in body.get("configs") or []]
        out = import_fleet(
            configs,
            policy_name=body.get("policy_name", "Inferred fleet policy"),
            quorum_pct=int(body.get("quorum_pct", 60)),
        )
        return out.to_dict()

    @app.post("/api/policy/migrate")
    async def policy_migrate(req: Request,
                                _user=Depends(get_current_user)):
        """v9.32 — render a control list against a target vendor."""
        from safecadence.policy.migrate import migrate
        body = await req.json()
        return migrate(
            body.get("source_vendor", ""),
            body.get("target_vendor", ""),
            body.get("control_ids") or [],
        ).to_dict()

    # ---- v9.32: AI-explain finding ------------------------------- #

    @app.post("/api/findings/explain")
    async def explain_finding(req: Request,
                                 _user=Depends(get_current_user)):
        """v9.32 — plain-English explanation of one finding.

        Trust posture: the request returns the EXACT prompt sent to
        the AI provider plus a `network_used` flag so the operator
        can verify air-gap claims. Honors SC_AI_DISABLED."""
        from safecadence.ai.explain_finding import explain
        body = await req.json()
        return explain(body or {}).to_dict()

    # ---- v9.32: policy change approval --------------------------- #

    @app.get("/api/policy/changes")
    def policy_changes_list(policy_id: Optional[str] = None,
                                status: Optional[str] = None,
                                _user=Depends(get_current_user)):
        from safecadence.policy.changes import list_changes, pending_count
        return {
            "changes": list_changes(policy_id=policy_id, status=status),
            "pending_count": pending_count(),
        }

    @app.post("/api/policy/changes")
    async def policy_changes_request(req: Request,
                                          user=Depends(require_writer)):
        from safecadence.policy.changes import request_change
        body = await req.json()
        try:
            rec = request_change(
                policy_id=body.get("policy_id", ""),
                action=body.get("action", "update"),
                before=body.get("before") or {},
                after=body.get("after") or {},
                requested_by=(user.get("username", "")
                                  if isinstance(user, dict) else ""),
                note=body.get("note", ""),
            )
            return rec.to_dict()
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.post("/api/policy/changes/{change_id}/approve")
    async def policy_changes_approve(change_id: str, req: Request,
                                          user=Depends(require_writer)):
        from safecadence.policy.changes import approve
        body = await req.json()
        rec = approve(
            change_id,
            approved_by=(user.get("username", "")
                            if isinstance(user, dict) else ""),
            note=body.get("note", ""),
        )
        if not rec:
            from fastapi import HTTPException
            raise HTTPException(404, "change not found or already decided")
        return rec

    @app.post("/api/policy/changes/{change_id}/reject")
    async def policy_changes_reject(change_id: str, req: Request,
                                         user=Depends(require_writer)):
        from safecadence.policy.changes import reject
        body = await req.json()
        rec = reject(
            change_id,
            approved_by=(user.get("username", "")
                            if isinstance(user, dict) else ""),
            note=body.get("note", ""),
        )
        if not rec:
            from fastapi import HTTPException
            raise HTTPException(404, "change not found or already decided")
        return rec

    # ---- v9.32: policy RBAC -------------------------------------- #

    @app.get("/api/policy/rbac")
    def policy_rbac_get(_user=Depends(get_current_user)):
        from safecadence.policy.rbac import load_mapping
        return {"mapping": load_mapping()}

    @app.post("/api/policy/rbac")
    async def policy_rbac_set(req: Request,
                                 _user=Depends(require_writer)):
        from safecadence.policy.rbac import save_mapping
        body = await req.json()
        return {"mapping": save_mapping(body.get("mapping") or {})}

    # ---- v9.32: scheduled evidence ------------------------------- #

    @app.get("/api/compliance/evidence-schedule")
    def ev_schedule_list(_user=Depends(get_current_user)):
        from safecadence.compliance.evidence_schedule import list_schedules
        return {"schedules": list_schedules()}

    @app.post("/api/compliance/evidence-schedule")
    async def ev_schedule_create(req: Request,
                                       _user=Depends(require_writer)):
        from safecadence.compliance.evidence_schedule import create
        body = await req.json()
        try:
            return create(
                framework=body.get("framework", "soc2"),
                freq=body.get("freq", "monthly"),
                notify_email=body.get("notify_email", ""),
            ).to_dict()
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/compliance/evidence-schedule/{schedule_id}")
    def ev_schedule_delete(schedule_id: str,
                                _user=Depends(require_writer)):
        from safecadence.compliance.evidence_schedule import delete
        return {"ok": delete(schedule_id)}

    # ---- v9.27..v9.30: compliance suite -------------------------- #

    # ---- v9.31: quick policy + dry-run + live preview + sandbox -- #

    @app.get("/api/policy/quick")
    def policy_quick_list(_user=Depends(get_current_user)):
        from safecadence.policy.quick import list_quick_policies
        return {"policies": list_quick_policies()}

    @app.post("/api/policy/quick")
    async def policy_quick_create(req: Request,
                                     user=Depends(require_writer)):
        from safecadence.policy.quick import quick_author
        body = await req.json()
        try:
            rec = quick_author(
                name=body.get("name", ""),
                target_group=body.get("target_group", ""),
                control_ids=body.get("control_ids") or [],
                mode=body.get("mode", "report_only"),
                created_by=(user.get("username", "")
                              if isinstance(user, dict) else ""),
            )
            return rec.to_dict()
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/policy/quick/{policy_id}")
    def policy_quick_delete(policy_id: str,
                              _user=Depends(require_writer)):
        from safecadence.policy.quick import delete_quick_policy
        return {"ok": delete_quick_policy(policy_id)}

    @app.post("/api/policy/{policy_id}/mode")
    async def policy_mode_set(policy_id: str, req: Request,
                                _user=Depends(require_writer)):
        """v9.31 — flip a policy between enforce / report_only / disabled."""
        from safecadence.policy.quick import set_mode
        body = await req.json()
        try:
            return set_mode(policy_id, body.get("mode", "enforce"))
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.post("/api/policy/preview-config")
    async def policy_preview_config(req: Request,
                                       _user=Depends(get_current_user)):
        """v9.31 — live vendor-native preview of a policy spec."""
        from safecadence.policy.quick import render_for_vendor
        body = await req.json()
        return render_for_vendor(
            body.get("vendor", ""),
            body.get("control_ids") or [],
        )

    @app.post("/api/policy/sandbox/{asset_id}")
    async def policy_sandbox(asset_id: str, req: Request,
                                _user=Depends(get_current_user)):
        """v9.31 — apply a policy to ONE asset, sandboxed.

        Returns what would change vs already-satisfied, plus a
        rendered preview the operator can copy/paste.
        """
        from safecadence.policy.quick import simulate_on_asset
        body = await req.json()
        target = next(
            (a for a in list_assets()
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        if not target:
            from fastapi import HTTPException
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return simulate_on_asset(target,
                                    body.get("control_ids") or [])

    @app.get("/api/settings/compliance-mode")
    def settings_compliance_mode_get(_user=Depends(get_current_user)):
        """v9.31 — read the compliance-on/off flag."""
        from safecadence.settings import get_compliance_mode
        return get_compliance_mode()

    @app.post("/api/settings/compliance-mode")
    async def settings_compliance_mode_set(req: Request,
                                              _user=Depends(require_writer)):
        """v9.31 — toggle the compliance-on/off flag."""
        from safecadence.settings import set_compliance_mode
        body = await req.json()
        return set_compliance_mode(bool(body.get("enabled", True)))

    @app.get("/api/compliance/frameworks")
    def compliance_frameworks(_user=Depends(get_current_user)):
        """v9.27 — list every framework we ship mappings for + counts."""
        from safecadence.compliance import list_frameworks
        return {"frameworks": list_frameworks()}

    @app.get("/api/compliance/coverage/{framework}")
    def compliance_coverage(framework: str,
                              _user=Depends(get_current_user)):
        """v9.27 — coverage matrix for one framework."""
        from safecadence.compliance import coverage
        return coverage(framework)

    @app.get("/api/compliance/control/{control_id}")
    def compliance_control(control_id: str,
                             _user=Depends(get_current_user)):
        """v9.27 — full mapping + metadata for one SafeCadence control."""
        from safecadence.compliance import control_detail
        return control_detail(control_id)

    @app.get("/api/compliance/sla")
    def compliance_sla_summary(_user=Depends(get_current_user)):
        """v9.28 — SLA breach summary for /findings + /home."""
        from safecadence.compliance.sla import (
            annotate_findings, breach_summary,
        )
        try:
            from safecadence.intel._store import read as _read
            findings = _read("findings", []) or []
        except Exception:
            findings = []
        return {
            "summary": breach_summary(findings),
            "annotated": [a.to_dict()
                            for a in annotate_findings(findings)],
        }

    @app.get("/api/compliance/exceptions")
    def compliance_exceptions(status: Optional[str] = None,
                                _user=Depends(get_current_user)):
        """v9.28 — list exception lifecycle records."""
        from safecadence.compliance.exception_lifecycle import (
            list_exceptions, expiring_exceptions,
        )
        return {
            "exceptions": list_exceptions(status=status),
            "expiring_within_14d": expiring_exceptions(within_days=14),
        }

    @app.post("/api/compliance/exceptions")
    async def compliance_exception_create(req: Request,
                                            user=Depends(require_writer)):
        """v9.28 — create a new exception with justification + expiry."""
        from safecadence.compliance.exception_lifecycle import create_exception
        body = await req.json()
        try:
            rec = create_exception(
                control_id=body.get("control_id", ""),
                asset_id=body.get("asset_id", ""),
                finding_id=body.get("finding_id", ""),
                justification=body.get("justification", ""),
                accepted_by=body.get("accepted_by", "")
                              or (user.get("username", "") if isinstance(user, dict) else ""),
                valid_for_days=int(body.get("valid_for_days", 90)),
            )
            return rec.to_dict()
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/compliance/exceptions/{exception_id}")
    def compliance_exception_revoke(exception_id: str,
                                       user=Depends(require_writer)):
        """v9.28 — revoke an active exception."""
        from safecadence.compliance.exception_lifecycle import revoke_exception
        ok = revoke_exception(exception_id,
                                by=(user.get("username", "")
                                      if isinstance(user, dict) else ""))
        return {"ok": ok}

    @app.get("/api/compliance/control-history/{control_id}")
    def compliance_control_history(control_id: str, days: int = 90,
                                       _user=Depends(get_current_user)):
        """v9.28 — Type 2 evidence: every test result for one control."""
        from safecadence.compliance.control_history import history
        return {"control_id": control_id,
                "history": history(control_id=control_id, days=days)}

    @app.get("/api/compliance/control-history-summary")
    def compliance_control_history_summary(days: int = 90,
                                              _user=Depends(get_current_user)):
        """v9.28 — per-control rollup for the evidence pack header."""
        from safecadence.compliance.control_history import (
            summary_for_evidence_pack,
        )
        return {"days": days,
                "controls": summary_for_evidence_pack(days=days)}

    @app.get("/api/compliance/risks")
    def compliance_risks(_user=Depends(get_current_user)):
        """v9.29 — risk register list + summary."""
        from safecadence.compliance.risk_register import list_risks, summary
        return {"risks": list_risks(), "summary": summary()}

    @app.post("/api/compliance/risks")
    async def compliance_risk_create(req: Request,
                                       _user=Depends(require_writer)):
        """v9.29 — create a risk."""
        from safecadence.compliance.risk_register import create_risk
        body = await req.json()
        try:
            rec = create_risk(
                title=body.get("title", ""),
                description=body.get("description", ""),
                owner=body.get("owner", ""),
                domain=body.get("domain", "general"),
                likelihood=int(body.get("likelihood", 1)),
                impact=int(body.get("impact", 1)),
                control_ids=body.get("control_ids") or [],
                mitigation=body.get("mitigation", ""),
            )
            return rec.to_dict()
        except (ValueError, TypeError) as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/compliance/risks/{risk_id}")
    def compliance_risk_delete(risk_id: str,
                                  _user=Depends(require_writer)):
        from safecadence.compliance.risk_register import delete_risk
        return {"ok": delete_risk(risk_id)}

    @app.get("/api/compliance/baseline/{asset_id}")
    def compliance_baseline_get(asset_id: str,
                                   _user=Depends(get_current_user)):
        """v9.29 — read baseline metadata + drift report."""
        from safecadence.compliance.baseline_drift import (
            get_baseline_meta, drift_for_asset,
        )
        meta = get_baseline_meta(asset_id) or {}
        target = next(
            (a for a in list_assets()
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        report = drift_for_asset(target).to_dict() if target else {
            "asset_id": asset_id, "has_baseline": bool(meta),
        }
        return {"meta": meta, "drift": report}

    @app.post("/api/compliance/baseline/{asset_id}")
    async def compliance_baseline_set(asset_id: str, req: Request,
                                        user=Depends(require_writer)):
        """v9.29 — set the declared baseline from an uploaded config."""
        from safecadence.compliance.baseline_drift import set_baseline
        body = await req.json()
        config_text = body.get("config_text") or ""
        try:
            return set_baseline(asset_id, config_text,
                                  set_by=(user.get("username", "")
                                            if isinstance(user, dict) else "operator"))
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.get("/api/compliance/auditor/tokens")
    def compliance_auditor_tokens(_user=Depends(require_writer)):
        """v9.30 — list issued auditor tokens (hashes never returned)."""
        from safecadence.compliance.auditor_portal import list_tokens
        return {"tokens": list_tokens()}

    @app.post("/api/compliance/auditor/tokens")
    async def compliance_auditor_issue(req: Request,
                                          _user=Depends(require_writer)):
        """v9.30 — mint a new auditor token. Secret returned ONCE."""
        from safecadence.compliance.auditor_portal import issue
        body = await req.json()
        try:
            rec, secret = issue(
                name=body.get("name", ""),
                issued_to=body.get("issued_to", ""),
                valid_for_days=int(body.get("valid_for_days", 30)),
                scope=body.get("scope") or None,
                note=body.get("note", ""),
            )
            return {"token": rec.to_dict(),
                    "secret": secret,
                    "warning": "Secret shown once. Save it now — "
                                  "we only store the hash."}
        except ValueError as e:
            from fastapi import HTTPException
            raise HTTPException(400, str(e))

    @app.delete("/api/compliance/auditor/tokens/{token_id}")
    def compliance_auditor_revoke(token_id: str,
                                     _user=Depends(require_writer)):
        from safecadence.compliance.auditor_portal import revoke
        return {"ok": revoke(token_id)}

    @app.get("/api/compliance/evidence-chain")
    def compliance_evidence_chain(framework: Optional[str] = None,
                                     _user=Depends(get_current_user)):
        """v9.30 — list of evidence chain records + integrity proof."""
        from safecadence.compliance.evidence_chain import (
            list_chain, verify_chain,
        )
        return {"chain": list_chain(framework=framework),
                "integrity": verify_chain()}

    @app.post("/api/compliance/evidence-chain/append")
    async def compliance_evidence_append(req: Request,
                                            _user=Depends(require_writer)):
        """v9.30 — append a generated evidence pack to the hash chain."""
        from safecadence.compliance.evidence_chain import append
        body = await req.json()
        return append(
            framework=body.get("framework", ""),
            content=(body.get("content_b64") or "").encode("utf-8"),
            generated_by=body.get("generated_by", "safecadence"),
            note=body.get("note", ""),
        )

    # ---- v9.26: posture + best-practice + software-currency ------ #

    @app.get("/api/scores/posture/{asset_id}")
    def posture_endpoint(asset_id: str,
                          _user=Depends(get_current_user)):
        """v9.26 — Per-asset posture credit breakdown (earned + missing)."""
        from safecadence.scores.posture import evaluate_asset
        from fastapi import HTTPException
        target = next(
            (a for a in list_assets()
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        if not target:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return evaluate_asset(target).to_dict()

    @app.get("/api/scores/best-practice/{asset_id}")
    def best_practice_endpoint(asset_id: str,
                                 _user=Depends(get_current_user)):
        """v9.26 — Vendor best-practice config check breakdown.

        Returns empty vendor_key when we don't ship a pack for the
        asset's vendor; the cockpit hides the section in that case.
        """
        from safecadence.scores.best_practice import evaluate_asset
        from fastapi import HTTPException
        target = next(
            (a for a in list_assets()
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        if not target:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return evaluate_asset(target).to_dict()

    @app.get("/api/scores/software-currency/{asset_id}")
    def software_currency_endpoint(asset_id: str,
                                      _user=Depends(get_current_user)):
        """v9.26 — Is the running firmware/OS on the recommended version?"""
        from safecadence.scores.software_currency import evaluate_asset
        from fastapi import HTTPException
        target = next(
            (a for a in list_assets()
              if (a.get("identity") or {}).get("asset_id") == asset_id),
            None,
        )
        if not target:
            raise HTTPException(404, f"asset {asset_id!r} not found")
        return evaluate_asset(target).to_dict()

    # ---- v9.25: Safe Score history -------------------------------- #

    @app.get("/api/scores/safe/history")
    def safe_score_history(days: int = 30,
                            _user=Depends(get_current_user)):
        """v9.25 — Fleet Safe Score history. One row per daemon cycle.
        Powers the sparkline on /home and the trend chart on /scores."""
        from safecadence.scores import fleet_history, trend
        return {
            "history": fleet_history(days=days),
            "trend": trend(days=7),
        }

    @app.get("/api/scores/safe/{asset_id}/history")
    def safe_score_asset_history(asset_id: str, days: int = 30,
                                    _user=Depends(get_current_user)):
        """v9.25 — Per-asset Safe Score history."""
        from safecadence.scores import asset_history
        return {"asset_id": asset_id,
                "history": asset_history(asset_id, days=days)}

    @app.post("/api/scores/safe/snapshot")
    def safe_score_snapshot_now(_user=Depends(get_current_user)):
        """v9.25 — Force-write a snapshot now. Useful when first
        connecting the UI to a long-running deployment so the trend
        line has at least one point. The daemon writes one per cycle
        otherwise."""
        from safecadence.scores import score_fleet_safe, append_snapshot
        assets, findings, paths, cves = _gather_score_inputs()
        fleet = score_fleet_safe(
            assets, findings=findings, paths=paths, cves=cves,
        )
        return append_snapshot(fleet)

    @app.post("/api/settings/splunk/test")
    async def settings_splunk_test(_user=Depends(get_current_user)):
        """v9.25 — Send a single canary event to the configured HEC.
        Useful for verifying URL + token work before enabling. Returns
        the notifier's result dict (sent / status / reason)."""
        from safecadence.settings import get_splunk_config
        from safecadence.notifier import notify_splunk_hec
        cfg = get_splunk_config(masked=False)
        if not cfg.get("hec_url") or not cfg.get("hec_token"):
            return {"sent": False,
                    "reason": "hec_url + hec_token must both be set"}
        return notify_splunk_hec(
            cfg["hec_url"], cfg["hec_token"],
            [{"kind": "canary",
                "message": "SafeCadence test event — config is working.",
                "ts": int(__import__("time").time())}],
            source=cfg.get("source") or "safecadence",
            sourcetype=cfg.get("sourcetype") or "safecadence:event",
            index=cfg.get("index") or None,
        )

    @app.get("/api/platform/shadow-it")
    def shadow_it_endpoint(_user=Depends(get_current_user)):
        """Run shadow-IT detection across the current platform inventory.

        Buckets every stored asset by its identity.discovery_source, runs
        merge_asset_groups, and returns the shadow-IT list.
        """
        from collections import defaultdict
        from safecadence.intel.asset_dedup import (
            merge_asset_groups, find_shadow_it, describe_dedup_result,
        )
        groups: dict[str, list[dict]] = defaultdict(list)
        for a in list_assets():
            src = ((a.get("identity") or {}).get("discovery_source")
                   or "unknown")
            groups[src].append(a)
        result = merge_asset_groups(dict(groups))
        shadow = find_shadow_it(result)
        return {
            "summary": describe_dedup_result(result),
            "counts_by_source": result.counts_by_source,
            "shadow_it_count": len(shadow),
            "shadow_it": [
                {"asset_id": c.asset_id, "hostname": c.hostname,
                 "primary_ip": c.primary_ip, "sources": c.sources,
                 "vendor": c.vendor, "asset_type": c.asset_type}
                for c in shadow],
        }

    # v9.2 — manual add device endpoint (used by /inventory "+ Add device" form)
    @app.post("/api/platform/asset")
    def create_asset_endpoint(body: dict = Body(...),
                              user=Depends(require_writer)):
        """Create or upsert one asset from a flat form payload.

        Required: hostname, asset_type, vendor.
        Optional: model, mgmt_ip, mgmt_url, site, environment, owner,
                  team, criticality, serial_number, notes, enrich_ai (bool).
        """
        import re
        from datetime import datetime, timezone
        b = dict(body or {})
        hostname = (b.get("hostname") or "").strip()
        asset_type = (b.get("asset_type") or "").strip().lower()
        vendor = (b.get("vendor") or "").strip().lower()
        if not hostname:
            raise HTTPException(400, detail="hostname is required")
        if not asset_type:
            raise HTTPException(400, detail="asset_type is required")
        if not vendor:
            raise HTTPException(400, detail="vendor is required")

        # asset_id = hostname slug, sanitized to allowed charset
        aid = re.sub(r"[^a-zA-Z0-9._\-]+", "-", hostname).strip("-")
        if not aid:
            raise HTTPException(400, detail="hostname produced empty asset_id")

        now = datetime.now(timezone.utc).isoformat()
        identity = {
            "asset_id": aid,
            "hostname": hostname,
            "asset_type": asset_type,
            "vendor": vendor,
            "model": (b.get("model") or "").strip(),
            "serial_number": (b.get("serial_number") or "").strip(),
            "site": (b.get("site") or "").strip(),
            "environment": (b.get("environment") or "").strip(),
            "owner": (b.get("owner") or "").strip(),
            "team": (b.get("team") or "").strip(),
            "criticality": (b.get("criticality") or "").strip(),
            "mgmt_ip": (b.get("mgmt_ip") or "").strip(),
            "mgmt_url": (b.get("mgmt_url") or "").strip(),
            "discovery_source": "manual",
            "tags": [],
            "custom_fields": {},
            "first_seen": now,
            "last_seen": now,
        }
        if b.get("notes"):
            identity["custom_fields"]["notes"] = str(b["notes"]).strip()

        asset = {"identity": identity}

        # Optional AI enrichment so the device gets role/criticality/tags.
        enriched_role = ""
        if b.get("enrich_ai"):
            try:
                from safecadence.intel.asset_enrichment import (
                    enrich_asset, merge_enrichment,
                )
                e = enrich_asset(asset)
                asset = merge_enrichment(asset, e)
                enriched_role = e.inferred_role or ""
            except Exception:
                pass

        try:
            save_asset(asset)
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc))
        return {"asset_id": aid, "saved": True,
                "enriched": bool(b.get("enrich_ai")),
                "enriched_role": enriched_role}

    @app.get("/api/platform/blast-radius/{start_asset_id}")
    def blast_radius_endpoint(start_asset_id: str, max_hops: int = 8,
                              _user=Depends(get_current_user)):
        from safecadence.platform.attack_paths import blast_radius
        return blast_radius(start_asset_id, list_assets(), max_hops=max_hops)

    @app.get("/api/platform/blast-radius/{start_asset_id}/viz",
             response_class=HTMLResponse)
    def blast_radius_viz_endpoint(start_asset_id: str, max_hops: int = 8,
                                   _user=Depends(get_current_user)):
        from safecadence.platform.attack_paths import blast_radius
        from safecadence.platform.attack_paths_viz import render_attack_path_viz
        br = blast_radius(start_asset_id, list_assets(), max_hops=max_hops)
        return HTMLResponse(render_attack_path_viz(
            br, title=f"Blast radius from {start_asset_id}"))

    @app.get("/api/platform/attack-paths-to/{target_asset_id}")
    def attack_paths_to_endpoint(target_asset_id: str, max_hops: int = 6,
                                 user=Depends(get_current_user)):
        # v10.0.0 — capability gate. Attack-path data exposes
        # identity-graph internals; require read.identity to align
        # with the rest of the v9.x capability sweep.
        from safecadence.capabilities import has_capability
        from fastapi import HTTPException
        if not has_capability(username=getattr(user, "username", ""),
                                roles=list(getattr(user, "roles", []) or []),
                                capability="read.identity",
                                tenant=getattr(user, "tenant", "default")):
            raise HTTPException(403,
                "Missing capability: read.identity")
        from safecadence.platform.attack_paths import attack_paths_to
        return {"target": target_asset_id,
                "paths": attack_paths_to(target_asset_id, list_assets(), max_hops=max_hops)}

    @app.get("/api/platform/top-attack-paths")
    def top_attack_paths_endpoint(k: int = 10, max_hops: int = 6,
                                  user=Depends(get_current_user)):
        """K shortest internet → crown-jewel paths, ranked by risk."""
        # v10.0.0 — capability gate (see attack_paths_to_endpoint).
        from safecadence.capabilities import has_capability
        from fastapi import HTTPException
        if not has_capability(username=getattr(user, "username", ""),
                                roles=list(getattr(user, "roles", []) or []),
                                capability="read.identity",
                                tenant=getattr(user, "tenant", "default")):
            raise HTTPException(403,
                "Missing capability: read.identity")
        from safecadence.platform.attack_paths import top_k_paths_to_crown_jewels
        return {"k": k, "max_hops": max_hops,
                "paths": top_k_paths_to_crown_jewels(
                    list_assets(), k=k, max_hops=max_hops)}

    # ---- v7.3: unified onboarding (CSV / discovery / cloud / manual) ----
    @app.get("/api/platform/import/csv-template",
              response_class=PlainTextResponse)
    def csv_template_endpoint(_user=Depends(get_current_user)):
        from fastapi.responses import PlainTextResponse as _PR
        from safecadence.onboarding import template_csv
        return _PR(template_csv(),
                    headers={"Content-Disposition":
                              'attachment; filename="safecadence-assets-template.csv"'})

    @app.post("/api/platform/import/csv-preview")
    def csv_preview_endpoint(body: dict = Body(...),
                              _user=Depends(get_current_user)):
        """Body: {csv: '...'} — parse + validate, return preview."""
        from safecadence.onboarding import parse_csv
        text = body.get("csv") or ""
        if not text.strip():
            raise HTTPException(400, detail="csv body is empty")
        from dataclasses import asdict as _ad
        result = parse_csv(text)
        return {
            "headers":     result.headers,
            "valid_count": result.valid_count,
            "error_count": result.error_count,
            "summary":     result.summary,
            "rows":        [_ad(r) for r in result.rows],
        }

    @app.post("/api/platform/import/csv-commit")
    def csv_commit_endpoint(body: dict = Body(...),
                              user=Depends(require_writer)):
        """Body: {csv: '...', overwrite: false}."""
        from safecadence.onboarding import parse_csv, commit_preview
        text = body.get("csv") or ""
        if not text.strip():
            raise HTTPException(400, detail="csv body is empty")
        preview = parse_csv(text)
        return commit_preview(preview,
                                overwrite=bool(body.get("overwrite")))

    @app.post("/api/platform/import/credentials-preview")
    def credentials_preview_endpoint(body: dict = Body(...),
                                       _user=Depends(get_current_user)):
        from safecadence.onboarding import parse_credentials_csv
        text = body.get("csv") or ""
        if not text.strip():
            raise HTTPException(400, detail="csv body is empty")
        return parse_credentials_csv(text)

    @app.post("/api/platform/import/credentials-commit")
    def credentials_commit_endpoint(body: dict = Body(...),
                                      user=Depends(require_writer)):
        from safecadence.onboarding import (
            parse_credentials_csv, commit_credentials_preview,
        )
        text = body.get("csv") or ""
        if not text.strip():
            raise HTTPException(400, detail="csv body is empty")
        preview = parse_credentials_csv(text)
        return commit_credentials_preview(preview,
                                            overwrite=bool(body.get("overwrite")))

    @app.get("/api/platform/evidence-pack")
    def evidence_pack_endpoint(framework: str = "pci",
                                  _user=Depends(get_current_user)):
        """v7.2 — Generate a SOC 2 / PCI / HIPAA / NIST / ISO / Zero
        Trust evidence pack PDF for an auditor."""
        from fastapi.responses import Response
        from safecadence.evidence_pack import generate
        pdf = generate(framework)
        return Response(content=pdf, media_type="application/pdf",
                         headers={"Content-Disposition":
                            f'attachment; filename="safecadence-{framework}-evidence.pdf"'})

    @app.post("/api/platform/digest/send")
    def digest_send_endpoint(_user=Depends(get_current_user)):
        """v7.2 — fire the digest email now (test from the UI)."""
        from safecadence.digest import send
        return send()

    @app.get("/api/platform/digest/preview")
    def digest_preview_endpoint(_user=Depends(get_current_user)):
        from safecadence.digest import build_digest, render_text
        d = build_digest()
        return {"text": render_text(d), "data": d}

    # ---- v7.4: SSO (OIDC + SAML stub) ------------------------------ #
    @app.get("/api/auth/oidc/login")
    def oidc_login_endpoint(redirect_after: str = ""):
        """Redirect the browser to the configured IdP."""
        from fastapi.responses import RedirectResponse
        from safecadence.sso import load_config, oidc_login_url
        cfg = load_config()
        if not cfg.enabled or cfg.flow != "oidc":
            raise HTTPException(404, detail="OIDC SSO is not configured")
        try:
            url = oidc_login_url(cfg, redirect_after=redirect_after)
        except Exception as e:
            raise HTTPException(500, detail=f"OIDC login init failed: {e}")
        return RedirectResponse(url=url)

    @app.get("/api/auth/oidc/callback")
    def oidc_callback_endpoint(code: str = Query(...),
                                  state: str = Query(...)):
        """Token exchange + ID-token verify + JWT issuance."""
        from safecadence.sso import load_config, oidc_callback
        cfg = load_config()
        if not cfg.enabled or cfg.flow != "oidc":
            raise HTTPException(404, detail="OIDC SSO is not configured")
        try:
            result = oidc_callback(cfg, code=code, state=state)
        except Exception as e:
            raise HTTPException(403, detail=f"OIDC callback failed: {e}")
        # Mint a SafeCadence JWT for the user. Load the same secret
        # create_app() persisted so the issued token validates on the
        # next request just like a username/password login.
        #
        # v9.56.1 — fixed precedence. Pre-v9.56.1 the loader read as:
        #     (env_var or file_read) IF file_exists ELSE None
        # which meant SC_JWT_SECRET was IGNORED unless the file
        # already existed — surprising and wrong for fresh installs
        # where the env var IS the secret. The correct precedence is
        # env first, file fallback, fail loud if neither.
        from safecadence.server.auth import CurrentUser, make_jwt
        from pathlib import Path as _P
        import os as _os
        _sec = _os.environ.get("SC_JWT_SECRET", "").strip() or None
        if not _sec:
            _secret_file = _P.home() / ".safecadence" / "jwt_secret"
            if _secret_file.exists():
                try:
                    _sec = _secret_file.read_text(encoding="utf-8").strip() or None
                except OSError:                             # pragma: no cover
                    _sec = None
        if not _sec:
            raise HTTPException(500, detail="JWT secret not initialised")
        user = CurrentUser(username=result["username"],
                            tenant=result["tenant"],
                            roles=[result["role"]])
        token = make_jwt(user, secret=_sec, ttl_minutes=480)
        # v9.54 — apply IdP-group → capability auto-grant. Best-effort:
        # if the capability_map is empty or the reconcile fails for
        # any reason, the login still succeeds. The reconcile failure
        # is logged via _emit_activity inside grant/revoke, so the
        # security team will see it on /audit even if the user doesn't.
        cap_summary = {"granted": [], "revoked": [], "unchanged": [],
                       "wanted": result.get("capabilities", []) or []}
        try:
            from safecadence.capabilities.store import (
                reconcile_sso_grants,
            )
            cap_summary = reconcile_sso_grants(
                username=user.username,
                tenant=user.tenant,
                wanted=result.get("capabilities") or [],
                actor=f"oidc:{cfg.oidc_issuer or 'unknown-issuer'}",
                reason=f"login by {user.username}",
            )
        except Exception:                                   # pragma: no cover
            pass
        return {"access_token": token, "token_type": "bearer",
                "username": user.username, "role": result["role"],
                "tenant": user.tenant,
                "capabilities": cap_summary,
                "redirect_after": result.get("redirect_after", "")}

    @app.get("/api/auth/saml/metadata",
              response_class=PlainTextResponse)
    def saml_metadata_endpoint():
        """SP metadata XML — IdP admin uploads this to configure SafeCadence."""
        from safecadence.sso import load_config, saml_sp_metadata
        cfg = load_config()
        try:
            return saml_sp_metadata(cfg)
        except ValueError as e:
            raise HTTPException(409, detail=str(e))

    @app.get("/api/auth/saml/login")
    def saml_login_endpoint(relay_state: str = ""):
        """Redirect to the IdP with an AuthnRequest. v7.5 ships full
        response validation; v7.4 only ships the redirect."""
        from fastapi.responses import RedirectResponse
        from safecadence.sso import load_config, saml_authn_request
        cfg = load_config()
        try:
            url = saml_authn_request(cfg, relay_state=relay_state)
        except ValueError as e:
            raise HTTPException(409, detail=str(e))
        return RedirectResponse(url=url)

    @app.post("/api/auth/saml/acs")
    def saml_acs_endpoint(SAMLResponse: str = Query(...)):
        from safecadence.sso import saml_consume_response, load_config
        try:
            saml_consume_response(load_config(),
                                    saml_response_b64=SAMLResponse)
        except NotImplementedError as e:
            raise HTTPException(501, detail=str(e))

    @app.get("/api/platform/license")
    def license_status_endpoint(_user=Depends(get_current_user)):
        """v7.1 — license status (counts, expiry, features, tenants)."""
        from dataclasses import asdict as _ad
        from safecadence.license import status as _status
        assets = list_assets()
        return _ad(_status(asset_count=len(assets)))

    # v10.0.0 — shared capability gate for topology endpoints.
    # Topology data is "view assets" → read.asset (in viewer floor).
    def _require_read_asset(user=Depends(get_current_user)):
        from safecadence.capabilities import has_capability
        from fastapi import HTTPException
        if not has_capability(username=getattr(user, "username", ""),
                                roles=list(getattr(user, "roles", []) or []),
                                capability="read.asset",
                                tenant=getattr(user, "tenant", "default")):
            raise HTTPException(403, "Missing capability: read.asset")
        return user

    @app.get("/api/platform/topology/{view}")
    def topology_view_endpoint(view: str,
                                 _user=Depends(_require_read_asset)):
        """v7.1 — return a Cytoscape.js payload for one of 9 named views."""
        from safecadence.platform.topology_views import render
        return render(view, list_assets())

    # v9.13 — geographic / multi-site topology (default for /topology).
    # Aggregates assets per site, infers WAN links, returns one node per
    # site with health rollup + asset count + type breakdown.
    @app.get("/api/platform/topology-sites")
    def topology_sites_endpoint(_user=Depends(_require_read_asset)):
        from safecadence.platform.physical_topology import build_site_graph
        return build_site_graph(list_assets())

    # v9.14 — Christmas-tree hierarchy: Internet → firewall → edge →
    # core → distribution → access → endpoints, with identity & cloud
    # side rails. Auto-classifies devices by role tags + hostname.
    @app.get("/api/platform/topology-xmas")
    def topology_xmas_endpoint(_user=Depends(_require_read_asset)):
        from safecadence.platform.physical_topology import build_xmas_tree
        return build_xmas_tree(list_assets())

    # v9.9 — unified topology with physical L2 + logical + identity + cloud
    # layers, each edge tagged so the UI can toggle visibility client-side.
    @app.get("/api/platform/topology-unified")
    def topology_unified_endpoint(
        physical: bool = True,
        logical: bool = True,
        identity: bool = True,
        cloud: bool = True,
        _user=Depends(_require_read_asset),
    ):
        from safecadence.platform.physical_topology import build_unified_graph
        return build_unified_graph(
            list_assets(),
            include_physical=physical,
            include_logical=logical,
            include_identity=identity,
            include_cloud=cloud,
        )

    @app.get("/api/platform/adapter-manifest")
    def adapter_manifest_endpoint(_user=Depends(get_current_user)):
        """Truthful adapter classification (production / experimental / stub).

        Surfaces the inflated 45-adapter marketing claim as the actual
        ~10 production / ~14 experimental / ~26 stub split, so operators
        can size deployments honestly.
        """
        from safecadence.adapter_manifest import manifest
        return manifest()

    @app.post("/api/platform/load-demo")
    def load_demo_endpoint(overwrite: bool = False,
                           user=Depends(require_writer)):
        """Materialise the v6.3 demo fleet — 30 realistic fake assets."""
        from safecadence.demo import load_demo_fleet
        return load_demo_fleet(overwrite=overwrite)

    # ---- v6.4 — asset groups ---- #
    @app.get("/api/platform/asset-groups")
    def asset_groups_list(_user=Depends(get_current_user)):
        from safecadence.policy.asset_groups import list_groups, resolve_members
        from dataclasses import asdict as _ad
        groups = list_groups()
        all_assets = list_assets()
        out = []
        for g in groups:
            members = resolve_members(g, all_assets)
            row = _ad(g)
            row["member_count"] = len(members)
            out.append(row)
        return {"groups": out, "total": len(out)}

    @app.post("/api/platform/asset-groups")
    def asset_groups_create(body: dict = Body(...),
                            user=Depends(require_writer)):
        from safecadence.policy.asset_groups import (
            AssetGroup, save, validate_group, get,
        )
        gid = body.get("group_id") or ""
        if get(gid) is not None:
            raise HTTPException(status_code=409,
                                detail=f"asset group '{gid}' already exists")
        g = AssetGroup(
            group_id=gid,
            name=body.get("name", ""),
            description=body.get("description", ""),
            asset_ids=body.get("asset_ids") or [],
            filter=body.get("filter") or {},
            exclude_asset_ids=body.get("exclude_asset_ids") or [],
            tenant=getattr(user, "tenant", "local"),
        )
        errs = validate_group(g)
        if errs:
            raise HTTPException(status_code=400, detail="; ".join(errs))
        save(g)
        return {"saved": True, "group_id": g.group_id}

    @app.get("/api/platform/asset-groups/{group_id}")
    def asset_group_detail(group_id: str,
                           _user=Depends(get_current_user)):
        from safecadence.policy.asset_groups import get, resolve_members
        from dataclasses import asdict as _ad
        g = get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="asset group not found")
        members = resolve_members(g, list_assets())
        return {**_ad(g),
                "member_count": len(members),
                "members": [(a.get("identity") or {}).get("asset_id")
                            for a in members]}

    @app.put("/api/platform/asset-groups/{group_id}")
    def asset_group_update(group_id: str, body: dict = Body(...),
                            user=Depends(require_writer)):
        from safecadence.policy.asset_groups import (
            get, save, validate_group,
        )
        g = get(group_id)
        if not g:
            raise HTTPException(status_code=404, detail="asset group not found")
        for k in ("name", "description", "asset_ids", "filter",
                   "exclude_asset_ids"):
            if k in body:
                setattr(g, k, body[k])
        errs = validate_group(g)
        if errs:
            raise HTTPException(status_code=400, detail="; ".join(errs))
        save(g)
        return {"saved": True, "group_id": g.group_id}

    @app.delete("/api/platform/asset-groups/{group_id}")
    def asset_group_delete(group_id: str,
                            user=Depends(require_writer)):
        from safecadence.policy.asset_groups import delete as _del
        ok = _del(group_id)
        if not ok:
            raise HTTPException(status_code=404, detail="asset group not found")
        return {"deleted": True, "group_id": group_id}

    @app.post("/api/platform/asset-groups/preview")
    def asset_group_preview(body: dict = Body(...),
                             _user=Depends(get_current_user)):
        """Dry-run a filter spec WITHOUT saving — for the builder UI."""
        from safecadence.policy.asset_groups import (
            AssetGroup, resolve_members, validate_group,
        )
        g = AssetGroup(
            group_id="__preview__",
            name="preview",
            asset_ids=body.get("asset_ids") or [],
            filter=body.get("filter") or {},
            exclude_asset_ids=body.get("exclude_asset_ids") or [],
        )
        # Skip group_id validation but keep filter validation
        errs = [e for e in validate_group(g)
                if "group_id" not in e and "name" not in e]
        if errs:
            raise HTTPException(status_code=400, detail="; ".join(errs))
        members = resolve_members(g, list_assets())
        return {
            "member_count": len(members),
            "members": [(a.get("identity") or {}).get("asset_id")
                         for a in members][:200],
        }

    @app.get("/api/platform/ui", response_class=HTMLResponse)
    def platform_ui_page(user=Depends(get_current_user)):
        from safecadence.ui.platform_ui import render_platform_ui
        return HTMLResponse(render_platform_ui(tenant=getattr(user, "tenant", "local")))

    @app.get("/api/platform/inventory")
    def inventory(asset_type: Optional[str] = None, vendor: Optional[str] = None,
                  user=Depends(get_current_user)):
        return {"assets": list_assets(asset_type=asset_type, vendor=vendor)}

    @app.get("/api/platform/asset/{asset_id}")
    def asset_detail(asset_id: str, user=Depends(get_current_user)):
        a = get_asset(asset_id)
        if not a:
            raise HTTPException(status_code=404, detail=f"asset not found: {asset_id}")
        return a

    # v9.12 — edit one asset's identity / custom_fields / tags in place
    @app.put("/api/platform/asset/{asset_id}")
    def asset_update_endpoint(asset_id: str, body: dict = Body(...),
                              user=Depends(require_writer)):
        """Patch the identity block of an existing asset. Whitelisted
        fields only; raw_collection / interfaces / etc. stay untouched."""
        a = get_asset(asset_id)
        if not a:
            raise HTTPException(404, detail=f"asset not found: {asset_id}")
        ident = a.setdefault("identity", {})
        editable = ("hostname", "asset_type", "vendor", "model",
                    "serial_number", "site", "environment", "owner",
                    "team", "criticality", "mgmt_ip", "mgmt_url",
                    "discovery_source")
        for k in editable:
            if k in body and body[k] is not None:
                ident[k] = (body[k] or "").strip() if isinstance(body[k], str) else body[k]
        if "tags" in body and isinstance(body["tags"], list):
            ident["tags"] = [str(t).strip() for t in body["tags"] if str(t).strip()]
        if "custom_fields" in body and isinstance(body["custom_fields"], dict):
            cf = ident.setdefault("custom_fields", {})
            for k, v in body["custom_fields"].items():
                cf[str(k)] = v
        from datetime import datetime, timezone
        ident["last_modified"] = datetime.now(timezone.utc).isoformat()
        save_asset(a)
        return {"saved": True, "asset_id": asset_id}

    # v10.4 — single-field inline edit (double-click cell on inventory)
    @app.post("/api/platform/asset/{asset_id}/field")
    def asset_update_field(asset_id: str, body: dict = Body(...),
                           user=Depends(require_writer)):
        """Patch a single whitelisted identity field. Backs the inventory
        double-click inline editor. Same allowlist + persistence as the
        full PUT endpoint above; just narrower so the UI doesn't have to
        send the whole identity blob."""
        field = (body or {}).get("field")
        value = (body or {}).get("value")
        editable = {"owner", "site", "criticality", "team", "environment",
                    "vendor", "model", "mgmt_ip", "mgmt_url"}
        if field not in editable:
            raise HTTPException(400, detail=f"field not editable: {field!r}")
        a = get_asset(asset_id)
        if not a:
            raise HTTPException(404, detail=f"asset not found: {asset_id}")
        ident = a.setdefault("identity", {})
        if isinstance(value, str):
            value = value.strip()
        ident[field] = value
        from datetime import datetime, timezone
        ident["last_modified"] = datetime.now(timezone.utc).isoformat()
        save_asset(a)
        return {"saved": True, "asset_id": asset_id, "field": field, "value": value}

    # v10.4 — inventory XLSX export (server-side rendering via stdlib zip)
    @app.post("/api/platform/inventory/xlsx")
    def inventory_xlsx_endpoint(body: dict = Body(...),
                                _user=Depends(get_current_user)):
        """Render a {headers, rows} payload to an .xlsx workbook and
        return raw bytes with the right Content-Type so the browser
        downloads it. Read-only — no asset mutation."""
        from fastapi.responses import Response
        try:
            from safecadence.reports.renderers import render_inventory_xlsx
        except Exception as e:                              # pragma: no cover
            raise HTTPException(500, detail=f"xlsx renderer unavailable: {e}")
        headers = list((body or {}).get("headers") or [])
        rows = list((body or {}).get("rows") or [])
        data = render_inventory_xlsx(headers, rows)
        return Response(
            content=data,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="inventory.xlsx"'},
        )

    # v9.12 — delete an asset (with optional purge of policy targeting)
    @app.delete("/api/platform/asset/{asset_id}")
    def asset_delete_endpoint(asset_id: str,
                              user=Depends(require_writer)):
        """Delete one asset. Best-effort across Postgres + file-backed."""
        ok = False
        try:
            from safecadence import storage_pg
            if storage_pg.is_enabled():
                ok = storage_pg.delete_asset(asset_id)
        except Exception:                                # pragma: no cover
            pass
        if not ok:
            try:
                f = _safe_asset_path(asset_id)
                if f.exists():
                    f.unlink(); ok = True
            except Exception:
                pass
        if not ok:
            raise HTTPException(404, detail=f"asset not found: {asset_id}")
        return {"deleted": True, "asset_id": asset_id}

    # v9.12 — group membership management (add/remove static members).
    # The existing /api/platform/asset-groups endpoints already do create
    # + read + filter-based membership; this fills in the explicit-list
    # add/remove that the inventory bulk-select UI uses.
    @app.post("/api/platform/asset-groups/{group_id}/members")
    def asset_group_add_members(group_id: str, body: dict = Body(...),
                                user=Depends(require_writer)):
        from safecadence.policy.asset_groups import get, save
        g = get(group_id)
        if not g:
            raise HTTPException(404, detail=f"group not found: {group_id}")
        ids = list(body.get("asset_ids") or [])
        if not ids:
            raise HTTPException(400, detail="asset_ids required")
        existing = set(g.asset_ids or [])
        added = [i for i in ids if i not in existing]
        g.asset_ids = list(existing | set(ids))
        save(g)
        return {"saved": True, "added": added, "total": len(g.asset_ids)}

    @app.delete("/api/platform/asset-groups/{group_id}/members/{asset_id}")
    def asset_group_remove_member(group_id: str, asset_id: str,
                                  user=Depends(require_writer)):
        from safecadence.policy.asset_groups import get, save
        g = get(group_id)
        if not g:
            raise HTTPException(404, detail=f"group not found: {group_id}")
        if asset_id in (g.asset_ids or []):
            g.asset_ids = [i for i in g.asset_ids if i != asset_id]
            save(g)
            return {"removed": True, "remaining": len(g.asset_ids)}
        return {"removed": False, "reason": "not in static member list"}

    @app.delete("/api/platform/asset-groups/{group_id}")
    def asset_group_delete(group_id: str, user=Depends(require_writer)):
        from safecadence.policy.asset_groups import delete
        if not delete(group_id):
            raise HTTPException(404, detail=f"group not found: {group_id}")
        return {"deleted": True, "group_id": group_id}

    # v9.2 — config snapshot for the cockpit "Take config snapshot" action
    @app.post("/api/platform/asset/{asset_id}/snapshot")
    def asset_snapshot_endpoint(asset_id: str,
                                 user=Depends(require_writer)):
        """Save the current running config as a timestamped snapshot in
        the asset's raw_collection.snapshots[] array."""
        from datetime import datetime, timezone
        a = get_asset(asset_id)
        if not a:
            raise HTTPException(status_code=404, detail=f"asset not found: {asset_id}")
        raw = a.setdefault("raw_collection", {})
        cfg = raw.get("running") or raw.get("config") or raw.get("startup") or ""
        if not cfg:
            raise HTTPException(409, detail="no running config to snapshot")
        snaps = raw.setdefault("snapshots", [])
        ts = datetime.now(timezone.utc).isoformat()
        snaps.append({"timestamp": ts, "bytes": len(cfg), "config": cfg})
        # Cap history at last 20 snapshots to keep storage bounded.
        if len(snaps) > 20:
            raw["snapshots"] = snaps[-20:]
        save_asset(a)
        return {"saved": True, "timestamp": ts, "bytes": len(cfg),
                "total_snapshots": len(raw["snapshots"])}

    @app.get("/api/platform/servers")
    def servers(user=Depends(get_current_user)):
        a = list_assets(asset_type="server")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/storage")
    def storage(user=Depends(get_current_user)):
        a = list_assets(asset_type="storage")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/virtualization")
    def virtualization(user=Depends(get_current_user)):
        a = list_assets(asset_type="hypervisor")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/network")
    def network(user=Depends(get_current_user)):
        a = list_assets(asset_type="network")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/cloud")
    def cloud(user=Depends(get_current_user)):
        a = list_assets(asset_type="cloud")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/backup")
    def backup(user=Depends(get_current_user)):
        a = list_assets(asset_type="backup")
        return {"summary": _summarize(a), "assets": a}

    @app.get("/api/platform/health")
    def health_overview(user=Depends(get_current_user)):
        all_assets = list_assets()
        domain_summaries = {
            d: _summarize(list_assets(asset_type=d))
            for d in ("server", "storage", "hypervisor", "network", "cloud", "backup")
        }
        return {"total": len(all_assets), "domains": domain_summaries}

    @app.get("/api/platform/lifecycle")
    def lifecycle(within_days: int = Query(365, ge=0, le=3650),
                  user=Depends(get_current_user)):
        out = []
        for a in list_assets():
            lc = a.get("lifecycle") or {}
            days = lc.get("days_until_eos")
            if isinstance(days, (int, float)) and 0 <= days <= within_days:
                out.append({
                    "asset_id": (a.get("identity") or {}).get("asset_id"),
                    "vendor": (a.get("identity") or {}).get("vendor"),
                    "model": (a.get("identity") or {}).get("model"),
                    "asset_type": (a.get("identity") or {}).get("asset_type"),
                    "days_until_eos": days,
                    "eos_date": lc.get("eos_date", ""),
                    "warranty_status": lc.get("warranty_status", ""),
                })
        out.sort(key=lambda x: x["days_until_eos"])
        return {"window_days": within_days, "at_risk": out}

    # IMPORTANT: static `/correlate/orphans` MUST come BEFORE the
    # `/correlate/{asset_id}` catch-all, otherwise FastAPI matches the latter
    # first and treats "orphans" as an asset_id (returns 404).
    @app.get("/api/platform/correlate/orphans")
    def correlate_orphans(user=Depends(get_current_user)):
        from safecadence.platform.correlation import find_orphans
        return {"orphans": find_orphans(list_assets())}

    @app.get("/api/platform/correlate/{asset_id}")
    def correlate(asset_id: str, user=Depends(get_current_user)):
        from safecadence.platform.correlation import build_dependency_chain
        a = get_asset(asset_id)
        if not a:
            raise HTTPException(status_code=404, detail=f"asset not found: {asset_id}")
        return build_dependency_chain(a, list_assets())

    @app.get("/api/platform/reports")
    def list_reports(user=Depends(get_current_user)):
        from safecadence.reports.platform_reports import REPORT_REGISTRY
        return {"reports": [{"id": k, "title": v["title"], "description": v["description"]}
                            for k, v in REPORT_REGISTRY.items()]}

    @app.get("/api/platform/reports/{report_id}")
    def run_report(report_id: str, user=Depends(get_current_user)):
        from safecadence.reports.platform_reports import REPORT_REGISTRY
        if report_id not in REPORT_REGISTRY:
            raise HTTPException(status_code=404, detail=f"unknown report: {report_id}")
        return REPORT_REGISTRY[report_id]["fn"](list_assets())
