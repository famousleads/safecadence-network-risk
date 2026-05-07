"""
v7.9 — REST API for the intel modules.

  POST /api/intel/ask                  — AI assistant
  POST /api/intel/briefing             — generate briefing
  GET  /api/intel/timeline             — timeline events
  GET  /api/intel/watchlists           — list watches
  POST /api/intel/watchlists           — add watch
  DELETE /api/intel/watchlists/{id}    — remove watch
  GET  /api/intel/comments             — list (filterable)
  POST /api/intel/comments             — add comment
  POST /api/intel/assignments          — assign
  GET  /api/intel/assignments          — list
  POST /api/intel/assignments/{id}/status  — update
  GET  /api/intel/automation/rules     — list rules
  POST /api/intel/automation/rules     — save rule
  DELETE /api/intel/automation/rules/{id}  — delete rule
  POST /api/intel/automation/preview   — preview which rules would fire
"""

from __future__ import annotations

from dataclasses import asdict


def register(app, get_current_user, require_writer):
    from fastapi import Body, Depends, HTTPException, Query, Request

    # ---------------- AI assistant (v9.56 hardening) ----------------
    #
    # Pre-v9.56 this endpoint was authenticated but capability-free —
    # any viewer-tier user could dump the fleet snapshot to a third-
    # party LLM. v9.56 layers three defenses:
    #
    #   1. Capability gate: requires READ_ASSET + READ_FINDING
    #      (already in the viewer floor — no behavior change for
    #      well-configured tenants, but tenants that revoked
    #      these per-user now correctly block /ask).
    #
    #   2. Per-user rate limit: token-bucket keyed on username +
    #      remote IP. Default 10 questions per 60s; overridable via
    #      env. Catches both runaway scripts and malicious abuse
    #      that would otherwise burn the API budget.
    #
    #   3. Audit row: question hash + provider + used_ai land in the
    #      activity log's `extra` so a year from now an auditor can
    #      ask "show me every ask call alice made in March."
    #
    # The deterministic-fallback path is unaffected — those answers
    # don't leave the box. We still rate-limit it because the
    # snapshot build is non-trivial on a 1000-asset fleet.
    _ASK_BUCKET: dict = {}        # (user, ip) -> [timestamps]

    @app.post("/api/intel/ask")
    def intel_ask(body: dict = Body(...), request: Request = None,
                    user=Depends(get_current_user)):
        from safecadence.intel.ai_assistant import (
            ask_assistant, MAX_QUESTION_CHARS,
        )
        from safecadence.capabilities import has_capability
        import hashlib
        import os
        import time

        q = (body.get("question") or "").strip()
        if not q:
            raise HTTPException(400, "question is required")
        if len(q) > MAX_QUESTION_CHARS:
            raise HTTPException(
                413,
                f"question too long ({len(q)} chars; cap {MAX_QUESTION_CHARS})",
            )

        # --- v9.56 #2: capability gate -----------------------------------
        uname = getattr(user, "username", "")
        roles = list(getattr(user, "roles", []) or [])
        tenant = getattr(user, "tenant", "default")
        for cap in ("read.asset", "read.finding"):
            if not has_capability(username=uname, roles=roles,
                                    capability=cap, tenant=tenant):
                raise HTTPException(
                    403,
                    f"Missing capability: {cap}. /ask sends "
                    "fleet data to an LLM; both read.asset and "
                    "read.finding are required."
                )

        # --- v9.56 #3: token-bucket rate limit ----------------------------
        # Keyed on (username, client_ip). 60-second window, default
        # 10 calls. Pre-1.0 implementation: prune old entries +
        # check len < N. Good enough for now; swap for redis if
        # ever multi-process.
        try:
            window = int(os.environ.get("SC_ASK_RATE_WINDOW_SEC", "60") or "60")
            limit = int(os.environ.get("SC_ASK_RATE_LIMIT", "10") or "10")
        except ValueError:
            window, limit = 60, 10
        ip = (request.client.host if request and request.client
                else "unknown")
        key = (uname or "anonymous", ip)
        now = time.time()
        timestamps = [t for t in _ASK_BUCKET.get(key, []) if now - t < window]
        if len(timestamps) >= limit:
            retry_after = int(window - (now - timestamps[0]))
            raise HTTPException(
                429,
                f"rate limit ({limit}/{window}s) — retry in "
                f"{max(1, retry_after)}s",
            )
        timestamps.append(now)
        _ASK_BUCKET[key] = timestamps

        ans = ask_assistant(q)

        # --- v9.56 #7: audit row -----------------------------------------
        # Question is hashed (SHA256, first 16 hex chars) so the
        # activity log captures provenance without storing the
        # plaintext question — which might contain sensitive
        # context the operator typed in. Provider + used_ai go in
        # plain because they're not sensitive.
        try:
            from safecadence.activity import append, ActivityRecord
            from datetime import datetime, timezone
            qhash = hashlib.sha256(q.encode("utf-8")).hexdigest()[:16]
            append(ActivityRecord(
                ts=datetime.now(timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z"),
                actor=uname or "anonymous",
                tenant=tenant or "default",
                method="POST", path="/api/intel/ask",
                status=200, ip=ip, duration_ms=0,
                request_id=f"ask_{int(now * 1000)}",
                extra={
                    "question_sha256_16": qhash,
                    "question_len": len(q),
                    "used_ai": ans.used_ai,
                    "fallback_reason": ans.fallback_reason or "",
                    "cited_count": len(ans.cited or []),
                },
            ))
        except Exception:                               # pragma: no cover
            # Never fail the user request because audit failed.
            pass

        return {
            "answer": ans.text, "cited": ans.cited,
            "used_ai": ans.used_ai, "fallback_reason": ans.fallback_reason,
        }

    # ---------------- Briefing --------------------
    @app.post("/api/intel/briefing")
    def intel_briefing(body: dict = Body(default={}),
                         user=Depends(get_current_user)):
        from safecadence.intel.briefing import build_briefing, render_text
        b = build_briefing(user=getattr(user, "username", "default"))
        return {
            "briefing": asdict(b),
            "text": render_text(b),
        }

    # ---------------- Timeline --------------------
    @app.get("/api/intel/timeline")
    def intel_timeline(since_seconds: int = 7 * 86400,
                        kinds: str = "",
                        entity_id: str = "",
                        limit: int = 200,
                        user=Depends(get_current_user)):
        from safecadence.intel.timeline import build_timeline
        events = build_timeline(
            since_seconds=since_seconds,
            kinds=[k for k in kinds.split(",") if k] or None,
            entity_id=entity_id or None,
            limit=limit,
        )
        return {"count": len(events),
                "events": [
                    {"timestamp": e.timestamp, "kind": e.kind,
                      "entity_kind": e.entity_kind, "entity_id": e.entity_id,
                      "actor": e.actor, "summary": e.summary,
                      "severity": e.severity}
                    for e in events
                ]}

    # ---------------- Watchlists ------------------
    @app.get("/api/intel/watchlists")
    def intel_watch_list(user=Depends(get_current_user)):
        from safecadence.intel.watchlists import list_watches
        return {"watches": [asdict(w) for w in list_watches(
            user=getattr(user, "username", "default"))]}

    @app.post("/api/intel/watchlists")
    def intel_watch_add(body: dict = Body(...),
                          user=Depends(require_writer)):
        from safecadence.intel.watchlists import add_watch
        try:
            w = add_watch(
                entity_kind=body["entity_kind"],
                entity_id=body["entity_id"],
                label=body.get("label", ""),
                user=getattr(user, "username", "default"),
            )
        except KeyError as e:
            raise HTTPException(400, f"missing field: {e}")
        return asdict(w)

    @app.delete("/api/intel/watchlists/{watch_id}")
    def intel_watch_del(watch_id: str,
                          user=Depends(require_writer)):
        from safecadence.intel.watchlists import remove_watch
        ok = remove_watch(watch_id,
                           user=getattr(user, "username", "default"))
        return {"removed": ok}

    # ---------------- Comments + assignments -----
    @app.get("/api/intel/comments")
    def intel_comment_list(entity_kind: str = "",
                             entity_id: str = "",
                             user=Depends(get_current_user)):
        from safecadence.intel.comments import list_comments
        return {"comments": [
            asdict(c) for c in list_comments(
                entity_kind=entity_kind or None,
                entity_id=entity_id or None,
            )
        ]}

    @app.post("/api/intel/comments")
    def intel_comment_add(body: dict = Body(...),
                            user=Depends(require_writer)):
        from safecadence.intel.comments import add_comment
        try:
            c = add_comment(
                entity_kind=body["entity_kind"], entity_id=body["entity_id"],
                user=getattr(user, "username", "anonymous"),
                text=body["text"],
                parent_comment_id=body.get("parent_comment_id", ""),
            )
        except KeyError as e:
            raise HTTPException(400, f"missing field: {e}")
        return asdict(c)

    @app.post("/api/intel/assignments")
    def intel_assign(body: dict = Body(...),
                       user=Depends(require_writer)):
        from safecadence.intel.comments import assign
        try:
            a = assign(
                entity_kind=body["entity_kind"], entity_id=body["entity_id"],
                assigned_to=body["assigned_to"],
                assigned_by=getattr(user, "username", "system"),
                note=body.get("note", ""),
            )
        except KeyError as e:
            raise HTTPException(400, f"missing field: {e}")
        return asdict(a)

    @app.get("/api/intel/assignments")
    def intel_assign_list(assigned_to: str = "",
                            status: str = "",
                            user=Depends(get_current_user)):
        from safecadence.intel.comments import list_assignments
        return {"assignments": [
            asdict(a) for a in list_assignments(
                assigned_to=assigned_to or None,
                status=status or None,
            )
        ]}

    @app.post("/api/intel/assignments/{assignment_id}/status")
    def intel_assign_status(assignment_id: str,
                              body: dict = Body(...),
                              user=Depends(require_writer)):
        from safecadence.intel.comments import update_assignment
        try:
            a = update_assignment(assignment_id, status=body.get("status", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        if a is None:
            raise HTTPException(404, "assignment not found")
        return asdict(a)

    # ---------------- Automation -----------------
    # v9.55 — write paths gated by the existing v9.48 WRITE_AUTOMATION
    # capability instead of the legacy v7.x require_writer role check.
    # The capability is in the analyst floor so existing analyst-tier
    # users keep working without admin intervention; operators can
    # also revoke it per-user via /users#capabilities for high-trust
    # tenants where automation rules should be admin-only.
    def _require_write_automation(user=Depends(get_current_user)):
        from safecadence.capabilities import has_capability
        if not has_capability(username=getattr(user, "username", ""),
                                roles=list(getattr(user, "roles", []) or []),
                                capability="write.automation",
                                tenant=getattr(user, "tenant", "default")):
            raise HTTPException(
                status_code=403,
                detail=("Missing capability: write.automation. An admin "
                        "can grant it via /users#caps."),
            )
        return user

    @app.get("/api/intel/automation/rules")
    def intel_auto_list(user=Depends(get_current_user)):
        from safecadence.intel.automation import list_rules
        return {"rules": [asdict(r) for r in list_rules()]}

    @app.post("/api/intel/automation/rules")
    def intel_auto_save(body: dict = Body(...),
                          user=Depends(_require_write_automation)):
        from safecadence.intel.automation import save_rule
        r = save_rule(body)
        return asdict(r)

    @app.delete("/api/intel/automation/rules/{rule_id}")
    def intel_auto_del(rule_id: str,
                         user=Depends(_require_write_automation)):
        from safecadence.intel.automation import delete_rule
        return {"deleted": delete_rule(rule_id)}

    @app.post("/api/intel/automation/preview")
    def intel_auto_preview(user=Depends(get_current_user)):
        """Preview what would fire right now without applying."""
        from safecadence.intel.automation import evaluate_rules
        from safecadence.identity.findings import scan_findings
        try:
            from safecadence.server.platform_api import list_assets
            assets = list_assets()
        except Exception:
            assets = []
        findings = scan_findings(assets)
        fires = evaluate_rules(findings, apply_actions=False)
        return {"would_fire": len(fires), "fires": fires}

    # v9.55 — historical fires endpoint (no equivalent of audit-log
    # CSV export, but at least surfaces the last 500 stored fires
    # so the /automation page can show recent history without the
    # user needing to grep automation.json).
    @app.get("/api/intel/automation/fires")
    def intel_auto_fires(limit: int = 100,
                            user=Depends(get_current_user)):
        from safecadence.intel._store import read
        try:
            n = max(1, min(int(limit), 500))
        except (TypeError, ValueError):
            n = 100
        data = read("automation", {"rules": [], "fires": []})
        fires = list(data.get("fires") or [])
        # newest first
        fires = sorted(fires, key=lambda f: f.get("at", 0), reverse=True)
        return {"count": len(fires), "fires": fires[:n]}

    # ---------------- v9.1: asset enrichment -----
    @app.post("/api/intel/enrich/{asset_id}")
    def intel_enrich(asset_id: str,
                       merge: bool = False,
                       user=Depends(get_current_user)):
        """Compute enrichment for one asset. Returns the structured
        Enrichment + (optionally) merges suggested tags + ai_* custom
        fields into the stored asset."""
        from safecadence.intel.asset_enrichment import (
            enrich_asset, merge_enrichment,
        )
        from safecadence.server.platform_api import (
            list_assets, save_asset,
        )
        try:
            assets = list_assets()
        except Exception:
            assets = []
        target = next((a for a in assets
                        if (a.get("identity") or {}).get("asset_id") == asset_id),
                       None)
        if target is None:
            raise HTTPException(404, f"asset not found: {asset_id}")
        enrichment = enrich_asset(target)
        result = {"asset_id": asset_id,
                  "enrichment": asdict(enrichment), "merged": False}
        if merge:
            new_asset = merge_enrichment(target, enrichment)
            try:
                save_asset(new_asset)
                result["merged"] = True
            except Exception as e:
                result["merge_error"] = str(e)
        return result

    @app.post("/api/intel/enrich-all")
    def intel_enrich_all(merge: bool = False,
                           user=Depends(require_writer)):
        """Bulk-enrich every asset in the platform store. Returns a
        summary with count + per-role breakdown."""
        from safecadence.intel.asset_enrichment import (
            enrich_fleet, merge_enrichment,
        )
        from safecadence.server.platform_api import (
            list_assets, save_asset,
        )
        try:
            assets = list_assets()
        except Exception:
            assets = []
        enrichments = enrich_fleet(assets)
        roles: dict[str, int] = {}
        merged_count = 0
        for a, e in zip(assets, enrichments):
            roles[e.inferred_role] = roles.get(e.inferred_role, 0) + 1
            if merge:
                try:
                    save_asset(merge_enrichment(a, e))
                    merged_count += 1
                except Exception:
                    pass
        return {
            "asset_count": len(assets),
            "merged": merged_count if merge else 0,
            "by_role": roles,
            "results": [asdict(e) for e in enrichments[:50]],
        }

    # ---------------- v8.0: simulator -----------
    @app.post("/api/intel/simulate")
    def intel_simulate(body: dict = Body(...),
                          user=Depends(get_current_user)):
        from safecadence.identity.ir import validate_ir
        from safecadence.intel.simulator import simulate
        try:
            ir = validate_ir(body.get("ir") or {})
        except Exception as e:
            raise HTTPException(400, f"invalid IR: {e}")
        result = simulate(ir)
        return {
            "intent": result.intent,
            "summary": result.summary,
            "matched_assets": result.matched_assets,
            "matched_principals": result.matched_principals,
            "closing_findings": result.closing_findings,
            "opening_gaps": result.opening_gaps,
            "risk_delta": result.risk_delta,
        }

    # ---------------- v8.0: share ---------------
    @app.post("/api/intel/share/create")
    def intel_share_create(body: dict = Body(...),
                              user=Depends(require_writer)):
        from safecadence.intel.sharing import create_share
        try:
            t = create_share(
                scope=body.get("scope", "summary"),
                issued_to=body.get("issued_to", ""),
                issued_by=getattr(user, "username", "operator"),
                ttl_seconds=int(body.get("ttl_seconds", 7 * 86400)),
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        return t.__dict__

    @app.get("/api/intel/share/list")
    def intel_share_list(user=Depends(get_current_user)):
        from safecadence.intel.sharing import list_shares
        return {"shares": [s.__dict__ for s in list_shares()]}

    @app.post("/api/intel/share/{token_id}/revoke")
    def intel_share_revoke(token_id: str,
                              user=Depends(require_writer)):
        from safecadence.intel.sharing import revoke_share
        return {"revoked": revoke_share(token_id)}
