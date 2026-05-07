"""
v7.7 — Identity REST API.

Mounts /api/identity/* onto the existing FastAPI app. The endpoints
are thin wrappers around the same engine the CLI drives (one path,
one source of truth) so the UI, CLI, and external automation all
agree on shape and behavior.

Auth: every endpoint that mutates state (apply, jit/grant, jit/revoke)
requires the same writer-or-better JWT the rest of the platform uses.
Read-only endpoints (preview, who-can, jit/list, findings) require any
authenticated user.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional


def register(app, get_current_user, require_writer):
    """Register /api/identity/* endpoints. Called from server/app.py."""
    from fastapi import Body, Depends, HTTPException, Query

    # ---- helper: build adapter for a target ---------------------------
    def _adapter_for(target: str, *, override_target: str = "",
                       override_credentials: Optional[dict] = None):
        """v9.34 #1 — prefer the IdentityVault, fall back to env vars.
        ``override_*`` lets the connect endpoint instantiate an adapter
        with form values (not yet persisted) for test_connection."""
        from safecadence.platform.adapters.identity_adapters import (
            ActiveDirectoryAdapter, CiscoISEAdapter, EntraIDAdapter,
            HPEClearPassAdapter, OktaAdapter,
        )
        target_to_class = {
            "okta": OktaAdapter,
            "ise": CiscoISEAdapter,
            "ad": ActiveDirectoryAdapter,
            "entra": EntraIDAdapter,
            "clearpass": HPEClearPassAdapter,
        }
        cls = target_to_class.get(target)
        if cls is None:
            raise HTTPException(400, f"unknown target: {target}")
        if override_credentials is not None:
            return cls(target=override_target or
                          f"stub.{target}.local",
                       credentials=dict(override_credentials))
        # v9.34 #1 — vault first.
        try:
            from safecadence.identity.vault import IdentityVault
            rec = IdentityVault().load_creds(target)
        except Exception:                                       # pragma: no cover
            rec = None
        if rec is not None:
            return cls(target=rec.target, credentials=dict(rec.credentials))
        # Fallback: env vars (preserves prior behavior).
        return cls(target=os.environ.get(_host_env(target),
                                          f"stub.{target}.local"),
                   credentials=_creds_for_target(target))

    # ---- translate ---------------------------------------------------
    @app.post("/api/identity/translate")
    def identity_translate(body: dict = Body(...),
                            user=Depends(get_current_user)):
        """NL → IR. Body: {intent, form?, groups?, actions?, ...}.
        If `form: true`, uses the no-AI guided path."""
        from safecadence.identity.ai_translator import (
            translate as ai_translate, from_form,
        )
        try:
            if body.get("form"):
                ir = from_form(
                    intent=body.get("intent", ""),
                    groups=list(body.get("groups") or []),
                    actions=list(body.get("actions") or ["ssh"]),
                    environments=list(body.get("environments") or ["prod"]),
                    effect=body.get("effect", "deny"),
                    require_mfa=bool(body.get("require_mfa", True)),
                    targets=list(body.get("targets") or []) or None,
                )
            else:
                intent = body.get("intent", "")
                if not intent:
                    raise HTTPException(400, "intent is required")
                result = ai_translate(intent)
                ir = result.ir
        except Exception as e:
            raise HTTPException(400, f"translate failed: {e}")
        return {"ir": asdict(ir)}

    # ---- preview -----------------------------------------------------
    @app.post("/api/identity/preview")
    def identity_preview(body: dict = Body(...),
                          user=Depends(get_current_user)):
        """IR → per-system change preview (deterministic, no network)."""
        from safecadence.identity.compiler import compile_plan
        from safecadence.identity.ir import validate_ir
        try:
            ir = validate_ir(body.get("ir") or body)
        except Exception as e:
            raise HTTPException(400, f"invalid IR: {e}")
        plan = compile_plan(ir)
        return {
            "diff": plan.diff(),
            "operations": [
                {"target": o.target, "op_kind": o.op_kind,
                  "summary": o.summary, "payload": o.payload,
                  "risk": o.risk, "deferred": o.deferred}
                for o in plan.operations
            ],
            "warnings": plan.warnings,
        }

    # ---- apply -------------------------------------------------------
    @app.post("/api/identity/apply")
    def identity_apply(body: dict = Body(...),
                        user=Depends(require_writer)):
        """Apply (or dry-run) IR against a single target.
        Body: {ir, target, dry_run?, confirm_token?}.

        v9.33 #2 — commit (``dry_run=False``) requires a
        ``confirm_token`` from a prior dry-run with the same IR +
        target + actor. Missing/stale tokens return HTTP 409 so the
        UI can show "your preview is stale, re-review and try again".
        """
        from safecadence.identity.ir import validate_ir
        try:
            ir = validate_ir(body.get("ir") or {})
        except Exception as e:
            raise HTTPException(400, f"invalid IR: {e}")
        target = body.get("target", "okta")
        dry_run = bool(body.get("dry_run", True))
        adapter = _adapter_for(target)
        actor = getattr(user, "username", "api")
        out = adapter.apply_policy(
            ir, dry_run=dry_run, actor=actor,
            confirm_token=body.get("confirm_token"),
        )
        if (not dry_run) and (out.get("error") or "").startswith(
                "confirm_token rejected:"):
            raise HTTPException(409, detail=out["error"])
        return out

    # ---- apply-all (transactional, v7.7) ----------------------------
    @app.post("/api/identity/apply-all")
    def identity_apply_all(body: dict = Body(...),
                            user=Depends(require_writer)):
        """Apply IR across multiple targets atomically. Body:
        {ir, targets, dry_run?, confirm_token?, on_failure}.

        v9.33 #2 — commit requires a ``confirm_token`` from a prior
        dry-run against the same sorted target set + actor.
        """
        from safecadence.identity.transactional import apply_all
        from safecadence.identity.ir import validate_ir
        try:
            ir = validate_ir(body.get("ir") or {})
        except Exception as e:
            raise HTTPException(400, f"invalid IR: {e}")
        targets = list(body.get("targets") or ir.targets)
        adapters = {t: _adapter_for(t) for t in targets if t != "all"}
        actor = getattr(user, "username", "api")
        out = apply_all(
            ir, adapters,
            dry_run=bool(body.get("dry_run", True)),
            actor=actor,
            confirm_token=body.get("confirm_token"),
            on_failure=body.get("on_failure", "rollback"),
        )
        if out.get("status") == "rejected":
            raise HTTPException(409,
                detail=(out.get("failure") or {}).get(
                    "error", "confirm_token rejected"))
        return out

    # ---- v9.33 #4: onboarding (discover + connector status) ----------
    @app.post("/api/identity/discover")
    def identity_discover(body: dict = Body(default={}),
                            user=Depends(get_current_user)):
        """v9.33 #4 — probe the local environment for reachable Okta /
        Entra / ISE / ClearPass / AD systems. Returns findings with
        confidence + env-var recipe. Pure read; nothing committed.

        Body (all optional): {email_domain, entra_tenant, ad_domain,
        lan_cidrs: [str]}.
        """
        try:
            from safecadence.identity.discover import discover
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(500, f"discover unavailable: {e}")
        findings = discover(
            email_domain=body.get("email_domain"),
            entra_tenant_hint=body.get("entra_tenant"),
            ad_domain=body.get("ad_domain"),
            lan_cidrs=list(body.get("lan_cidrs") or []) or None,
        ) or []
        return {"count": len(findings),
                 "findings": [{
                    "system": f.system, "target": f.target,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "next_step": f.next_step,
                    "env_vars": dict(f.env_vars or {}),
                 } for f in findings]}

    @app.get("/api/identity/connectors-status")
    def identity_connectors_status(_user=Depends(get_current_user)):
        """v9.33 #4 / v9.34 #1 — vault-aware connector status. Vault
        record (saved + tested) wins over env vars. Used by the
        /identity hero band to surface the "0 of 5 connected" state
        honestly."""
        import os as _os
        # v9.34 #1 — read vault state.
        vault_rows: dict[str, dict] = {}
        try:
            from safecadence.identity.vault import IdentityVault
            for r in IdentityVault().list_connected():
                vault_rows[r["system"]] = r
        except Exception:                                       # pragma: no cover
            vault_rows = {}
        rows = []
        for sys_name, required in [
            ("okta",      ("OKTA_DOMAIN", "OKTA_API_TOKEN")),
            ("entra",     ("ENTRA_TENANT", "ENTRA_CLIENT_ID",
                              "ENTRA_CLIENT_SECRET")),
            ("ise",       ("ISE_HOST", "ISE_USERNAME", "ISE_PASSWORD")),
            ("clearpass", ("CLEARPASS_HOST", "CLEARPASS_CLIENT_ID",
                              "CLEARPASS_CLIENT_SECRET")),
            ("ad",        ("AD_SERVER", "AD_BIND_DN", "AD_BIND_PASSWORD",
                              "AD_BASE_DN")),
        ]:
            v = vault_rows.get(sys_name)
            if v and v.get("last_test_ok"):
                rows.append({
                    "system": sys_name, "configured": True,
                    "source": "vault",
                    "target": v.get("target", ""),
                    "last_test_at": v.get("last_test_at", ""),
                    "last_synced_at": v.get("last_synced_at", ""),
                    "have": len(required), "need": len(required),
                    "missing": [],
                })
                continue
            present = [k for k in required if _os.environ.get(k)]
            rows.append({
                "system": sys_name,
                "configured": len(present) == len(required),
                "source": "env" if present else "none",
                "have": len(present), "need": len(required),
                "missing": [k for k in required if not _os.environ.get(k)],
            })
        configured_count = sum(1 for r in rows if r["configured"])
        return {"total": 5, "configured": configured_count,
                 "systems": rows}

    # ---- v9.34 #1: connect form (Test + optionally Save) ------------
    @app.post("/api/identity/connect")
    def identity_connect(body: dict = Body(...),
                          user=Depends(require_writer)):
        """v9.34 #1 — Test connection (and optionally Save) for a
        single identity system. Body:

          {system, target, credentials, mode}

        Modes:
          ``test_only``  — instantiate adapter, call test_connection,
                            return ok/error. **Never persists.**
          ``save``       — same as test_only, then on success persist
                            to the encrypted IdentityVault. On failure
                            the vault is **not** touched.

        Trust property: an untested credential blob can never reach
        the vault. The vault layer (#2) enforces this independently
        via ``test_passed=True``; this endpoint enforces it at the
        HTTP boundary too.
        """
        system = (body.get("system") or "").strip().lower()
        target = (body.get("target") or "").strip()
        creds  = body.get("credentials") or {}
        mode   = (body.get("mode") or "test_only").strip().lower()
        if mode not in ("test_only", "save"):
            raise HTTPException(400, "mode must be test_only or save")
        from safecadence.identity.vault import (
            IdentityVault, SUPPORTED_SYSTEMS,
        )
        if system not in SUPPORTED_SYSTEMS:
            raise HTTPException(400,
                f"system must be one of {list(SUPPORTED_SYSTEMS)}")
        if not target:
            raise HTTPException(400, "target is required")
        if not isinstance(creds, dict) or not creds:
            raise HTTPException(400, "credentials must be a non-empty object")

        # Instantiate against the form values — no vault read here.
        try:
            adapter = _adapter_for(
                system,
                override_target=target,
                override_credentials=creds,
            )
        except HTTPException:
            raise
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(400, f"adapter init failed: {e}")

        # Real test_connection call. Adapters return {ok, error}.
        try:
            test = adapter.test_connection() or {}
        except Exception as e:
            test = {"ok": False, "error": f"raised: {e}"}
        ok = bool(test.get("ok"))
        if not ok:
            # v9.34.2 — translate raw socket / HTTP errors into something
            # an operator can act on. The adapter's test_connection puts
            # the underlying error string under "error" but it's often
            # the bare OS errno text ("[Errno 8] nodename nor servname
            # provided"). Surface a hint about the right input shape.
            raw_err = str(test.get("error") or
                            "test_connection returned not-ok")
            err_lower = raw_err.lower()
            hint = ""
            if ("nodename nor servname" in err_lower
                    or "name or service not known" in err_lower
                    or "no address associated" in err_lower
                    or "getaddrinfo" in err_lower):
                hint = (
                    f"Could not resolve {target!r}. "
                    f"The {system} target should be a fully-qualified "
                    f"hostname like the placeholder example, not a "
                    f"username or single word."
                )
            elif "401" in err_lower or "unauthorized" in err_lower:
                hint = ("Credentials were rejected by the target. "
                        "Check the API token / client secret and the "
                        "scope it was issued with.")
            elif "403" in err_lower or "forbidden" in err_lower:
                hint = ("The target accepted the credentials but "
                        "refused the request. The token may not have "
                        "the read scope required for sync.")
            elif "ssl" in err_lower or "certificate" in err_lower:
                hint = ("TLS handshake failed. Check the hostname "
                        "matches the certificate or, for lab tenants, "
                        "set verify_ssl=False (not recommended in prod).")
            elif "timed out" in err_lower or "timeout" in err_lower:
                hint = (f"Connection to {target!r} timed out. Check "
                        "firewall rules and that the host is reachable "
                        "from this machine.")
            return {
                "tested": True, "ok": False, "saved": False,
                "system": system, "target": target,
                "error": raw_err,
                "hint": hint,
            }

        # v9.52.1 — surface the v9.51 groups_probe so the operator
        # sees at connect time whether the IdP-groups cache will
        # populate. Pass-through; the adapter's test_connection
        # already populated this field.
        groups_probe = test.get("groups_probe") or {}

        if mode == "test_only":
            return {"tested": True, "ok": True, "saved": False,
                     "system": system, "target": target,
                     "groups_probe": groups_probe}

        # mode == save — persist only after a passing test.
        try:
            IdentityVault().save_creds(
                system=system, target=target,
                credentials=creds, test_passed=True,
                actor=getattr(user, "username", "ui"),
            )
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(500, f"vault save failed: {e}")
        return {"tested": True, "ok": True, "saved": True,
                 "system": system, "target": target,
                 "groups_probe": groups_probe}

    # ---- v9.34 #3: initial sync workflow -----------------------------
    @app.post("/api/identity/sync/{system}")
    def identity_sync(system: str,
                       user=Depends(require_writer)):
        """v9.34 #3 — pull users/groups/policies from a connected
        system. Real flow:

          1. Load creds from the encrypted IdentityVault (refuse if
             system isn't connected).
          2. Build the adapter against those creds.
          3. Call adapter.collect() — real outbound network call.
          4. Call adapter.normalize() — produces a UnifiedAsset.
          5. Persist the asset via save_asset() so list_assets() and
             every downstream surface (/access, /paths, /findings)
             can read it.
          6. Mark the vault record's last_synced_at.
          7. Return a receipt with counts.

        Trust property: sync only ever READS from the target system.
        Write-back is a separate flow (apply_policy, gated by the
        confirm_token from v9.33 #2). A misconfigured sync cannot
        mutate the target.
        """
        from safecadence.identity.vault import (
            IdentityVault, SUPPORTED_SYSTEMS,
        )
        sys_l = (system or "").strip().lower()
        if sys_l not in SUPPORTED_SYSTEMS:
            raise HTTPException(400,
                f"system must be one of {list(SUPPORTED_SYSTEMS)}")
        vault = IdentityVault()
        rec = vault.load_creds(sys_l)
        if rec is None:
            raise HTTPException(409,
                f"{sys_l} is not connected. POST "
                "/api/identity/connect with mode=save first.")
        try:
            adapter = _adapter_for(sys_l)
        except HTTPException:
            raise
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(400, f"adapter init failed: {e}")
        # Asset id convention: <system>:<target>. One UnifiedAsset per
        # tenant. Repeat sync upserts the same id.
        asset_id = f"{sys_l}:{rec.target}"
        try:
            raw = adapter.collect(asset_id) or {}
        except Exception as e:
            raise HTTPException(502,
                f"{sys_l} collect failed: {e}")
        if isinstance(raw, dict) and raw.get("error"):
            raise HTTPException(502,
                f"{sys_l} collect returned error: {raw['error']}")
        # Per-bucket counts — every adapter exposes lists; we just
        # count them so the receipt is honest.
        counts: dict[str, int] = {}
        for k, v in (raw.items() if isinstance(raw, dict) else []):
            if isinstance(v, list):
                counts[k] = len(v)
            elif isinstance(v, dict) and "value" in v and isinstance(
                    v["value"], list):
                # MS Graph wraps lists in {"value": [...]}
                counts[k] = len(v["value"])
        # Normalize + persist.
        try:
            unified = adapter.normalize(asset_id, raw)
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(500, f"{sys_l} normalize failed: {e}")
        try:
            from safecadence.server.platform_api import save_asset
            saved_id = save_asset(unified)
        except Exception as e:                                  # pragma: no cover
            raise HTTPException(500, f"persist failed: {e}")
        # Mark the vault record so the connector strip shows
        # "last synced 2s ago".
        try:
            vault.mark_synced(sys_l)
        except Exception:                                       # pragma: no cover
            pass
        return {
            "system": sys_l, "target": rec.target,
            "asset_id": saved_id,
            "counts": counts,
            "ok": True,
        }

    @app.post("/api/identity/disconnect/{system}")
    def identity_disconnect(system: str,
                              user=Depends(require_writer)):
        """v9.34 #1 — remove a saved connector from the vault. Idempotent."""
        from safecadence.identity.vault import IdentityVault
        try:
            removed = IdentityVault().disconnect(system)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"system": system, "disconnected": bool(removed)}

    # ---- v9.34 #5: NHI tab + lifecycle ------------------------------
    @app.get("/api/identity/nhi")
    def nhi_list(_user=Depends(get_current_user)):
        from safecadence.identity import nhi_store
        return {"nhis": [asdict(r) for r in nhi_store.list_all()]}

    @app.post("/api/identity/nhi")
    def nhi_create(body: dict = Body(...),
                    user=Depends(require_writer)):
        from safecadence.identity import nhi_store
        try:
            rec = nhi_store.register(
                name=body.get("name", ""),
                subtype=body.get("subtype", "service_account"),
                provider=body.get("provider", ""),
                owner=body.get("owner", ""),
                rotation_policy_days=int(
                    body.get("rotation_policy_days", 0) or 0),
                notes=body.get("notes", ""),
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        return asdict(rec)

    @app.post("/api/identity/nhi/{nhi_id}/attest")
    def nhi_attest(nhi_id: str, user=Depends(require_writer)):
        from safecadence.identity import nhi_store
        try:
            rec = nhi_store.attest(nhi_id,
                                     by=getattr(user, "username", "ui"))
        except KeyError:
            raise HTTPException(404, f"nhi not found: {nhi_id}")
        return asdict(rec)

    @app.post("/api/identity/nhi/{nhi_id}/rotate")
    def nhi_rotate(nhi_id: str, user=Depends(require_writer)):
        from safecadence.identity import nhi_store
        try:
            rec = nhi_store.rotate(nhi_id)
        except KeyError:
            raise HTTPException(404, f"nhi not found: {nhi_id}")
        return asdict(rec)

    @app.post("/api/identity/nhi/{nhi_id}/deprecate")
    def nhi_deprecate(nhi_id: str, user=Depends(require_writer)):
        from safecadence.identity import nhi_store
        try:
            rec = nhi_store.deprecate(nhi_id)
        except KeyError:
            raise HTTPException(404, f"nhi not found: {nhi_id}")
        return asdict(rec)

    @app.get("/api/identity/nhi/findings")
    def nhi_findings(stale_days: int = 90,
                       _user=Depends(get_current_user)):
        from safecadence.identity import nhi_store
        return {"findings": nhi_store.stale_findings(
            stale_unused_days=int(stale_days))}

    # ---- who-can -----------------------------------------------------
    @app.get("/api/identity/who-can")
    def identity_who_can(action: str = Query(...),
                          resource: str = Query(...),
                          principal: str = Query(...),
                          groups: str = Query(""),
                          mfa: bool = Query(False),
                          posture: bool = Query(False),
                          device_trusted: bool = Query(False),
                          user=Depends(get_current_user)):
        """Effective-permission lookup composed across connected systems."""
        from safecadence.identity.effective_permissions import (
            decide, rules_from_assets,
        )
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []

        rules = rules_from_assets(assets)
        resource_attrs: dict = {}
        for a in assets:
            ident = (a.get("identity") or {})
            if ident.get("asset_id") == resource or ident.get("hostname") == resource:
                resource_attrs = {
                    "asset_type": ident.get("asset_type", ""),
                    "env": ident.get("environment", ""),
                    "criticality": ident.get("criticality", ""),
                    "site": ident.get("site", ""),
                }
                break

        decision = decide(
            principal, action, resource,
            context={"mfa": mfa, "posture_compliant": posture,
                      "device_trusted": device_trusted},
            rules=rules,
            principal_groups=[g for g in groups.split(",") if g],
            resource_attrs=resource_attrs,
        )
        return {
            "allowed": decision.allowed,
            "requires_step_up": decision.requires_step_up,
            "systems_consulted": decision.systems_consulted,
            "reasons": decision.reasons,
            "chain": [
                {"system": r.system, "rule_name": r.rule_name,
                  "effect": r.effect, "matched_on": r.matched_on}
                for r in decision.chain
            ],
        }

    # ---- per-principal asset breakdown (v9.40) ------------------------
    @app.get("/api/identity/access")
    def identity_access_breakdown(
        principal: str = Query(...),
        groups: str = Query(""),
        actions: str = Query(""),
        only_granted: bool = Query(False),
        mfa: bool = Query(False),
        posture: bool = Query(False),
        device_trusted: bool = Query(False),
        _user=Depends(get_current_user),
    ):
        """v9.40 — every asset this principal can reach, plus the
        chain of declared rules + systems that contributed each grant.

        Different shape than ``/api/identity/who-can``: that endpoint
        answers a single (action, resource, principal) question;
        this one returns the full per-principal access map across
        the fleet so an auditor can see least-privilege at a glance.
        """
        from safecadence.identity.access_breakdown import (
            breakdown_for_principal, DEFAULT_ACTIONS,
        )
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []
        action_tuple = tuple(
            a.strip() for a in actions.split(",") if a.strip()
        ) or DEFAULT_ACTIONS
        return breakdown_for_principal(
            principal=principal,
            assets=assets,
            principal_groups=[g for g in groups.split(",") if g],
            actions=action_tuple,
            context={"mfa": mfa, "posture_compliant": posture,
                     "device_trusted": device_trusted},
            only_granted=only_granted,
        )

    # ---- attack paths -------------------------------------------------
    @app.get("/api/identity/attack-paths")
    def identity_attack_paths(limit: int = 20,
                                user=Depends(get_current_user)):
        from safecadence.identity.attack_paths import compute_identity_paths
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []
        paths = compute_identity_paths(assets)
        return {
            "count": len(paths),
            "paths": [
                {"chain_summary": p.chain_summary(),
                  "terminal_asset": p.terminal_asset,
                  "risk_score": p.risk_score,
                  "reasons": p.reasons}
                for p in paths[:limit]
            ],
        }

    # ---- findings (stale / over-privileged) ---------------------------
    @app.get("/api/identity/findings")
    def identity_findings(stale_days: int = 90,
                            user=Depends(get_current_user)):
        from safecadence.identity.findings import scan_findings
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []
        findings = scan_findings(assets, stale_days=stale_days)
        return {
            "count": len(findings),
            "findings": [
                {"finding_id": f.finding_id, "severity": f.severity,
                  "kind": f.kind, "title": f.title, "evidence": f.evidence,
                  "principal": f.principal, "suggested_ir": f.suggested_ir}
                for f in findings
            ],
        }

    # ---- remediation playbook for an attack path ---------------------
    @app.post("/api/identity/remediate-path")
    def identity_remediate_path(body: dict = Body(...),
                                  user=Depends(get_current_user)):
        """Body: {chain_summary} OR {edges: [{src,dst,kind}, ...]}.
        Returns a UnifiedPolicyIR JSON that severs the path."""
        from safecadence.identity.findings import remediate_path
        ir = remediate_path(body)
        return {"ir": asdict(ir)}

    # ---- JIT ---------------------------------------------------------
    @app.post("/api/identity/jit/grant")
    def identity_jit_grant(body: dict = Body(...),
                            user=Depends(require_writer)):
        from safecadence.identity.jit import grant
        try:
            g = grant(
                principal=body["principal"], action=body["action"],
                resource=body["resource"],
                duration_seconds=int(body.get("duration_seconds", 14400)),
                target=body.get("target", "okta"),
                created_by=getattr(user, "username", "api"),
                reason=body.get("reason", ""),
            )
        except (KeyError, ValueError) as e:
            raise HTTPException(400, str(e))
        return asdict(g)

    @app.get("/api/identity/jit/list")
    def identity_jit_list(active_only: bool = False,
                           user=Depends(get_current_user)):
        from safecadence.identity.jit import list_grants
        return {"grants": [asdict(g) for g in list_grants(only_active=active_only)]}

    @app.post("/api/identity/jit/expire-due")
    def identity_jit_expire_due(user=Depends(require_writer)):
        from safecadence.identity.jit import expire_due
        return {"expired": [asdict(g) for g in expire_due()]}

    @app.post("/api/identity/jit/revoke/{grant_id}")
    def identity_jit_revoke(grant_id: str,
                              user=Depends(require_writer)):
        from safecadence.identity.jit import revoke
        g = revoke(grant_id)
        if g is None:
            raise HTTPException(404, f"grant not found: {grant_id}")
        return asdict(g)

    # ---- auto-fix (v7.8) ---------------------------------------------
    @app.post("/api/identity/auto-fix/{finding_id}")
    def identity_auto_fix(finding_id: str,
                            dry_run: bool = True,
                            confirm_token: str = "",
                            user=Depends(require_writer)):
        """One-click auto-fix for a finding. v7.8 only auto-applies for
        findings classified low-risk (severity in {low, medium, info}).
        High/critical require explicit operator review through /apply.
        """
        from safecadence.identity.findings import scan_findings
        from safecadence.identity.ir import validate_ir
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []
        target = next((f for f in scan_findings(assets)
                        if f.finding_id == finding_id), None)
        if target is None:
            raise HTTPException(404, f"finding not found: {finding_id}")
        if target.severity in ("critical", "high"):
            raise HTTPException(409,
                f"finding severity={target.severity} requires manual review; "
                "use /api/identity/apply with the suggested IR after operator "
                "confirmation.")
        if not target.suggested_ir:
            raise HTTPException(400,
                f"finding {finding_id} has no suggested_ir to auto-fix")
        try:
            ir = validate_ir(target.suggested_ir)
        except Exception as e:
            raise HTTPException(400, f"suggested_ir invalid: {e}")
        adapter_target = ir.targets[0] if ir.targets else "okta"
        if adapter_target == "all":
            adapter_target = "okta"
        adapter = _adapter_for(adapter_target)
        actor = getattr(user, "username", "api")
        # v9.33 #2 — auto-fix dry-run mints a confirm_token; the UI
        # chains a second call with that token to commit. Commit
        # without a token returns 409.
        out = adapter.apply_policy(
            ir, dry_run=dry_run, actor=actor,
            confirm_token=(confirm_token or None),
        )
        if (not dry_run) and (out.get("error") or "").startswith(
                "confirm_token rejected:"):
            raise HTTPException(409, detail=out["error"])
        return {"finding_id": finding_id, "result": out}

    # ---- evidence pack -----------------------------------------------
    @app.get("/api/identity/evidence-pack")
    def identity_evidence_pack(format: str = "json",
                                 user=Depends(get_current_user)):
        from safecadence.identity.evidence_pack import build_pack
        from safecadence.server.platform_api import list_assets
        try:
            assets = list_assets()
        except Exception:
            assets = []
        pack = build_pack(assets, requested_by=getattr(user, "username", "api"))
        if format == "pdf":
            from fastapi.responses import Response
            return Response(content=pack["pdf_bytes"],
                            media_type="application/pdf",
                            headers={"Content-Disposition":
                                     "attachment; filename=identity-evidence.pdf"})
        if format == "csv":
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(pack["csv_text"],
                                      media_type="text/csv")
        # default JSON
        return pack["json"]


# ---- helpers --------------------------------------------------------

def _host_env(target: str) -> str:
    return {
        "okta": "OKTA_DOMAIN", "ise": "ISE_HOST", "ad": "AD_SERVER",
        "entra": "ENTRA_TENANT", "clearpass": "CLEARPASS_HOST",
    }.get(target, "")


def _creds_for_target(target: str) -> dict:
    table = {
        "okta": [("api_token", "OKTA_API_TOKEN")],
        "ise": [("username", "ISE_USERNAME"), ("password", "ISE_PASSWORD")],
        "ad": [("bind_dn", "AD_BIND_DN"),
                ("bind_password", "AD_BIND_PASSWORD"),
                ("base_dn", "AD_BASE_DN")],
        "entra": [("tenant_id", "ENTRA_TENANT"),
                   ("client_id", "ENTRA_CLIENT_ID"),
                   ("client_secret", "ENTRA_CLIENT_SECRET")],
        "clearpass": [("client_id", "CLEARPASS_CLIENT_ID"),
                       ("client_secret", "CLEARPASS_CLIENT_SECRET")],
    }
    return {k: os.environ.get(env, "") for k, env in table.get(target, [])}
