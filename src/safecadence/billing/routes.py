"""
FastAPI routes for the v10.9 billing system.

Mounts:

  POST /api/billing/webhook            — Stripe webhook receiver
  POST /api/v1/billing/checkout        — create checkout session
  POST /api/v1/billing/portal          — return Stripe Customer Portal URL
  GET  /api/v1/billing/plan            — get current org plan + usage
  GET  /api/v1/billing/plans           — list all plans (public)

Every endpoint either returns clean JSON or a 503 ``{"error":
"billing_not_configured"}`` when ``STRIPE_SECRET_KEY`` is unset. The
demo droplet keeps responding 200 to ``/api/v1/billing/plans`` regardless
because the plan catalog is hardcoded — it's safe to surface.
"""

from __future__ import annotations

import logging
import os

try:
    from fastapi import APIRouter, Body, HTTPException, Request
    from fastapi.responses import JSONResponse
    _FASTAPI_OK = True
except Exception:                                      # pragma: no cover
    _FASTAPI_OK = False

_log = logging.getLogger("safecadence.billing.routes")


def _make_router():
    if not _FASTAPI_OK:                                # pragma: no cover
        return None

    router = APIRouter()

    @router.get("/api/v1/billing/plans")
    def list_plans_route():
        """Public — never gated. Returns the plan catalog."""
        from safecadence.billing.plans import list_plans
        return {"plans": [p.to_dict() for p in list_plans()]}

    @router.get("/api/v1/billing/tiers")
    def list_tiers_route():
        """v12 — Stripe product/price-id-aware tier catalog.

        Returns the same four tiers as ``/api/v1/billing/plans`` but
        with live Stripe price ids attached (or None where unconfigured).
        Operators can hide the buy button when ``is_purchasable`` is false.
        """
        from safecadence.billing.stripe_products import list_tiers
        return {"tiers": list_tiers()}

    @router.get("/api/v1/billing/plan")
    def current_plan_route(request: Request):
        from safecadence.billing.plans import (
            get_org_billing, check_quota,
        )
        org_id = (
            request.headers.get("X-SafeCadence-Org")
            or request.query_params.get("org_id")
            or ""
        ).strip()
        if not org_id:
            raise HTTPException(400, "org_id required (X-SafeCadence-Org or ?org_id=)")
        rec = get_org_billing(org_id)
        return {
            "org_id": org_id,
            "billing": rec,
            "quota": {
                "assets": check_quota(org_id, "assets"),
                "reports": check_quota(org_id, "reports"),
                "api_calls": check_quota(org_id, "api_calls"),
            },
        }

    @router.post("/api/v1/billing/checkout")
    def checkout_route(payload: dict = Body(...)):
        from safecadence.billing import stripe_client
        if not stripe_client.is_configured():
            return JSONResponse(
                {"error": "billing_not_configured",
                 "detail": "Stripe is not configured on this server."},
                status_code=503,
            )
        plan = (payload.get("plan") or "").strip()
        org_id = (payload.get("org_id") or "").strip()
        email = (payload.get("email") or "").strip()
        success_url = (payload.get("success_url") or "").strip() \
            or os.environ.get(
                "STRIPE_SUCCESS_URL",
                "https://app.safecadence.com/portal/billing?ok=1",
            )
        cancel_url = (payload.get("cancel_url") or "").strip() \
            or os.environ.get(
                "STRIPE_CANCEL_URL",
                "https://app.safecadence.com/portal/billing?cancelled=1",
            )
        if not plan or not org_id or not email:
            raise HTTPException(400, "plan, org_id, email required")
        try:
            out = stripe_client.create_checkout_session(
                plan=plan,
                customer_email=email,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={"org_id": org_id, "plan": plan},
            )
        except stripe_client.BillingNotConfigured as exc:
            return JSONResponse(
                {"error": "billing_not_configured", "detail": str(exc)},
                status_code=503,
            )
        except stripe_client.StripeError as exc:
            return JSONResponse(
                {"error": "stripe_error", "status": exc.status,
                 "detail": exc.body[:500]},
                status_code=502,
            )
        return out

    @router.post("/api/v1/billing/portal")
    def portal_route(payload: dict = Body(...)):
        from safecadence.billing import stripe_client
        from safecadence.billing.plans import get_org_billing
        if not stripe_client.is_configured():
            return JSONResponse(
                {"error": "billing_not_configured"}, status_code=503,
            )
        org_id = (payload.get("org_id") or "").strip()
        return_url = (payload.get("return_url") or "").strip() \
            or "https://app.safecadence.com/portal/billing"
        if not org_id:
            raise HTTPException(400, "org_id required")
        rec = get_org_billing(org_id)
        cid = rec.get("stripe_customer_id")
        if not cid:
            raise HTTPException(400, "no Stripe customer on file for this org")
        try:
            out = stripe_client.create_billing_portal_session(cid, return_url)
        except stripe_client.StripeError as exc:
            return JSONResponse(
                {"error": "stripe_error", "status": exc.status,
                 "detail": exc.body[:500]},
                status_code=502,
            )
        return {"url": out.get("url")}

    @router.post("/api/billing/webhook")
    async def webhook_route(request: Request):
        from safecadence.billing import webhook as wh
        body = await request.body()
        sig = request.headers.get("Stripe-Signature") or ""
        # If a webhook secret is configured, REQUIRE a valid signature.
        # If it isn't, accept events for dev-mode but log loudly.
        secret = os.environ.get("STRIPE_WEBHOOK_SECRET") or ""
        if secret:
            if not wh.verify_webhook_signature(body, sig, secret):
                raise HTTPException(400, "invalid signature")
        else:
            _log.warning("Stripe webhook accepted without signature "
                         "verification (STRIPE_WEBHOOK_SECRET unset)")
        try:
            import json as _json
            event = _json.loads(body.decode("utf-8") or "{}")
        except Exception as exc:
            raise HTTPException(400, f"bad json: {exc}") from exc
        result = wh.handle_event(event)
        return result

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
