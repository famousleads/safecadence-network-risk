"""
Stripe webhook signature verification + event dispatch (v10.9).

Stripe signs every webhook with HMAC-SHA256 over a payload of the form::

    <timestamp>.<raw_body>

The ``Stripe-Signature`` header carries one or more ``v1=`` signatures
plus a ``t=`` timestamp. We verify by:

  1. Splitting the header on commas + ``=``.
  2. Recomputing HMAC-SHA256 of ``f"{t}.{body}"`` with the webhook
     secret.
  3. Comparing the hex digest to each ``v1`` value via
     :func:`hmac.compare_digest`.

If any ``v1`` matches, the request is authentic. We do **not** enforce
a max-age check here — for production hardening, callers can compare
``t`` against ``time.time()`` and reject if the delta exceeds 5 min.
The webhook secret comes from ``STRIPE_WEBHOOK_SECRET``.

Event dispatch
--------------
:func:`handle_event` looks at ``event.type`` and updates the org's
billing record accordingly. The ``org_id`` is read from the event
object's ``metadata.org_id`` field (we set it whenever we create a
Stripe object). If the metadata is missing, we fall back to looking
up the org by ``customer.email``.

Supported events:

  * ``checkout.session.completed``  → activate subscription on the org
  * ``customer.subscription.created`` / ``.updated``
                                     → sync plan + status
  * ``customer.subscription.deleted`` → mark cancelled
  * ``invoice.payment_failed``      → flag org as ``past_due``
  * ``invoice.paid``                → record payment + reactivate
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from typing import Any

_log = logging.getLogger("safecadence.billing.webhook")


# --------------------------------------------------------------------------
# Signature verification
# --------------------------------------------------------------------------


def verify_webhook_signature(payload: bytes, sig_header: str,
                              secret: str | None = None,
                              tolerance: int = 300) -> bool:
    """HMAC-SHA256 verification per Stripe's documented protocol.

    Args:
        payload:    raw request body as bytes.
        sig_header: contents of the ``Stripe-Signature`` header.
        secret:     defaults to ``STRIPE_WEBHOOK_SECRET`` env var.
        tolerance:  max age of the signature in seconds (default 5 min).

    Returns True on a valid + fresh signature, False otherwise. Never
    raises.
    """
    secret = (secret or os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()
    if not secret or not sig_header or not isinstance(payload, (bytes, bytearray)):
        return False
    try:
        parts = [p.strip() for p in sig_header.split(",") if "=" in p]
        kv = {}
        v1_signatures: list[str] = []
        for p in parts:
            k, _, v = p.partition("=")
            k = k.strip()
            v = v.strip()
            if k == "v1":
                v1_signatures.append(v)
            else:
                kv[k] = v
        ts = kv.get("t") or ""
        if not ts or not v1_signatures:
            return False
        # Tolerance check — protects against replay.
        try:
            ts_int = int(ts)
            if tolerance > 0 and abs(time.time() - ts_int) > tolerance:
                return False
        except ValueError:
            return False
        signed_payload = f"{ts}.".encode("utf-8") + payload
        expected = hmac.new(
            secret.encode("utf-8"), signed_payload, hashlib.sha256
        ).hexdigest()
        for sig in v1_signatures:
            if hmac.compare_digest(expected, sig):
                return True
        return False
    except Exception:                                  # pragma: no cover
        return False


# --------------------------------------------------------------------------
# Event dispatch
# --------------------------------------------------------------------------


def _resolve_org_id(event_obj: dict, org_id_override: str | None = None) -> str:
    """Best-effort resolve the org id from a Stripe object.

    Order: explicit ``org_id_override`` > ``metadata.org_id`` >
    nested object metadata > ``client_reference_id`` on checkout sessions.
    """
    if org_id_override:
        return org_id_override
    meta = event_obj.get("metadata") or {}
    if isinstance(meta, dict) and meta.get("org_id"):
        return str(meta["org_id"])
    crid = event_obj.get("client_reference_id")
    if crid:
        return str(crid)
    # subscription nested under invoice
    sub = event_obj.get("subscription_details") or {}
    if isinstance(sub, dict):
        meta = sub.get("metadata") or {}
        if isinstance(meta, dict) and meta.get("org_id"):
            return str(meta["org_id"])
    return ""


def _plan_from_price(price_id: str) -> str:
    """Reverse-lookup plan id from a Stripe price id.

    Uses env vars ``STRIPE_PRICE_PRO`` / ``STRIPE_PRICE_ENTERPRISE``;
    falls back to keyword sniffing on the price id string so the demo
    works without env config.
    """
    if not price_id:
        return "Free"
    if price_id == os.environ.get("STRIPE_PRICE_ENTERPRISE", "price_enterprise_placeholder"):
        return "Enterprise"
    if price_id == os.environ.get("STRIPE_PRICE_PRO", "price_pro_placeholder"):
        return "Pro"
    low = price_id.lower()
    if "enterprise" in low:
        return "Enterprise"
    if "pro" in low:
        return "Pro"
    return "Free"


def handle_event(event: dict, org_id: str | None = None) -> dict:
    """Dispatch a Stripe webhook event. Returns a small audit dict.

    The caller is expected to have already verified the signature.
    Unknown event types are ignored (return ``{"handled": False, "type": ...}``).
    """
    from safecadence.billing.plans import set_org_plan, get_org_billing

    if not isinstance(event, dict):
        return {"handled": False, "reason": "bad_payload"}
    etype = event.get("type") or ""
    data = (event.get("data") or {}).get("object") or {}
    resolved_org = _resolve_org_id(data, org_id) if isinstance(data, dict) else ""
    info: dict[str, Any] = {"handled": False, "type": etype, "org_id": resolved_org}

    if not isinstance(data, dict):
        return info

    if etype == "checkout.session.completed":
        # Activate the chosen plan. Try to read price from line items.
        plan = "Pro"
        # Stripe may include `display_items` (legacy) or `line_items` expanded.
        line_items = (data.get("line_items") or {}).get("data") or []
        if line_items and isinstance(line_items, list):
            price = (line_items[0].get("price") or {}).get("id") or ""
            plan = _plan_from_price(price)
        # Fallback to metadata.plan if set.
        meta = data.get("metadata") or {}
        if isinstance(meta, dict) and meta.get("plan"):
            plan = str(meta["plan"])
        if resolved_org:
            set_org_plan(
                resolved_org, plan, source="webhook", status="active",
                stripe_customer_id=data.get("customer"),
                stripe_subscription_id=data.get("subscription"),
            )
            info["handled"] = True
            info["plan"] = plan
        return info

    if etype in ("customer.subscription.created",
                 "customer.subscription.updated"):
        items = (data.get("items") or {}).get("data") or []
        price_id = ""
        if items and isinstance(items, list):
            price_id = (items[0].get("price") or {}).get("id") or ""
        plan = _plan_from_price(price_id)
        status = data.get("status") or "active"
        # Stripe statuses: trialing, active, past_due, canceled, unpaid, ...
        if resolved_org:
            set_org_plan(
                resolved_org, plan, source="webhook", status=status,
                stripe_customer_id=data.get("customer"),
                stripe_subscription_id=data.get("id"),
                trial_ends_at=data.get("trial_end"),
            )
            info["handled"] = True
            info["plan"] = plan
            info["status"] = status
        return info

    if etype == "customer.subscription.deleted":
        if resolved_org:
            rec = get_org_billing(resolved_org)
            set_org_plan(
                resolved_org, "Free", source="webhook", status="cancelled",
                stripe_customer_id=rec.get("stripe_customer_id"),
            )
            info["handled"] = True
            info["plan"] = "Free"
            info["status"] = "cancelled"
        return info

    if etype == "invoice.payment_failed":
        if resolved_org:
            rec = get_org_billing(resolved_org)
            set_org_plan(
                resolved_org, rec.get("plan_id") or "Free",
                source="webhook", status="past_due",
                stripe_customer_id=rec.get("stripe_customer_id"),
                stripe_subscription_id=rec.get("stripe_subscription_id"),
            )
            info["handled"] = True
            info["status"] = "past_due"
        return info

    if etype == "invoice.paid":
        if resolved_org:
            rec = get_org_billing(resolved_org)
            set_org_plan(
                resolved_org, rec.get("plan_id") or "Free",
                source="webhook", status="active",
                stripe_customer_id=rec.get("stripe_customer_id"),
                stripe_subscription_id=rec.get("stripe_subscription_id"),
            )
            # Append a payment record so the customer portal can show it.
            _append_payment_record(resolved_org, data)
            info["handled"] = True
            info["status"] = "active"
        return info

    return info


def _append_payment_record(org_id: str, invoice: dict) -> None:
    """Best-effort write a payment row to ``payments.jsonl``."""
    try:
        from safecadence.storage.org_store import org_data_dir
        path = org_data_dir(org_id) / "payments.jsonl"
        row = {
            "id": invoice.get("id"),
            "amount_paid": invoice.get("amount_paid"),
            "currency": invoice.get("currency"),
            "hosted_invoice_url": invoice.get("hosted_invoice_url"),
            "status": invoice.get("status"),
            "created": invoice.get("created"),
        }
        with path.open("a", encoding="utf-8") as fp:
            import json as _json
            fp.write(_json.dumps(row) + "\n")
    except Exception:                                  # pragma: no cover
        pass


__all__ = [
    "verify_webhook_signature",
    "handle_event",
]
