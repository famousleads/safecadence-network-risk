"""
Stdlib Stripe REST client (v10.9).

Why no ``stripe`` package?
--------------------------
The product is open-source and shipped to air-gapped environments. Pulling
in the official Stripe SDK adds 30+ transitive dependencies and changes
the security posture of every installed copy. The endpoints we hit are a
handful of stable REST calls (checkout sessions, customers, subscriptions,
invoices, billing portal). stdlib :mod:`urllib` is more than enough.

Public surface
--------------
``create_checkout_session(plan, customer_email, success_url, cancel_url)``
``create_customer(email, name=None)``
``create_subscription(customer_id, price_id, trial_days=14)``
``cancel_subscription(subscription_id, at_period_end=True)``
``create_billing_portal_session(customer_id, return_url)``
``get_invoice(invoice_id)``
``list_invoices(customer_id, limit=20)``
``is_configured()``

Every method raises :class:`BillingNotConfigured` if ``STRIPE_SECRET_KEY``
is not set. Network failures raise :class:`StripeError` with the upstream
status code + body so callers can surface a useful message.

The plan-id → Stripe price-id mapping uses these env vars (set them when
provisioning the Stripe products in the dashboard):

* ``STRIPE_PRICE_PRO`` (default placeholder ``price_pro_placeholder``)
* ``STRIPE_PRICE_ENTERPRISE`` (default ``price_enterprise_placeholder``)

Free plans never touch Stripe — they're activated in-process.
"""

from __future__ import annotations

import json as _json
import logging
import os
from typing import Any
from urllib import error as _urlerr
from urllib import parse as _urlparse
from urllib import request as _urlreq

_log = logging.getLogger("safecadence.billing.stripe_client")

_API_BASE = "https://api.stripe.com/v1"


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class BillingNotConfigured(RuntimeError):
    """Raised when ``STRIPE_SECRET_KEY`` (or related env) is missing.

    The message is human-readable and is meant to be surfaced through the
    API as a 503 ``{"error": "billing_not_configured", "detail": "..."}``.
    """


class StripeError(RuntimeError):
    """Raised for non-2xx responses from Stripe's REST API."""

    def __init__(self, status: int, body: str, code: str | None = None):
        self.status = status
        self.body = body
        self.code = code
        super().__init__(f"Stripe API error {status} {code or ''}: {body[:200]}")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def is_configured() -> bool:
    """True iff ``STRIPE_SECRET_KEY`` is set."""
    return bool(os.environ.get("STRIPE_SECRET_KEY"))


def _require_key() -> str:
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not key:
        raise BillingNotConfigured(
            "Stripe is not configured. Set STRIPE_SECRET_KEY to enable "
            "billing endpoints."
        )
    return key


def price_id_for_plan(plan_id: str) -> str:
    """Map a plan id (e.g. ``Pro``) to a Stripe price id from env.

    Free returns ``""`` — the Free plan is not a Stripe product.
    """
    pid = (plan_id or "").strip().lower()
    if pid in ("free", ""):
        return ""
    if pid == "pro":
        return os.environ.get("STRIPE_PRICE_PRO", "price_pro_placeholder")
    if pid == "enterprise":
        return os.environ.get(
            "STRIPE_PRICE_ENTERPRISE", "price_enterprise_placeholder"
        )
    raise ValueError(f"Unknown plan_id: {plan_id!r}")


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


def _request(
    method: str,
    path: str,
    *,
    form: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> dict:
    """POST/GET a Stripe REST endpoint with form-url-encoded payload.

    Stripe accepts ``application/x-www-form-urlencoded`` everywhere and
    that's the documented shape, so we don't bother with JSON.
    Nested dicts are flattened using bracket-notation
    (``metadata[org_id]=foo``) per Stripe's convention.
    """
    key = _require_key()
    url = _API_BASE + (path if path.startswith("/") else "/" + path)
    body: bytes | None = None
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Stripe-Version": os.environ.get("STRIPE_API_VERSION", "2024-04-10"),
        "User-Agent": "safecadence-netrisk/10.9 (stdlib)",
    }
    if form:
        flat = _flatten_form(form)
        body = _urlparse.urlencode(flat, doseq=True).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = _urlreq.Request(url, data=body, headers=headers, method=method)
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw:
                return {}
            try:
                return _json.loads(raw)
            except ValueError:
                return {"_raw": raw}
    except _urlerr.HTTPError as exc:
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        code = None
        try:
            parsed = _json.loads(body_text or "{}")
            code = (parsed.get("error") or {}).get("code")
        except Exception:
            pass
        raise StripeError(exc.code, body_text, code=code) from exc
    except _urlerr.URLError as exc:
        raise StripeError(0, f"network error: {exc.reason}") from exc


def _flatten_form(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dict into Stripe's bracketed form encoding."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}[{k}]" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_form(v, key))
        elif isinstance(v, (list, tuple)):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    out.update(_flatten_form(item, f"{key}[{i}]"))
                else:
                    out[f"{key}[{i}]"] = item
        elif v is None:
            continue
        elif isinstance(v, bool):
            out[key] = "true" if v else "false"
        else:
            out[key] = v
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def create_customer(email: str, name: str | None = None,
                    metadata: dict | None = None) -> str:
    """Create a Stripe Customer; return its id.

    Raises :class:`BillingNotConfigured` when keys aren't set.
    """
    form: dict[str, Any] = {"email": (email or "").strip().lower()}
    if name:
        form["name"] = name
    if metadata:
        form["metadata"] = metadata
    out = _request("POST", "/customers", form=form)
    cid = out.get("id")
    if not cid:
        raise StripeError(500, f"missing id in response: {out}")
    return cid


def create_checkout_session(
    plan: str,
    customer_email: str,
    success_url: str,
    cancel_url: str,
    *,
    customer_id: str | None = None,
    trial_days: int | None = 14,
    metadata: dict | None = None,
) -> dict:
    """Create a Checkout Session for ``plan``. Returns ``{url, session_id}``.

    ``plan`` is a plan id (``Pro`` / ``Enterprise``); ``Free`` is rejected
    because no checkout is required.
    """
    pid = (plan or "").strip().lower()
    if pid == "free":
        raise ValueError("Free plan does not require a checkout session.")
    price_id = price_id_for_plan(pid)
    form: dict[str, Any] = {
        "mode": "subscription",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items": [{"price": price_id, "quantity": 1}],
    }
    if customer_id:
        form["customer"] = customer_id
    elif customer_email:
        form["customer_email"] = customer_email
    if trial_days and trial_days > 0:
        form["subscription_data"] = {"trial_period_days": trial_days}
    if metadata:
        form["metadata"] = metadata
    out = _request("POST", "/checkout/sessions", form=form)
    return {"url": out.get("url"), "session_id": out.get("id")}


def create_subscription(customer_id: str, price_id: str,
                         trial_days: int = 14,
                         metadata: dict | None = None) -> dict:
    """Create a subscription directly (skipping checkout)."""
    form: dict[str, Any] = {
        "customer": customer_id,
        "items": [{"price": price_id}],
    }
    if trial_days and trial_days > 0:
        form["trial_period_days"] = trial_days
    if metadata:
        form["metadata"] = metadata
    return _request("POST", "/subscriptions", form=form)


def cancel_subscription(subscription_id: str,
                         at_period_end: bool = True) -> dict:
    """Cancel a subscription. By default, cancels at period end (no refund)."""
    if at_period_end:
        return _request("POST", f"/subscriptions/{subscription_id}",
                        form={"cancel_at_period_end": True})
    return _request("DELETE", f"/subscriptions/{subscription_id}")


def create_billing_portal_session(customer_id: str,
                                    return_url: str) -> dict:
    """Create a Customer Portal session; returns ``{url, ...}``."""
    return _request(
        "POST",
        "/billing_portal/sessions",
        form={"customer": customer_id, "return_url": return_url},
    )


def get_invoice(invoice_id: str) -> dict:
    return _request("GET", f"/invoices/{invoice_id}")


def list_invoices(customer_id: str, limit: int = 20) -> list[dict]:
    out = _request("GET",
                   f"/invoices?customer={_urlparse.quote(customer_id)}"
                   f"&limit={int(limit)}")
    data = out.get("data") or []
    if not isinstance(data, list):
        return []
    return data


__all__ = [
    "BillingNotConfigured",
    "StripeError",
    "is_configured",
    "price_id_for_plan",
    "create_customer",
    "create_checkout_session",
    "create_subscription",
    "cancel_subscription",
    "create_billing_portal_session",
    "get_invoice",
    "list_invoices",
]
