"""
v12.0 — Stripe product/price ID registry (scaffold).

SafeCadence is and stays free + MIT. This module exists for operators
who want to offer **hosted support / managed-tier services** alongside
the open-source product — it gives them a single place to wire Stripe
price IDs without forking the code.

Design choices made on the user's behalf
----------------------------------------

* **One product per tier.** Free / Starter / Pro / Enterprise.
  Stripe lets you attach multiple prices to one product, so monthly
  and annual variants live under the same product id.

* **Tier names are the source of truth, not Stripe ids.** The rest
  of the platform asks "is this org on Pro?" — never "is this org on
  price `price_xxx`?". This module is the only place that knows the
  mapping.

* **All ids loaded from env vars, never hard-coded.** Each operator
  brings their own Stripe account; we never ship anyone else's price
  ids. Missing env vars degrade to "tier not for sale" rather than
  crashing.

* **No webhook handling here.** Webhook routing already lives in
  `safecadence.billing.webhook`. This module is *just* the static
  catalog.

Env vars consumed
-----------------

::

    SC_STRIPE_PRICE_STARTER_MONTHLY
    SC_STRIPE_PRICE_STARTER_ANNUAL
    SC_STRIPE_PRICE_PRO_MONTHLY
    SC_STRIPE_PRICE_PRO_ANNUAL
    SC_STRIPE_PRICE_ENTERPRISE_MONTHLY
    SC_STRIPE_PRICE_ENTERPRISE_ANNUAL

Public API
----------

* ``list_tiers()``                    — all tiers with metadata + price ids.
* ``get_price_id(tier, cadence)``     — single id lookup or None.
* ``is_purchasable(tier)``            — True if any price id is configured.
"""
from __future__ import annotations

import os


# Static tier metadata. The pricing numbers here are *display only* —
# Stripe is the source of truth for what actually gets charged.
TIERS: list[dict] = [
    {
        "id": "free",
        "name": "Free",
        "display_price_monthly_usd": 0,
        "display_price_annual_usd": 0,
        "includes": [
            "All product features (open source)",
            "Community support",
            "Self-hosted only",
        ],
    },
    {
        "id": "starter",
        "name": "Starter Support",
        "display_price_monthly_usd": 49,
        "display_price_annual_usd": 490,
        "includes": [
            "Email support, 3-business-day response",
            "Quarterly health-check call",
            "Up to 100 assets / org",
        ],
    },
    {
        "id": "pro",
        "name": "Pro Support",
        "display_price_monthly_usd": 149,
        "display_price_annual_usd": 1490,
        "includes": [
            "Email + chat support, 1-business-day response",
            "Monthly health-check + roadmap session",
            "Up to 1000 assets / org",
        ],
    },
    {
        "id": "enterprise",
        "name": "Enterprise Support",
        "display_price_monthly_usd": 499,
        "display_price_annual_usd": 4990,
        "includes": [
            "Phone + chat + email, 4-hour response",
            "Dedicated solutions engineer",
            "Unlimited assets",
            "SAML / SSO included",
            "Air-gap distribution + SBOM",
        ],
    },
]


def _env(name: str) -> str | None:
    """Strip + return None for empty strings, so unset == empty."""
    v = (os.getenv(name) or "").strip()
    return v or None


def get_price_id(tier: str, cadence: str = "monthly") -> str | None:
    """Look up the configured Stripe price id for (tier, cadence).

    Returns None when the env var isn't set (no purchase path for that
    combination). Callers should hide the buy button in that case.
    """
    if tier == "free":
        return None
    cadence = cadence.lower()
    if cadence not in ("monthly", "annual"):
        return None
    env_name = f"SC_STRIPE_PRICE_{tier.upper()}_{cadence.upper()}"
    return _env(env_name)


def is_purchasable(tier: str) -> bool:
    """True when at least one cadence has a price id configured."""
    if tier == "free":
        return True  # free is always 'purchasable' (sign up, no payment)
    return bool(get_price_id(tier, "monthly") or get_price_id(tier, "annual"))


def list_tiers() -> list[dict]:
    """Return TIERS with current Stripe price ids attached."""
    out: list[dict] = []
    for t in TIERS:
        row = dict(t)
        row["price_id_monthly"] = get_price_id(t["id"], "monthly")
        row["price_id_annual"] = get_price_id(t["id"], "annual")
        row["is_purchasable"] = is_purchasable(t["id"])
        out.append(row)
    return out


__all__ = ["TIERS", "get_price_id", "is_purchasable", "list_tiers"]
