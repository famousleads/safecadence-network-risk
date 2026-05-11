"""
SafeCadence billing + commercialization modules (v10.9).

Submodules
----------
* ``stripe_client``  — stdlib urllib HTTP client for Stripe's REST API.
  No ``stripe`` package dependency.
* ``webhook``        — HMAC-SHA256 signature verification + event dispatch.
* ``plans``          — Free / Pro / Enterprise plan registry, per-org plan
  assignment, quota enforcement.
* ``usage``          — append-only JSONL usage log + monthly aggregation,
  wired into asset / report / api-call counters.

Everything is env-gated on ``STRIPE_SECRET_KEY``. Missing config means the
billing endpoints raise :class:`BillingNotConfigured` (or return HTTP 503)
and the rest of the platform keeps working — the public read-only demo
must never break because Stripe isn't wired up.
"""

from safecadence.billing.stripe_client import BillingNotConfigured  # noqa: F401

__all__ = ["BillingNotConfigured"]
