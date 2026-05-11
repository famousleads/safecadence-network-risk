"""
Plan registry, per-org plan assignment, and quota enforcement (v10.9).

Plans
-----
Three tiers, hardcoded so the demo-without-config path keeps working::

  Free        $0/mo       25 assets       5 reports/mo     no API
  Pro         $49/mo      250 assets      unlimited        API enabled
  Enterprise  $499/mo     unlimited       unlimited        SAML + dedicated

``-1`` in any limit field means "unlimited" — that's the convention used
by the rest of the codebase (mirrors what reports/budgets already do).

Plan assignment
---------------
Per-org plan lives in
``~/.safecadence/orgs/<org_id>/billing.json``::

    {
      "plan_id":           "Pro",
      "status":            "active" | "past_due" | "cancelled" | "trialing",
      "source":            "manual" | "webhook" | "signup",
      "stripe_customer_id": "cus_xxx" | None,
      "stripe_subscription_id": "sub_xxx" | None,
      "trial_ends_at":     1700000000 | None,
      "updated_at":        1700000000
    }

If the file doesn't exist, the org is treated as Free.

Quota check
-----------
:func:`check_quota` reads from :func:`safecadence.billing.usage.get_usage`
for the current month and compares against the plan's limit. Returns::

    {"ok": True/False, "used": <int>, "limit": <int>, "plan": "<id>"}
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Plan registry
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_cents: int          # monthly price, USD cents
    asset_limit: int          # -1 = unlimited
    report_limit: int         # -1 = unlimited
    api_calls_limit: int      # -1 = unlimited, 0 = disabled
    api_enabled: bool
    saml_sso: bool
    features: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "price_cents": self.price_cents,
            "asset_limit": self.asset_limit,
            "report_limit": self.report_limit,
            "api_calls_limit": self.api_calls_limit,
            "api_enabled": self.api_enabled,
            "saml_sso": self.saml_sso,
            "features": list(self.features),
        }


_FREE = Plan(
    id="Free",
    name="Free",
    price_cents=0,
    asset_limit=25,
    report_limit=5,
    api_calls_limit=0,
    api_enabled=False,
    saml_sso=False,
    features=("Local-first scanning", "Community support",
              "Single-user", "All adapters"),
)

_PRO = Plan(
    id="Pro",
    name="Pro",
    price_cents=4900,
    asset_limit=250,
    report_limit=-1,
    api_calls_limit=100_000,
    api_enabled=True,
    saml_sso=False,
    features=("Everything in Free", "REST API",
              "Email support", "All integrations",
              "Compliance reports", "14-day free trial"),
)

_ENTERPRISE = Plan(
    id="Enterprise",
    name="Enterprise",
    price_cents=49900,
    asset_limit=-1,
    report_limit=-1,
    api_calls_limit=-1,
    api_enabled=True,
    saml_sso=True,
    features=("Everything in Pro", "SAML SSO",
              "Dedicated support", "Custom integrations",
              "SOC 2 attestation", "Audit log export"),
)


_REGISTRY: dict[str, Plan] = {
    "free": _FREE,
    "pro": _PRO,
    "enterprise": _ENTERPRISE,
}


def get_plan(plan_id: str) -> Plan:
    """Return the canonical Plan for ``plan_id`` (case-insensitive).

    Unknown ids fall through to ``Free`` — never raises, so callers
    can blindly trust the result.
    """
    key = (plan_id or "").strip().lower()
    return _REGISTRY.get(key, _FREE)


def list_plans() -> list[Plan]:
    """All plans in display order: Free → Pro → Enterprise."""
    return [_FREE, _PRO, _ENTERPRISE]


# --------------------------------------------------------------------------
# Per-org plan storage
# --------------------------------------------------------------------------


def _billing_path(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "billing.json"


def _read_billing(org_id: str) -> dict:
    path = _billing_path(org_id)
    if not path.exists():
        return {}
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write_billing(org_id: str, payload: dict) -> None:
    path = _billing_path(org_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def get_org_plan(org_id: str) -> Plan:
    """Return the org's current Plan. Missing org → Free."""
    if not org_id:
        return _FREE
    rec = _read_billing(org_id)
    return get_plan(rec.get("plan_id") or "Free")


def get_org_billing(org_id: str) -> dict:
    """Return the raw billing record (plan + status + Stripe ids)."""
    if not org_id:
        return {"plan_id": "Free", "status": "active", "source": "default"}
    rec = _read_billing(org_id)
    if not rec:
        return {"plan_id": "Free", "status": "active", "source": "default"}
    rec.setdefault("plan_id", "Free")
    rec.setdefault("status", "active")
    return rec


def set_org_plan(org_id: str, plan_id: str, *,
                  source: str = "manual",
                  status: str = "active",
                  stripe_customer_id: str | None = None,
                  stripe_subscription_id: str | None = None,
                  trial_ends_at: int | None = None) -> dict:
    """Assign ``plan_id`` to ``org_id`` and persist the metadata."""
    if not org_id:
        raise ValueError("org_id is required")
    plan = get_plan(plan_id)
    rec = _read_billing(org_id)
    rec.update({
        "plan_id": plan.id,
        "status": status,
        "source": source,
        "updated_at": int(time.time()),
    })
    if stripe_customer_id is not None:
        rec["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        rec["stripe_subscription_id"] = stripe_subscription_id
    if trial_ends_at is not None:
        rec["trial_ends_at"] = trial_ends_at
    _write_billing(org_id, rec)
    return rec


# --------------------------------------------------------------------------
# Quota enforcement
# --------------------------------------------------------------------------


_RESOURCE_LIMITS = {
    "assets": "asset_limit",
    "reports": "report_limit",
    "api_calls": "api_calls_limit",
}


def check_quota(org_id: str, resource: str) -> dict:
    """Return ``{ok, used, limit, plan}`` for ``resource`` in the current month.

    ``resource`` must be one of ``"assets"``, ``"reports"``, ``"api_calls"``.
    A limit of ``-1`` means unlimited — ``ok`` is always True.
    A limit of ``0`` means the feature is disabled — ``ok`` is always False
    once a single use is recorded.
    """
    if resource not in _RESOURCE_LIMITS:
        raise ValueError(f"Unknown resource: {resource!r}")
    plan = get_org_plan(org_id)
    limit = getattr(plan, _RESOURCE_LIMITS[resource])
    from safecadence.billing.usage import get_usage
    usage = get_usage(org_id, period="month")
    used = int(usage.get(resource) or 0)
    if limit == -1:
        ok = True
    elif limit == 0:
        ok = False
    else:
        ok = used < limit
    return {
        "ok": ok,
        "used": used,
        "limit": limit,
        "plan": plan.id,
        "resource": resource,
    }


def quota_error_payload(quota: dict, upgrade_url: str | None = None) -> dict:
    """Build the 402-style JSON body for a quota-exceeded response."""
    return {
        "error": "quota_exceeded",
        "resource": quota.get("resource"),
        "plan": quota.get("plan"),
        "used": quota.get("used"),
        "limit": quota.get("limit"),
        "upgrade_url": upgrade_url
            or "https://app.safecadence.com/portal/billing",
        "message": (
            f"You've used {quota.get('used')} of {quota.get('limit')} "
            f"{quota.get('resource')} on the {quota.get('plan')} plan. "
            "Upgrade to continue."
        ),
    }


__all__ = [
    "Plan",
    "get_plan",
    "list_plans",
    "get_org_plan",
    "get_org_billing",
    "set_org_plan",
    "check_quota",
    "quota_error_payload",
]
