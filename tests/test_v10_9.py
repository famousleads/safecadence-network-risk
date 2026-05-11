"""
v10.9 tests — Stripe billing, plan quotas, usage metering, signup flow,
customer portal, pricing page asset.

Every external service (Stripe API, SMTP) is mocked. None of these tests
hit the network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "sc_data"))
    # Wipe relevant env so each test sees a deterministic configuration.
    for var in (
        "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_PRO", "STRIPE_PRICE_ENTERPRISE",
        "STRIPE_SUCCESS_URL", "STRIPE_CANCEL_URL",
        "SC_AUTH_DISABLED", "SC_READONLY",
        "SC_SMTP_HOST", "SC_SMTP_FROM",
        "SC_PUBLIC_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    # Auth disabled keeps the portal happy without magic-link flow.
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    yield


def _new_org(name="acme", email="alice@acme.com"):
    from safecadence.storage.org_store import create_org
    return create_org(name=name, owner_email=email)


# --------------------------------------------------------------------------
# 1. Stripe client
# --------------------------------------------------------------------------


def test_stripe_client_raises_when_not_configured(monkeypatch):
    from safecadence.billing import stripe_client
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    assert stripe_client.is_configured() is False
    with pytest.raises(stripe_client.BillingNotConfigured):
        stripe_client.create_customer("a@b.com")
    with pytest.raises(stripe_client.BillingNotConfigured):
        stripe_client.create_checkout_session(
            "Pro", "a@b.com",
            "https://x/success", "https://x/cancel",
        )


def test_stripe_client_price_id_lookup(monkeypatch):
    from safecadence.billing.stripe_client import price_id_for_plan
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_real_pro")
    monkeypatch.setenv("STRIPE_PRICE_ENTERPRISE", "price_real_ent")
    assert price_id_for_plan("Pro") == "price_real_pro"
    assert price_id_for_plan("Enterprise") == "price_real_ent"
    assert price_id_for_plan("Free") == ""


def test_stripe_client_create_customer_mocked(monkeypatch):
    """Verify the request shape + response parsing without hitting the network."""
    from safecadence.billing import stripe_client
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_xxx")

    captured: dict = {}

    def fake_request(method, path, *, form=None, timeout=15.0):
        captured["method"] = method
        captured["path"] = path
        captured["form"] = form
        return {"id": "cus_TEST123", "email": form.get("email")}

    monkeypatch.setattr(stripe_client, "_request", fake_request)
    cid = stripe_client.create_customer("Alice@Acme.com",
                                          metadata={"org_id": "org_x"})
    assert cid == "cus_TEST123"
    assert captured["method"] == "POST"
    assert captured["path"] == "/customers"
    assert captured["form"]["email"] == "alice@acme.com"
    assert captured["form"]["metadata"] == {"org_id": "org_x"}


# --------------------------------------------------------------------------
# 2. Webhook signature verification
# --------------------------------------------------------------------------


def test_webhook_signature_valid(monkeypatch):
    from safecadence.billing.webhook import verify_webhook_signature
    secret = "whsec_test"
    body = b'{"id":"evt_1","type":"invoice.paid"}'
    ts = str(int(time.time()))
    signed = f"{ts}.".encode() + body
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={ts},v1={sig}"
    assert verify_webhook_signature(body, header, secret) is True


def test_webhook_signature_invalid(monkeypatch):
    from safecadence.billing.webhook import verify_webhook_signature
    secret = "whsec_test"
    body = b'{"id":"evt_2"}'
    ts = str(int(time.time()))
    sig = "deadbeef" * 8  # wrong
    header = f"t={ts},v1={sig}"
    assert verify_webhook_signature(body, header, secret) is False
    # Missing header
    assert verify_webhook_signature(body, "", secret) is False
    # Missing secret
    assert verify_webhook_signature(body, header, "") is False


def test_webhook_signature_replay_rejected(monkeypatch):
    from safecadence.billing.webhook import verify_webhook_signature
    secret = "whsec_test"
    body = b'{"id":"evt_3"}'
    ts = str(int(time.time()) - 999_999)  # ancient
    signed = f"{ts}.".encode() + body
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={ts},v1={sig}"
    assert verify_webhook_signature(body, header, secret) is False


def test_webhook_event_dispatch_checkout_completed(monkeypatch):
    from safecadence.billing.webhook import handle_event
    from safecadence.billing.plans import get_org_billing
    org = _new_org()
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "metadata": {"org_id": org.id, "plan": "Pro"},
            "customer": "cus_x",
            "subscription": "sub_x",
        }},
    }
    out = handle_event(event)
    assert out["handled"] is True
    assert out["plan"] == "Pro"
    rec = get_org_billing(org.id)
    assert rec["plan_id"] == "Pro"
    assert rec["stripe_customer_id"] == "cus_x"


def test_webhook_event_payment_failed_marks_past_due(monkeypatch):
    from safecadence.billing.webhook import handle_event
    from safecadence.billing.plans import set_org_plan, get_org_billing
    org = _new_org()
    set_org_plan(org.id, "Pro", stripe_customer_id="cus_x",
                  stripe_subscription_id="sub_x")
    event = {
        "type": "invoice.payment_failed",
        "data": {"object": {"metadata": {"org_id": org.id}}},
    }
    out = handle_event(event)
    assert out["handled"] is True
    rec = get_org_billing(org.id)
    assert rec["status"] == "past_due"


# --------------------------------------------------------------------------
# 3. Plans + quota
# --------------------------------------------------------------------------


def test_plan_registry_basics():
    from safecadence.billing.plans import get_plan, list_plans
    free = get_plan("Free")
    pro = get_plan("pro")
    ent = get_plan("Enterprise")
    assert free.asset_limit == 25
    assert pro.asset_limit == 250
    assert ent.asset_limit == -1
    assert pro.api_enabled is True
    assert ent.saml_sso is True
    assert [p.id for p in list_plans()] == ["Free", "Pro", "Enterprise"]


def test_set_and_get_org_plan(monkeypatch):
    from safecadence.billing.plans import (
        set_org_plan, get_org_plan, get_org_billing,
    )
    org = _new_org()
    assert get_org_plan(org.id).id == "Free"
    set_org_plan(org.id, "Pro", source="manual",
                  stripe_customer_id="cus_y")
    assert get_org_plan(org.id).id == "Pro"
    assert get_org_billing(org.id)["stripe_customer_id"] == "cus_y"


def test_quota_exceeded_returns_402_shape(monkeypatch):
    from safecadence.billing.plans import check_quota, quota_error_payload
    from safecadence.billing.usage import record_usage
    org = _new_org()
    # Free plan: 25 asset cap. Record 25 hits.
    for _ in range(25):
        record_usage(org.id, "assets")
    q = check_quota(org.id, "assets")
    assert q["limit"] == 25
    assert q["used"] >= 25
    assert q["ok"] is False
    body = quota_error_payload(q)
    assert body["error"] == "quota_exceeded"
    assert body["plan"] == "Free"
    assert body["used"] >= 25
    assert "upgrade_url" in body


def test_quota_api_disabled_on_free(monkeypatch):
    from safecadence.billing.plans import check_quota
    org = _new_org()
    q = check_quota(org.id, "api_calls")
    # Free plan disables the API entirely → ok=False from the start.
    assert q["limit"] == 0
    assert q["ok"] is False


def test_quota_unlimited_on_enterprise(monkeypatch):
    from safecadence.billing.plans import set_org_plan, check_quota
    from safecadence.billing.usage import record_usage
    org = _new_org()
    set_org_plan(org.id, "Enterprise")
    for _ in range(1000):
        record_usage(org.id, "assets")
    q = check_quota(org.id, "assets")
    assert q["limit"] == -1
    assert q["ok"] is True


# --------------------------------------------------------------------------
# 4. Usage metering
# --------------------------------------------------------------------------


def test_record_and_aggregate_usage(monkeypatch):
    from safecadence.billing.usage import record_usage, get_usage
    org = _new_org()
    record_usage(org.id, "reports", count=2)
    record_usage(org.id, "reports")
    record_usage(org.id, "api_calls", count=10)
    record_usage(org.id, "assets", count=5)
    out = get_usage(org.id, period="month")
    assert out["reports"] == 3
    assert out["api_calls"] == 10
    assert out["assets"] == 5
    assert out["period"]   # YYYY-MM string


def test_usage_history_returns_n_months(monkeypatch):
    from safecadence.billing.usage import record_usage, get_usage_history
    org = _new_org()
    record_usage(org.id, "reports", count=3)
    rows = get_usage_history(org.id, "reports", months=4)
    assert len(rows) == 4
    # Last row is the current month and should have the count we recorded.
    assert rows[-1]["count"] == 3


def test_usage_readonly_is_noop(monkeypatch):
    from safecadence.billing.usage import record_usage, get_usage
    org = _new_org()
    monkeypatch.setenv("SC_READONLY", "1")
    assert record_usage(org.id, "reports") is None
    out = get_usage(org.id)
    assert out["reports"] == 0


def test_usage_unknown_resource_rejected(monkeypatch):
    from safecadence.billing.usage import record_usage
    org = _new_org()
    with pytest.raises(ValueError, match="resource"):
        record_usage(org.id, "bogus")


# --------------------------------------------------------------------------
# 5. Signup
# --------------------------------------------------------------------------


def test_signup_round_trip_free_plan(monkeypatch):
    from safecadence.auth import signup
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    result = signup.request_signup("bob@beta.com", "Beta Inc", plan="Free")
    assert result["sent"] is True
    token = result["token"]
    out = signup.verify_signup(token)
    assert out["ok"] is True
    assert out["plan"] == "Free"
    assert out["org_id"].startswith("org_")
    assert out["session_token"]
    # Owner has ADMIN role.
    from safecadence.auth.rbac import get_role, UserRole
    assert get_role(out["org_id"], "bob@beta.com") == UserRole.ADMIN


def test_signup_paid_plan_attempts_checkout_when_configured(monkeypatch):
    """Pro signup should produce a checkout URL when Stripe is configured."""
    from safecadence.auth import signup
    from safecadence.billing import stripe_client
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_xxx")
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")

    def fake_create(*args, **kwargs):
        return {"url": "https://checkout.stripe.com/c/test",
                "session_id": "cs_test"}

    monkeypatch.setattr(stripe_client, "create_checkout_session", fake_create)
    result = signup.request_signup("carol@c.com", "C Corp", plan="Pro")
    out = signup.verify_signup(result["token"])
    assert out["ok"] is True
    assert out["plan"] == "Pro"
    assert out["checkout_url"] == "https://checkout.stripe.com/c/test"


def test_signup_bad_email_rejected(monkeypatch):
    from safecadence.auth import signup
    out = signup.request_signup("notanemail", "Org")
    assert out["sent"] is False
    assert "email" in (out.get("error") or "").lower()


def test_signup_token_expired(monkeypatch, tmp_path):
    from safecadence.auth import signup
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    result = signup.request_signup("dave@d.com", "D Co", plan="Free")
    # Tamper the persisted record to be expired.
    path = signup._signups_path()
    payload = json.loads(path.read_text())
    for v in payload.values():
        v["expires_at"] = int(time.time()) - 1
    path.write_text(json.dumps(payload))
    out = signup.verify_signup(result["token"])
    assert out["ok"] is False
    assert "expired" in (out.get("error") or "").lower()


def test_signup_readonly_refused(monkeypatch):
    from safecadence.auth import signup
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        signup.request_signup("e@e.com", "E Co", plan="Free")


# --------------------------------------------------------------------------
# 6. Customer portal
# --------------------------------------------------------------------------


def _portal_app():
    """Build a minimal FastAPI app with just the v10.9 routers for testing."""
    from fastapi import FastAPI
    app = FastAPI()
    # Auth routes provide the session machinery the portal depends on.
    from safecadence.auth.routes import router as auth_router
    if auth_router is not None:
        app.include_router(auth_router)
    from safecadence.auth.signup_routes import router as signup_router
    if signup_router is not None:
        app.include_router(signup_router)
    from safecadence.billing.routes import router as billing_router
    if billing_router is not None:
        app.include_router(billing_router)
    from safecadence.portal.customer import router as portal_router
    if portal_router is not None:
        app.include_router(portal_router)
    return app


def test_portal_dashboard_renders_sections(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    org = _new_org()
    app = _portal_app()
    with TestClient(app) as client:
        resp = client.get("/portal", cookies={"sc_org": org.id})
        assert resp.status_code == 200
        body = resp.text
        # Every navigation section is present.
        for word in ("Overview", "Billing", "Team", "Usage", "Support",
                     "Current plan", "Free"):
            assert word in body, f"missing {word!r} in dashboard HTML"


def test_portal_billing_lists_plans(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    org = _new_org()
    app = _portal_app()
    with TestClient(app) as client:
        resp = client.get("/portal/billing", cookies={"sc_org": org.id})
        assert resp.status_code == 200
        body = resp.text
        assert "Pro" in body
        assert "Enterprise" in body
        assert "Free" in body


def test_billing_plans_api_public(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    app = _portal_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/billing/plans")
        assert resp.status_code == 200
        data = resp.json()
        assert [p["id"] for p in data["plans"]] == ["Free", "Pro", "Enterprise"]


def test_billing_checkout_503_when_stripe_unset(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _portal_app()
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/billing/checkout",
            json={"plan": "Pro", "org_id": "org_x", "email": "a@b.com"},
        )
        assert resp.status_code == 503
        assert resp.json()["error"] == "billing_not_configured"


# --------------------------------------------------------------------------
# 7. Pricing page asset
# --------------------------------------------------------------------------


def test_pricing_page_present_in_outputs_dir():
    """The mirrored pricing page exists and contains the three plan names."""
    # Walk up from this test file: tests/test_v10_9.py -> repo root.
    repo_root = Path(__file__).resolve().parent.parent
    # The outputs/safecadence-site/ dir is a SIBLING of the repo root.
    candidates = [
        repo_root.parent / "outputs" / "safecadence-site" / "pricing" / "index.html",
        Path("/sessions/happy-zealous-ritchie/mnt/outputs/safecadence-site/pricing/index.html"),
        Path.home() / ("Library/Application Support/Claude/local-agent-mode-sessions/"
                       "ae432b8a-abf6-4496-91e5-af7058585363/"
                       "8fc9522b-fae9-48e2-b393-36dd7e291571/"
                       "local_9b3100bc-acaf-43b2-812b-92ddac5020d8/"
                       "outputs/safecadence-site/pricing/index.html"),
    ]
    found = None
    for p in candidates:
        if p.exists():
            found = p
            break
    if not found:
        pytest.skip("pricing page asset is a deploy artifact — skipped when "
                    "outputs/ dir is not present in this environment")
    text = found.read_text(encoding="utf-8")
    for token in ("Free", "Pro", "Enterprise"):
        assert token in text, f"pricing page missing {token!r}"
    assert "/srv/safecadence/sites/safecadence.com" in text   # path comment
