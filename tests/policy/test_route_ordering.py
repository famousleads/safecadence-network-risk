"""Regression test for the v5.0/v5.1 route-ordering bug.

The bug: FastAPI matches routes in registration order. When the catch-all
`/api/policy/{pid}` (or `/api/platform/correlate/{asset_id}`) is declared
BEFORE its sibling static paths (`/api/policy/audit`, `/api/policy/ui`,
`/api/platform/correlate/orphans`, etc.), the catch-all swallows them and
returns 404 because no policy/asset by that "name" exists.

These tests verify each known-static path actually resolves to its
intended handler — not the catch-all.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def client():
    os.environ.setdefault("SC_JWT_SECRET", "test")
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def _is_not_pid_404(resp) -> bool:
    """Returns True if the response did NOT come from the {pid} catch-all."""
    if resp.status_code == 200:
        return True
    # FastAPI 404s with detail "policy not found: <name>" / "asset not found: <name>"
    # are the smoking gun that the catch-all swallowed the request.
    body = resp.text or ""
    return "policy not found" not in body and "asset not found" not in body


def test_policy_audit_does_not_get_swallowed(client):
    r = client.get("/api/policy/audit")
    assert _is_not_pid_404(r), f"swallowed by /{{pid}}: {r.status_code} {r.text}"
    assert r.status_code == 200
    assert "events" in r.json()


def test_policy_compliance_does_not_get_swallowed(client):
    r = client.get("/api/policy/compliance")
    assert _is_not_pid_404(r), f"swallowed by /{{pid}}: {r.status_code} {r.text}"
    assert r.status_code == 200
    assert "policies" in r.json()


def test_policy_shadow_does_not_get_swallowed(client):
    r = client.get("/api/policy/shadow")
    assert _is_not_pid_404(r), f"swallowed by /{{pid}}: {r.status_code} {r.text}"
    assert r.status_code == 200
    assert "shadow_assets" in r.json()


def test_policy_webhooks_does_not_get_swallowed(client):
    r = client.get("/api/policy/webhooks")
    assert _is_not_pid_404(r), f"swallowed by /{{pid}}: {r.status_code} {r.text}"
    assert r.status_code == 200


def test_policy_ui_does_not_get_swallowed(client):
    r = client.get("/api/policy/ui")
    assert _is_not_pid_404(r), f"swallowed by /{{pid}}: {r.status_code} {r.text}"
    assert r.status_code == 200
    # Must return HTML, not the JSON 404 from the catch-all
    assert "text/html" in r.headers.get("content-type", "")
    assert "<html" in r.text.lower()


def test_platform_correlate_orphans_does_not_get_swallowed(client):
    r = client.get("/api/platform/correlate/orphans")
    assert _is_not_pid_404(r), f"swallowed by /correlate/{{asset_id}}: {r.status_code} {r.text}"
    assert r.status_code == 200
    assert "orphans" in r.json()


def test_platform_reports_does_not_get_swallowed_by_report_id(client):
    """The bare /reports endpoint must work (not be matched as report_id="")."""
    r = client.get("/api/platform/reports")
    assert r.status_code == 200
    assert "reports" in r.json()


def test_platform_reports_specific_report_works(client):
    r = client.get("/api/platform/reports/risk_register")
    assert r.status_code == 200
    body = r.json()
    assert "title" in body or "summary" in body


def test_platform_ui_does_not_get_swallowed(client):
    r = client.get("/api/platform/ui")
    assert _is_not_pid_404(r), f"swallowed: {r.status_code} {r.text}"
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
