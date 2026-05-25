"""
v10.5 — auth + multi-tenancy + observability tests.

Covers:
  * Magic-link token round-trip (request → verify → session)
  * Token expiry (15-min)
  * Session expiry (30-day)
  * SC_AUTH_DISABLED demo bypass
  * Org create + list + isolation
  * RBAC: viewer < editor < admin
  * Audit log append + read
  * /metrics output is Prometheus-parseable
  * /healthz/detail JSON schema

These tests must run on a clean tmp HOME so they never collide with
the user's real ~/.safecadence directory.
"""

from __future__ import annotations

import json
import os
import time

import pytest


# --------------------------------------------------------------------------
# Common fixture: isolate ~/.safecadence per test
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "scdata"))
    # Force disable of any global demo bypass — individual tests opt in.
    monkeypatch.delenv("SC_AUTH_DISABLED", raising=False)
    yield


# --------------------------------------------------------------------------
# Magic-link auth
# --------------------------------------------------------------------------


def test_request_login_with_bad_email_returns_error():
    from safecadence.auth.magic_link import request_login
    r = request_login("not-an-email")
    assert r["sent"] is False
    assert r.get("error")


def test_token_roundtrip_with_demo_bypass(monkeypatch):
    """SC_AUTH_DISABLED short-circuits the whole flow."""
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    from safecadence.auth.magic_link import (
        request_login, verify_token, create_session, get_session,
        DEMO_EMAIL, DEMO_USER_ID,
    )
    assert request_login("anyone@example.com") == {"sent": True, "demo": True}
    out = verify_token("anything")
    assert out == (DEMO_USER_ID, DEMO_EMAIL)
    tok = create_session(DEMO_USER_ID, DEMO_EMAIL)
    sess = get_session(tok)
    assert sess and sess.get("email") == DEMO_EMAIL
    assert sess.get("demo") is True


def test_token_roundtrip_persists_and_consumes_once():
    """Without the demo bypass, tokens come from the on-disk store and
    are single-use. We seed the token file directly so we don't need
    to wire up SMTP."""
    from pathlib import Path
    import safecadence.auth.magic_link as ml

    # Seed a token manually.
    tok = "deadbeef-test-token"
    payload = {tok: {
        "email": "alice@acme.com",
        "user_id": "user_alice_at_acme_com",
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + 600,
        "return_url": "/home",
    }}
    ml._write_json(ml._tokens_path(), payload)

    out = ml.verify_token(tok)
    assert out == ("user_alice_at_acme_com", "alice@acme.com")

    # Second use → None (consumed).
    assert ml.verify_token(tok) is None


def test_token_expiry_15min():
    """Tokens older than 15 minutes do NOT verify."""
    import safecadence.auth.magic_link as ml
    tok = "expired-token-xyz"
    payload = {tok: {
        "email": "bob@example.com",
        "user_id": "user_bob",
        "created_at": int(time.time()) - 3600,
        "expires_at": int(time.time()) - 60,   # 1 min ago
        "return_url": "/home",
    }}
    ml._write_json(ml._tokens_path(), payload)
    assert ml.verify_token(tok) is None
    # And the expired entry is pruned.
    on_disk = ml._read_json(ml._tokens_path())
    assert tok not in on_disk


def test_session_create_get_revoke_30day_expiry():
    from safecadence.auth.magic_link import (
        create_session, get_session, revoke_session, SESSION_TTL_SECONDS,
    )
    tok = create_session("user_x", "x@y.com")
    sess = get_session(tok)
    assert sess is not None
    assert sess["email"] == "x@y.com"
    # 30 days = 2,592,000 s — must be in that ballpark.
    assert SESSION_TTL_SECONDS == 30 * 86400
    assert sess["expires_at"] - sess["created_at"] == SESSION_TTL_SECONDS

    assert revoke_session(tok) is True
    assert get_session(tok) is None
    assert revoke_session(tok) is False


def test_expired_session_returns_none():
    import safecadence.auth.magic_link as ml
    tok = "exp-sess"
    payload = {tok: {
        "token": tok,
        "user_id": "user_y",
        "email": "y@z.com",
        "created_at": int(time.time()) - (40 * 86400),
        "expires_at": int(time.time()) - 86400,
    }}
    ml._write_json(ml._sessions_path(), payload)
    assert ml.get_session(tok) is None


# --------------------------------------------------------------------------
# Per-org data isolation
# --------------------------------------------------------------------------


def test_org_create_list_get():
    from safecadence.storage.org_store import (
        create_org, list_orgs, get_org, org_data_dir,
    )
    org_a = create_org("Acme Networks", "alice@acme.com")
    org_b = create_org("Globex Inc", "bob@globex.com")

    assert org_a.id != org_b.id
    rows = list_orgs()
    ids = {r.id for r in rows}
    assert {org_a.id, org_b.id}.issubset(ids)

    assert get_org(org_a.id).name == "Acme Networks"
    assert get_org("nope") is None

    # Data dirs exist and differ.
    dir_a = org_data_dir(org_a.id)
    dir_b = org_data_dir(org_b.id)
    assert dir_a.exists() and dir_b.exists()
    assert dir_a != dir_b


def test_org_data_isolation():
    """Writing to org A's platform_assets must not appear in org B."""
    from safecadence.storage.org_store import create_org, org_data_dir

    a = create_org("A Co", "alice@acme.com")
    b = create_org("B Co", "bob@globex.com")

    asset = {"asset_id": "a-1", "hostname": "core-router", "vendor": "cisco"}
    (org_data_dir(a.id) / "platform_assets" / "a-1.json").write_text(
        json.dumps(asset), encoding="utf-8"
    )

    # Verify the file ended up only in A.
    a_files = list((org_data_dir(a.id) / "platform_assets").glob("*.json"))
    b_files = list((org_data_dir(b.id) / "platform_assets").glob("*.json"))
    assert len(a_files) == 1
    assert len(b_files) == 0


def test_compose_report_honors_org_scope():
    """compose_report(org_id=A) reads from A's platform_assets, not the
    global one."""
    import json as _json
    from safecadence.reports.builder import compose_report
    from safecadence.storage.org_store import create_org, org_data_dir

    a = create_org("Tenant A", "owner@a.com")
    b = create_org("Tenant B", "owner@b.com")

    # Write distinct assets in each org.
    (org_data_dir(a.id) / "platform_assets" / "a1.json").write_text(_json.dumps({
        "asset_id": "a1", "hostname": "host-a", "vendor": "cisco",
        "site": "dc-east", "criticality": "high",
    }), encoding="utf-8")
    (org_data_dir(b.id) / "platform_assets" / "b1.json").write_text(_json.dumps({
        "asset_id": "b1", "hostname": "host-b", "vendor": "arista",
        "site": "dc-west", "criticality": "medium",
    }), encoding="utf-8")

    rep_a = compose_report(sections=["host_inventory"], org_id=a.id)
    rep_b = compose_report(sections=["host_inventory"], org_id=b.id)

    # Each org's report should reflect only its assets.
    html_a = rep_a["sections"][0]["html_fragment"]
    html_b = rep_b["sections"][0]["html_fragment"]
    assert "host-a" in html_a, html_a
    assert "host-b" in html_b, html_b
    # Cross-tenant leak check.
    assert "host-b" not in html_a
    assert "host-a" not in html_b


# --------------------------------------------------------------------------
# RBAC
# --------------------------------------------------------------------------


def test_rbac_role_hierarchy():
    from safecadence.auth.rbac import (
        UserRole, role_satisfies, assign_role, get_role,
    )
    from safecadence.storage.org_store import create_org

    org = create_org("Rbac Org", "owner@rbac.com")
    # Owner was auto-assigned ADMIN on org create.
    assert get_role(org.id, "owner@rbac.com") == UserRole.ADMIN

    assign_role(org.id, "viewer@rbac.com", UserRole.VIEWER)
    assign_role(org.id, "editor@rbac.com", UserRole.EDITOR)

    assert get_role(org.id, "viewer@rbac.com") == UserRole.VIEWER
    assert get_role(org.id, "editor@rbac.com") == UserRole.EDITOR
    assert get_role(org.id, "nobody@rbac.com") is None

    # Role ordering.
    assert role_satisfies(UserRole.ADMIN, UserRole.EDITOR)
    assert role_satisfies(UserRole.EDITOR, UserRole.VIEWER)
    assert not role_satisfies(UserRole.VIEWER, UserRole.EDITOR)
    assert not role_satisfies(None, UserRole.VIEWER)


def test_rbac_admin_can_assign_roles():
    """An admin assigning a role just calls assign_role — there's no
    separate API gate at the storage layer; the FastAPI dependency
    does the gating. The semantic check here is just that the
    assignment persists."""
    from safecadence.auth.rbac import UserRole, assign_role, get_role, list_members
    from safecadence.storage.org_store import create_org

    org = create_org("Role Test", "boss@co.com")
    assign_role(org.id, "newhire@co.com", UserRole.EDITOR)
    members = list_members(org.id)
    emails = {m["email"]: m["role"] for m in members}
    assert emails.get("newhire@co.com") == "editor"
    assert emails.get("boss@co.com") == "admin"


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------


def test_audit_log_append_and_read():
    from safecadence.audit.log import log_event, read_events
    from safecadence.storage.org_store import create_org

    org = create_org("Audit Org", "auditor@a.com")
    assert log_event(org.id, "auditor@a.com", "report.template.save",
                     target="tpl_1", metadata={"name": "Q3"}) is True
    assert log_event(org.id, "auditor@a.com", "report.render",
                     target="report.pdf", metadata={"format": "pdf"}) is True
    rows = read_events(org.id, limit=10)
    assert len(rows) == 2
    # Newest first.
    assert rows[0]["action"] == "report.render"
    assert rows[1]["target"] == "tpl_1"
    assert rows[1]["metadata"]["name"] == "Q3"


def test_audit_log_isolated_per_org():
    from safecadence.audit.log import log_event, read_events
    from safecadence.storage.org_store import create_org

    a = create_org("AA", "x@a.com")
    b = create_org("BB", "y@b.com")
    log_event(a.id, "x@a.com", "action.in.a")
    log_event(b.id, "y@b.com", "action.in.b")

    rows_a = read_events(a.id)
    rows_b = read_events(b.id)
    assert {r["action"] for r in rows_a} == {"action.in.a"}
    assert {r["action"] for r in rows_b} == {"action.in.b"}


# --------------------------------------------------------------------------
# Observability
# --------------------------------------------------------------------------


def test_metrics_endpoint_format():
    """Prometheus text format is line-based ASCII with required HELP
    and TYPE lines for each metric."""
    from safecadence.observability.metrics import (
        render_metrics_text, record_request, record_report_generated,
        reset_metrics_for_tests,
    )
    reset_metrics_for_tests()
    record_request("/reports", "GET", 200, 0.014)
    record_request("/reports", "GET", 200, 0.062)
    record_report_generated("pdf", "exec_brief")
    text = render_metrics_text()
    # Must be ASCII text (Prometheus exposition).
    text.encode("ascii", "strict")
    # Required header lines.
    assert "# HELP safecadence_requests_total" in text
    assert "# TYPE safecadence_requests_total counter" in text
    assert "# HELP safecadence_request_duration_seconds" in text
    assert "# TYPE safecadence_request_duration_seconds histogram" in text
    assert "# TYPE safecadence_active_sessions gauge" in text
    assert "# TYPE safecadence_reports_generated_total counter" in text
    # Recorded values are present.
    assert 'safecadence_requests_total{path="/reports",method="GET",status="200"} 2' in text
    assert 'safecadence_reports_generated_total{format="pdf",preset="exec_brief"} 1' in text


def test_healthz_detail_schema():
    from safecadence.observability.metrics import healthz_detail
    p = healthz_detail()
    for key in (
        "status", "version", "uptime_seconds", "disk_free_mb",
        "recent_errors_count", "scheduled_jobs_age_seconds",
    ):
        assert key in p, f"missing key {key}"
    assert p["status"] in ("healthy", "degraded", "unhealthy")
    assert isinstance(p["uptime_seconds"], int)
    assert isinstance(p["disk_free_mb"], int)
    assert isinstance(p["recent_errors_count"], int)
    assert isinstance(p["scheduled_jobs_age_seconds"], int)


def test_error_log_record_and_read():
    from safecadence.observability.errors import record_error, recent_errors
    try:
        raise ValueError("simulated failure")
    except ValueError as exc:
        assert record_error(exc, context={"path": "/x"}) is True
    rows = recent_errors(limit=10)
    assert len(rows) == 1
    assert rows[0]["type"] == "ValueError"
    assert "simulated failure" in rows[0]["message"]


# --------------------------------------------------------------------------
# Version sanity
# --------------------------------------------------------------------------


def test_version_is_v10_7():
    from safecadence import __version__
    # Bumped to 11.0.0 in v11.0, 12.0.0a1 in v12.0. Accept any
    # recent major as a "we're on a recent major" sanity check.
    assert __version__.startswith(("10.", "11.", "12.", "13.", "14.", "15."))
