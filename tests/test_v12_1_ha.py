"""
Tests for v12.1 — High availability (active/standby) layer.

Covers:
  * cluster/guards.py    — @active_only, require_active, is_standby
  * cluster/replication_lag.py — single-node + no-driver fallbacks
  * /api/v1/cluster/status route shape
  * /api/v1/cluster/transfer route behavior (single-node + simulated standby)
  * mutation guard integration: send_webhook + send_email + run_due
    + run_due_schedules all short-circuit on standby

The cluster/failover.py Redis loop is tested via monkey-patching
am_i_active so we don't need a live Redis in CI.
"""
from __future__ import annotations

import os

import pytest


# Make sure the lease loop never starts during tests.
os.environ.pop("SC_REDIS_URL", None)


# --------------------------------------------------------------------------
# guards.py
# --------------------------------------------------------------------------


def test_guards_is_standby_false_in_single_node_mode():
    from safecadence.cluster.guards import is_standby
    assert is_standby() is False


def test_guards_active_only_passes_through_when_active():
    from safecadence.cluster.guards import active_only

    @active_only()
    def w(x): return x * 2

    assert w(5) == 10


def test_guards_active_only_returns_default_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    from safecadence.cluster.guards import active_only

    monkeypatch.setattr(fo, "am_i_active", lambda: False)

    @active_only(default_return={"skipped": "standby"})
    def w(x): return {"got": x}

    assert w("ignored") == {"skipped": "standby"}


def test_guards_active_only_raises_when_configured(monkeypatch):
    import safecadence.cluster.failover as fo
    from safecadence.cluster.guards import IsStandbyError, active_only

    monkeypatch.setattr(fo, "am_i_active", lambda: False)

    @active_only(raise_on_standby=True)
    def w(): return "did it"

    with pytest.raises(IsStandbyError):
        w()


def test_guards_require_active_raises_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    from safecadence.cluster.guards import IsStandbyError, require_active

    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    with pytest.raises(IsStandbyError):
        require_active()


def test_guards_defensive_when_failover_module_raises(monkeypatch):
    """If am_i_active() itself raises, we should ACT AS active."""
    import safecadence.cluster.failover as fo
    from safecadence.cluster.guards import is_standby

    def boom():
        raise RuntimeError("redis exploded")
    monkeypatch.setattr(fo, "am_i_active", boom)
    # is_standby returns False on exception → guards treat us as active
    assert is_standby() is False


# --------------------------------------------------------------------------
# replication_lag.py
# --------------------------------------------------------------------------


def test_replication_lag_no_database_url_returns_unknown(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from safecadence.cluster.replication_lag import probe_lag
    p = probe_lag()
    assert p["status"] == "unknown"
    assert p["role"] == "unknown"
    assert "DATABASE_URL" in p["note"]


def test_replication_lag_sqlite_url_returns_unknown(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///tmp/x.db")
    from safecadence.cluster.replication_lag import probe_lag
    p = probe_lag()
    assert p["status"] == "unknown"


def test_replication_lag_safe_to_failover_when_unknown(monkeypatch):
    """No Postgres = nothing to wait for = safe."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from safecadence.cluster.replication_lag import is_safe_to_failover
    assert is_safe_to_failover() is True


def test_replication_lag_fake_postgres_degrades_to_unknown(monkeypatch):
    monkeypatch.setenv("DATABASE_URL",
                       "postgresql://fake:fake@127.0.0.1:5432/nope")
    from safecadence.cluster.replication_lag import probe_lag
    p = probe_lag()
    # Either psycopg isn't installed, or it can't reach the fake host —
    # either way, "unknown" not a crash.
    assert p["status"] == "unknown"


# --------------------------------------------------------------------------
# /api/v1/cluster/* routes
# --------------------------------------------------------------------------


@pytest.fixture()
def client():
    os.environ["SC_AUTH_DISABLED"] = "1"
    os.environ.pop("SC_REDIS_URL", None)
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def test_route_cluster_status_returns_expected_keys(client):
    r = client.get("/api/v1/cluster/status")
    assert r.status_code == 200
    d = r.json()
    for key in ("local", "peers", "peer_count", "reachable_peers",
                "healthy", "replication_lag"):
        assert key in d, f"missing key: {key}"


def test_route_cluster_status_single_node_is_active(client):
    r = client.get("/api/v1/cluster/status")
    d = r.json()
    assert d["local"]["is_active_node"] is True
    assert d["peer_count"] == 0
    assert d["replication_lag"]["status"] == "unknown"


def test_route_cluster_transfer_single_node_releases(client):
    """In single-node mode, am_i_active is True so transfer "succeeds"
    by releasing the (fake) lease; second call becomes a noop."""
    r1 = client.post("/api/v1/cluster/transfer")
    assert r1.status_code == 200
    assert r1.json()["action"] in ("released", "noop")


def test_route_cluster_transfer_standby_is_noop(client, monkeypatch):
    import safecadence.cluster.failover as fo
    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    r = client.post("/api/v1/cluster/transfer")
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "noop"


# --------------------------------------------------------------------------
# Mutation guard integration
# --------------------------------------------------------------------------


def test_send_webhook_skips_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    from safecadence.notifier.providers import send_webhook
    ok, msg = send_webhook(
        provider="slack",
        url="https://hooks.slack.com/services/T/B/X",
        event={"title": "test"},
    )
    assert ok is False
    assert "standby" in msg.lower()


def test_send_email_skips_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    from safecadence.notifier.email_notifier import send_email
    ok, msg = send_email(to="ops@example.com",
                          subject="t", body="b")
    assert ok is False
    assert "standby" in msg.lower()


def test_report_scheduler_skips_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    from safecadence.reports.scheduler import run_due
    out = run_due()
    assert isinstance(out, list)
    assert any("standby" in str(r).lower() for r in out)


def test_evidence_scheduler_skips_on_standby(monkeypatch):
    import safecadence.cluster.failover as fo
    monkeypatch.setattr(fo, "am_i_active", lambda: False)
    from safecadence.compliance.evidence_schedule import run_due_schedules
    out = run_due_schedules()
    assert isinstance(out, list)
    assert any("standby" in str(r).lower() for r in out)
