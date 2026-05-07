"""
v9.36 — Discover section audit fixes.

Tests pin the four fixes from `docs/v9.36-discover-audit.md`:
  1. fire_job is the single source of truth used by both daemon + HTTP
  2. validate_params catches missing required keys at create time
  3. /coverage recommendations include a `reason` field
  4. /api/platform/discovery-jobs/sources lists supported sources +
     required params per source
"""

from __future__ import annotations

import os
import pytest

from safecadence.intel import discovery_jobs as DJ
from safecadence.intel.coverage import compute_coverage


# ---------------------------------------------------------- #1 fire_job


def test_fire_job_is_module_level_callable():
    """The whole point of v9.36 was to make fire_job available outside
    the daemon. Confirm the module exposes it."""
    assert callable(DJ.fire_job)


def test_fire_job_rejects_unknown_source():
    j = DJ.DiscoveryJob(job_id="t1", name="t", source="not-a-source",
                         params={})
    ok, err = DJ.fire_job(j)
    assert ok is False
    assert "must be one of" in err


def test_fire_job_rejects_missing_required_params(tmp_path, monkeypatch):
    """A job that's somehow saved with bad params should fail at fire
    time too — defense in depth (in addition to v9.36 #2's create-time
    check)."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    j = DJ.DiscoveryJob(job_id="t-snmp-bad", name="bad",
                         source="snmp", params={})  # missing host
    ok, err = DJ.fire_job(j)
    assert ok is False
    assert "host" in err


# ----------------------------------------------------- #2 validate_params


def test_validate_params_lan_scan_requires_cidr():
    ok, err = DJ.validate_params("lan-scan", {})
    assert ok is False and "cidr" in err

    ok, err = DJ.validate_params("lan-scan", {"cidr": "10.0.0.0/24"})
    assert ok is True and err == ""


def test_validate_params_snmp_requires_host():
    ok, err = DJ.validate_params("snmp", {"community": "public"})
    assert ok is False and "host" in err

    ok, err = DJ.validate_params("snmp", {"host": "10.0.0.1"})
    assert ok is True


def test_validate_params_ad_requires_server_and_base_dn():
    # missing both
    ok, err = DJ.validate_params("ad", {})
    assert ok is False
    assert "server" in err and "base_dn" in err
    # only server
    ok, _ = DJ.validate_params("ad", {"server": "ad.acme.local"})
    assert ok is False
    # both
    ok, _ = DJ.validate_params("ad",
                                {"server": "ad.acme.local",
                                 "base_dn": "dc=acme,dc=local"})
    assert ok is True


def test_validate_params_entra_requires_three_keys():
    ok, err = DJ.validate_params("entra", {"tenant_id": "t"})
    assert ok is False
    assert "client_id" in err and "client_secret" in err


def test_validate_params_dhcp_has_no_required_keys():
    """DHCP defaults to /var/lib/dhcp/dhcpd.leases, so an empty params
    dict is OK at create time (the runner will still error if the file
    doesn't exist)."""
    ok, _ = DJ.validate_params("dhcp", {})
    assert ok is True


def test_validate_params_unknown_source_rejected():
    ok, err = DJ.validate_params("badsource", {"x": 1})
    assert ok is False
    assert "must be one of" in err


def test_create_job_rejects_missing_params_at_create_time(tmp_path, monkeypatch):
    """Before v9.36 you could save a job that would only fail at the
    first fire. Now create_job raises ValueError so the HTTP endpoint
    returns 400 and the operator sees the problem immediately."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        DJ.create_job(name="bad", source="lan-scan", params={})
    assert "cidr" in str(exc.value)


def test_create_job_succeeds_with_valid_params(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    j = DJ.create_job(name="good", source="lan-scan",
                       params={"cidr": "10.0.0.0/24"},
                       interval_hours=12)
    assert j.job_id
    assert j.source == "lan-scan"
    assert j.params == {"cidr": "10.0.0.0/24"}
    # next_run_at populated for enabled jobs
    assert j.next_run_at


# -------------------------------------------------- #3 /coverage reason


def test_coverage_recommendations_have_reason_field():
    out = compute_coverage([])      # empty fleet → all sources missing
    recs = out.get("recommendations", [])
    # Empty fleet → at least snmp + ad recs surface as high priority
    assert recs, "coverage should surface recs on empty fleet"
    for r in recs:
        assert "reason" in r, f"rec missing 'reason': {r}"
        assert r["reason"], f"rec has empty reason: {r}"


def test_coverage_high_priority_sources_have_distinguishing_reasons():
    out = compute_coverage([])
    by_key = {r["source_key"]: r for r in out["recommendations"]}
    # snmp + ad both rank high but for different reasons
    assert by_key["snmp"]["priority"] == "high"
    assert by_key["ad"]["priority"] == "high"
    assert by_key["snmp"]["reason"] != by_key["ad"]["reason"]


# ----------------------------------------------- #4 sources endpoint


def test_supported_sources_and_required_params_in_sync():
    """REQUIRED_PARAMS keys must be a subset of SUPPORTED_SOURCES — if a
    new source is added one place it must be added the other place too,
    or validate_params silently passes."""
    extra = set(DJ.REQUIRED_PARAMS) - set(DJ.SUPPORTED_SOURCES)
    assert not extra, (
        f"REQUIRED_PARAMS has sources not in SUPPORTED_SOURCES: {extra}"
    )


def test_source_descriptions_cover_every_supported_source():
    """Every supported source needs a UI-facing description so the
    /sources endpoint can render it. Catches drift when adding a
    source."""
    missing = [s for s in DJ.SUPPORTED_SOURCES
               if s not in DJ.SOURCE_DESCRIPTIONS]
    assert not missing, (
        f"SOURCE_DESCRIPTIONS missing entries for: {missing}"
    )


# --------------------------------------------- #5 daemon shim is thin


def test_daemon_fire_discovery_job_delegates_to_intel_module(tmp_path,
                                                              monkeypatch):
    """The daemon's _fire_discovery_job is now a thin shim that calls
    intel.discovery_jobs.fire_job. Patch fire_job and confirm the
    daemon shim picks up the override."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence import daemon as DAEMON

    captured: dict = {}

    def fake_fire(job):
        captured["job_id"] = job.job_id
        return True, ""

    monkeypatch.setattr(DJ, "fire_job", fake_fire)

    j = DJ.DiscoveryJob(job_id="shim-test", name="t",
                         source="lan-scan",
                         params={"cidr": "10.0.0.0/24"})
    ok, err = DAEMON._fire_discovery_job(j)
    assert ok is True
    assert captured["job_id"] == "shim-test"


# -------------------------------------- HTTP endpoint smoke (run-now)


@pytest.mark.skipif("not _has_fastapi()")
def test_run_now_calls_fire_job_and_records_real_outcome(
    tmp_path, monkeypatch
):
    """Before v9.36 this endpoint stamped ok=True without firing.
    Now it must call fire_job and persist the actual outcome."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")

    import yaml
    from safecadence.server.auth import hash_password
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [{
            "username": "alice",
            "password_hash": hash_password("hunter2"),
            "roles": ["admin"],
        }]}}
    }))

    from fastapi.testclient import TestClient
    from safecadence.server import create_app

    # Create a job with known params so we can verify fire_job got it
    DJ.create_job(name="rn-test", source="lan-scan",
                   params={"cidr": "10.99.0.0/24"})
    job_id = next(j.job_id for j in DJ.list_jobs())

    # Stub fire_job so we don't actually probe a network
    fired: list = []

    def fake_fire(job):
        fired.append((job.job_id, job.source, dict(job.params)))
        return True, ""

    monkeypatch.setattr(DJ, "fire_job", fake_fire)

    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret")
    c = TestClient(app)
    r = c.post("/api/login",
                data={"username": "alice", "password": "hunter2"})
    tok = r.json()["access_token"]
    hdr = {"Authorization": f"Bearer {tok}"}

    r = c.post(f"/api/platform/discovery-jobs/{job_id}/run-now",
                headers=hdr)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["status"] == "ok"
    assert body["source"] == "lan-scan"
    # fire_job actually got called with the real job's params
    assert fired and fired[0][2] == {"cidr": "10.99.0.0/24"}


@pytest.mark.skipif("not _has_fastapi()")
def test_sources_endpoint_lists_every_supported_source(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")

    import yaml
    from safecadence.server.auth import hash_password
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [{
            "username": "alice",
            "password_hash": hash_password("hunter2"),
            "roles": ["admin"],
        }]}}
    }))

    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret")
    c = TestClient(app)
    tok = c.post("/api/login",
                  data={"username": "alice", "password": "hunter2"}
                  ).json()["access_token"]
    r = c.get("/api/platform/discovery-jobs/sources",
               headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    keys = {s["source"] for s in body["sources"]}
    assert keys == set(DJ.SUPPORTED_SOURCES)
    # Each entry has the four expected fields
    for s in body["sources"]:
        assert "label" in s
        assert "required_params" in s
        assert "needs" in s


# --- helper for skipif --------------------------------------------------

def _has_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        return True
    except ImportError:
        return False
