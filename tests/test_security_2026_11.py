"""Regression tests for the November 2026 security fixes (report by Kaccy; the discovery-job secrets finding is ours).

F2  require_role() annotation made every role-gated endpoint return 422
    + the bypass behind it: no org id meant no role check at all
F3  DHCP discovery job opened any lease_file path and echoed OS errors
F1  identity discovery probes reached any address the caller chose
S1  discovery job list returned stored credentials to any signed-in user, across tenants
"""
from __future__ import annotations

import os

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI                     # noqa: E402
from fastapi.testclient import TestClient               # noqa: E402


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("SC_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("SC_DHCP_LEASE_DIRS", raising=False)
    return tmp_path


# ------------------------------------------------------------------ F2 and the org-id bypass

def _role_app():
    from safecadence.auth.rbac import UserRole, require_role
    app = FastAPI()

    @app.get("/viewer")
    def viewer(s=Depends(require_role(UserRole.VIEWER))):
        return {"ok": True}

    @app.get("/admin")
    def admin(s=Depends(require_role(UserRole.ADMIN))):
        return {"ok": True}

    return TestClient(app)


def _token(email):
    from safecadence.auth.magic_link import create_session
    return {"Authorization": "Bearer " + create_session("u-" + email, email)}


def test_role_gate_no_longer_422_and_checks_role(home):
    from safecadence.auth.rbac import UserRole, assign_role
    from safecadence.storage.org_store import create_org
    org = create_org("Acme", "owner@acme.test")
    assign_role(org.id, "viewer@acme.test", UserRole.VIEWER)
    c = _role_app()
    v = _token("viewer@acme.test")
    assert c.get("/viewer", headers=v).status_code == 200            # was 422 for everyone
    assert c.get("/admin", headers=v).status_code == 403             # role is checked
    assert c.get("/admin", headers=_token("owner@acme.test")).status_code == 200


def test_missing_org_id_is_not_a_bypass(home):
    from safecadence.auth.rbac import UserRole, assign_role
    from safecadence.storage.org_store import create_org
    a = create_org("A", "owner@a.test")
    b = create_org("B", "owner@b.test")
    assign_role(a.id, "multi@x.test", UserRole.VIEWER)
    assign_role(b.id, "multi@x.test", UserRole.VIEWER)
    c = _role_app()
    # a viewer without the org header used to pass every role gate
    assert c.get("/admin", headers=_token("multi@x.test")).status_code == 403
    # in several orgs and none named: must choose
    r = c.get("/viewer", headers=_token("multi@x.test"))
    assert r.status_code == 403 and "Choose an organization" in r.text
    # in no org at all
    assert c.get("/viewer", headers=_token("nobody@x.test")).status_code == 403
    # naming one works
    assert c.get("/viewer", headers={**_token("multi@x.test"), "X-SafeCadence-Org": a.id}).status_code == 200


def test_unknown_or_malformed_org_is_refused(home):
    from safecadence.storage.org_store import create_org
    create_org("A", "owner@a.test")
    c = _role_app()
    h = _token("owner@a.test")
    for bad in ("org_doesnotexist", "../../etc", "..", "a/b"):
        assert c.get("/viewer", headers={**h, "X-SafeCadence-Org": bad}).status_code == 403
    assert not (home / "etc").exists()


def test_signed_out_is_401(home):
    assert _role_app().get("/viewer").status_code == 401


# ------------------------------------------------------------------ F3: lease_file

def test_lease_file_outside_allowed_dirs_is_refused(home, tmp_path):
    from safecadence.intel import discovery_jobs as dj
    secret = tmp_path / "secret.txt"
    secret.write_text("not a lease file")
    with pytest.raises(ValueError):
        dj.create_job(name="x", source="dhcp", params={"lease_file": str(secret)})
    # a job saved by an older version is refused at fire time, without echoing the path or OS error
    job = dj.DiscoveryJob(job_id="legacy1", name="x", source="dhcp", params={"lease_file": str(secret)})
    ok, err = dj.fire_job(job)
    assert not ok and str(secret) not in err and "Errno" not in err


def test_traversal_and_symlinks_cannot_leave_allowed_dir(home, tmp_path, monkeypatch):
    from safecadence.intel import discovery_jobs as dj
    allowed = tmp_path / "leases"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    monkeypatch.setenv("SC_DHCP_LEASE_DIRS", str(allowed))
    assert dj.safe_lease_path(str(allowed / ".." / "outside.txt")) is None
    link = allowed / "link.leases"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert dj.safe_lease_path(str(link)) is None


def test_lease_file_inside_allowed_dir_runs(home, tmp_path, monkeypatch):
    from safecadence.intel import discovery_jobs as dj
    allowed = tmp_path / "leases"
    allowed.mkdir()
    lf = allowed / "dhcpd.leases"
    lf.write_text('lease 10.0.0.5 {\n  hardware ethernet 00:11:22:33:44:55;\n  client-hostname "pc1";\n}\n')
    monkeypatch.setenv("SC_DHCP_LEASE_DIRS", str(allowed))
    j = dj.create_job(name="ok", source="dhcp", params={"lease_file": str(lf)})
    ok, err = dj.fire_job(j)
    assert ok, err
    missing = dj.DiscoveryJob(job_id="m1", name="m", source="dhcp", params={"lease_file": str(allowed / "nope")})
    ok, err = dj.fire_job(missing)
    assert not ok and err == "could not read the DHCP lease file"


# ------------------------------------------------------------------ S1: secrets and tenants in the job list

class _U:
    def __init__(self, tenant, roles=("admin",)):
        self.username, self.tenant, self.roles = "u", tenant, list(roles)


def _platform_app(user):
    from safecadence.server.platform_api import register
    app = FastAPI()
    register(app, lambda: user, lambda: user)
    return TestClient(app)


def test_job_list_hides_credentials_and_other_tenants(home):
    from safecadence.intel import discovery_jobs as dj
    dj.create_job(name="ad", source="ad", params={"server": "ldaps://dc1", "base_dn": "DC=a",
                                                    "bind_dn": "cn=svc", "password": "hunter2"}, tenant="t1")
    dj.create_job(name="entra", source="entra", params={"tenant_id": "t", "client_id": "c",
                                                          "client_secret": "s3cret"}, tenant="t2")
    r = _platform_app(_U("t1")).get("/api/platform/discovery-jobs")
    assert r.status_code == 200
    body = r.text
    assert "hunter2" not in body and "s3cret" not in body
    jobs = r.json()["jobs"]
    assert [j["name"] for j in jobs] == ["ad"]                       # t2's job is not listed
    assert jobs[0]["params"]["password"] == dj.SECRET_PLACEHOLDER
    assert jobs[0]["params"]["server"] == "ldaps://dc1"
    # the runner still has the real value
    assert any(j.params.get("password") == "hunter2" for j in dj.list_jobs())


def test_other_tenants_jobs_cannot_be_run_or_deleted(home):
    from safecadence.intel import discovery_jobs as dj
    j = dj.create_job(name="theirs", source="dhcp", params={}, tenant="t2")
    c = _platform_app(_U("t1"))
    assert c.post(f"/api/platform/discovery-jobs/{j.job_id}/run-now").status_code == 404
    assert c.delete(f"/api/platform/discovery-jobs/{j.job_id}").status_code == 404
    assert dj.get_job(j.job_id) is not None


def test_job_files_are_private(home):
    from safecadence.intel import discovery_jobs as dj
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    j = dj.create_job(name="ad", source="ad", params={"server": "s", "base_dn": "b", "password": "p"})
    assert oct(os.stat(dj._path_for(j.job_id)).st_mode & 0o777) == "0o600"


# ------------------------------------------------------------------ F1: identity discovery targets

@pytest.mark.parametrize("cidr", ["127.0.0.0/24", "169.254.169.0/24", "8.8.8.0/24", "10.0.0.0/16",
                                  "224.0.0.0/24", "0.0.0.0/24", "not-a-range", "fd00::/64"])
def test_lan_ranges_must_be_small_private_lan(cidr):
    from safecadence.identity.discover import validate_lan_cidrs
    with pytest.raises(ValueError):
        validate_lan_cidrs([cidr])


def test_lan_ranges_ok_and_capped():
    from safecadence.identity.discover import MAX_LAN_CIDRS, validate_lan_cidrs
    assert validate_lan_cidrs(["10.0.0.0/24", "192.168.1.0/24", "172.16.5.0/25"]) == \
        ["10.0.0.0/24", "192.168.1.0/24", "172.16.5.0/25"]
    with pytest.raises(ValueError):
        validate_lan_cidrs([f"10.0.{i}.0/24" for i in range(MAX_LAN_CIDRS + 1)])


def test_probes_never_touch_loopback_or_metadata(monkeypatch):
    from safecadence.identity import discover as d

    def boom(*a, **k):
        raise AssertionError("no connection may be attempted")
    monkeypatch.setattr(d, "_tcp_open", boom)
    for host in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "8.8.8.8"):
        assert d._probe_clearpass(host) is None
        assert d._probe_ise(host) is None


def test_caller_supplied_domains_must_be_public(monkeypatch):
    from safecadence.identity import discover as d
    for bad in ("127.0.0.1", "localhost", "intranet", "a.b.c.d:8080", "evil.test/x", "user@host.example"):
        assert d._public_domain(bad) is None
    monkeypatch.setattr(d.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("10.1.2.3", 443))])
    assert d._public_domain("internal.example.com") is None      # resolves to a private address
    monkeypatch.setattr(d.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.215.14", 443))])
    assert d._public_domain("example.com") == "example.com"
    assert d._probe_entra("../../evil") is None


def test_discover_endpoint_needs_writer_and_rejects_bad_ranges():
    from fastapi import HTTPException
    from safecadence.server.identity_api import register

    def viewer():
        raise HTTPException(403, "writer role required")
    app = FastAPI()
    register(app, lambda: _U("t1", ("viewer",)), viewer)
    assert TestClient(app).post("/api/identity/discover", json={"lan_cidrs": ["10.0.0.0/24"]}).status_code == 403
    app2 = FastAPI()
    register(app2, lambda: _U("t1"), lambda: _U("t1"))
    r = TestClient(app2).post("/api/identity/discover", json={"lan_cidrs": ["127.0.0.0/24"]})
    assert r.status_code == 400 and "private LAN" in r.text
