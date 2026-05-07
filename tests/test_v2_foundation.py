"""v2.0 foundation tests — vault, CSV import, storage, FastAPI server."""

import json
import os
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------- #
# Vault (only runs if cryptography is installed)
# ---------------------------------------------------------------- #
@pytest.mark.skipif(
    pytest.importorskip("cryptography", reason="cryptography not installed") is None,
    reason="cryptography not installed",
)
class TestVault:
    def test_set_get_roundtrip(self, tmp_path):
        from safecadence.security import EncryptedVault, generate_key
        key = generate_key()
        v = EncryptedVault(tmp_path / "creds.vault", key=key)
        v.set("site.password", "s3cret")
        v.save()
        v2 = EncryptedVault(tmp_path / "creds.vault", key=key)
        assert v2.get("site.password") == "s3cret"

    def test_wrong_key_fails(self, tmp_path):
        from safecadence.security import EncryptedVault, VaultError, generate_key
        key1, key2 = generate_key(), generate_key()
        v = EncryptedVault(tmp_path / "v.vault", key=key1)
        v.set("k", "v"); v.save()
        with pytest.raises(VaultError):
            EncryptedVault(tmp_path / "v.vault", key=key2)

    def test_passphrase_derivation_stable(self, tmp_path):
        from safecadence.security import derive_key
        salt = tmp_path / "s"
        k1 = derive_key("hunter2", salt_path=salt, iterations=1000)
        k2 = derive_key("hunter2", salt_path=salt, iterations=1000)
        assert k1 == k2


# ---------------------------------------------------------------- #
# CSV import / export
# ---------------------------------------------------------------- #
class TestCSV:
    def test_inventory_roundtrip(self, tmp_path):
        from safecadence.io_csv import read_inventory_csv, write_inventory_csv
        devs = [
            {"host": "10.0.0.1", "name": "DC-CORE-01", "vendor": "cisco-ios",
             "username": "netops", "password": "env:NETOPS_PW", "port": 22},
            {"host": "10.0.0.2", "name": "SPINE-01", "vendor": "arista-eos",
             "username": "netops", "key_file": "~/.ssh/id_rsa"},
        ]
        path = tmp_path / "inv.csv"
        n = write_inventory_csv(devs, path)
        assert n == 2
        round_trip = read_inventory_csv(path)
        assert len(round_trip) == 2
        assert round_trip[0]["host"] == "10.0.0.1"
        assert round_trip[0]["password"] == "env:NETOPS_PW"
        assert round_trip[1]["key_file"] == "~/.ssh/id_rsa"

    def test_export_assets_csv(self, tmp_path):
        from safecadence.io_csv import write_assets_csv
        scan = {
            "vendor": "cisco-ios", "started_at": "2026-05-03T00:00:00Z",
            "health_score": 11, "risk_score": 100, "health_band": "critical",
            "risk_band": "critical", "summary": "x",
            "asset": {"hostname": "DC-CORE-01", "ip": "10.0.0.1",
                       "device_type": "router", "business_criticality": "high"},
            "parsed_summary": {"hostname": "DC-CORE-01", "os": "ios", "version": "15.2"},
            "findings": [{"severity": "critical"}] * 5,
            "cves": [{"kev": True}, {"kev": False}],
            "eol": {"status_today": "end-of-support"},
        }
        path = tmp_path / "assets.csv"
        n = write_assets_csv([scan], path)
        assert n == 1
        text = path.read_text()
        assert "DC-CORE-01" in text and "end-of-support" in text and "5" in text


# ---------------------------------------------------------------- #
# Storage (SQLite always; SQL backend tested if SQLAlchemy installed)
# ---------------------------------------------------------------- #
class TestStorage:
    def _fake_scan(self, hostname="A1", risk=90):
        return {
            "vendor": "cisco-ios", "source": f"{hostname}.txt",
            "started_at": "2026-05-03T00:00:00Z",
            "health_score": 30, "risk_score": risk,
            "health_band": "critical", "risk_band": "critical",
            "summary": "x",
            "asset": {"hostname": hostname, "ip": "10.0.0.1"},
            "parsed_summary": {"hostname": hostname, "os": "ios", "version": "15.2"},
            "findings": [], "cves": [], "eol": None, "parsed_raw": "",
        }

    def test_sqlite_save_and_list(self, tmp_path):
        from safecadence.storage import open_store
        store = open_store(sqlite_path=str(tmp_path / "h.db"))
        sid1 = store.save(self._fake_scan("A1", risk=90), tenant_id="t1")
        sid2 = store.save(self._fake_scan("A2", risk=40), tenant_id="t1")
        store.save(self._fake_scan("A1", risk=95), tenant_id="t1")
        store.save(self._fake_scan("X1", risk=99), tenant_id="other")

        # tenant scoping
        rows_t1 = store.list(tenant_id="t1")
        assert all(r["tenant_id"] == "t1" for r in rows_t1)
        assert len(rows_t1) == 3
        assert "X1" not in {r["hostname"] for r in rows_t1}

        latest = store.latest_per_host(tenant_id="t1")
        by = {r["hostname"]: r for r in latest}
        assert by["A1"]["risk_score"] == 95
        assert by["A2"]["risk_score"] == 40

    def test_audit_log(self, tmp_path):
        from safecadence.storage import open_store
        store = open_store(sqlite_path=str(tmp_path / "h.db"))
        store.audit(tenant_id="t1", actor="alice", action="login")
        # exists if the call doesn't raise; we don't expose a list method yet


# ---------------------------------------------------------------- #
# FastAPI app — only runs if [server] extras are installed
# ---------------------------------------------------------------- #
fastapi = pytest.importorskip("fastapi", reason="server extras not installed")


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    users_file = tmp_path / "users.yaml"
    db_file = tmp_path / "h.db"
    os.environ["SC_USERS_FILE"] = str(users_file)
    os.environ["SC_JWT_SECRET"] = "test-secret-do-not-use-in-prod"
    app = create_app(db_url=f"sqlite:///{db_file}", users_file=str(users_file),
                     jwt_secret="test-secret-do-not-use-in-prod")
    return TestClient(app)


def _login(client) -> str:
    """The auth bootstrap creates 'admin' with a random password printed to stderr.
    For tests we rewrite users.yaml with a known admin."""
    import yaml
    from safecadence.server.auth import hash_password
    users_file = Path(os.environ["SC_USERS_FILE"])
    users_file.write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [
            {"username": "alice", "password_hash": hash_password("hunter2"),
             "roles": ["admin"]},
            {"username": "bob", "password_hash": hash_password("readonly"),
             "roles": ["viewer"]},
        ]}}
    }))
    r = client.post("/api/login", data={"username": "alice", "password": "hunter2"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


class TestAPI:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200 and r.json()["status"] == "ok"

    def test_login_bad_password(self, client):
        _login(client)  # write known users
        r = client.post("/api/login", data={"username": "alice", "password": "wrong"})
        assert r.status_code == 401

    def test_protected_endpoint_requires_token(self, client):
        r = client.get("/api/me")
        assert r.status_code == 401

    def test_me(self, client):
        token = _login(client)
        r = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "alice"
        assert "admin" in body["roles"]
        assert body["tenant"] == "acme"

    def test_vendors_endpoint(self, client):
        token = _login(client)
        r = client.get("/api/vendors", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        slugs = [v["slug"] for v in r.json()]
        assert "cisco-ios" in slugs and "juniper-junos" in slugs

    def test_scan_upload(self, client):
        token = _login(client)
        sample = Path(__file__).resolve().parents[1] / "examples" / "sample_configs" / "cisco_ios_running.txt"
        with open(sample, "rb") as fh:
            r = client.post(
                "/api/scan",
                files={"file": ("config.txt", fh, "text/plain")},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_id"] > 0
        assert body["summary"]["vendor"] == "cisco-ios"
        # devices endpoint should now show this host
        r2 = client.get("/api/devices", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200
        devs = r2.json()
        assert any(d["hostname"] == "BRANCH-EDGE-01" for d in devs)

    def test_writer_role_enforced(self, client):
        _login(client)  # bootstrap users
        r = client.post("/api/login", data={"username": "bob", "password": "readonly"})
        viewer_token = r.json()["access_token"]
        sample = Path(__file__).resolve().parents[1] / "examples" / "sample_configs" / "cisco_ios_running.txt"
        with open(sample, "rb") as fh:
            r = client.post("/api/scan",
                            files={"file": ("c.txt", fh, "text/plain")},
                            headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 403
