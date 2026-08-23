"""Two-distribution split: core must degrade gracefully without the
safecadence-publicsafety add-on (guarded imports + stub pages)."""
from __future__ import annotations

import sys

import pytest


_PS_MODULES = [
    "safecadence.ui.desat_pages",
    "safecadence.platform.public_safety",
    "safecadence.platform.evidence_health",
    "safecadence.demo_sheriff",
]


@pytest.fixture()
def no_ps(monkeypatch):
    """Simulate a core-only install: importing any PS module raises."""
    for name in _PS_MODULES:
        monkeypatch.setitem(sys.modules, name, None)   # import -> ImportError
    yield


def test_stub_pages_replace_desat_pages(no_ps):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.ui.ps_stub import register
    app = fastapi.FastAPI()
    register(app)
    client = TestClient(app)
    for path in ("/map", "/evidence-infrastructure", "/incidents", "/events"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "pip install safecadence-publicsafety" in r.text
        assert "90-day trial" in r.text


def test_hosted_app_serves_stubs_when_ps_absent(no_ps, tmp_path, monkeypatch):
    """server.create_app falls back to stubs — sidebar links never 404."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "scdata"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                      db_url=f"sqlite:///{tmp_path}/sc.db",
                      jwt_secret="test-secret-do-not-use-in-prod")
    client = TestClient(app)
    for path in ("/map", "/events", "/incidents", "/evidence-infrastructure"):
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, path
        assert "safecadence-publicsafety" in r.text, path


def test_bridge_classifies_without_ps(no_ps):
    """Asset bridge must still build assets when taxonomy is absent."""
    from safecadence.platform.bridge import discovered_to_asset
    asset = discovered_to_asset({
        "ip": "10.0.0.5", "hostname": "core-sw-1", "mac": "aa:bb:cc:dd:ee:ff",
        "vendor_guess": "cisco", "os_guess": "ios",
        "device_type_guess": "switch", "open_ports": [22], "banners": {}})
    assert asset is not None
    assert (asset.identity.hostname or asset.identity.ip_address)


def test_report_section_degrades_without_ps(no_ps):
    from safecadence.reports.sections import evidence_infrastructure
    out = evidence_infrastructure(None, {})
    assert out["empty"] is True
    assert "safecadence-publicsafety" in out["html_fragment"]
