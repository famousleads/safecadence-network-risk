"""v7.1 — Tier 3 SSH gating, Postgres adapter shape, Cytoscape views,
license manager, Chrome extension manifest, Next.js scaffold sanity."""

from __future__ import annotations

import json
import os
from pathlib import Path


# --------------------------------------------------------------------------
# Tier 3 — three-gate activation
# --------------------------------------------------------------------------

def test_tier3_refuses_when_env_off(monkeypatch):
    """SC_TIER3_ENABLED unset → first gate trips, no other check matters."""
    monkeypatch.delenv("SC_TIER3_ENABLED", raising=False)
    from safecadence.execution import tier3
    from safecadence.execution.rbac import Role
    import pytest
    with pytest.raises(tier3.Tier3DisabledError) as exc:
        tier3._check_activation(role=Role.SUPER_ADMIN,
                                 acknowledge=True, i_mean_it=True)
    assert "SC_TIER3_ENABLED" in str(exc.value)


def test_tier3_refuses_without_execute_real(monkeypatch):
    """Even Super Admin doesn't have EXECUTE_REAL by default."""
    monkeypatch.setenv("SC_TIER3_ENABLED", "1")
    from safecadence.execution import tier3
    from safecadence.execution.rbac import Role
    import pytest
    with pytest.raises(tier3.Tier3DisabledError) as exc:
        tier3._check_activation(role=Role.SUPER_ADMIN,
                                 acknowledge=True, i_mean_it=True)
    assert "EXECUTE_REAL" in str(exc.value)


def test_tier3_refuses_without_acknowledge(monkeypatch):
    """The acknowledge=True / i_mean_it=True belt-and-braces gate."""
    monkeypatch.setenv("SC_TIER3_ENABLED", "1")
    from safecadence.execution import tier3
    from safecadence.execution.rbac import Role
    # Patch capabilities to grant EXECUTE_REAL just for this test
    from safecadence.execution import rbac
    orig = rbac._MATRIX[Role.SUPER_ADMIN]
    rbac._MATRIX[Role.SUPER_ADMIN] = orig | {rbac.Capability.EXECUTE_REAL}
    try:
        import pytest
        with pytest.raises(tier3.Tier3DisabledError) as exc:
            tier3._check_activation(role=Role.SUPER_ADMIN,
                                     acknowledge=False, i_mean_it=False)
        assert "acknowledge" in str(exc.value).lower()
    finally:
        rbac._MATRIX[Role.SUPER_ADMIN] = orig


def test_tier3_emergency_stop_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_EMERGENCY_STOP_PATH", str(tmp_path / "STOP"))
    from safecadence.execution import tier3
    assert tier3._check_emergency_stop() is False
    tier3.emergency_stop_now(actor="test")
    assert tier3._check_emergency_stop() is True
    tier3.emergency_clear(actor="test")
    assert tier3._check_emergency_stop() is False


# --------------------------------------------------------------------------
# Postgres adapter — shape, opt-in
# --------------------------------------------------------------------------

def test_pg_adapter_disabled_without_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from safecadence import storage_pg
    assert storage_pg.is_enabled() is False
    # All public functions return None / [] cleanly when disabled.
    assert storage_pg.get_asset("nope") is None
    assert storage_pg.list_assets() == []
    assert storage_pg.read_audit() == []


def test_pg_adapter_module_imports_clean():
    """Import shouldn't blow up even without sqlalchemy installed."""
    from safecadence import storage_pg
    assert hasattr(storage_pg, "save_asset")
    assert hasattr(storage_pg, "list_jobs")
    assert hasattr(storage_pg, "write_audit")


# --------------------------------------------------------------------------
# Cytoscape topology — 9 named views
# --------------------------------------------------------------------------

def test_topology_views_count():
    from safecadence.platform import topology_views
    assert set(topology_views.VIEWS.keys()) == {
        "global", "campus", "subnet", "security_zone",
        "cloud", "risk_heat", "lifecycle", "health", "vulnerability",
    }


def test_topology_view_returns_cytoscape_envelope(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.platform.topology_views import VIEWS
    load_demo_fleet()
    for view_name, fn in VIEWS.items():
        out = fn()
        assert "elements" in out, f"{view_name} missing elements"
        assert "nodes" in out["elements"]
        assert "edges" in out["elements"]
        assert "layout" in out
        assert "stats" in out
        # Demo fleet has 31 assets so every view should produce
        # at least one node.
        assert len(out["elements"]["nodes"]) >= 1, (
            f"{view_name} returned no nodes"
        )


def test_topology_unknown_view_returns_error_envelope():
    from safecadence.platform.topology_views import render
    r = render("not_a_view")
    assert "error" in r
    assert "available" in r
    assert "global" in r["available"]


# --------------------------------------------------------------------------
# License manager
# --------------------------------------------------------------------------

def test_license_free_tier_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_LICENSE_PATH", str(tmp_path / "missing.json"))
    from safecadence.license import load_license, status, feature_enabled
    lic = load_license()
    assert lic.licensee == "open-source"
    assert lic.max_assets == 200
    assert "base" in lic.features
    s = status(asset_count=10)
    assert s.licensee == "open-source"
    assert s.over_limit is False
    assert feature_enabled("base") is True
    assert feature_enabled("tier3") is False


def test_license_over_limit_signals_correctly(tmp_path, monkeypatch):
    p = tmp_path / "license.json"
    p.write_text(json.dumps({
        "licensee": "Acme Corp", "max_assets": 50, "features": ["base"],
    }), encoding="utf-8")
    monkeypatch.setenv("SC_LICENSE_PATH", str(p))
    from safecadence.license import status
    s = status(asset_count=75)
    assert s.over_limit is True


def test_license_require_feature_raises_for_unlicensed(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_LICENSE_PATH", str(tmp_path / "missing.json"))
    from safecadence.license import require_feature
    import pytest
    with pytest.raises(PermissionError):
        require_feature("tier3")
    # Free-tier feature should succeed
    require_feature("base")


def test_license_tenant_quota_enforced(tmp_path, monkeypatch):
    p = tmp_path / "license.json"
    p.write_text(json.dumps({
        "licensee": "MSP-ABC", "max_assets": 0,
        "features": ["base"],
        "tenants": {"alpha": {"max_assets": 100},
                    "bravo": {"max_assets": 1000}},
    }), encoding="utf-8")
    monkeypatch.setenv("SC_LICENSE_PATH", str(p))
    from safecadence.license import enforce_asset_quota
    ok, _ = enforce_asset_quota("alpha", 99)
    assert ok is True
    ok, reason = enforce_asset_quota("alpha", 100)
    assert ok is False
    assert "alpha" in reason
    ok, _ = enforce_asset_quota("bravo", 500)
    assert ok is True


# --------------------------------------------------------------------------
# Chrome extension manifest
# --------------------------------------------------------------------------

def test_chrome_extension_manifest_v3():
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repo / "chrome-extension" / "manifest.json").read_text())
    assert manifest["manifest_version"] == 3
    assert "popup.html" in manifest["action"]["default_popup"]
    # Must NOT request broad permissions
    assert "tabs" not in manifest.get("permissions", [])
    assert "storage" in manifest["permissions"]


def test_chrome_extension_popup_does_not_call_home():
    """Popup script must not embed any external URL beyond the user-
    configured host. Catches the regression where someone adds a
    'phone home for analytics' line by accident."""
    repo = Path(__file__).resolve().parents[2]
    js = (repo / "chrome-extension" / "popup.js").read_text()
    forbidden = ["safecadence.com", "googleapis.com", "datadog",
                 "sentry.io", "amplitude.com"]
    lower = js.lower()
    for f in forbidden:
        assert f not in lower, f"popup.js contains forbidden URL: {f}"


# --------------------------------------------------------------------------
# Next.js scaffold sanity
# --------------------------------------------------------------------------

def test_nextjs_scaffold_exists():
    repo = Path(__file__).resolve().parents[2]
    web = repo / "webui"
    for must in ("package.json", "next.config.mjs", "tsconfig.json",
                  "tailwind.config.ts", "app/layout.tsx", "app/page.tsx",
                  "app/inventory/page.tsx", "app/command/page.tsx"):
        assert (web / must).exists(), f"missing webui/{must}"
    pkg = json.loads((web / "package.json").read_text())
    assert pkg["dependencies"]["next"].startswith("14.")
    assert "tailwindcss" in pkg["devDependencies"]
