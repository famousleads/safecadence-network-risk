"""Tests for the v10.1 multi-section reports wizard."""

from __future__ import annotations

import os
import pathlib

import pytest


# --------------------------------------------------------------------------
# Per-section composers — empty store
# --------------------------------------------------------------------------


@pytest.fixture
def empty_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.storage.sqlite_store import SqliteStore
    s = SqliteStore(tmp_path / "history.db")
    yield s
    s.close()


@pytest.fixture
def populated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.storage.sqlite_store import SqliteStore
    s = SqliteStore(tmp_path / "history.db")
    sample = {
        "started_at": "2026-05-08T10:00:00Z",
        "source": "demo",
        "vendor": "cisco",
        "asset": {
            "hostname": "core-rtr-01",
            "ip": "10.0.0.1",
            "device_type": "network",
            "criticality": "critical",
            "location": {"site": "dc-east-1"},
            "public_exposure": True,
        },
        "parsed_summary": {"hostname": "core-rtr-01", "model": "ISR-4451"},
        "health_score": 62,
        "risk_score": 88,
        "risk_band": "critical",
        "eol": {"status_today": "end-of-support", "eos_date": "2024-09-30",
                "days_past_eos": 220},
        "cves": [
            {"id": "CVE-2024-12345", "cvss": 9.8, "kev": True,
             "summary": "Remote unauth code exec in IOS XE web UI"},
            {"id": "CVE-2023-99999", "cvss": 7.5, "kev": False,
             "summary": "Privilege escalation"},
        ],
        "findings": [
            {"rule_id": "iosxe.web.disable", "title": "Disable web UI",
             "severity": "critical", "remediation": "no ip http server",
             "controls": {"NIST 800-53": "AC-3", "CIS v8": "4.4"}},
            {"rule_id": "ssh.v2only", "title": "Restrict SSH to v2",
             "severity": "high", "remediation": "ip ssh version 2",
             "controls": {"PCI DSS": "2.2.5"}},
        ],
        "identity": {
            "admins": [
                {"name": "alice", "mfa_enabled": False},
                {"name": "bob", "mfa_enabled": True},
            ],
            "privileged": [{"name": "stale-svc", "last_login_days": 412}],
            "users": [{"name": "legacy", "password_age_days": 540}],
        },
        "summary": "Demo scan",
    }
    s.save(sample)
    yield s
    s.close()


def test_section_keys_metadata():
    from safecadence.reports import list_section_keys
    keys = list_section_keys()
    assert isinstance(keys, list)
    assert len(keys) == 10
    expected = {
        "kpi_summary", "host_inventory", "cve_exposure", "compliance_posture",
        "eol_hardware", "attack_paths", "identity_drift", "recommended_actions",
        "recent_changes", "executive_summary",
    }
    assert {k["key"] for k in keys} == expected
    for k in keys:
        assert "name" in k and "description" in k and "category" in k


def test_scope_keys_metadata():
    from safecadence.reports import list_scope_keys
    sc = list_scope_keys()
    assert {s["key"] for s in sc} == {"site", "criticality", "asset_type", "vendor", "date_range"}


@pytest.mark.parametrize("key", [
    "kpi_summary", "host_inventory", "cve_exposure", "compliance_posture",
    "eol_hardware", "attack_paths", "identity_drift", "recommended_actions",
    "recent_changes", "executive_summary",
])
def test_each_section_handles_empty_store(empty_store, key):
    from safecadence.reports.sections import get_section
    meta = get_section(key)
    res = meta["fn"](empty_store, {})
    assert isinstance(res, dict)
    assert "title" in res and "data" in res
    # Empty store -> sections must mark themselves empty
    assert res.get("empty") is True


@pytest.mark.parametrize("key", [
    "kpi_summary", "host_inventory", "cve_exposure", "compliance_posture",
    "eol_hardware", "attack_paths", "identity_drift", "recommended_actions",
    "executive_summary",
])
def test_each_section_returns_data_when_populated(populated_store, key):
    from safecadence.reports.sections import get_section
    meta = get_section(key)
    res = meta["fn"](populated_store, {})
    assert isinstance(res, dict)
    assert res.get("empty") is False, f"{key} unexpectedly empty"
    assert isinstance(res.get("html_fragment"), str) and res["html_fragment"]


def test_compose_report_default_sections(populated_store):
    from safecadence.reports import compose_report
    r = compose_report(store=populated_store)
    assert r["title"]
    assert r["generated_at"]
    assert isinstance(r["sections"], list) and len(r["sections"]) >= 5


def test_compose_report_round_trips_through_render_html(populated_store):
    from safecadence.reports import compose_report, render_html
    r = compose_report(store=populated_store,
                       sections=["kpi_summary", "host_inventory", "cve_exposure"])
    html = render_html(r, standalone=True)
    assert html.startswith("<!doctype html>")
    assert "core-rtr-01" in html
    assert "CVE-2024-12345" in html


def test_render_json_strips_html_fragments(populated_store):
    import json as _json
    from safecadence.reports import compose_report, render_json
    r = compose_report(store=populated_store)
    parsed = _json.loads(render_json(r))
    for s in parsed["sections"]:
        assert "html_fragment" not in s


def test_render_pdf_returns_bytes(populated_store):
    from safecadence.reports import compose_report, render_pdf
    r = compose_report(store=populated_store, sections=["kpi_summary"])
    b = render_pdf(r)
    assert isinstance(b, (bytes, bytearray))
    assert len(b) > 0


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------


def test_template_save_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    from safecadence.reports import templates as tpl
    saved = tpl.save_template({
        "name": "Weekly exec",
        "sections": ["kpi_summary", "executive_summary"],
        "scope": {"criticality": ["critical", "high"]},
    })
    assert saved["id"]
    loaded = tpl.load_template(saved["id"])
    assert loaded == saved
    listing = tpl.list_templates()
    assert any(t["id"] == saved["id"] for t in listing)
    assert tpl.delete_template(saved["id"]) is True
    assert tpl.load_template(saved["id"]) is None


def test_readonly_mode_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_READONLY", "1")
    from safecadence.reports import templates as tpl
    with pytest.raises(PermissionError):
        tpl.save_template({"name": "ro"})
    with pytest.raises(PermissionError):
        tpl.delete_template("anything")


def test_share_token_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    from safecadence.reports import templates as tpl
    saved = tpl.save_template({"name": "Share me", "sections": ["kpi_summary"]})
    out = tpl.ensure_share_token(saved["id"])
    token = out["share_token"]
    assert token
    found = tpl.find_by_share_token(token)
    assert found and found["id"] == saved["id"]


def test_invalid_template_id_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    from safecadence.reports import templates as tpl
    with pytest.raises(ValueError):
        tpl.load_template("../etc/passwd")


# --------------------------------------------------------------------------
# platform_assets fallback
# --------------------------------------------------------------------------


@pytest.fixture
def platform_assets_dir(tmp_path, monkeypatch):
    """Seed ~/.safecadence/platform_assets/*.json into a tmp dir, isolated via
    SC_DATA_DIR so the section helpers read from there."""
    import json as _json
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    pa = tmp_path / "platform_assets"
    pa.mkdir(parents=True, exist_ok=True)
    asset_a = {
        "identity": {
            "asset_id": "rds-host-01",
            "asset_type": "server",
            "vendor": "microsoft",
            "hostname": "rds-host-01",
            "criticality": "high",
            "site": "branch-nyc",
        },
        "lifecycle": {"days_until_eos": 30, "hardware_status": "ok",
                      "software_status": "eos"},
        "security": {"critical_cves": 2, "high_cves": 5, "kev_cves": 1},
        "network": {"mgmt_ip": "10.20.0.10"},
    }
    asset_b = {
        "identity": {
            "asset_id": "ad-acme-local",
            "asset_type": "identity",
            "vendor": "microsoft",
            "hostname": "ad-acme-local",
            "criticality": "crown-jewel",
            "site": "hq",
        },
        "lifecycle": {"days_until_eos": 365},
        "security": {"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        "identity_block": {"mfa_enrolled": False, "password_min_length": 8,
                            "last_login": "2024-01-01T00:00:00Z"},
    }
    (pa / "rds-host-01.json").write_text(_json.dumps(asset_a), encoding="utf-8")
    (pa / "ad-acme-local.json").write_text(_json.dumps(asset_b), encoding="utf-8")
    return tmp_path


def test_kpi_summary_falls_back_to_platform_assets(empty_store, platform_assets_dir):
    """When scan history is empty but platform_assets has entries, kpi_summary
    must report real numbers (hosts, critical, high, KEV, EOL)."""
    from safecadence.reports.sections import kpi_summary
    res = kpi_summary(empty_store, {})
    assert res["empty"] is False
    d = res["data"]
    assert d["hosts"] == 2
    # 2 + 0 = 2 critical CVEs across both
    assert d["critical"] == 2
    # 5 + 1 = 6 high
    assert d["high"] == 6
    # 1 device with KEV
    assert d["kev"] == 1
    # asset_a has software_status=eos -> eos_software counted
    assert d["eos_software"] >= 1


def test_scopes_returns_values_from_platform_assets(platform_assets_dir):
    """The platform_assets store should populate sites + vendors that the
    /api/reports/scopes endpoint hands to the wizard."""
    from safecadence.reports.sections import _scope_values_from_assets
    extra = _scope_values_from_assets()
    assert "branch-nyc" in extra["sites"]
    assert "hq" in extra["sites"]
    assert "microsoft" in extra["vendors"]


# --------------------------------------------------------------------------
# Smoke import
# --------------------------------------------------------------------------


def test_public_api_exports():
    from safecadence.reports import (
        compose_report, list_section_keys, list_scope_keys,
        render_html, render_json, render_pdf,
        save_template, load_template, list_templates, delete_template,
    )
    assert callable(compose_report)
    assert callable(list_section_keys)
    assert callable(list_scope_keys)
    assert callable(render_html)
    assert callable(render_json)
    assert callable(render_pdf)
    assert callable(save_template)
    assert callable(load_template)
    assert callable(list_templates)
    assert callable(delete_template)
