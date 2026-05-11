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
    assert len(keys) >= 10
    expected_core = {
        "kpi_summary", "host_inventory", "cve_exposure", "compliance_posture",
        "eol_hardware", "attack_paths", "identity_drift", "recommended_actions",
        "recent_changes", "executive_summary",
    }
    assert expected_core.issubset({k["key"] for k in keys})
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
        list_presets, get_preset, apply_preset,
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
    assert callable(list_presets)
    assert callable(get_preset)
    assert callable(apply_preset)


# --------------------------------------------------------------------------
# visuals
# --------------------------------------------------------------------------


@pytest.mark.parametrize("score", [0, 25, 50, 75, 100])
def test_risk_gauge_returns_valid_svg(score):
    from safecadence.reports.visuals import risk_gauge
    svg = risk_gauge(score)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert str(score) in svg
    assert 'aria-label' in svg


def test_severity_donut_with_data():
    from safecadence.reports.visuals import severity_donut
    out = severity_donut({"critical": 4, "high": 8, "medium": 2, "low": 1})
    assert "<svg" in out
    assert "FINDINGS" in out


def test_severity_donut_empty_no_crash():
    from safecadence.reports.visuals import severity_donut
    out = severity_donut({})
    assert "<svg" in out


def test_compliance_radar_renders():
    from safecadence.reports.visuals import compliance_radar
    fws = [
        {"framework": "NIST 800-53", "score": 72},
        {"framework": "CIS v8", "score": 60},
        {"framework": "PCI DSS", "score": 80},
        {"framework": "HIPAA", "score": 55},
        {"framework": "SOC 2", "score": 88},
    ]
    out = compliance_radar(fws)
    assert "<svg" in out
    for fw in fws:
        assert fw["framework"] in out


def test_compliance_radar_empty():
    from safecadence.reports.visuals import compliance_radar
    out = compliance_radar([])
    assert "sc-empty" in out


def test_compliance_heatmap_classifies_status():
    from safecadence.reports.visuals import compliance_heatmap
    out = compliance_heatmap([
        {"control": "AC-3", "status": "pass"},
        {"control": "SI-2", "status": "fail"},
        {"control": "CM-6", "status": "partial"},
    ])
    assert 'sc-heat-grid' in out
    assert 'sc-heat-legend' in out


def test_severity_bars_render():
    from safecadence.reports.visuals import severity_bars
    out = severity_bars({"critical": 3, "high": 2, "medium": 5, "low": 1})
    assert "<svg" in out
    assert "Critical" in out


def test_sparkline_handles_short_input():
    from safecadence.reports.visuals import sparkline
    assert sparkline([1]) == ""
    assert sparkline([]) == ""
    assert "<svg" in sparkline([1, 2, 3, 2, 4])


def test_attack_path_graph_renders():
    from safecadence.reports.visuals import attack_path_graph
    nodes = [
        {"id": "internet", "label": "Internet", "kind": "internet", "tier": 0},
        {"id": "fw1", "label": "edge-fw", "kind": "edge", "tier": 1},
        {"id": "dc01", "label": "dc01", "kind": "crown-jewel", "tier": 2},
    ]
    edges = [{"from": "internet", "to": "fw1"}, {"from": "fw1", "to": "dc01"}]
    out = attack_path_graph(nodes, edges)
    assert "<svg" in out
    assert "dc01" in out
    assert 'marker-end="url(#sc-arrow)"' in out


def test_attack_path_graph_empty_returns_placeholder():
    from safecadence.reports.visuals import attack_path_graph
    assert "sc-empty" in attack_path_graph([], [])


def test_kpi_card_html_structure():
    from safecadence.reports.visuals import kpi_card
    out = kpi_card("Hosts", 34, sub="assets evaluated", tone="info")
    assert "Hosts" in out
    assert "34" in out
    assert 'sc-kpi' in out


def test_cve_badge_combinations():
    from safecadence.reports.visuals import cve_badge
    plain = cve_badge("high")
    assert "High" in plain
    assert "KEV" not in plain
    kev = cve_badge("critical", kev=True)
    assert "KEV" in kev
    expl = cve_badge("medium", kev=True, exploit=True)
    assert "EXPLOIT" in expl


def test_cover_gradient_svg():
    from safecadence.reports.visuals import cover_gradient_svg
    out = cover_gradient_svg()
    assert "<svg" in out
    assert "sc-cov" in out
    assert "linearGradient" in out


# --------------------------------------------------------------------------
# AI helpers (deterministic fallback path)
# --------------------------------------------------------------------------


def test_executive_summary_uses_real_numbers(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SAFECADENCE_LOCAL_LLM", raising=False)
    from safecadence.reports.ai_helpers import generate_executive_summary
    text = generate_executive_summary(
        {"kpi": {"hosts": 34, "critical": 14, "high": 42, "kev": 5,
                 "eol": 4, "eos_software": 2, "cves": 56}},
        tone="professional",
    )
    assert "34" in text
    assert "14" in text
    assert "42" in text
    assert "5" in text


@pytest.mark.parametrize("tone", ["executive", "technical", "audit", "forward-looking", "professional"])
def test_executive_summary_supports_each_tone(monkeypatch, tone):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    from safecadence.reports.ai_helpers import generate_executive_summary
    out = generate_executive_summary(
        {"kpi": {"hosts": 10, "critical": 1, "high": 2, "kev": 0,
                 "eol": 0, "eos_software": 0, "cves": 3}},
        tone=tone,
    )
    assert isinstance(out, str) and len(out) > 50


def test_executive_summary_empty_scope():
    from safecadence.reports.ai_helpers import generate_executive_summary
    out = generate_executive_summary({"kpi": {"hosts": 0}})
    assert "No assets" in out


def test_explain_cve_plain_language(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from safecadence.reports.ai_helpers import explain_cve_plain_language
    out = explain_cve_plain_language("CVE-2024-12345", "critical", host="dc01")
    assert "CVE-2024-12345" in out
    assert "dc01" in out
    assert "critical" in out.lower()


def test_find_quick_wins_orders_by_leverage():
    from safecadence.reports.ai_helpers import find_quick_wins
    findings = [
        {"title": "Disable telnet", "severity": "high",
         "risk_reduction": 12, "effort_minutes": 10},
        {"title": "Replace EOL switch", "severity": "high",
         "risk_reduction": 30, "effort_minutes": 480},
        {"title": "Enable SSH v2", "severity": "medium",
         "risk_reduction": 20, "effort_minutes": 5, "fix_snippet": "ip ssh v2"},
    ]
    out = find_quick_wins(findings, max_results=3)
    assert len(out) == 3
    # SSH v2 has the highest ratio (20/5 = 4)
    assert out[0]["title"] == "Enable SSH v2"
    # The 480-minute item should be last
    assert out[-1]["title"] == "Replace EOL switch"


def test_find_quick_wins_empty():
    from safecadence.reports.ai_helpers import find_quick_wins
    assert find_quick_wins([]) == []


def test_sequence_patches_orders_identity_first():
    from safecadence.reports.ai_helpers import sequence_patches
    findings = [
        {"title": "App fix", "asset_type": "app"},
        {"title": "AD fix", "asset_type": "identity"},
        {"title": "Server fix", "asset_type": "server"},
        {"title": "Edge fix", "asset_type": "firewall"},
    ]
    waves = sequence_patches(findings)
    titles = [w["items"][0]["title"] for w in waves]
    assert titles[0] == "AD fix"


@pytest.mark.parametrize("audience", ["ceo", "ciso", "engineer", "auditor", "soc-analyst"])
def test_stakeholder_narrative_per_audience(monkeypatch, audience):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from safecadence.reports.ai_helpers import stakeholder_narrative
    out = stakeholder_narrative(
        {"kpi": {"hosts": 5, "critical": 2, "high": 3, "kev": 1,
                 "eol": 0, "eos_software": 0, "cves": 6}},
        audience=audience,
    )
    assert isinstance(out, str) and len(out) > 80


# --------------------------------------------------------------------------
# Presets
# --------------------------------------------------------------------------


def test_list_presets_has_four_required():
    from safecadence.reports import list_presets
    ps = list_presets()
    ids = {p["id"] for p in ps}
    assert {"exec_brief", "technical_deepdive",
            "compliance_audit", "quarterly_review"}.issubset(ids)


def test_get_preset_round_trip():
    from safecadence.reports import get_preset
    p = get_preset("exec_brief")
    assert p["id"] == "exec_brief"
    assert "kpi_summary" in p["sections"]
    assert get_preset("__none__") is None


def test_apply_preset_returns_render_options():
    from safecadence.reports import apply_preset
    out = apply_preset("compliance_audit", {"site": "hq"})
    assert out["preset_id"] == "compliance_audit"
    assert "compliance_posture" in out["sections"]
    assert out["scope"]["site"] == "hq"
    assert out["render_options"]["narrative_tone"] == "audit"
    assert out["render_options"]["extras"]["include_evidence_appendix"] is True


def test_apply_preset_unknown_id_raises():
    from safecadence.reports import apply_preset
    with pytest.raises(ValueError):
        apply_preset("nope")


def test_render_preset_card_html():
    from safecadence.reports.presets import render_preset_card_html, get_preset
    p = get_preset("exec_brief")
    card = render_preset_card_html(p)
    assert "rep-preset-card" in card
    assert "Executive brief" in card
    assert "<svg" in card  # icon


@pytest.mark.parametrize("pid", ["exec_brief", "technical_deepdive",
                                  "compliance_audit", "quarterly_review"])
def test_each_preset_renders_without_crash(populated_store, pid):
    from safecadence.reports import compose_report, render_html, apply_preset
    preset = apply_preset(pid)
    r = compose_report(store=populated_store,
                       sections=preset["sections"],
                       scope=preset["scope"])
    out = render_html(r, standalone=True, preset=preset)
    assert out.startswith("<!doctype html>")
    assert "OVERALL RISK INDEX" in out
    assert "SafeCadence NetRisk v10.7.0" in out


def test_render_html_includes_visuals(populated_store):
    """The flagship report must contain the new visuals."""
    from safecadence.reports import compose_report, render_html
    r = compose_report(store=populated_store)
    out = render_html(r, standalone=True)
    assert "<svg" in out
    assert "OVERALL RISK INDEX" in out
    assert "sc-kpi-band" in out
    assert "Contents" in out


def test_render_html_action_plan_renders_priority(populated_store):
    """Action rows must render with priority cells."""
    from safecadence.reports import compose_report, render_html
    r = compose_report(store=populated_store,
                       sections=["kpi_summary", "recommended_actions"])
    out = render_html(r, standalone=True)
    assert "sc-action" in out
    assert "P0" in out or "P1" in out


# ==========================================================================
# Round 2 — delta reports
# ==========================================================================


@pytest.fixture
def delta_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    yield tmp_path


def test_snapshot_save_load_diff(delta_dir):
    from safecadence.reports import delta as d
    s1 = d.snapshot_now(label="prev")
    assert s1["id"]
    snaps = d.list_snapshots()
    assert len(snaps) == 1 and snaps[0]["id"] == s1["id"]
    full = d.get_snapshot(s1["id"])
    assert full and full["id"] == s1["id"] and "report" in full
    # second snapshot same day -> overwrites (same id), still 1 file.
    s2 = d.snapshot_now(label="now")
    assert s2["id"] == s1["id"]
    assert len(d.list_snapshots()) == 1


def test_compute_delta_with_two_synthetic_snapshots(delta_dir):
    """Manually craft two snapshots with different KPIs and check the diff."""
    from safecadence.reports import delta as d
    import json as _json
    snap_dir = delta_dir / "reports" / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)

    def _w(day, kpi, findings_cves):
        rec = {
            "id": f"{day}__abc12345",
            "label": day,
            "created_at": f"{day}T00:00:00Z",
            "kpi": kpi,
            "report": {
                "sections": [
                    {"key": "kpi_summary", "data": kpi, "title": "KPI", "html_fragment": ""},
                    {"key": "cve_exposure",
                     "data": {"cves": findings_cves}, "title": "CVE", "html_fragment": ""},
                ]
            },
        }
        (snap_dir / f"{rec['id']}.json").write_text(_json.dumps(rec), encoding="utf-8")

    _w("2026-04-01",
       {"hosts": 30, "critical": 17, "high": 40, "kev": 5, "eol": 4,
        "eos_software": 1, "medium": 2, "low": 0, "cves": 60},
       [{"id": "CVE-2026-0001", "host": "h1", "severity": "high"},
        {"id": "CVE-2026-0002", "host": "h2", "severity": "high"}])
    _w("2026-04-15",
       {"hosts": 34, "critical": 14, "high": 42, "kev": 5, "eol": 4,
        "eos_software": 1, "medium": 2, "low": 0, "cves": 65},
       [{"id": "CVE-2026-0001", "host": "h1", "severity": "critical"},  # regressed
        {"id": "CVE-2026-0003", "host": "h3", "severity": "high"}])  # new

    delta = d.compute_delta()
    assert delta["available"]
    assert delta["kpis"]["hosts"]["change"] == 4
    assert delta["kpis"]["hosts"]["trend"] == "up"
    assert delta["kpis"]["critical"]["change"] == -3
    assert delta["kpis"]["critical"]["trend"] == "down"
    new_ids = {f["id"] for f in delta["new_findings"]}
    fixed_ids = {f["id"] for f in delta["fixed_findings"]}
    regr_ids = {f["id"] for f in delta["regressed"]}
    assert any("cve-2026-0003" in i for i in new_ids)
    assert any("cve-2026-0002" in i for i in fixed_ids)
    assert any("cve-2026-0001" in i for i in regr_ids)
    assert "rose" in delta["summary_text"] or "fell" in delta["summary_text"]


def test_trend_series_returns_oldest_first(delta_dir):
    from safecadence.reports import delta as d
    import datetime as _dt
    import json as _json
    snap_dir = delta_dir / "reports" / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    today = _dt.datetime.now(_dt.timezone.utc).date()
    for i, offset in enumerate([4, 2, 0]):
        day = (today - _dt.timedelta(days=offset)).isoformat()
        rec = {"id": f"{day}__id{i}xxxx", "kpi": {"critical": 10 + i},
               "report": {"sections": []}}
        (snap_dir / f"{rec['id']}.json").write_text(_json.dumps(rec), encoding="utf-8")
    series = d.trend_series("critical", days=30)
    assert series == [10.0, 11.0, 12.0]


def test_snapshot_now_readonly_raises(delta_dir, monkeypatch):
    from safecadence.reports import delta as d
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        d.snapshot_now()


def test_cleanup_old_snapshots_readonly_raises(delta_dir, monkeypatch):
    from safecadence.reports import delta as d
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        d.cleanup_old_snapshots(keep=1)


def test_compute_delta_returns_unavailable_with_no_snapshots(delta_dir):
    from safecadence.reports import delta as d
    out = d.compute_delta()
    assert out["available"] is False


def test_kpi_decoration_inserts_change_indicator(delta_dir):
    from safecadence.reports import delta as d
    delta_payload = {
        "kpis": {
            "critical": {"now": 14, "prev": 17, "change": -3, "trend": "down"},
            "hosts": {"now": 34, "prev": 32, "change": 2, "trend": "up"},
        },
        "available": True,
    }
    html = (
        '<div class="sc-kpi"><div class="sc-kpi-num">34</div>'
        '<div class="sc-kpi-lbl">Hosts</div></div>'
        '<div class="sc-kpi"><div class="sc-kpi-num">14</div>'
        '<div class="sc-kpi-lbl">Critical CVEs</div></div>'
    )
    out = d.decorate_kpi_with_delta(html, delta=delta_payload, include_sparklines=False)
    assert "sc-kpi-delta" in out
    assert "sc-up" in out and "sc-down" in out
    assert "&uarr;" in out and "&darr;" in out


def test_compose_report_with_include_delta_attaches_delta_block(delta_dir):
    from safecadence.reports import compose_report
    # Take a single snapshot so compute_delta has something to read.
    from safecadence.reports import delta as d
    d.snapshot_now()
    r = compose_report(sections=["kpi_summary"], scope={}, include_delta=True)
    assert "delta" in r
    assert "kpis" in r["delta"]


def test_quarterly_review_preset_carries_include_delta_flag():
    from safecadence.reports import get_preset
    p = get_preset("quarterly_review")
    assert p["extras"].get("include_delta") is True


# ==========================================================================
# Round 2 — webhooks
# ==========================================================================


@pytest.fixture
def wh_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    yield tmp_path


def test_webhook_add_list_remove(wh_dir):
    from safecadence.reports import webhooks as w
    assert w.list_webhook_endpoints() == []
    rec = w.add_webhook_endpoint(url="https://example.com/hook", kind="generic")
    assert rec["id"].startswith("wh-")
    assert rec["url"] == "https://example.com/hook"
    # secret hash absent when no secret given
    assert rec.get("secret_hash") is None
    items = w.list_webhook_endpoints()
    assert len(items) == 1
    assert "_secret" not in items[0]
    assert w.remove_webhook_endpoint(rec["id"]) is True
    assert w.list_webhook_endpoints() == []
    assert w.remove_webhook_endpoint(rec["id"]) is False


def test_webhook_secret_produces_hash(wh_dir):
    from safecadence.reports import webhooks as w
    rec = w.add_webhook_endpoint(url="https://x", kind="slack", secret="topsecret")
    assert rec["secret_hash"] and rec["secret_hash"].startswith("sha256:")


def test_webhook_invalid_kind_raises(wh_dir):
    from safecadence.reports import webhooks as w
    with pytest.raises(ValueError):
        w.add_webhook_endpoint(url="https://x", kind="zapier")


def test_webhook_readonly_raises(wh_dir, monkeypatch):
    from safecadence.reports import webhooks as w
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        w.add_webhook_endpoint(url="https://x", kind="slack")
    with pytest.raises(PermissionError):
        w.remove_webhook_endpoint("wh-xxx")


def test_slack_payload_shape():
    from safecadence.reports.webhooks import build_slack_payload
    p = build_slack_payload("report.generated",
                            {"title": "Q2 review",
                             "kpi": {"hosts": 34, "critical": 14, "high": 42,
                                     "kev": 5, "eol": 4},
                             "download_url": "https://demo/r/abc"})
    assert "blocks" in p
    assert any(b.get("type") == "header" for b in p["blocks"])
    assert any(b.get("type") == "actions" for b in p["blocks"])
    assert "34 hosts" in p["text"]


def test_teams_payload_shape():
    from safecadence.reports.webhooks import build_teams_payload
    p = build_teams_payload("report.generated",
                            {"title": "Test", "kpi": {"hosts": 1, "critical": 0,
                                                       "high": 0, "kev": 0, "eol": 0}})
    assert p["type"] == "message"
    assert p["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert p["attachments"][0]["content"]["type"] == "AdaptiveCard"


def test_generic_payload_shape():
    from safecadence.reports.webhooks import build_generic_payload
    p = build_generic_payload("e",
                              {"title": "x",
                               "kpi": {"hosts": 0, "critical": 0, "high": 0,
                                       "kev": 0, "eol": 0},
                               "download_url": "u"})
    assert p["event"] == "e"
    assert "generated_at" in p
    assert p["download_url"] == "u"


def test_webhook_signature_header(monkeypatch, wh_dir):
    """fire_webhook should compute an HMAC signature when a secret is set."""
    from safecadence.reports import webhooks as w
    rec = w.add_webhook_endpoint(url="https://example.invalid/hook",
                                 kind="generic", secret="s3cr3t")
    captured = {}
    real_send = w._send

    def fake_send(url, body, headers, *, timeout=5.0):
        captured["headers"] = dict(headers)
        captured["body"] = body
        return 200, "OK"
    monkeypatch.setattr(w, "_send", fake_send)
    out = w.fire_webhook(endpoint_id=rec["id"], event="report.generated",
                         report_summary={"title": "x", "kpi": {"hosts": 0}})
    assert out["ok"] is True
    sig = captured["headers"].get("X-SafeCadence-Signature", "")
    assert sig.startswith("sha256=") and len(sig) > 20


def test_fire_all_webhooks_returns_one_result_per_endpoint(monkeypatch, wh_dir):
    from safecadence.reports import webhooks as w
    w.add_webhook_endpoint(url="https://a/hook", kind="generic")
    w.add_webhook_endpoint(url="https://b/hook", kind="slack")
    monkeypatch.setattr(w, "_send", lambda *a, **k: (204, "no content"))
    out = w.fire_all_webhooks(event="report.generated",
                              report_summary={"title": "x"})
    assert len(out) == 2
    assert all(o["status"] == 204 for o in out)


# ==========================================================================
# Round 2 — industry templates
# ==========================================================================


def test_list_industry_templates_has_four():
    from safecadence.reports import list_industry_templates
    items = list_industry_templates()
    assert len(items) == 4
    ids = {t["id"] for t in items}
    assert ids == {"healthcare_hipaa", "finance_pci_sox",
                   "defense_cmmc_fedramp", "saas_soc2_iso27001"}


@pytest.mark.parametrize("tpl_id", [
    "healthcare_hipaa", "finance_pci_sox",
    "defense_cmmc_fedramp", "saas_soc2_iso27001",
])
def test_each_industry_template_loads_with_required_fields(tpl_id):
    from safecadence.reports import get_industry_template
    t = get_industry_template(tpl_id)
    assert t and t["id"] == tpl_id
    for k in ("name", "description", "industry", "regulations",
              "audience", "sections", "scope_defaults", "narrative_tone"):
        assert k in t, f"{tpl_id} missing {k}"
    assert isinstance(t["regulations"], list) and t["regulations"]
    assert isinstance(t["sections"], list) and len(t["sections"]) >= 4


def test_industry_template_apply_returns_render_options():
    from safecadence.reports import apply_industry_template
    out = apply_industry_template("healthcare_hipaa", {"site": "main"})
    assert out["template_id"] == "healthcare_hipaa"
    assert out["industry"] == "healthcare"
    assert out["scope"]["site"] == "main"
    assert "phi_exposure" in out["sections"]
    assert "hipaa" in out["scope"]["compliance_frameworks"]


def test_industry_template_unknown_raises():
    from safecadence.reports import apply_industry_template
    with pytest.raises(ValueError):
        apply_industry_template("does_not_exist")


@pytest.mark.parametrize("tpl_id", [
    "healthcare_hipaa", "finance_pci_sox",
    "defense_cmmc_fedramp", "saas_soc2_iso27001",
])
def test_each_industry_template_renders_without_crash(populated_store, tpl_id):
    from safecadence.reports import (
        compose_report, render_html, apply_industry_template,
    )
    t = apply_industry_template(tpl_id)
    r = compose_report(store=populated_store,
                       sections=t["sections"], scope=t["scope"])
    out = render_html(r, standalone=True)
    assert out.startswith("<!doctype html>")


def test_industry_specific_section_returns_placeholder_when_no_data(empty_store):
    from safecadence.reports.industry import phi_exposure, baa_gap_analysis
    r = phi_exposure(empty_store, {})
    assert r["empty"] is False
    assert "HIPAA" in r["html_fragment"] or "phi" in r["html_fragment"].lower()
    r = baa_gap_analysis(empty_store, {})
    assert r["empty"] is False


# ==========================================================================
# Round 2 — ticketing
# ==========================================================================


@pytest.fixture
def tk_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    yield tmp_path


def test_ticketing_add_list_remove(tk_dir):
    from safecadence.reports import ticketing as t
    assert t.list_ticketing_integrations() == []
    rec = t.add_ticketing_integration(
        kind="jira", url="https://acme.atlassian.net",
        project="SEC", auth_email="bot@acme.com", auth_token="abc")
    assert rec["id"].startswith("tk-")
    assert rec["auth_token"] == "***"
    items = t.list_ticketing_integrations()
    assert len(items) == 1
    assert items[0]["auth_token"] == "***"
    assert t.remove_ticketing_integration(rec["id"]) is True
    assert t.remove_ticketing_integration(rec["id"]) is False


def test_ticketing_invalid_kind_raises(tk_dir):
    from safecadence.reports import ticketing as t
    with pytest.raises(ValueError):
        t.add_ticketing_integration(kind="todo", url="https://x", project="P")


def test_ticketing_readonly_raises(tk_dir, monkeypatch):
    from safecadence.reports import ticketing as t
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        t.add_ticketing_integration(kind="jira", url="x", project="P")
    with pytest.raises(PermissionError):
        t.remove_ticketing_integration("tk-xxx")
    with pytest.raises(PermissionError):
        t.auto_create_tickets({"sections": []})


def test_ticketing_jira_payload_shape():
    from safecadence.reports.ticketing import build_jira_payload
    p = build_jira_payload(
        {"project": "SEC"},
        {"title": "CVE-2024-1: x", "body": "details", "severity": "critical",
         "kev": True})
    assert p["fields"]["project"]["key"] == "SEC"
    assert p["fields"]["priority"]["name"] == "Highest"
    assert "kev" in p["fields"]["labels"]
    assert p["fields"]["issuetype"]["name"] == "Task"


def test_ticketing_servicenow_payload_shape():
    from safecadence.reports.ticketing import build_servicenow_payload
    p = build_servicenow_payload(
        {"project": "Security"},
        {"title": "x", "body": "y", "severity": "critical"})
    assert p["category"] == "Security"
    assert p["urgency"] == "1" and p["impact"] == "1"
    assert p["short_description"] == "x"


def test_ticketing_github_payload_shape():
    from safecadence.reports.ticketing import build_github_payload
    p = build_github_payload(
        {"project": "org/repo"},
        {"title": "x", "body": "y", "severity": "high", "kev": False})
    assert p["title"] == "x"
    assert "high" in p["labels"]
    assert "safecadence" in p["labels"]


def test_ticketing_linear_payload_shape():
    from safecadence.reports.ticketing import build_linear_payload
    p = build_linear_payload(
        {"project": "team-id"},
        {"title": "x", "body": "y", "severity": "medium"})
    assert "issueCreate" in p["query"]
    assert p["variables"]["input"]["title"] == "x"
    assert p["variables"]["input"]["priority"] == 3
    assert p["variables"]["input"]["teamId"] == "team-id"


def test_ticketing_auto_create_dedupes_by_external_id(monkeypatch, tk_dir):
    from safecadence.reports import ticketing as t
    rec = t.add_ticketing_integration(
        kind="generic", url="https://hooks.invalid/x",
        project="P", auth_token="tok")
    monkeypatch.setattr(t, "_send", lambda *a, **k: (201, '{"id":"FOO-1"}'))
    report = {
        "sections": [
            {"key": "cve_exposure",
             "data": {"cves": [
                 {"id": "CVE-2024-1", "host": "h1", "severity": "critical",
                  "summary": "x"},
                 {"id": "CVE-2024-2", "host": "h2", "severity": "high",
                  "summary": "y"},
             ]}},
        ],
    }
    out = t.auto_create_tickets(report, severity_threshold="high")
    assert out["created"] == 2
    assert out["skipped_existing"] == 0
    out2 = t.auto_create_tickets(report, severity_threshold="high")
    assert out2["created"] == 0
    assert out2["skipped_existing"] == 2
    persisted = t.list_created_tickets()
    assert len(persisted) == 2


def test_ticketing_auto_create_threshold_filters(monkeypatch, tk_dir):
    from safecadence.reports import ticketing as t
    t.add_ticketing_integration(kind="generic", url="https://x", project="P")
    monkeypatch.setattr(t, "_send", lambda *a, **k: (201, ""))
    report = {"sections": [{"key": "cve_exposure", "data": {"cves": [
        {"id": "CVE-1", "host": "h", "severity": "low"},
        {"id": "CVE-2", "host": "h", "severity": "critical"},
    ]}}]}
    out = t.auto_create_tickets(report, severity_threshold="critical")
    assert out["created"] == 1


def test_ticketing_token_obfuscated_at_rest(tk_dir):
    from safecadence.reports import ticketing as t
    import json as _json
    t.add_ticketing_integration(kind="jira", url="https://x",
                                project="P", auth_email="e", auth_token="raw-secret")
    raw = (tk_dir / "reports" / "ticketing.json").read_text(encoding="utf-8")
    assert "raw-secret" not in raw
    assert "b64:" in raw
