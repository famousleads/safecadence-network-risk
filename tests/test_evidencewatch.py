"""EvidenceWatch — the Monday One-Pager + Audit Button."""
from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path / "platform_assets"))
    yield tmp_path


def _fleet():
    from safecadence.demo_sheriff import build_sheriff_fleet
    return build_sheriff_fleet()


def test_report_finds_dark_cameras_and_storage_risk():
    from safecadence.evidencewatch import build_report
    r = build_report(_fleet())
    assert r["sense_total"] > 5
    assert r["dark_count"] >= 1                 # S1 dead d1 cameras
    assert r["overall"] in ("warning", "critical")
    assert any(s["pct_used"] > 85 for s in r["storage"])   # S2 NAS at 91%
    assert r["chain"]["overall_status"] == "critical"
    assert r["action"] and "camera" in r["action"].lower() or "storage" in r["action"].lower()


def test_report_healthy_on_empty_fleet():
    from safecadence.evidencewatch import build_report
    r = build_report([])
    assert r["dark_count"] == 0
    assert r["sense_total"] == 0


def test_render_one_pager_is_escaped_and_complete():
    from safecadence.evidencewatch import build_report, render_report_html
    fleet = _fleet()
    fleet[0]["identity"]["hostname"] = '<script>alert(1)</script>'
    html = render_report_html(build_report(fleet), agency="Cypress County SO")
    assert "<script>alert(1)</script>" not in html          # escaped
    assert "&lt;script&gt;" in html or "alert(1)" not in html
    for marker in ("EVIDENCEWATCH", "ONE ACTION", "DARK CAMERAS",
                    "EVIDENCE CHAIN", "EVIDENCE STORAGE",
                    "no data leaves your network"):
        assert marker in html, marker


def test_snapshot_chain_and_tamper_detection(_iso):
    from safecadence import evidencewatch as ew
    ew.snapshot(ew.build_report(_fleet()))
    ew.snapshot(ew.build_report(_fleet()))
    v = ew.verify_history()
    assert v["ok"] and v["weeks"] >= 1
    # tamper with the first snapshot -> chain breaks
    f = sorted((_iso / "evidencewatch").glob("week-*.json"))[0]
    e = json.loads(f.read_text()); e["overall"] = "healthy"
    f.write_text(json.dumps(e))
    assert ew.verify_history()["ok"] is False


def test_audit_export_renders(_iso):
    from safecadence import evidencewatch as ew
    ew.snapshot(ew.build_report(_fleet()))
    html = ew.audit_export(agency="Cypress County SO")
    assert "Audit Pack" in html and "VERIFIED" in html
    assert "not an audit, attestation, or certification" in html


def test_ui_routes(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.demo_sheriff import load_sheriff_demo
    from safecadence.ui.desat_pages import register
    load_sheriff_demo(target_dir=_iso / "platform_assets")
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    r = c.get("/evidencewatch?agency=Test SO")
    assert r.status_code == 200 and "EVIDENCEWATCH" in r.text
    r = c.get("/api/v1/desat/evidencewatch")
    assert r.status_code == 200 and r.json()["sense_total"] > 0
    r = c.get("/evidencewatch/audit")
    assert r.status_code == 200 and "Audit Pack" in r.text
