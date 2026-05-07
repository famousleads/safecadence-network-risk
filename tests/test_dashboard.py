"""Dashboard builder + renderer tests."""

import json
import os
import re
import tempfile
from pathlib import Path

import pytest

from safecadence.dashboard import build_dashboard_data, load_scan_dir, render_dashboard


def _fake_scan(hostname: str, *, vendor="cisco-ios", os_="ios", version="15.2",
               health=20, risk=85, cves=None, eol=None, findings=None) -> dict:
    return {
        "source": f"{hostname}.txt",
        "vendor": vendor,
        "duration_ms": 12,
        "started_at": "2026-05-03T00:00:00+00:00",
        "health_score": health,
        "health_band": "critical" if health < 40 else "warning" if health < 75 else "good",
        "risk_score": risk,
        "risk_band": "critical" if risk >= 81 else "high" if risk >= 61 else "medium" if risk >= 31 else "low",
        "summary": "test",
        "asset": {
            "asset_id": hostname, "hostname": hostname, "vendor": vendor,
            "os": os_, "version": version, "device_type": "router",
            "ip": "10.0.0.1", "interfaces": [],
        },
        "findings": findings or [
            {"rule_id": "test-rule-1", "title": "Test critical", "severity": "critical",
             "description": "", "remediation": "", "fix_snippet": "",
             "references": [], "evidence": "", "domain": "security", "matched_at": ""},
        ],
        "cves": cves or [],
        "eol": eol,
        "parsed_summary": {
            "hostname": hostname, "model": "", "os": os_, "version": version,
            "interfaces": 0, "neighbors": 0,
        },
        "parsed_raw": "hostname " + hostname + "\nversion " + version + "\n",
    }


@pytest.fixture
def scan_dir(tmp_path):
    """Create a temp dir with three scan JSON files."""
    s1 = _fake_scan("DC-CORE-01", vendor="cisco-ios", risk=100, health=11,
                    cves=[{"cve_id":"CVE-2017-3881","severity":"critical","cvss":9.8,"kev":True,
                           "title":"Test","references":[]}],
                    eol={"vendor":"cisco-ios","os":"ios","version_prefix":"15.2",
                         "end_of_software":"2022-09-30","end_of_support":"2025-09-30",
                         "status_today":"end-of-support","notes":""})
    s2 = _fake_scan("SPINE-01", vendor="arista-eos", os_="eos", version="4.28.3M",
                    risk=58, health=45)
    s3 = _fake_scan("CAMPUS-CORE-01", vendor="aruba-cx", os_="aos-cx", version="10.10.1000",
                    risk=72, health=38)
    for i, scan in enumerate([s1, s2, s3]):
        (tmp_path / f"scan_{i}.json").write_text(json.dumps(scan), encoding="utf-8")
    return tmp_path


# ----------------------------------------------------------------- #
# Loader
# ----------------------------------------------------------------- #
class TestLoader:
    def test_loads_all_json(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        assert len(scans) == 3

    def test_skips_non_json(self, scan_dir):
        (scan_dir / "readme.txt").write_text("not a scan")
        scans = load_scan_dir(scan_dir)
        assert len(scans) == 3

    def test_handles_missing_dir(self):
        scans = load_scan_dir("/nonexistent/path/whatever")
        assert scans == []

    def test_skips_invalid_json(self, scan_dir):
        (scan_dir / "broken.json").write_text("{ not json")
        scans = load_scan_dir(scan_dir)
        assert len(scans) == 3   # broken file silently skipped


# ----------------------------------------------------------------- #
# Builder
# ----------------------------------------------------------------- #
class TestBuilder:
    def test_overview_aggregates(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        assert data.overview["device_count"] == 3
        assert data.overview["avg_risk"] == int((100 + 58 + 72) / 3)
        assert data.overview["critical_devices"] >= 1   # DC-CORE-01 risk=100
        assert data.overview["eol_devices"] >= 1        # DC-CORE-01 EoS
        assert data.overview["kev_devices"] >= 1        # DC-CORE-01 has KEV CVE
        assert data.overview["findings_critical"] >= 3   # one per scan in fixture

    def test_vendor_breakdown(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        assert data.overview["vendor_breakdown"]["cisco-ios"] == 1
        assert data.overview["vendor_breakdown"]["arista-eos"] == 1
        assert data.overview["vendor_breakdown"]["aruba-cx"] == 1

    def test_devices_have_running_config(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        for d in data.devices:
            assert d["scan"]["parsed_raw"], f"running config missing for {d['name']}"

    def test_cves_deduped_with_affected_devices(self):
        # Two devices with the same CVE
        cve = {"cve_id":"CVE-2017-3881","severity":"critical","cvss":9.8,"kev":True,
               "title":"x","references":[]}
        scans = [
            _fake_scan("A", cves=[cve]),
            _fake_scan("B", cves=[cve]),
            _fake_scan("C"),
        ]
        data = build_dashboard_data(scans)
        assert len(data.cves_by_id) == 1
        assert sorted(data.cves_by_id[0]["affected_devices"]) == ["A", "B"]

    def test_eol_summary_dedupes(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        # one EOL record (DC-CORE-01)
        assert len(data.eol_summary) >= 1
        assert any("DC-CORE-01" in r["affected_devices"] for r in data.eol_summary)


# ----------------------------------------------------------------- #
# Renderer
# ----------------------------------------------------------------- #
class TestRenderer:
    def test_renders_valid_html(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        html = render_dashboard(data)
        assert "<!doctype html>" in html
        assert "</html>" in html
        # Inline SVG renderers — no CDN
        assert "DC-CORE-01" in html
        assert "SPINE-01" in html

    def test_renders_with_no_cdn(self, scan_dir):
        """Dashboard must be 100% self-contained; no external scripts."""
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        html = render_dashboard(data)
        import re
        externals = re.findall(r'<script[^>]+src=["\']https?://', html)
        assert not externals, f"CDN scripts present: {externals}"
        # Stylesheets too
        ext_css = re.findall(r'<link[^>]+href=["\']https?://', html)
        assert not ext_css, f"CDN stylesheets present: {ext_css}"

    def test_data_payload_is_valid_json(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        html = render_dashboard(data)
        m = re.search(r"const DATA = (\{.*?\});\s*\n\s*//", html, re.DOTALL)
        assert m, "could not find DATA payload"
        payload = json.loads(m.group(1))
        assert payload["overview"]["device_count"] == 3
        assert len(payload["devices"]) == 3

    def test_running_config_embedded(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        html = render_dashboard(data)
        # Each device's parsed_raw should be reachable in the embedded JSON
        assert "hostname DC-CORE-01" in html

    def test_topology_optional(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        # Without topology
        data = build_dashboard_data(scans)
        assert data.topology is None
        # With topology
        topo = {"nodes": [{"name":"X"}], "edges":[]}
        data2 = build_dashboard_data(scans, topology=topo)
        assert data2.topology == topo

    def test_title_substitution(self, scan_dir):
        scans = load_scan_dir(scan_dir)
        data = build_dashboard_data(scans)
        html = render_dashboard(data, title="My Custom Title")
        assert "<title>My Custom Title</title>" in html
