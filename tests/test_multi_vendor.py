"""End-to-end tests across every shipped adapter."""

from pathlib import Path

import pytest

from safecadence.core.registry import AdapterRegistry
from safecadence.core.schema import Asset, ScanResult
from safecadence.engines.config_audit import ConfigAuditEngine, load_rules
from safecadence.engines.health import compute_health, health_band
from safecadence.engines.risk import compute_risk, risk_band, summarize
from safecadence.reports.docx import to_docx_bytes
from safecadence.reports.html import to_html
from safecadence.reports.json import to_json
from safecadence.reports.markdown import to_markdown


SAMPLES = Path(__file__).resolve().parents[1] / "examples" / "sample_configs"

VENDOR_SAMPLES = [
    ("cisco-ios",  "cisco_ios_running.txt"),
    ("cisco-nxos", "cisco_nxos_running.txt"),
    ("cisco-asa",  "cisco_asa_running.txt"),
    ("aruba-cx",   "aruba_cx_running.txt"),
    ("arista-eos", "arista_eos_running.txt"),
]


def _scan(slug: str, fname: str) -> ScanResult:
    path = SAMPLES / fname
    text = path.read_text(encoding="utf-8")
    adapter = AdapterRegistry.get(slug)
    assert adapter is not None, f"adapter {slug!r} not registered"
    parsed = adapter.parse_config(text)
    findings = ConfigAuditEngine(vendor=slug).run(parsed)
    health = compute_health(parsed, findings)
    risk = compute_risk(findings)
    asset = Asset(asset_id=parsed.hostname or path.stem, hostname=parsed.hostname,
                  vendor=slug, model=parsed.model, os=parsed.os, version=parsed.version,
                  device_type=parsed.device_type, findings=findings,
                  health_score=health, risk_score=risk,
                  health_band=health_band(health), risk_band=risk_band(risk))
    return ScanResult(source=str(path), vendor=slug, duration_ms=0,
                      parsed=parsed, asset=asset, findings=findings,
                      health_score=health, risk_score=risk,
                      health_band=health_band(health), risk_band=risk_band(risk),
                      summary=summarize(findings))


# ---------------------------------------------------------------------------
# Per-vendor smoke tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_adapter_registered(slug, fname):
    assert AdapterRegistry.get(slug) is not None


@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_auto_detect(slug, fname):
    text = (SAMPLES / fname).read_text(encoding="utf-8")
    detected = AdapterRegistry.detect(text, filename=fname)
    assert detected is not None, f"could not auto-detect {slug}"
    assert detected.slug == slug, f"expected {slug}, got {detected.slug}"


@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_rules_load_for_vendor(slug, fname):
    rules = load_rules(vendor=slug)
    assert len(rules) >= 5, f"{slug} should ship at least 5 rules, has {len(rules)}"


@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_findings_produced(slug, fname):
    result = _scan(slug, fname)
    # Each deliberately-broken sample should produce at least 3 findings
    assert len(result.findings) >= 3, \
        f"{slug} sample should produce findings, got {len(result.findings)}"


@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_scoring_in_range(slug, fname):
    result = _scan(slug, fname)
    assert 0 <= result.health_score <= 100
    assert 0 <= result.risk_score <= 100


# ---------------------------------------------------------------------------
# Renderer tests — make sure none of them throw on any vendor
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("slug,fname", VENDOR_SAMPLES)
def test_renderers_produce_output(slug, fname):
    result = _scan(slug, fname)
    md = to_markdown(result)
    js = to_json(result)
    html = to_html(result)
    docx = to_docx_bytes(result)

    assert "SafeCadence" in md
    assert '"findings"' in js
    assert "<!doctype html>" in html
    assert docx[:2] == b"PK", "docx bytes should be a valid zip"
    assert len(docx) > 500


def test_specific_findings_per_vendor():
    """Spot-check that some characteristic rules fire for each vendor."""
    expected = {
        "cisco-ios":  "cisco-ios-snmp-default-community",
        "cisco-nxos": "cisco-nxos-snmp-default-community",
        "cisco-asa":  "cisco-asa-snmp-default-community",
        "aruba-cx":   "aruba-cx-snmp-default-community",
        "arista-eos": "arista-eos-snmp-default-community",
    }
    for slug, fname in VENDOR_SAMPLES:
        result = _scan(slug, fname)
        ids = {f.rule_id for f in result.findings}
        assert expected[slug] in ids, \
            f"{slug}: expected rule {expected[slug]!r} to fire, got {sorted(ids)}"
