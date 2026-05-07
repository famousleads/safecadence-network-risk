"""End-to-end tests: parse sample config, run audit, score."""

from pathlib import Path

import pytest

from safecadence.adapters.cisco_ios import parser as ios_parser
from safecadence.core.registry import AdapterRegistry
from safecadence.core.schema import Severity
from safecadence.engines.config_audit import ConfigAuditEngine, load_rules
from safecadence.engines.health import compute_health, health_band
from safecadence.engines.risk import compute_risk, risk_band, summarize


SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_configs" / "cisco_ios_running.txt"


@pytest.fixture(scope="module")
def parsed():
    return ios_parser.parse(SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def findings(parsed):
    return ConfigAuditEngine(vendor="cisco-ios").run(parsed)


def test_adapter_auto_detected():
    text = SAMPLE.read_text(encoding="utf-8")
    adapter = AdapterRegistry.detect(text, filename=str(SAMPLE))
    assert adapter is not None
    assert adapter.slug == "cisco-ios"


def test_rules_load():
    rules = load_rules(vendor="cisco-ios")
    assert len(rules) >= 25, f"expected >=25 cisco-ios rules, got {len(rules)}"


def test_findings_produced(findings):
    # The deliberately-vulnerable sample should produce a healthy stack of findings
    assert len(findings) >= 10


def test_telnet_detected(findings):
    assert any(f.rule_id == "cisco-ios-telnet-enabled" for f in findings)


def test_default_snmp_detected(findings):
    assert any(f.rule_id == "cisco-ios-snmp-default-community" for f in findings)


def test_rw_snmp_detected(findings):
    assert any(f.rule_id == "cisco-ios-snmp-rw-community" for f in findings)


def test_no_aaa_detected(findings):
    assert any(f.rule_id == "cisco-ios-no-aaa" for f in findings)


def test_http_server_detected(findings):
    assert any(f.rule_id == "cisco-ios-http-server-enabled" for f in findings)


def test_findings_sorted_by_severity(findings):
    weights = [f.severity.weight for f in findings]
    assert weights == sorted(weights, reverse=True), "findings should be severity-sorted desc"


def test_scoring(parsed, findings):
    h = compute_health(parsed, findings)
    r = compute_risk(findings)
    assert 0 <= h <= 100
    assert 0 <= r <= 100
    # Sample is intentionally junk → risk should be elevated, health degraded
    assert r >= 30
    assert h <= 80
    assert health_band(h) in {"excellent", "good", "warning", "poor", "critical"}
    assert risk_band(r) in {"low", "medium", "high", "critical"}


def test_summary_format(findings):
    s = summarize(findings)
    for word in ("critical", "high", "medium", "low", "info"):
        assert word in s
