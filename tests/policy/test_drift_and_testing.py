"""Drift comparison + policy testing harness."""

from __future__ import annotations

from safecadence.policy.drift import detect_drift, persist_evaluation
from safecadence.policy.evaluator import evaluate
from safecadence.policy.templates import load_template
from safecadence.policy.testing import run_test_dict


def test_drift_with_no_history_returns_empty():
    res = detect_drift("does_not_exist_yet")
    assert res["history_size"] == 0
    assert res["regressions"] == []


def test_drift_detects_regression(cisco_router_clean, cisco_router_messy):
    """Save 2 evaluations: clean first, messy second → expect regressions."""
    p = load_template("tmpl_network_hardening")
    persist_evaluation(evaluate(p, [cisco_router_clean]))
    # Re-tag the messy router with the same asset_id so drift sees a regression
    cisco_router_messy["identity"]["asset_id"] = "r1"
    persist_evaluation(evaluate(p, [cisco_router_messy]))
    res = detect_drift(p.policy_id)
    assert res["history_size"] == 2
    assert any(r["asset_id"] == "r1" for r in res["regressions"])


def test_run_test_dict_passes_for_clean_router(cisco_router_clean):
    spec = {
        "name": "smoke",
        "policy": "tmpl_network_hardening",
        "fixture": cisco_router_clean,
        "expect": {"pass": ["enforce_ssh_v2", "enable_ntp"]},
    }
    res = run_test_dict(spec)
    assert res["passed"], res


def test_run_test_dict_fails_when_expectation_unmet():
    spec = {
        "name": "should_fail",
        "policy": "tmpl_network_hardening",
        "fixture": {"identity": {"asset_id": "z", "vendor": "cisco",
                                   "asset_type": "network"},
                    "os": {"os_type": "ios"},
                    "raw_collection": {"show_running-config": ""}},
        "expect": {"pass": ["disable_telnet", "enforce_ssh_v2", "require_aaa",
                            "enforce_snmpv3", "enable_syslog", "enable_ntp"]},
    }
    res = run_test_dict(spec)
    assert not res["passed"]
    assert res["diffs"]["missing_pass"]
