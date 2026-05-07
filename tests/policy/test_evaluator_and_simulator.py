"""Evaluator + simulator behavior."""

from __future__ import annotations

from safecadence.policy.evaluator import evaluate
from safecadence.policy.simulator import simulate
from safecadence.policy.templates import load_template


def test_evaluate_clean_router_high_pass(cisco_router_clean):
    p = load_template("tmpl_network_hardening")
    ev = evaluate(p, [cisco_router_clean])
    assert ev.fail_count == 0, [v.evidence for v in ev.violations]
    assert ev.pass_count >= 5


def test_evaluate_messy_router_has_violations(cisco_router_messy):
    p = load_template("tmpl_network_hardening")
    ev = evaluate(p, [cisco_router_messy])
    assert ev.fail_count > 0
    cids = {v.control_id for v in ev.violations}
    # At minimum we should catch telnet + missing syslog + snmpv2 community
    assert "disable_telnet" in cids
    assert "enforce_snmpv3" in cids


def test_simulator_returns_summary_without_persisting(cisco_router_messy):
    p = load_template("tmpl_network_hardening")
    res = simulate(p, [cisco_router_messy])
    assert res["would_fail"] >= 1
    assert "summary" in res and "If enforced today" in res["summary"]


def test_evaluate_skips_assets_outside_scope(cisco_router_clean):
    p = load_template("tmpl_cloud_security")  # only targets cloud assets
    ev = evaluate(p, [cisco_router_clean])
    # No cloud assets in fixture → no per-asset results
    assert ev.asset_results == []


def test_exception_marks_control_NA(cisco_router_messy):
    from safecadence.policy.schema import PolicyException
    p = load_template("tmpl_network_hardening")
    p.exceptions = [PolicyException(
        exception_id="exc_1", asset_id="r2", control_id="disable_telnet",
        justification="legacy access required", approved_by="ops", status="active",
    )]
    ev = evaluate(p, [cisco_router_messy])
    cids = {v.control_id for v in ev.violations}
    # disable_telnet should now NOT appear in violations because of exception
    assert "disable_telnet" not in cids
