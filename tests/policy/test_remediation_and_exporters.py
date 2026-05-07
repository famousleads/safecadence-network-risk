"""End-to-end: evaluator → remediation plan → all exporters."""

from __future__ import annotations

import pytest

from safecadence.policy.evaluator import evaluate
from safecadence.policy.exporters import export, list_exporters
from safecadence.policy.remediation import generate_plan
from safecadence.policy.templates import load_template


def test_plan_translates_violations(cisco_router_messy):
    p = load_template("tmpl_network_hardening")
    ev = evaluate(p, [cisco_router_messy])
    plan = generate_plan(p, ev, {"r2": cisco_router_messy})
    assert plan.summary["total"] >= 1
    assert plan.summary["translated"] >= 1
    # Every step must have either fix commands or a notes message
    for s in plan.steps:
        assert s.fix_commands or s.notes


@pytest.mark.parametrize("fmt", ["raw", "ansible", "terraform", "bash",
                                  "powershell", "markdown", "pdf"])
def test_all_exporters_produce_output(cisco_router_messy, fmt):
    p = load_template("tmpl_network_hardening")
    ev = evaluate(p, [cisco_router_messy])
    plan = generate_plan(p, ev, {"r2": cisco_router_messy})
    out = export(fmt, p, plan)
    assert out
    if isinstance(out, bytes):
        assert len(out) > 100
    else:
        assert len(out) > 50


def test_ansible_exporter_targets_correct_module(cisco_router_messy):
    p = load_template("tmpl_network_hardening")
    ev = evaluate(p, [cisco_router_messy])
    plan = generate_plan(p, ev, {"r2": cisco_router_messy})
    yml = export("ansible", p, plan)
    assert "cisco.ios.ios_config" in yml
    assert "connection: network_cli" in yml


def test_exporters_registry_complete():
    fmts = list_exporters()
    assert {"raw", "ansible", "terraform", "bash", "powershell", "markdown", "pdf"}.issubset(fmts)
