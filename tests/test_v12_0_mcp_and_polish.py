"""v12.0 — MCP server + multi-dim Safe Score + Risk Economics + Exec Risk Brief preset.

Tests cover:
  * MCP server handshake (initialize → initialized)
  * MCP tools/list returns all 7 tools
  * MCP tools/call dispatches to the right tool
  * Each tool returns a sensible response shape
  * RBAC + audit logging hooks don't crash on missing data
  * Multi-dim Safe Score: structure, ranges, fallbacks
  * Risk Economics: $ exposures, ROI ranking, technical debt
  * Executive Risk Brief preset is registered and pickable
"""
from __future__ import annotations

import io
import json

import pytest


# --------------------------------------------------------------------------
# MCP server — protocol handshake + dispatch
# --------------------------------------------------------------------------


def _make_server_with_streams(input_lines: list[str]):
    """Build an MCPServer wired to in-memory stdin/stdout."""
    from safecadence.mcp.server import MCPServer
    stdin = io.StringIO("\n".join(input_lines) + "\n")
    stdout = io.StringIO()
    server = MCPServer(stdin=stdin, stdout=stdout)
    return server, stdin, stdout


def _run_and_collect_responses(server, stdout) -> list[dict]:
    """Run server.run() to completion, return parsed response messages."""
    server.run()
    stdout.seek(0)
    out = []
    for line in stdout.readlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def test_mcp_initialize_handshake():
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "0.1"},
        },
    }
    server, _, stdout = _make_server_with_streams([json.dumps(init_req)])
    responses = _run_and_collect_responses(server, stdout)
    assert len(responses) == 1
    resp = responses[0]
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "safecadence"
    assert "protocolVersion" in resp["result"]
    assert "tools" in resp["result"]["capabilities"]


def test_mcp_tools_list_returns_seven_tools():
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    tools_resp = [r for r in responses if r["id"] == 2][0]
    tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
    expected = {
        "query_topology", "retrieve_findings", "query_compliance",
        "fetch_evidence", "inspect_identities", "generate_report",
        "evaluate_posture",
    }
    assert expected.issubset(tool_names)


def test_mcp_tools_list_blocked_without_initialize():
    """Calling tools/list before initialize should return an error."""
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    assert responses[0]["error"]["code"] == -32002


def test_mcp_unknown_method_returns_error():
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "not/a/real/method"}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    err_resp = [r for r in responses if r["id"] == 2][0]
    assert err_resp["error"]["code"] == -32601  # Method not found


def test_mcp_call_unknown_tool_returns_error():
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "no_such_tool", "arguments": {}}}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    err_resp = [r for r in responses if r["id"] == 2][0]
    assert err_resp["error"]["code"] == -32601


def test_mcp_parse_error_keeps_loop_alive():
    """A malformed JSON line should produce an error response but keep
    the server running so subsequent valid requests still work."""
    server, _, stdout = _make_server_with_streams([
        "this is not json",
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    # Should have a parse error + a successful initialize
    parse_errors = [r for r in responses
                    if r.get("error", {}).get("code") == -32700]
    inits = [r for r in responses if r.get("id") == 1]
    assert len(parse_errors) >= 1
    assert len(inits) == 1


def test_mcp_notifications_get_no_response():
    """Notifications (no `id`) must not get responses."""
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    # Only one response — the initialize. Notification gets no reply.
    assert len(responses) == 1
    assert responses[0]["id"] == 1


def test_mcp_shutdown_exits_cleanly():
    server, _, stdout = _make_server_with_streams([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    ])
    responses = _run_and_collect_responses(server, stdout)
    shutdown_resp = [r for r in responses if r["id"] == 2][0]
    assert shutdown_resp["result"] is None
    assert server.shutdown_requested


# --------------------------------------------------------------------------
# MCP tools — individual call shapes
# --------------------------------------------------------------------------


def test_query_topology_returns_expected_shape():
    from safecadence.mcp.tools import query_topology
    out = query_topology({"scope": "all", "include_relationships": True})
    assert "assets" in out
    assert "relationships" in out
    assert "summary" in out
    assert "asset_count" in out["summary"]


def test_retrieve_findings_returns_filtered_list():
    from safecadence.mcp.tools import retrieve_findings
    out = retrieve_findings({"severity": "critical", "limit": 10})
    assert "findings" in out
    assert "count" in out
    assert out["filters_applied"]["severity"] == "critical"


def test_query_compliance_requires_framework():
    from safecadence.mcp.tools import query_compliance, MCPToolError
    with pytest.raises(MCPToolError) as exc_info:
        query_compliance({})
    assert "framework parameter is required" in str(exc_info.value)


def test_fetch_evidence_requires_both_args():
    from safecadence.mcp.tools import fetch_evidence, MCPToolError
    with pytest.raises(MCPToolError):
        fetch_evidence({"framework": "soc2"})  # missing control_id
    with pytest.raises(MCPToolError):
        fetch_evidence({"control_id": "CC6.7"})  # missing framework


def test_inspect_identities_returns_list_shape():
    from safecadence.mcp.tools import inspect_identities
    out = inspect_identities({})
    assert "identities" in out
    assert "count" in out
    assert isinstance(out["identities"], list)


def test_generate_report_validates_format():
    from safecadence.mcp.tools import generate_report, MCPToolError
    with pytest.raises(MCPToolError) as exc_info:
        generate_report({"format": "doc"})  # not a valid format
    assert "Unsupported format" in str(exc_info.value)


def test_generate_report_validates_preset():
    from safecadence.mcp.tools import generate_report, MCPToolError
    with pytest.raises(MCPToolError) as exc_info:
        generate_report({"preset": "not_a_real_preset", "format": "html"})
    assert "Unknown preset" in str(exc_info.value)


def test_evaluate_posture_returns_multidim_shape():
    from safecadence.mcp.tools import evaluate_posture
    out = evaluate_posture({})
    assert "overall" in out
    assert "dimensions" in out


# --------------------------------------------------------------------------
# Multi-dimensional Safe Score
# --------------------------------------------------------------------------


def test_multidim_score_has_six_dimensions():
    from safecadence.scores.multi_dim_score import compute_multidim_score
    score = compute_multidim_score()
    expected = {
        "compliance_health", "identity_health", "drift_stability",
        "patch_freshness", "attack_path_risk", "ai_governance_readiness",
    }
    assert expected == set(score["dimensions"].keys())


def test_multidim_score_each_dimension_has_value_and_factors():
    from safecadence.scores.multi_dim_score import compute_multidim_score
    score = compute_multidim_score()
    for name, dim in score["dimensions"].items():
        assert "value" in dim, f"{name} missing 'value'"
        assert "confidence_band" in dim, f"{name} missing 'confidence_band'"
        assert "top_factors" in dim, f"{name} missing 'top_factors'"


def test_multidim_score_overall_is_in_0_100_range():
    from safecadence.scores.multi_dim_score import compute_multidim_score
    score = compute_multidim_score()
    overall = score["overall"]
    if overall is not None:
        assert 0 <= overall <= 100


def test_multidim_score_history_only_when_requested():
    from safecadence.scores.multi_dim_score import compute_multidim_score
    score_no_hist = compute_multidim_score(include_history=False)
    score_with_hist = compute_multidim_score(include_history=True)
    assert "history" not in score_no_hist
    assert "history" in score_with_hist


def test_compute_safe_score_flat_returns_a_number_or_none():
    from safecadence.scores.multi_dim_score import compute_safe_score_flat
    v = compute_safe_score_flat()
    assert v is None or (0 <= v <= 100)


# --------------------------------------------------------------------------
# Risk Economics
# --------------------------------------------------------------------------


def test_estimated_audit_exposure_zero_findings():
    from safecadence.reports.risk_economics import estimated_audit_exposure
    out = estimated_audit_exposure([], ["soc2", "pci-dss-v4"])
    assert out["total_exposure_usd"] == 0
    assert out["deal_block_risk_usd"] == 0


def test_estimated_audit_exposure_with_pci_findings():
    from safecadence.reports.risk_economics import estimated_audit_exposure
    findings = [
        {"severity": "critical", "controls": [{"framework": "pci-dss-v4"}]},
        {"severity": "high", "controls": [{"framework": "pci-dss-v4"}]},
    ]
    out = estimated_audit_exposure(findings, ["pci-dss-v4"])
    assert out["total_exposure_usd"] > 0
    assert "pci-dss-v4" in out["by_framework"]
    assert out["by_framework"]["pci-dss-v4"]["finding_count"] == 2


def test_estimated_audit_exposure_soc2_deal_block():
    """6+ critical/high SOC 2 findings → deal-block risk surfaces."""
    from safecadence.reports.risk_economics import estimated_audit_exposure
    findings = [
        {"severity": "critical", "controls": [{"framework": "soc2"}]}
        for _ in range(6)
    ]
    out = estimated_audit_exposure(findings, ["soc2"])
    assert out["deal_block_risk_usd"] > 0


def test_estimated_remediation_cost_sums_correctly():
    from safecadence.reports.risk_economics import (
        estimated_remediation_cost,
        REMEDIATION_COST_PER_SEVERITY,
    )
    findings = [{"severity": "critical"}, {"severity": "high"}, {"severity": "low"}]
    out = estimated_remediation_cost(findings)
    expected = (REMEDIATION_COST_PER_SEVERITY["critical"]
                + REMEDIATION_COST_PER_SEVERITY["high"]
                + REMEDIATION_COST_PER_SEVERITY["low"])
    assert out["total_cost_usd"] == expected
    assert out["by_severity"]["critical"]["count"] == 1
    assert out["by_severity"]["high"]["count"] == 1


def test_risk_reduction_roi_ranks_high_severity_first():
    from safecadence.reports.risk_economics import risk_reduction_roi
    findings = [
        {"id": "low-1", "severity": "low", "title": "minor"},
        {"id": "crit-1", "severity": "critical", "title": "big"},
        {"id": "med-1", "severity": "medium", "title": "mid"},
    ]
    ranked = risk_reduction_roi(findings, top_n=3)
    assert len(ranked) == 3
    # Critical should be first because risk-points-per-hour is highest
    assert ranked[0]["severity"] == "critical"


def test_technical_debt_score_no_findings_is_100():
    from safecadence.reports.risk_economics import technical_debt_score
    out = technical_debt_score([])
    assert out["score"] == 100.0
    assert out["stale_over_90d"] == 0


def test_technical_debt_score_drops_with_stale_findings():
    from safecadence.reports.risk_economics import technical_debt_score
    findings = [
        {"severity": "critical", "age_days": 200},
        {"severity": "high", "age_days": 100},
    ]
    out = technical_debt_score(findings)
    assert out["score"] < 100
    assert out["stale_over_90d"] == 2
    assert out["stale_over_180d"] == 1


def test_operational_risk_velocity_with_insufficient_data():
    from safecadence.reports.risk_economics import operational_risk_velocity
    out = operational_risk_velocity([])
    assert out["trend"] == "insufficient-data"


def test_operational_risk_velocity_detects_increasing_trend():
    from safecadence.reports.risk_economics import operational_risk_velocity
    history = [
        {"timestamp": "2026-01-01", "findings_count": 10},
        {"timestamp": "2026-01-08", "findings_count": 12},
        {"timestamp": "2026-01-15", "findings_count": 13},
        {"timestamp": "2026-01-22", "findings_count": 25},  # spike
    ]
    out = operational_risk_velocity(history)
    assert out["trend"] == "increasing"


def test_compliance_burn_down_computes_weeks_to_target():
    from safecadence.reports.risk_economics import compliance_burn_down
    status = {
        "soc2": {"passed": 50, "failed": 14, "passed_this_week": 2},
    }
    out = compliance_burn_down(status)
    assert out["soc2"]["current_pct"] == 78.1
    assert out["soc2"]["weeks_to_target"] is not None


def test_compute_risk_economics_full_shape():
    from safecadence.reports.risk_economics import compute_risk_economics
    findings = [
        {"severity": "critical", "controls": [{"framework": "soc2"}], "age_days": 50},
        {"severity": "high", "controls": [{"framework": "pci-dss-v4"}], "age_days": 100},
    ]
    out = compute_risk_economics(findings, frameworks=["soc2", "pci-dss-v4"])
    assert "estimated_audit_exposure" in out
    assert "estimated_remediation_cost" in out
    assert "risk_reduction_roi_top10" in out
    assert "technical_debt_score" in out
    assert "disclaimer" in out  # always present, anchors expectations


# --------------------------------------------------------------------------
# Executive Risk Brief preset
# --------------------------------------------------------------------------


def test_executive_risk_brief_preset_is_registered():
    from safecadence.reports.presets import get_preset
    preset = get_preset("executive_risk_brief")
    assert preset is not None
    assert preset["audience"] == "ceo"
    assert "multi_dim_safe_score" in preset["sections"]
    assert "risk_economics" in preset["sections"]
    assert "top_5_executive_actions" in preset["sections"]


def test_executive_risk_brief_signals_five_minute_target():
    """The 'five_minute_target' flag is what the homepage demo flow keys on."""
    from safecadence.reports.presets import get_preset
    preset = get_preset("executive_risk_brief")
    assert preset["extras"]["five_minute_target"] is True


def test_legacy_exec_brief_still_works():
    """v12 added a new preset; the old one must still resolve."""
    from safecadence.reports.presets import get_preset
    legacy = get_preset("exec_brief")
    assert legacy is not None
    assert "executive_summary" in legacy["sections"]


def test_all_v12_presets_have_required_fields():
    from safecadence.reports.presets import list_presets
    required = {"id", "name", "description", "audience", "sections",
                "visual_style", "narrative_tone", "extras"}
    for p in list_presets():
        missing = required - set(p.keys())
        assert not missing, f"Preset {p.get('id')} missing fields: {missing}"
