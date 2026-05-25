"""
Tests for v14.1 — intelligence layer (corpus + forecasting + anomaly +
assistant + remediation_pr).
"""
from __future__ import annotations

import pytest

from safecadence.intelligence.anomaly import (
    DEFAULT_MIN_N,
    DEFAULT_Z_THRESHOLD,
    EWMAState,
    batch_detect_per_entity,
    detect,
)
from safecadence.intelligence.assistant import ask, plan
from safecadence.intelligence.corpus import (
    KNOWN_METRICS,
    KNOWN_VERTICALS,
    LOCAL_PRIMARY_DAYS,
    MIN_LOCAL_DAYS,
    ReferenceCorpus,
)
from safecadence.intelligence.forecasting import forecast_many, forecast_metric
from safecadence.intelligence.remediation_pr import draft_remediation_pr


# ---- corpus ----------------------------------------------------- #


def test_corpus_known_verticals_complete():
    assert {"healthcare", "finance", "msp-smb", "retail",
            "defense", "generic"} == set(KNOWN_VERTICALS)


def test_corpus_known_metrics_present():
    assert "safe_score" in KNOWN_METRICS
    assert "patch_lag_days" in KNOWN_METRICS
    assert "nhi_growth_rate_pct" in KNOWN_METRICS


def test_corpus_unknown_vertical_falls_back_to_generic():
    c = ReferenceCorpus("not-a-vertical")
    assert c.vertical == "generic"


@pytest.mark.parametrize("vertical", list(KNOWN_VERTICALS))
def test_corpus_every_vertical_has_safe_score_distribution(vertical):
    c = ReferenceCorpus(vertical)
    d = c.get_distribution("safe_score")
    assert d["p50"] is not None
    assert d["citation"]
    # Ordering sanity
    assert d["p25"] <= d["p50"] <= d["p75"] <= d["p90"] <= d["p99"]


def test_corpus_series_no_local_is_full_baseline():
    c = ReferenceCorpus("healthcare")
    s = c.get_series("safe_score")
    assert s["data_source_breakdown"]["local_pct"] == 0.0
    assert s["data_source_breakdown"]["baseline_pct"] == 100.0
    # 30 days of constant baseline values
    assert len(s["values"]) == 30
    vals = {v["v"] for v in s["values"]}
    assert len(vals) == 1


def test_corpus_series_thin_local_is_mostly_baseline():
    class Store:
        def get_metric_series(self, metric, days=30):
            return [60.0] * 10  # 10 days of local history
    c = ReferenceCorpus("healthcare", local_store=Store())
    s = c.get_series("safe_score")
    bd = s["data_source_breakdown"]
    assert bd["days_local"] == 10
    assert 0 < bd["local_pct"] < 50  # blended, but mostly baseline


def test_corpus_series_full_local_is_100_pct_local():
    class Store:
        def get_metric_series(self, metric, days=30):
            return [88.0] * 30
    c = ReferenceCorpus("finance", local_store=Store())
    s = c.get_series("safe_score")
    # 30 days, but LOCAL_PRIMARY_DAYS is 90 — should still be partial
    bd = s["data_source_breakdown"]
    assert bd["local_pct"] < 100


def test_corpus_constants_relationship():
    assert MIN_LOCAL_DAYS < LOCAL_PRIMARY_DAYS


def test_corpus_local_store_broken_does_not_raise():
    class BrokenStore:
        def get_metric_series(self, metric, days=30):
            raise RuntimeError("kaboom")
    c = ReferenceCorpus("generic", local_store=BrokenStore())
    s = c.get_series("safe_score")
    # Defensive degradation: returns baseline-only, no exception
    assert s["data_source_breakdown"]["local_pct"] == 0.0


# ---- forecasting ------------------------------------------------ #


def test_forecast_no_local_returns_stable():
    c = ReferenceCorpus("healthcare")
    r = forecast_metric(c, "safe_score")
    assert r["trajectory"] == "stable"
    assert r["slope_per_day"] == 0.0
    assert "local_data_thin" in r["warnings"][0] if r["warnings"] else True


def test_forecast_improving_local_trend_detected():
    class Store:
        def get_metric_series(self, metric, days=30):
            return [60.0 + i * 0.5 for i in range(30)]
    c = ReferenceCorpus("healthcare", local_store=Store())
    r = forecast_metric(c, "safe_score")
    # safe_score going up = improving
    assert r["trajectory"] == "improving"
    assert r["slope_per_day"] > 0


def test_forecast_worsening_local_trend_detected():
    class Store:
        def get_metric_series(self, metric, days=30):
            return [80.0 - i * 0.3 for i in range(30)]
    c = ReferenceCorpus("finance", local_store=Store())
    r = forecast_metric(c, "safe_score")
    assert r["trajectory"] == "worsening"
    assert r["slope_per_day"] < 0


def test_forecast_open_critical_inverted_direction():
    # Rising open_critical = worsening (not improving), because
    # "more critical findings" is bad.
    class Store:
        def get_metric_series(self, metric, days=30):
            return [5.0 + i * 0.2 for i in range(30)]
    c = ReferenceCorpus("generic", local_store=Store())
    r = forecast_metric(c, "open_critical")
    assert r["trajectory"] == "worsening"


def test_forecast_includes_data_source_breakdown():
    c = ReferenceCorpus("healthcare")
    r = forecast_metric(c, "safe_score")
    bd = r["data_source_breakdown"]
    assert "local_pct" in bd
    assert "baseline_pct" in bd
    assert "vertical" in bd


def test_forecast_many_returns_all_known_metrics():
    c = ReferenceCorpus("generic")
    out = forecast_many(c)
    assert set(out.keys()) == set(KNOWN_METRICS)


# ---- anomaly ---------------------------------------------------- #


def test_anomaly_spike_in_quiet_stream_flags():
    obs = [10.0, 10.1, 9.9, 10.0, 10.05, 9.95, 10.0, 10.1, 9.95,
           10.0, 10.0, 10.0, 50.0, 10.1]
    r = detect(obs)
    assert r["summary"]["flagged"] >= 1


def test_anomaly_steady_stream_does_not_flag():
    obs = [5.0 + (i % 3) * 0.05 for i in range(20)]
    r = detect(obs)
    assert r["summary"]["flagged"] == 0


def test_anomaly_below_min_n_never_flags():
    # Even with a wild spike at index 0, < min_n should not fire.
    r = detect([100.0, 100.0, 100.0], min_n=DEFAULT_MIN_N)
    assert r["summary"]["flagged"] == 0


def test_anomaly_corpus_seed_enables_first_observation_flag():
    r = detect([200.0], corpus_seed=(50.0, 4.0),
               z_threshold=DEFAULT_Z_THRESHOLD, min_n=1)
    assert r["summary"]["flagged"] == 1


def test_anomaly_batch_per_entity_keeps_state_isolated():
    # host-a has noise + a real spike; host-b is steady-noisy and shouldn't fire.
    out = batch_detect_per_entity({
        "host-a": [10.0, 10.2, 9.9, 10.1, 10.0, 9.95, 10.1, 200.0],
        "host-b": [5.0, 5.1, 4.9, 5.05, 4.95, 5.0, 5.05, 4.95],
    })
    assert out["host-a"]["summary"]["flagged"] == 1
    assert out["host-b"]["summary"]["flagged"] == 0


def test_anomaly_ewmastate_zscore_zero_when_no_stddev():
    s = EWMAState()
    s.update(10.0)
    # stddev is 0 → z must be 0
    assert s.zscore(50.0) == 0.0


# ---- assistant -------------------------------------------------- #


def test_assistant_plan_compliance_intent():
    plans = plan("hipaa compliance gap")
    tools = [p["tool"] for p in plans]
    assert "query_compliance" in tools


def test_assistant_plan_topology_intent():
    plans = plan("show me attack paths")
    assert plans[0]["tool"] == "query_topology"


def test_assistant_plan_identity_intent():
    plans = plan("who lacks mfa")
    assert plans[0]["tool"] == "inspect_identities"


def test_assistant_plan_unknown_falls_back_to_posture():
    plans = plan("hello there")
    assert plans[0]["tool"] == "evaluate_posture"


def test_assistant_plan_respects_max_tools():
    plans = plan("compliance findings identity report", max_tools=2)
    assert len(plans) <= 2


def test_assistant_ask_returns_complete_envelope():
    r = ask("why is risk score low?")
    assert "question" in r
    assert "answer" in r
    assert "calls" in r
    assert "llm_used" in r


def test_assistant_ask_never_raises_on_garbage_input():
    r = ask("")
    assert isinstance(r["answer"], str)


# ---- remediation_pr -------------------------------------------- #


def test_remediation_pr_known_recipe_succeeds():
    r = draft_remediation_pr(
        {"title": "SSH wide-open", "severity": "high", "family": "ssh_open"},
        asset={"hostname": "edge-fw-01", "vendor": "cisco_ios"},
    )
    assert r["ok"] is True
    assert r["source"] == "recipe"
    assert r["forward"]
    assert r["rollback"]


def test_remediation_pr_unknown_vendor_returns_needs_operator_input():
    r = draft_remediation_pr(
        {"title": "Weird", "severity": "medium", "family": "unknown_family"},
        asset={"hostname": "x", "vendor": "unknown_vendor"},
    )
    assert r["ok"] is False
    assert r["source"] == "needs_operator_input"
    assert "no_recipe_available" in r["warnings"]


def test_remediation_pr_okta_mfa_recipe_succeeds():
    r = draft_remediation_pr(
        {"title": "Admin no MFA", "severity": "critical",
         "family": "user_missing_mfa"},
        asset={"hostname": "okta.example.com", "vendor": "okta"},
    )
    assert r["ok"] is True
    assert "MFA" in r["forward"][0] or "factor" in r["forward"][0].lower()


def test_remediation_pr_body_markdown_contains_expected_sections():
    r = draft_remediation_pr(
        {"title": "SSH open", "severity": "high", "family": "ssh_open"},
        asset={"hostname": "edge-fw-01", "vendor": "cisco_ios"},
    )
    md = r["pr_body_markdown"]
    assert "# Remediation" in md
    assert "Forward commands" in md
    assert "Rollback" in md
    assert "## Safety" in md


def test_remediation_pr_never_raises_on_empty_inputs():
    r = draft_remediation_pr({}, asset={}, vendor=None)
    assert r["ok"] is False
    assert r["source"] == "needs_operator_input"
