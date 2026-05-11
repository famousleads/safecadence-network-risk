"""
v11.0 tests — ML + intelligence depth.

Stdlib-only feature surface: anomaly detection, predictive risk
scoring, finding clustering, drift forecasting, natural-language
query, threat-hunting playbooks, FastAPI routes.

No external dependencies are exercised. LLM-fallback tests check
that the parser behaves correctly when no API key is configured.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import random
import time
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "sc_data"))
    # Make sure no real LLM keys leak in
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_HOST",
                "SAFECADENCE_LOCAL_LLM"):
        monkeypatch.delenv(var, raising=False)
    yield


def _write_asset(tmp_path, asset_id: str, doc: dict, *, org_id: str | None = None):
    if org_id:
        from safecadence.storage.org_store import org_data_dir
        base = org_data_dir(org_id) / "platform_assets"
    else:
        base = Path(os.environ["SC_DATA_DIR"]) / "platform_assets"
    base.mkdir(parents=True, exist_ok=True)
    doc.setdefault("id", asset_id)
    (base / f"{asset_id}.json").write_text(json.dumps(doc), encoding="utf-8")
    return base / f"{asset_id}.json"


# --------------------------------------------------------------------------
# 1. Anomaly detection
# --------------------------------------------------------------------------


def test_anomaly_sliding_zscore_finds_planted_spike():
    from safecadence.ml.anomaly import detect_anomalies
    rng = random.Random(11)
    series = [10.0 + rng.gauss(0, 1.0) for _ in range(80)]
    # plant a clear spike at index 60
    series[60] = 60.0
    out = detect_anomalies(series, window=20, threshold=3.0)
    assert any(rec["index"] == 60 for rec in out), out
    rec60 = [r for r in out if r["index"] == 60][0]
    assert rec60["severity"] in ("medium", "high", "critical")


def test_anomaly_skips_short_warmup_and_constant_series():
    from safecadence.ml.anomaly import detect_anomalies
    # Constant series — zero variance, never flagged
    assert detect_anomalies([5.0] * 50, window=10) == []
    # Too short for window — empty
    assert detect_anomalies([1.0, 2.0, 3.0], window=10) == []


def test_seasonal_anomaly_flags_off_weekday_outlier():
    from safecadence.ml.anomaly import detect_seasonal_anomaly
    # Build 6 weeks of (ts, value) tuples — value ~ weekday * 10, then plant
    # a huge spike on the last Wednesday (weekday=2).
    base = _dt.datetime(2026, 1, 1)  # Thursday
    series = []
    for d in range(42):
        ts = (base + _dt.timedelta(days=d)).timestamp()
        wkd = (base + _dt.timedelta(days=d)).weekday()
        series.append((ts, float(wkd * 10)))
    # plant spike on last Wednesday
    spike_idx = 40
    spike_ts = series[spike_idx][0]
    series[spike_idx] = (spike_ts, 500.0)
    out = detect_seasonal_anomaly(series, period_days=7)
    assert any(r["index"] == spike_idx for r in out), out


def test_finding_anomaly_reads_history_jsonl():
    from safecadence.ml.anomaly import detect_finding_anomaly
    # Write a synthetic finding_history file in the global data dir.
    # Baseline has small variance so the trailing window has non-zero stdev.
    base = Path(os.environ["SC_DATA_DIR"])
    base.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)
    lines = []
    for i in range(30):
        date = (_dt.date(2026, 4, 1) + _dt.timedelta(days=i)).isoformat()
        # baseline 8 +/- ~2 noise; spike on day 25
        cnt = int(round(8 + rng.gauss(0, 2.0))) if i != 25 else 60
        lines.append(json.dumps({"date": date, "count": max(0, cnt)}))
    (base / "finding_history.jsonl").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    out = detect_finding_anomaly(None, window=10, threshold=2.5)
    assert out
    assert any(r.get("date") == "2026-04-26" for r in out)


# --------------------------------------------------------------------------
# 2. Predictive risk scoring
# --------------------------------------------------------------------------


def test_predict_risk_monotonic_upward_history_predicts_higher():
    from safecadence.ml.predict_risk import predict_risk_30d
    history = [(time.time() - (40 - i) * 86400, 30.0 + i) for i in range(40)]
    asset = {
        "id": "router-1",
        "identity": {"hostname": "router-1"},
        "risk_score": 70.0,
        "risk_history": history,
        "cves": [{"id": "CVE-2024-0001", "severity": "critical", "kev": True}],
    }
    out = predict_risk_30d(asset)
    assert out["predicted_score"] > out["current_score"]
    assert out["confidence"] > 0.0
    assert any("KEV" in d for d in out["drivers"])


def test_predict_risk_flat_history_is_stable():
    from safecadence.ml.predict_risk import predict_risk_30d
    history = [(time.time() - (40 - i) * 86400, 50.0) for i in range(40)]
    asset = {"id": "fw-1", "risk_score": 50.0, "risk_history": history}
    out = predict_risk_30d(asset)
    # Flat → predicted ~ current. Allow a small EWMA drift.
    assert abs(out["predicted_score"] - 50.0) < 3.0


def test_assets_trending_critical_surfaces_climbers(tmp_path):
    from safecadence.ml.predict_risk import assets_trending_critical
    # No org_id → global data dir. Build a climbing-risk asset.
    history = [(time.time() - (30 - i) * 86400, 40.0 + i) for i in range(30)]
    _write_asset(tmp_path, "rapid", {
        "identity": {"hostname": "rapid"},
        "risk_score": 65.0,
        "risk_history": history,
        "cves": [],
    })
    _write_asset(tmp_path, "calm", {
        "identity": {"hostname": "calm"},
        "risk_score": 20.0,
        "risk_history": [(time.time() - i * 86400, 20.0) for i in range(20)],
    })
    out = assets_trending_critical(None, horizon_days=30)
    ids = {r["asset_id"] for r in out}
    assert "rapid" in ids
    assert "calm" not in ids


# --------------------------------------------------------------------------
# 3. Pattern clustering
# --------------------------------------------------------------------------


def test_cluster_three_obvious_groups():
    from safecadence.ml.cluster_findings import cluster_similar
    findings = []
    for i in range(8):
        findings.append({"rule_id": "missing-mfa", "severity": "high",
                         "controls": ["NIST-AC-2"], "category": "identity"})
    for i in range(6):
        findings.append({"rule_id": "weak-tls", "severity": "medium",
                         "controls": ["PCI-4.1"], "category": "crypto"})
    for i in range(5):
        findings.append({"rule_id": "open-port-22", "severity": "low",
                         "controls": ["CIS-9.1"], "category": "network"})
    clusters = cluster_similar(findings)
    # silhouette is fuzzy — accept 2..4
    assert 2 <= len(clusters) <= 4
    total = sum(c.count for c in clusters)
    assert total == len(findings)
    # The biggest cluster should reflect the largest planted group
    clusters.sort(key=lambda c: c.count, reverse=True)
    assert clusters[0].count >= 6


def test_cluster_single_finding_returns_single_cluster():
    from safecadence.ml.cluster_findings import cluster_similar
    out = cluster_similar([{"rule_id": "x", "severity": "low"}])
    assert len(out) == 1
    assert out[0].count == 1


def test_cluster_empty_input():
    from safecadence.ml.cluster_findings import cluster_similar
    assert cluster_similar([]) == []


# --------------------------------------------------------------------------
# 4. Drift forecasting
# --------------------------------------------------------------------------


def test_drift_forecast_high_change_history_predicts_shorter_window():
    from safecadence.ml.drift_forecast import forecast_drift
    now = time.time()
    # Noisy asset: 20 events, one every 2 days
    busy = [
        {"ts": now - (40 - i * 2) * 86400, "severity": "high", "kind": "acl"}
        for i in range(20)
    ]
    # Quiet asset: 3 events over a year
    quiet = [
        {"ts": now - (365 - i * 120) * 86400, "severity": "low", "kind": "comment"}
        for i in range(3)
    ]
    fb = forecast_drift("busy", history=busy)
    fq = forecast_drift("quiet", history=quiet)
    assert fb["days_until_drift"] < fq["days_until_drift"]
    assert fb["confidence"] >= fq["confidence"]


def test_drift_forecast_empty_history():
    from safecadence.ml.drift_forecast import forecast_drift
    out = forecast_drift("orphan", history=[])
    assert out["days_until_drift"] == 365
    assert out["confidence"] == 0.0


# --------------------------------------------------------------------------
# 5. NLQ
# --------------------------------------------------------------------------


@pytest.mark.parametrize("q,expected", [
    (
        "show me all internet-facing assets with KEV CVEs over CVSS 8",
        {"public_exposure": True, "kev": True, "cvss_min": 8.0},
    ),
    (
        "list servers in dc-east-1",
        {"asset_type": "server", "site": "dc-east-1"},
    ),
    (
        "EOL devices missing MFA",
        {"eol": True, "mfa_missing": True},
    ),
    (
        "critical CVEs on cisco firewalls",
        {"severity_min": "critical", "vendor": "cisco", "asset_type": "firewall"},
    ),
    (
        "high severity findings on crown jewels",
        {"severity_min": "high", "criticality": "crown_jewel"},
    ),
    (
        "hosts with hostname matching prod-web",
        {"hostname_contains": "prod-web"},
    ),
])
def test_nlq_known_queries(q, expected):
    from safecadence.ml.nlq import parse_query
    parsed = parse_query(q)
    assert parsed.source == "rules", f"{q!r} → {parsed}"
    for k, v in expected.items():
        assert parsed.filter.get(k) == v, f"{q!r} → {parsed.filter}"


def test_nlq_no_pattern_no_llm_returns_parse_failed(monkeypatch):
    from safecadence.ml.nlq import parse_query
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    parsed = parse_query("zorp the floofs back")
    assert parsed.source == "parse_failed"
    assert "OPENAI_API_KEY" in parsed.note


def test_nlq_execute_filters_assets():
    from safecadence.ml.nlq import parse_query, execute_query
    store = [
        {
            "identity": {"hostname": "edge-1", "asset_type": "firewall",
                         "vendor": "cisco", "site": "dc-east-1"},
            "public_exposure": True,
            "cves": [{"id": "CVE-1", "kev": True, "cvss": 9.2, "severity": "critical"}],
        },
        {
            "identity": {"hostname": "wks-1", "asset_type": "workstation",
                         "vendor": "dell", "site": "hq"},
            "public_exposure": False,
            "cves": [],
        },
    ]
    parsed = parse_query("internet-facing KEV CVEs over CVSS 8")
    matches = execute_query(parsed, store=store)
    assert len(matches) == 1
    assert (matches[0]["identity"]["hostname"]) == "edge-1"


# --------------------------------------------------------------------------
# 6. Playbooks
# --------------------------------------------------------------------------


def test_playbook_list_includes_three_baselines():
    from safecadence.ml.playbooks import list_playbooks
    ids = {p["id"] for p in list_playbooks()}
    assert {"kev_response", "lateral_movement", "credential_compromise"} <= ids


def test_playbook_kev_response_returns_at_least_three_steps():
    from safecadence.ml.playbooks import run_playbook
    ctx = {
        "cve_id": "CVE-2025-0001",
        "assets": [
            {
                "id": "edge-1",
                "identity": {"hostname": "edge-1", "criticality": "crown_jewel",
                             "public_exposure": True},
                "public_exposure": True,
                "cves": [{"id": "CVE-2025-0001", "severity": "critical",
                          "kev": True, "patch_available": True}],
            },
        ],
    }
    steps = run_playbook("kev_response", ctx)
    assert len(steps) >= 3
    assert any("isolat" in s["title"].lower() or "isolate" in s["id"] for s in steps)
    assert any(s["severity"] == "critical" for s in steps)


def test_playbook_unknown_raises():
    from safecadence.ml.playbooks import run_playbook
    with pytest.raises(KeyError):
        run_playbook("does-not-exist", {})


def test_playbook_credential_compromise_privileged_path():
    from safecadence.ml.playbooks import run_playbook
    steps = run_playbook(
        "credential_compromise", {"user": "alice", "privileged": True}
    )
    # Privileged path elevates session-revocation to critical
    sess = [s for s in steps if s["id"] == "cred.session"][0]
    assert sess["severity"] == "critical"


# --------------------------------------------------------------------------
# 7. FastAPI endpoints
# --------------------------------------------------------------------------


@pytest.fixture()
def client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.ml.api import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_api_anomalies_with_inline_series(client):
    rng = random.Random(3)
    series = [10.0 + rng.gauss(0, 1.0) for _ in range(30)] + [60.0] + [
        10.0 + rng.gauss(0, 1.0) for _ in range(10)
    ]
    r = client.post(
        "/api/v1/ml/anomalies",
        json={"timeseries": series, "window": 15, "threshold": 3.0},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert any(a["index"] == 30 for a in body["anomalies"])


def test_api_predict_risk_with_inline_asset(client):
    asset = {
        "id": "x",
        "risk_score": 60.0,
        "risk_history": [(time.time() - i * 86400, 40 + (40 - i)) for i in range(40)],
    }
    r = client.post("/api/v1/ml/predict-risk", json={"asset": asset})
    assert r.status_code == 200
    assert "predicted_score" in r.json()["result"]


def test_api_cluster_findings_with_inline_list(client):
    findings = (
        [{"rule_id": "a", "severity": "high"}] * 4
        + [{"rule_id": "b", "severity": "low"}] * 4
    )
    r = client.post("/api/v1/ml/cluster-findings", json={"findings": findings})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1


def test_api_drift_forecast_inline(client):
    now = time.time()
    history = [
        {"ts": now - (30 - i * 2) * 86400, "severity": "high", "kind": "acl"}
        for i in range(15)
    ]
    r = client.post(
        "/api/v1/ml/drift-forecast",
        json={"asset_id": "router-1", "history": history},
    )
    assert r.status_code == 200
    assert r.json()["result"]["days_until_drift"] < 365


def test_api_nlq_round_trip(client):
    r = client.post(
        "/api/v1/ml/nlq", json={"query": "EOL devices missing MFA"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["parsed"]["filter"]["eol"] is True
    assert body["parsed"]["filter"]["mfa_missing"] is True


def test_api_playbooks_list_and_run(client):
    r = client.get("/api/v1/ml/playbooks")
    assert r.status_code == 200
    assert any(p["id"] == "kev_response" for p in r.json()["playbooks"])
    r2 = client.post(
        "/api/v1/ml/playbook/kev_response/run",
        json={"cve_id": "CVE-2025-0001"},
    )
    assert r2.status_code == 200
    assert r2.json()["count"] >= 3


def test_api_playbook_unknown_returns_404(client):
    r = client.post("/api/v1/ml/playbook/nope/run", json={})
    assert r.status_code == 404
