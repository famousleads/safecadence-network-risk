"""v9.56 — comprehensive coverage for the AI assistant.

Pre-v9.56 there were exactly 3 tests for ask_assistant in
tests/identity/test_v7_9.py (empty question, NHI count, crown-jewel
count). For a load-bearing surface that ships fleet data to a third
party LLM, that's not enough. This file backfills:

  #1 SC_AI_DISABLED honored
  #3 question length cap
  #4 ai_call test seam works without provider faking
  #5 snapshot truncation flagged + per-entity caps
  #6 citations cross-checked against real IDs
  #9 HTTP error reasons surface body excerpt + label
  + capability gate on /api/intel/ask
  + rate limit on /api/intel/ask
  + audit row on /api/intel/ask
"""
from __future__ import annotations

from unittest.mock import patch
import pytest


# ----------------------------------------------------- helpers

def _asset(asset_id, **kw):
    """Minimal asset shape ask_assistant._build_snapshot reads."""
    a = {
        "identity": {
            "asset_id": asset_id,
            "asset_type": kw.get("type", "switch"),
            "environment": kw.get("env", "prod"),
            "criticality": kw.get("crit", "medium"),
        },
    }
    if kw.get("crown"):
        a["identity"]["criticality"] = "crown-jewel"
    if kw.get("no_mfa"):
        a["identity_block"] = {"mfa_enrolled": False}
    if kw.get("nhi"):
        a["nhi"] = {"nhi_id": f"nhi-{asset_id}",
                     "subtype": kw.get("nhi_subtype", "service_account")}
    return a


def _finding(fid, kind="stale_nhi", severity="high",
              title="t", principal="alice"):
    from safecadence.identity.findings import Finding
    return Finding(
        finding_id=fid, kind=kind, severity=severity,
        title=title, principal=principal,
    )


# ----------------------------------------------------- #1 air-gap

def test_sc_ai_disabled_blocks_ai_path(monkeypatch):
    """SC_AI_DISABLED=1 → falls to deterministic, never invokes
    ai_call even if it's wired."""
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    from safecadence.intel.ai_assistant import ask_assistant
    called = {"ai": False}

    def fake_ai(_sys, _user, _model):
        called["ai"] = True
        return "should not be called"

    ans = ask_assistant("how many crown jewels?",
                         assets=[_asset("a1", crown=True)],
                         findings=[], attack_paths=[], ai_call=fake_ai)
    assert called["ai"] is False
    assert ans.used_ai is False
    assert "SC_AI_DISABLED" in ans.fallback_reason


def test_sc_ai_disabled_truthy_variants(monkeypatch):
    """'true', 'yes', 'on' all disable AI. Anything else → AI path."""
    from safecadence.intel.ai_assistant import _ai_globally_disabled
    for val in ("1", "true", "yes", "on", "TRUE", "On"):
        monkeypatch.setenv("SC_AI_DISABLED", val)
        assert _ai_globally_disabled() is True
    for val in ("0", "false", "no", "", "off"):
        monkeypatch.setenv("SC_AI_DISABLED", val)
        assert _ai_globally_disabled() is False


# ----------------------------------------------------- #3 length cap

def test_question_length_cap_rejects_huge():
    from safecadence.intel.ai_assistant import (
        ask_assistant, MAX_QUESTION_CHARS,
    )
    big = "x" * (MAX_QUESTION_CHARS + 100)
    ans = ask_assistant(big, assets=[], findings=[], attack_paths=[])
    assert ans.used_ai is False
    assert "exceeds" in ans.fallback_reason
    assert "too long" in ans.text


# ----------------------------------------------------- #4 ai_call seam

def test_ai_call_seam_overrides_provider(monkeypatch):
    """ai_call is honored even when no provider is in env. Tests
    must never hit a real provider just because OPENAI_API_KEY
    happens to be set in the dev shell."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SC_AI_DISABLED", raising=False)
    from safecadence.intel.ai_assistant import ask_assistant
    ans = ask_assistant(
        "stub", assets=[_asset("a1")], findings=[], attack_paths=[],
        ai_call=lambda s, u, m: "AI says hi",
    )
    assert ans.used_ai is True
    assert "AI says hi" in ans.text


def test_no_provider_returns_helpful_reason(monkeypatch):
    """No AI configured → deterministic answer with a fallback_reason
    telling the operator what to set."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SC_AI_DISABLED", raising=False)
    from safecadence.intel.ai_assistant import ask_assistant
    ans = ask_assistant("how many assets?", assets=[_asset("a1")],
                          findings=[], attack_paths=[])
    assert ans.used_ai is False
    assert ("OPENAI_API_KEY" in ans.fallback_reason
             or "ANTHROPIC_API_KEY" in ans.fallback_reason
             or "no AI" in ans.fallback_reason)


# ----------------------------------------------------- #5 truncation

def test_snapshot_caps_findings_with_flag():
    """200 findings → snapshot.findings has ≤50 + truncated_findings=True
    + total_findings=200."""
    from safecadence.intel.ai_assistant import _build_snapshot
    findings = [_finding(f"f_{i}") for i in range(200)]
    snap = _build_snapshot([], findings, [])
    assert len(snap["findings"]) == 50
    assert snap["truncated_findings"] is True
    assert snap["total_findings"] == 200


def test_snapshot_caps_paths_with_flag():
    from safecadence.intel.ai_assistant import _build_snapshot

    class P:
        def __init__(self, i):
            self.terminal_asset = f"t-{i}"
            self.risk_score = 0.5

        def chain_summary(self):
            return f"chain-{self.terminal_asset}"

    paths = [P(i) for i in range(50)]
    snap = _build_snapshot([], [], paths)
    assert len(snap["attack_paths"]) == 20
    assert snap["truncated_attack_paths"] is True
    assert snap["total_attack_paths"] == 50


def test_user_prompt_strips_internal_indexes():
    """The _internal_* keys must NOT leak into what the LLM sees."""
    from safecadence.intel.ai_assistant import (
        _build_snapshot, _build_user_prompt,
    )
    snap = _build_snapshot([_asset("real-asset-1")],
                              [_finding("real-finding-1")], [])
    prompt = _build_user_prompt("hi", snap)
    assert "_internal_asset_ids" not in prompt
    assert "_internal_finding_ids" not in prompt
    # Public ones still go through:
    assert "real-asset-1" in prompt or "real-finding-1" in prompt


def test_user_prompt_warns_on_truncation():
    """When the snapshot dump exceeds MAX_SNAPSHOT_CHARS, a warning
    is appended that the LLM can read."""
    from safecadence.intel.ai_assistant import _build_user_prompt
    huge = {"x": "y" * 10_000}
    prompt = _build_user_prompt("hi", huge)
    assert "truncated" in prompt.lower()
    assert "partial data" in prompt.lower()


# ----------------------------------------------------- #6 citations

def test_citations_cross_check_real_ids():
    """Hallucinated parens → not cited. Real IDs → cited with kind."""
    from safecadence.intel.ai_assistant import _extract_citations
    snap = {
        "_internal_asset_ids": ["srv-prod-01", "fw-edge-2"],
        "_internal_finding_ids": ["f_abc123"],
    }
    text = ("There are issues on srv-prod-01 and "
            "(see RFC 1234). Finding (f_abc123) is critical, also "
            "(approximately 5) related to fw-edge-2.")
    cites = _extract_citations(text, snapshot=snap)
    cited_ids = {c["id"] for c in cites}
    assert "srv-prod-01" in cited_ids
    assert "f_abc123" in cited_ids
    assert "fw-edge-2" in cited_ids
    # Crucially, the bogus ones are filtered:
    assert "see RFC 1234" not in cited_ids
    assert "approximately 5" not in cited_ids
    assert "RFC" not in cited_ids


def test_citations_empty_when_no_snapshot():
    """No snapshot to cross-check → no citations. Fabricating is worse
    than nothing."""
    from safecadence.intel.ai_assistant import _extract_citations
    cites = _extract_citations("(srv-prod-01) is broken")
    assert cites == []


def test_citations_distinguish_asset_vs_finding():
    from safecadence.intel.ai_assistant import _extract_citations
    snap = {
        "_internal_asset_ids": ["srv-1"],
        "_internal_finding_ids": ["f_1"],
    }
    cites = _extract_citations("(srv-1) and (f_1)", snapshot=snap)
    by_id = {c["id"]: c["kind"] for c in cites}
    assert by_id["srv-1"] == "asset"
    assert by_id["f_1"] == "finding"


# ----------------------------------------------------- #9 error reasons

def test_http_error_reason_429_says_rate_limit():
    from safecadence.intel.ai_assistant import _http_error_reason

    class FakeResp:
        status_code = 429
        text = '{"error":"too many requests"}'

    msg = _http_error_reason("openai", FakeResp())
    assert "429" in msg
    assert "rate limit" in msg.lower()
    assert "too many requests" in msg


def test_http_error_reason_401_says_auth():
    from safecadence.intel.ai_assistant import _http_error_reason

    class FakeResp:
        status_code = 401
        text = '{"error":"invalid_api_key"}'

    msg = _http_error_reason("anthropic", FakeResp())
    assert "auth" in msg.lower()
    assert "key" in msg.lower()


def test_http_error_reason_503_says_overloaded():
    from safecadence.intel.ai_assistant import _http_error_reason

    class FakeResp:
        status_code = 503
        text = ""

    msg = _http_error_reason("openai", FakeResp())
    assert "overload" in msg.lower()


# -------------------------------------------------- HTTP-level: gate + rate

def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.delenv("SC_AI_DISABLED", raising=False)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.server.intel_api import register
    from safecadence.server.auth import CurrentUser

    app = FastAPI()

    # Default: viewer-tier user with read.asset + read.finding via
    # role floor. Tests can swap this out for a stricter case.
    def _u():
        return CurrentUser(username="alice", tenant="default",
                            roles=["viewer"])

    register(app, get_current_user=_u, require_writer=_u)
    return TestClient(app)


def test_ask_endpoint_403_when_capability_missing(monkeypatch, tmp_path):
    """User with empty roles + explicit deny on read.asset → 403."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import revoke
    revoke("alice", "read.asset", actor="cto", reason="test")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.server.intel_api import register
    from safecadence.server.auth import CurrentUser

    app = FastAPI()

    def _u():
        return CurrentUser(username="alice", tenant="default",
                            roles=["viewer"])

    register(app, get_current_user=_u, require_writer=_u)
    client = TestClient(app)
    r = client.post("/api/intel/ask", json={"question": "test"})
    assert r.status_code == 403
    assert "read.asset" in r.json()["detail"]


def test_ask_endpoint_413_when_question_too_long(monkeypatch, tmp_path):
    client = _build_app(monkeypatch, tmp_path)
    big = "x" * 10_000
    r = client.post("/api/intel/ask", json={"question": big})
    assert r.status_code == 413
    assert "too long" in r.json()["detail"].lower()


def test_ask_endpoint_400_on_empty(monkeypatch, tmp_path):
    client = _build_app(monkeypatch, tmp_path)
    r = client.post("/api/intel/ask", json={"question": "  "})
    assert r.status_code == 400


def test_ask_endpoint_rate_limit_429(monkeypatch, tmp_path):
    """11th call in a 60s window → 429 with retry-after hint."""
    monkeypatch.setenv("SC_ASK_RATE_WINDOW_SEC", "60")
    monkeypatch.setenv("SC_ASK_RATE_LIMIT", "3")
    client = _build_app(monkeypatch, tmp_path)
    # First 3 succeed
    for i in range(3):
        r = client.post("/api/intel/ask",
                          json={"question": f"q-{i}"})
        assert r.status_code == 200, r.text
    # 4th gets 429
    r = client.post("/api/intel/ask", json={"question": "q-bust"})
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"].lower()
    assert "retry" in r.json()["detail"].lower()


def test_ask_endpoint_writes_audit_row(monkeypatch, tmp_path):
    """A successful /ask call lands one row in the activity log
    with question hash + cited count + used_ai flag."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)
    client = _build_app(monkeypatch, tmp_path)
    r = client.post("/api/intel/ask",
                      json={"question": "how many assets?"})
    assert r.status_code == 200, r.text
    from safecadence.activity import read_range
    rows = read_range(days=1, path_contains="/api/intel/ask")
    assert any(r.path == "/api/intel/ask" and r.actor == "alice"
                for r in rows)
    matching = [r for r in rows if r.path == "/api/intel/ask"]
    assert matching
    extra = matching[0].extra or {}
    assert "question_sha256_16" in extra
    assert extra["question_len"] == len("how many assets?")
    assert "used_ai" in extra
    assert "cited_count" in extra


def test_ask_endpoint_audit_does_not_store_plaintext(monkeypatch, tmp_path):
    """Audit row stores hash, NOT the plaintext question. The user's
    question may contain sensitive operational context."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    client = _build_app(monkeypatch, tmp_path)
    secret = "my-secret-investigation-target-xyz789"
    r = client.post("/api/intel/ask", json={"question": secret})
    assert r.status_code == 200
    from safecadence.activity import read_range
    rows = read_range(days=1, path_contains="/api/intel/ask")
    matching = [r for r in rows if r.path == "/api/intel/ask"]
    extra = matching[0].extra or {}
    serialized = str(extra)
    assert secret not in serialized
    # And the hash is present
    import hashlib
    expected = hashlib.sha256(secret.encode()).hexdigest()[:16]
    assert extra["question_sha256_16"] == expected
