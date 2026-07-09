"""v16.3 — Fable 5 support and the empty-response guard in safecadence.ai.client.

Covers:
  * an Anthropic response with no text block no longer returns '' in silence
    (the latent bug: a refusal / thinking-only / tool_use turn printed nothing)
  * stop_reason="refusal" arrives on HTTP 200 and raises AIRefusal
  * explain_findings retries once on the fallback model, and if that also
    declines it drops to the deterministic engine — a security tool must still
    explain itself
  * output_config.effort is sent and validated; no `temperature` on the Claude
    path; max_tokens raised because thinking blocks share the budget

No real network calls — _import_httpx is monkey-patched.
"""
from __future__ import annotations

import types

import pytest

from safecadence.ai import AIError, AIRefusal
from safecadence.ai import client as c


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = str(payload)

    def json(self):
        return self._payload


class _FakeHTTPX:
    class HTTPError(Exception):
        pass

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "payload": json})
        return self._responses.pop(0)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in (
        "SAFECADENCE_CLAUDE_MODEL", "SAFECADENCE_CLAUDE_FALLBACK",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST",
        "SAFECADENCE_LOCAL_LLM",
    ):
        monkeypatch.delenv(k, raising=False)


def _use(monkeypatch, fake):
    monkeypatch.setattr(c, "_import_httpx", lambda: fake)
    return fake


def _text(t):
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": t}]}


def _refusal():
    return {"stop_reason": "refusal", "content": []}


def _stub_result():
    """explain_findings only needs .findings for the no-findings fallback path."""
    return types.SimpleNamespace(findings=[])


# --------------------------------------------------------------------------
# the guard: never return an empty explanation silently
# --------------------------------------------------------------------------


def test_no_text_block_raises_instead_of_empty_string(monkeypatch):
    _use(monkeypatch, _FakeHTTPX(_Resp({"stop_reason": "end_turn", "content": []})))
    with pytest.raises(AIError) as exc:
        c._call_anthropic("p", api_key="k", model="m", timeout=5)
    assert "no text content" in str(exc.value)


def test_thinking_only_response_raises(monkeypatch):
    body = {"stop_reason": "end_turn",
            "content": [{"type": "thinking", "thinking": "..."}]}
    _use(monkeypatch, _FakeHTTPX(_Resp(body)))
    with pytest.raises(AIError):
        c._call_anthropic("p", api_key="k", model="m", timeout=5)


def test_ollama_empty_response_raises(monkeypatch):
    _use(monkeypatch, _FakeHTTPX(_Resp({"message": {}})))
    with pytest.raises(AIError):
        c._call_ollama("p", host="http://h", model="llama3.1", timeout=5)


# --------------------------------------------------------------------------
# Fable 5 wiring
# --------------------------------------------------------------------------


def test_defaults_to_fable5_with_opus_fallback():
    assert c._anthropic_model() == "claude-fable-5"
    assert c._anthropic_fallback_model() == "claude-opus-4-8"


def test_env_overrides_models(monkeypatch):
    monkeypatch.setenv("SAFECADENCE_CLAUDE_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("SAFECADENCE_CLAUDE_FALLBACK", "claude-haiku-4-5-20251001")
    assert c._anthropic_model() == "claude-sonnet-5"
    assert c._anthropic_fallback_model() == "claude-haiku-4-5-20251001"


def test_refusal_arrives_as_http_200_and_raises(monkeypatch):
    _use(monkeypatch, _FakeHTTPX(_Resp(_refusal(), status=200)))
    with pytest.raises(AIRefusal):
        c._call_anthropic("p", api_key="k", model="claude-fable-5", timeout=5)


def test_effort_sent_no_temperature_and_bigger_budget(monkeypatch):
    fake = _use(monkeypatch, _FakeHTTPX(_Resp(_text("ok"))))
    assert c._call_anthropic("p", api_key="k", model="m", timeout=5, effort="high") == "ok"
    payload = fake.calls[0]["payload"]
    assert payload["output_config"] == {"effort": "high"}
    assert "temperature" not in payload          # adaptive thinking is always on
    assert payload["max_tokens"] >= 4096         # thinking shares this budget


def test_invalid_effort_rejected(monkeypatch):
    _use(monkeypatch, _FakeHTTPX(_Resp(_text("ok"))))
    with pytest.raises(AIError) as exc:
        c._call_anthropic("p", api_key="k", model="m", timeout=5, effort="turbo")
    assert "Unknown effort" in str(exc.value)


# --------------------------------------------------------------------------
# refusal -> fallback model -> deterministic engine
# --------------------------------------------------------------------------


def test_refusal_retries_once_on_the_fallback_model(monkeypatch):
    monkeypatch.setattr(c, "build_user_prompt", lambda r: "P")
    fake = _use(monkeypatch,
                _FakeHTTPX(_Resp(_refusal()), _Resp(_text("fallback wrote this"))))
    out = c.explain_findings(_stub_result(), provider="anthropic", api_key="k")
    assert out == "fallback wrote this"
    assert [call["payload"]["model"] for call in fake.calls] == [
        "claude-fable-5", "claude-opus-4-8"
    ]


def test_both_models_refuse_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setattr(c, "build_user_prompt", lambda r: "P")
    _use(monkeypatch, _FakeHTTPX(_Resp(_refusal()), _Resp(_refusal())))
    out = c.explain_findings(_stub_result(), provider="anthropic", api_key="k")
    # No exception: the user still gets a briefing, and is told what happened.
    assert "declined" in out
    assert "deterministic engine" in out


def test_effort_flows_through_explain_findings(monkeypatch):
    monkeypatch.setattr(c, "build_user_prompt", lambda r: "P")
    fake = _use(monkeypatch, _FakeHTTPX(_Resp(_text("done"))))
    c.explain_findings(_stub_result(), provider="anthropic", api_key="k", effort="max")
    assert fake.calls[0]["payload"]["output_config"] == {"effort": "max"}
