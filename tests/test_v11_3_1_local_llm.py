"""v11.3.1 — Ollama + OpenAI-compatible base URL support in reports module.

These tests confirm the reports/ai_helpers.py module:
  * Detects Ollama when OLLAMA_HOST is set (precedence: Ollama > OpenAI > Anthropic)
  * Honors SC_AI_PROVIDER as an explicit override
  * Routes OpenAI calls to SAFECADENCE_AI_BASE_URL when set (LM Studio / vLLM /
    text-generation-inference / llama.cpp server / Hugging Face inference runners)
  * llm_status() correctly reports the active provider + endpoint
  * Empty / failed responses fall back to the deterministic engine

No real network calls — _http_post_json is monkey-patched.
"""
from __future__ import annotations

import os
from unittest import mock

import pytest

from safecadence.reports import ai_helpers as ah


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch):
    """Strip every LLM env var so each test starts from a clean slate."""
    for k in (
        "SC_AI_PROVIDER",
        "OLLAMA_HOST",
        "SAFECADENCE_LOCAL_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SAFECADENCE_AI_BASE_URL",
    ):
        monkeypatch.delenv(k, raising=False)
    # Reload module-level constant that snapshots env at import.
    monkeypatch.setattr(ah, "OPENAI_BASE_URL", "https://api.openai.com")
    yield


# --------------------------------------------------------------------------
# provider detection
# --------------------------------------------------------------------------


def test_no_env_returns_no_provider():
    assert ah._active_provider() is None
    assert ah._has_api_key() is False
    assert ah.llm_status() == {"provider": None, "model": None}


def test_ollama_detected_via_ollama_host(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    assert ah._active_provider() == "ollama"
    assert ah._has_api_key() is True
    status = ah.llm_status()
    assert status["provider"] == "ollama"
    assert status["endpoint"] == "http://127.0.0.1:11434"
    assert status["model"] == "llama3.1"


def test_ollama_detected_via_local_llm_alias(monkeypatch):
    """SAFECADENCE_LOCAL_LLM alone activates Ollama with that model name."""
    monkeypatch.setenv("SAFECADENCE_LOCAL_LLM", "mistral")
    assert ah._active_provider() == "ollama"
    assert ah.llm_status()["model"] == "mistral"


def test_ollama_beats_openai_when_both_set(monkeypatch):
    """Local-first: if Ollama is set, it wins even when OPENAI_API_KEY is present."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert ah._active_provider() == "ollama"


def test_sc_ai_provider_override_forces_openai(monkeypatch):
    """Explicit override beats auto-detect."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SC_AI_PROVIDER", "openai")
    assert ah._active_provider() == "openai"


def test_openai_detected_when_only_key_set(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert ah._active_provider() == "openai"
    assert ah.llm_status()["provider"] == "openai"
    # No custom endpoint → no 'endpoint' key in status.
    assert "endpoint" not in ah.llm_status()


def test_openai_status_includes_endpoint_when_base_url_set(monkeypatch):
    """SAFECADENCE_AI_BASE_URL=http://localhost:1234 → status reports endpoint."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(ah, "OPENAI_BASE_URL", "http://localhost:1234")
    status = ah.llm_status()
    assert status["provider"] == "openai"
    assert status["endpoint"] == "http://localhost:1234"


def test_anthropic_detected_when_only_anthropic_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert ah._active_provider() == "anthropic"


# --------------------------------------------------------------------------
# Ollama HTTP call
# --------------------------------------------------------------------------


def test_call_ollama_happy_path(monkeypatch):
    """_call_ollama posts to /api/chat and returns message.content."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        seen["payload"] = payload
        return {"message": {"content": "  Ollama replied.  "}}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_ollama("Hello", system="be brief", max_tokens=50)
    assert out == "Ollama replied."
    assert seen["url"] == "http://127.0.0.1:11434/api/chat"
    assert seen["payload"]["model"] == "llama3.1"
    assert seen["payload"]["stream"] is False
    assert seen["payload"]["options"]["num_predict"] == 50
    # system + user messages both included
    roles = [m["role"] for m in seen["payload"]["messages"]]
    assert roles == ["system", "user"]


def test_call_ollama_returns_none_on_empty_response(monkeypatch):
    monkeypatch.setattr(ah, "_http_post_json", lambda *a, **kw: None)
    assert ah._call_ollama("Hello") is None


def test_call_ollama_returns_none_on_missing_content(monkeypatch):
    monkeypatch.setattr(ah, "_http_post_json", lambda *a, **kw: {"message": {}})
    assert ah._call_ollama("Hello") is None


def test_call_ollama_honors_custom_model(monkeypatch):
    """SAFECADENCE_LOCAL_LLM picks the model name in the POST body."""
    monkeypatch.setenv("SAFECADENCE_LOCAL_LLM", "mistral:7b-instruct")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["model"] = payload["model"]
        return {"message": {"content": "ok"}}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    ah._call_ollama("Hello")
    assert seen["model"] == "mistral:7b-instruct"


# --------------------------------------------------------------------------
# OpenAI-compatible base URL
# --------------------------------------------------------------------------


def test_openai_call_uses_default_endpoint(monkeypatch):
    """No SAFECADENCE_AI_BASE_URL → hits api.openai.com."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        return {"choices": [{"message": {"content": "hello"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_openai("hi")
    assert out == "hello"
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"


def test_openai_call_uses_custom_base_url(monkeypatch):
    """SAFECADENCE_AI_BASE_URL=http://localhost:1234 → hits LM Studio.

    This is the headline v11.3.1 feature — same code path, different URL,
    enables Hugging Face models via any OpenAI-compatible local runner.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "lm-studio")
    monkeypatch.setattr(ah, "OPENAI_BASE_URL", "http://localhost:1234")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        return {"choices": [{"message": {"content": "from LM Studio"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_openai("hi")
    assert out == "from LM Studio"
    assert seen["url"] == "http://localhost:1234/v1/chat/completions"


def test_openai_base_url_strips_trailing_slash(monkeypatch):
    """User sets http://localhost:1234/ — we strip the trailing slash."""
    monkeypatch.setenv("SAFECADENCE_AI_BASE_URL", "http://localhost:1234/")
    # Reload the module-level constant the way the import would.
    import importlib
    importlib.reload(ah)
    assert ah.OPENAI_BASE_URL == "http://localhost:1234"


# --------------------------------------------------------------------------
# _try_ai routing
# --------------------------------------------------------------------------


def test_try_ai_routes_to_ollama_when_active(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(ah, "_call_ollama", lambda *a, **kw: "ollama said hi")
    monkeypatch.setattr(ah, "_call_openai", lambda *a, **kw: pytest.fail("should not be called"))
    monkeypatch.setattr(ah, "_call_anthropic", lambda *a, **kw: pytest.fail("should not be called"))
    assert ah._try_ai("hello") == "ollama said hi"


def test_try_ai_falls_back_to_openai_when_ollama_unreachable(monkeypatch):
    """Ollama configured but daemon down → try OpenAI if key is set."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(ah, "_call_ollama", lambda *a, **kw: None)  # daemon down
    monkeypatch.setattr(ah, "_call_openai", lambda *a, **kw: "fallback to cloud")
    assert ah._try_ai("hello") == "fallback to cloud"


def test_try_ai_returns_none_when_no_provider(monkeypatch):
    assert ah._try_ai("hello") is None


def test_try_ai_returns_none_when_provider_fails_silently(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(ah, "_call_ollama", lambda *a, **kw: None)
    assert ah._try_ai("hello") is None


# --------------------------------------------------------------------------
# end-to-end: executive summary still works without an LLM
# --------------------------------------------------------------------------


def test_executive_summary_works_without_llm_unchanged():
    """Make sure v11.3.1 didn't regress the deterministic fallback path."""
    kpi = {"hosts": 34, "critical": 14, "high": 42, "cves": 56, "kev": 5, "eol": 4, "eos_software": 2}
    out = ah.generate_executive_summary({"kpi": kpi}, tone="executive")
    assert isinstance(out, str)
    assert len(out) > 100
    # The numbers must be in the output (deterministic fallback used)
    assert "34" in out or "hosts" in out.lower()


def test_executive_summary_uses_ollama_when_available(monkeypatch):
    """When Ollama is up, exec summary uses the model output."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(
        ah, "_call_ollama",
        lambda *a, **kw: "Custom Ollama summary mentioning 34 hosts and 14 critical findings."
    )
    kpi = {"hosts": 34, "critical": 14, "high": 42}
    out = ah.generate_executive_summary({"kpi": kpi}, tone="executive")
    assert "Custom Ollama summary" in out
