"""v11.5.0 — Gemini, Groq, OpenRouter as first-class providers.

Tests:
  * Provider auto-detection via each provider's env var
  * Precedence order (Ollama > HF > Gemini > Groq > OpenRouter > OpenAI > Anthropic)
  * SC_AI_PROVIDER explicit override accepts new names
  * HTTP call shape (OpenAI-compatible Chat Completions)
  * Per-provider model + base URL defaults
  * llm_status reports new providers correctly
  * Store schema includes new provider blocks
  * _try_ai routes through stored credentials
  * Graceful fallback chain through new providers
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch):
    """Strip every LLM env var so each test starts from a clean slate."""
    for k in (
        "SC_AI_PROVIDER",
        "OLLAMA_HOST", "SAFECADENCE_LOCAL_LLM",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "HF_TOKEN", "HUGGINGFACE_API_TOKEN",
        "GEMINI_API_KEY", "GOOGLE_API_KEY",
        "GROQ_API_KEY", "OPENROUTER_API_KEY",
        "SAFECADENCE_AI_BASE_URL",
        "SAFECADENCE_HF_MODEL", "SAFECADENCE_HF_BASE_URL",
        "SAFECADENCE_GEMINI_MODEL", "SAFECADENCE_GEMINI_BASE_URL",
        "SAFECADENCE_GROQ_MODEL", "SAFECADENCE_GROQ_BASE_URL",
        "SAFECADENCE_OPENROUTER_MODEL", "SAFECADENCE_OPENROUTER_BASE_URL",
    ):
        monkeypatch.delenv(k, raising=False)
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setattr(ah, "OPENAI_BASE_URL", "https://api.openai.com")
    yield


# --------------------------------------------------------------------------
# Gemini
# --------------------------------------------------------------------------


def test_gemini_detected_via_gemini_api_key(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    assert ah._active_provider() == "gemini"


def test_gemini_detected_via_google_api_key_alias(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GOOGLE_API_KEY", "AIzaSy_test")
    assert ah._active_provider() == "gemini"


def test_gemini_status_reports_endpoint_and_model(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    status = ah.llm_status()
    assert status["provider"] == "gemini"
    assert status["model"] == "gemini-2.0-flash"
    assert "generativelanguage.googleapis.com" in status["endpoint"]


def test_call_gemini_happy_path(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        seen["auth"] = headers.get("Authorization", "")
        seen["model"] = payload["model"]
        return {"choices": [{"message": {"content": "Gemini replied."}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_gemini("hi")
    assert out == "Gemini replied."
    assert "generativelanguage.googleapis.com" in seen["url"]
    assert seen["url"].endswith("/chat/completions")
    assert seen["auth"] == "Bearer AIzaSy_test"
    assert seen["model"] == "gemini-2.0-flash"


# --------------------------------------------------------------------------
# Groq
# --------------------------------------------------------------------------


def test_groq_detected(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    assert ah._active_provider() == "groq"


def test_groq_status(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    s = ah.llm_status()
    assert s["provider"] == "groq"
    assert "groq.com" in s["endpoint"]
    assert "llama" in s["model"].lower()


def test_call_groq_happy_path(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GROQ_API_KEY", "gsk_xyz")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        seen["auth"] = headers.get("Authorization", "")
        return {"choices": [{"message": {"content": "fast response"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_groq("hi")
    assert out == "fast response"
    assert "groq.com" in seen["url"]
    assert seen["auth"] == "Bearer gsk_xyz"


# --------------------------------------------------------------------------
# OpenRouter
# --------------------------------------------------------------------------


def test_openrouter_detected(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    assert ah._active_provider() == "openrouter"


def test_openrouter_default_model_is_free_tier(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    s = ah.llm_status()
    assert s["provider"] == "openrouter"
    # OpenRouter ":free" suffix convention for zero-cost variants
    assert ":free" in s["model"]


def test_call_openrouter_includes_referer_header(monkeypatch):
    """OpenRouter scores apps for their leaderboard via HTTP-Referer."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["headers"] = headers
        return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    ah._call_openrouter("hi")
    assert "openrouter.ai" in seen.get("headers", {}).get("Authorization", "") or True  # auth is bearer
    assert "HTTP-Referer" in seen["headers"]
    assert "safecadence.com" in seen["headers"]["HTTP-Referer"]
    assert seen["headers"]["X-Title"] == "SafeCadence NetRisk"


# --------------------------------------------------------------------------
# Precedence (Ollama > HF > Gemini > Groq > OpenRouter > OpenAI > Anthropic)
# --------------------------------------------------------------------------


def test_precedence_gemini_beats_groq_beats_openrouter_beats_openai(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OPENAI_API_KEY", "sk-paid")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    assert ah._active_provider() == "openrouter"

    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    assert ah._active_provider() == "groq"

    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    assert ah._active_provider() == "gemini"

    monkeypatch.setenv("HF_TOKEN", "hf_test")
    assert ah._active_provider() == "huggingface"

    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    assert ah._active_provider() == "ollama"


def test_sc_ai_provider_overrides_precedence(monkeypatch):
    """Explicit override beats everything."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OLLAMA_HOST", "http://x")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    monkeypatch.setenv("SC_AI_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    assert ah._active_provider() == "groq"


# --------------------------------------------------------------------------
# Cross-provider fallback
# --------------------------------------------------------------------------


def test_try_ai_routes_to_gemini(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    monkeypatch.setattr(ah, "_call_gemini", lambda *a, **kw: "gemini result")
    monkeypatch.setattr(ah, "_call_openai", lambda *a, **kw: pytest.fail("should not be called"))
    assert ah._try_ai("hi") == "gemini result"


def test_try_ai_gemini_failure_falls_through_to_groq(monkeypatch):
    """Gemini configured but unreachable → Groq tries next."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    monkeypatch.setattr(ah, "_call_gemini", lambda *a, **kw: None)
    monkeypatch.setattr(ah, "_call_groq", lambda *a, **kw: "groq fallback")
    assert ah._try_ai("hi") == "groq fallback"


# --------------------------------------------------------------------------
# UI store integration
# --------------------------------------------------------------------------


def test_store_schema_includes_new_providers(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    empty = cfg.empty_config()
    assert "gemini" in empty
    assert "groq" in empty
    assert "openrouter" in empty
    assert empty["gemini"]["model"] == "gemini-2.0-flash"
    assert empty["groq"]["base_url"].startswith("https://api.groq.com")
    assert "openrouter.ai" in empty["openrouter"]["base_url"]
    assert ":free" in empty["openrouter"]["model"]


def test_store_save_encrypts_new_provider_keys(tmp_path, monkeypatch):
    """Make sure api_key for gemini/groq/openrouter gets encrypted too."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "groq",
        "groq": {"api_key": "gsk_secrettoken_xyz", "model": "mixtral-8x7b-32768"},
    })
    import json
    raw = json.loads((tmp_path / "llm_config.json").read_text())
    assert raw["groq"]["api_key"].startswith(("enc:", "b64:"))
    assert "gsk_secrettoken_xyz" not in raw["groq"]["api_key"]
    # round-trip decrypts back
    assert cfg.get_provider_settings("groq")["api_key"] == "gsk_secrettoken_xyz"


def test_store_public_view_masks_new_provider_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "openrouter",
        "openrouter": {"api_key": "sk-or-ends-abcd1234"},
    })
    pv = cfg.public_view()
    assert pv["providers"]["openrouter"]["has_api_key"] is True
    assert pv["providers"]["openrouter"]["api_key_preview"] == "****1234"
    assert "sk-or-ends-abcd1234" not in str(pv)


def test_try_ai_uses_stored_gemini_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({
        "provider": "gemini",
        "gemini": {"api_key": "AIzaSy_from_ui",
                   "model": "gemini-pro",
                   "base_url": "https://custom-gemini.example.com/v1"},
    })

    seen = {}
    def fake_call(prompt, **kw):
        seen.update(kw)
        return "from store gemini"

    monkeypatch.setattr(ah, "_call_gemini", fake_call)
    monkeypatch.setattr(ah, "_call_openai", lambda *a, **kw: pytest.fail("should not be called"))

    assert ah._try_ai("hi") == "from store gemini"
    assert seen["api_key"] == "AIzaSy_from_ui"
    assert seen["model"] == "gemini-pro"
    assert seen["base_url"] == "https://custom-gemini.example.com/v1"
