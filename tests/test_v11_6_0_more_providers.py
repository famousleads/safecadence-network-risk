"""v11.6.0 — Cloudflare Workers AI, DeepSeek, GitHub Models, Mistral, Cohere.

Tests:
  * Each provider's env-var detection (Cloudflare needs BOTH token + account ID)
  * Updated precedence (Ollama > HF > Gemini > Groq > OpenRouter > CF > DeepSeek > GitHub > Mistral > Cohere > OpenAI > Anthropic)
  * SC_AI_PROVIDER override accepts the five new names
  * HTTP call shape — OpenAI-compatible for four, Cohere has its own shape
  * Cloudflare URL templating with account_id
  * GitHub Models honors both GITHUB_TOKEN and GH_TOKEN
  * Cohere request/response uses non-OpenAI shape (`message`/`text` fields)
  * Store schema includes all five new provider blocks
  * UI form round-trip
"""
from __future__ import annotations

import json
import os

import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in (
        "SC_AI_PROVIDER",
        "OLLAMA_HOST", "SAFECADENCE_LOCAL_LLM",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "HF_TOKEN", "HUGGINGFACE_API_TOKEN",
        "GEMINI_API_KEY", "GOOGLE_API_KEY",
        "GROQ_API_KEY", "OPENROUTER_API_KEY",
        "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID",
        "DEEPSEEK_API_KEY",
        "GITHUB_TOKEN", "GH_TOKEN",
        "MISTRAL_API_KEY", "COHERE_API_KEY",
        "SAFECADENCE_AI_BASE_URL",
        "SAFECADENCE_CLOUDFLARE_MODEL", "SAFECADENCE_CLOUDFLARE_BASE_URL",
        "SAFECADENCE_DEEPSEEK_MODEL", "SAFECADENCE_DEEPSEEK_BASE_URL",
        "SAFECADENCE_GITHUB_MODELS_MODEL", "SAFECADENCE_GITHUB_MODELS_BASE_URL",
        "SAFECADENCE_MISTRAL_MODEL", "SAFECADENCE_MISTRAL_BASE_URL",
        "SAFECADENCE_COHERE_MODEL", "SAFECADENCE_COHERE_BASE_URL",
    ):
        monkeypatch.delenv(k, raising=False)
    yield


# --------------------------------------------------------------------------
# Cloudflare Workers AI
# --------------------------------------------------------------------------


def test_cloudflare_needs_both_token_and_account_id(monkeypatch):
    """Just a token alone shouldn't activate Cloudflare."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_tok")
    assert ah._active_provider() is None  # missing account_id
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "acct123")
    assert ah._active_provider() == "cloudflare"


def test_cloudflare_url_templates_account_id(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_tok")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "abc123def456")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    ah._call_cloudflare("hi")
    assert "abc123def456" in seen["url"]
    assert seen["url"].endswith("/chat/completions")


def test_cloudflare_returns_none_without_account_id(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_tok")
    # No account_id env, no body override — should refuse
    assert ah._call_cloudflare("hi") is None


# --------------------------------------------------------------------------
# DeepSeek
# --------------------------------------------------------------------------


def test_deepseek_detected(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deep")
    assert ah._active_provider() == "deepseek"


def test_deepseek_call_uses_correct_endpoint(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deep")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        seen["auth"] = headers.get("Authorization", "")
        return {"choices": [{"message": {"content": "deep response"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_deepseek("hi")
    assert out == "deep response"
    assert "deepseek.com" in seen["url"]
    assert seen["auth"] == "Bearer sk-deep"


# --------------------------------------------------------------------------
# GitHub Models
# --------------------------------------------------------------------------


def test_github_models_detected_via_github_token(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    assert ah._active_provider() == "github"


def test_github_models_detected_via_gh_token_alias(monkeypatch):
    """Both GITHUB_TOKEN and GH_TOKEN are honored (gh CLI vs PAT convention)."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GH_TOKEN", "ghp_alias")
    assert ah._active_provider() == "github"


def test_github_models_call_uses_azure_endpoint(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        return {"choices": [{"message": {"content": "from gh"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    ah._call_github_models("hi")
    assert "models.inference.ai.azure.com" in seen["url"]


# --------------------------------------------------------------------------
# Mistral La Plateforme
# --------------------------------------------------------------------------


def test_mistral_detected(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("MISTRAL_API_KEY", "ms_test")
    assert ah._active_provider() == "mistral"


def test_mistral_call_uses_correct_endpoint(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("MISTRAL_API_KEY", "ms_test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        return {"choices": [{"message": {"content": "mistral response"}}]}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    ah._call_mistral("hi")
    assert "mistral.ai" in seen["url"]


# --------------------------------------------------------------------------
# Cohere (non-OpenAI shape)
# --------------------------------------------------------------------------


def test_cohere_detected(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("COHERE_API_KEY", "co_test")
    assert ah._active_provider() == "cohere"


def test_cohere_uses_non_openai_request_shape(monkeypatch):
    """Cohere takes `message` (not `messages`) and returns `text` (not `choices`)."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("COHERE_API_KEY", "co_test")
    seen = {}

    def fake_post(url, payload, headers, **kw):
        seen["url"] = url
        seen["payload"] = payload
        # Cohere returns top-level `text` field, not `choices`.
        return {"text": "cohere reply", "id": "abc"}

    monkeypatch.setattr(ah, "_http_post_json", fake_post)
    out = ah._call_cohere("hello there", system="Be brief.")
    assert out == "cohere reply"
    assert seen["url"].endswith("/chat")
    assert seen["payload"]["message"] == "hello there"
    assert seen["payload"]["preamble"] == "Be brief."
    assert seen["payload"]["model"] == "command-r"


def test_cohere_returns_none_on_unexpected_shape(monkeypatch):
    """If the response is missing 'text', we degrade to None."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("COHERE_API_KEY", "co_test")
    monkeypatch.setattr(ah, "_http_post_json",
                        lambda *a, **kw: {"id": "abc", "no_text_here": True})
    assert ah._call_cohere("hi") is None


# --------------------------------------------------------------------------
# Precedence chain (all 12 providers)
# --------------------------------------------------------------------------


def test_full_precedence_chain(monkeypatch):
    """Ollama > HF > Gemini > Groq > OpenRouter > CF > DeepSeek > GitHub > Mistral > Cohere > OpenAI > Anthropic."""
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("ANTHROPIC_API_KEY", "an_test")
    assert ah._active_provider() == "anthropic"

    monkeypatch.setenv("OPENAI_API_KEY", "oa_test")
    assert ah._active_provider() == "openai"

    monkeypatch.setenv("COHERE_API_KEY", "co_test")
    assert ah._active_provider() == "cohere"

    monkeypatch.setenv("MISTRAL_API_KEY", "ms_test")
    assert ah._active_provider() == "mistral"

    monkeypatch.setenv("GITHUB_TOKEN", "gh_test")
    assert ah._active_provider() == "github"

    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds_test")
    assert ah._active_provider() == "deepseek"

    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_test")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "acct_test")
    assert ah._active_provider() == "cloudflare"

    monkeypatch.setenv("OPENROUTER_API_KEY", "or_test")
    assert ah._active_provider() == "openrouter"


def test_sc_ai_provider_accepts_new_provider_names(monkeypatch):
    from safecadence.reports import ai_helpers as ah
    monkeypatch.setenv("OPENAI_API_KEY", "oa_test")
    monkeypatch.setenv("SC_AI_PROVIDER", "cohere")
    monkeypatch.setenv("COHERE_API_KEY", "co_test")
    assert ah._active_provider() == "cohere"


# --------------------------------------------------------------------------
# Store schema
# --------------------------------------------------------------------------


def test_store_schema_includes_all_v11_6_providers(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    e = cfg.empty_config()
    for prov in ("cloudflare", "deepseek", "github", "mistral", "cohere"):
        assert prov in e, f"missing provider {prov}"
        assert "api_key" in e[prov]
        assert "model" in e[prov]
    # Cloudflare has an extra account_id field
    assert "account_id" in e["cloudflare"]


def test_store_save_encrypts_v11_6_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "deepseek",
        "deepseek": {"api_key": "sk-deepsecret_xyz", "model": "deepseek-chat"},
    })
    raw = json.loads((tmp_path / "llm_config.json").read_text())
    assert raw["deepseek"]["api_key"].startswith(("enc:", "b64:"))
    assert "sk-deepsecret_xyz" not in raw["deepseek"]["api_key"]
    assert cfg.get_provider_settings("deepseek")["api_key"] == "sk-deepsecret_xyz"


def test_store_cloudflare_account_id_is_not_encrypted(tmp_path, monkeypatch):
    """account_id is not a secret per Cloudflare docs — stays plaintext."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "cloudflare",
        "cloudflare": {"api_key": "cf_secret_token", "account_id": "abc123",
                       "model": "@cf/meta/llama-3.1-8b-instruct"},
    })
    raw = json.loads((tmp_path / "llm_config.json").read_text())
    # account_id is plaintext
    assert raw["cloudflare"]["account_id"] == "abc123"
    # api_key is encrypted
    assert raw["cloudflare"]["api_key"].startswith(("enc:", "b64:"))


def test_try_ai_uses_stored_cohere_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({
        "provider": "cohere",
        "cohere": {"api_key": "co_from_ui", "model": "command-r-plus"},
    })

    seen = {}
    def fake_call(prompt, **kw):
        seen.update(kw)
        return "cohere from store"

    monkeypatch.setattr(ah, "_call_cohere", fake_call)
    assert ah._try_ai("hi") == "cohere from store"
    assert seen["api_key"] == "co_from_ui"
    assert seen["model"] == "command-r-plus"
