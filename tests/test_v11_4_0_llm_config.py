"""v11.4.0 — Persistent UI-configurable LLM settings.

Tests cover:
  * Config store round-trip (save → load → same shape)
  * Secret-field encryption round-trip (Fernet or base64 fallback)
  * public_view() masks secrets correctly (boolean + 4-char preview)
  * empty_config() default + corrupt-JSON fallback
  * Resolver: store-configured provider beats env vars
  * Resolver: "env" mode falls through to env-var detection
  * Resolver: "none" mode short-circuits to None
  * _try_ai routes to the stored provider's credentials
  * llm_status reports source=ui when store is active
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Each test gets its own ~/.safecadence directory.

    Achieved by pointing SAFECADENCE_HOME at a tmp_path and reloading
    the llm_config module so its path helpers re-evaluate.
    """
    home = tmp_path / "safecadence"
    home.mkdir()
    monkeypatch.setenv("SAFECADENCE_HOME", str(home))
    # Clear any LLM env vars so they don't leak between tests
    for k in (
        "SC_AI_PROVIDER", "OLLAMA_HOST", "SAFECADENCE_LOCAL_LLM",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN",
        "HUGGINGFACE_API_TOKEN", "SAFECADENCE_AI_BASE_URL",
        "SAFECADENCE_HF_MODEL", "SAFECADENCE_HF_BASE_URL",
    ):
        monkeypatch.delenv(k, raising=False)
    yield


# --------------------------------------------------------------------------
# Config store basics
# --------------------------------------------------------------------------


def test_load_returns_default_when_no_file():
    from safecadence.reports import llm_config as cfg
    out = cfg.load_config()
    assert out["provider"] == "env"
    assert out["ollama"]["host"] == "http://127.0.0.1:11434"
    assert out["ollama"]["model"] == "llama3.1"
    assert out["huggingface"]["model"] == "meta-llama/Meta-Llama-3.1-8B-Instruct"


def test_load_returns_default_on_corrupt_json():
    from safecadence.reports import llm_config as cfg
    cfg._config_path().write_text("{not json", encoding="utf-8")
    out = cfg.load_config()
    assert out == cfg.empty_config()


def test_save_then_load_round_trip():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "ollama",
        "ollama": {"host": "http://custom:11434", "model": "mistral"},
    })
    out = cfg.load_config()
    assert out["provider"] == "ollama"
    assert out["ollama"]["host"] == "http://custom:11434"
    assert out["ollama"]["model"] == "mistral"


def test_save_rejects_unknown_provider():
    """If caller passes a junk provider, we silently keep the default."""
    from safecadence.reports import llm_config as cfg
    cfg.save_config({"provider": "not-a-real-provider"})
    assert cfg.load_config()["provider"] == "env"  # default preserved


# --------------------------------------------------------------------------
# Secret encryption
# --------------------------------------------------------------------------


def test_encrypt_decrypt_round_trip():
    from safecadence.reports import llm_config as cfg
    enc = cfg.encrypt_secret("hf_secrettoken12345")
    assert enc.startswith(("enc:", "b64:"))
    assert "hf_secrettoken12345" not in enc          # not in cleartext
    plain = cfg.decrypt_secret(enc)
    assert plain == "hf_secrettoken12345"


def test_encrypt_empty_returns_empty():
    from safecadence.reports import llm_config as cfg
    assert cfg.encrypt_secret("") == ""
    assert cfg.decrypt_secret("") == ""


def test_save_encrypts_secret_fields():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "hf_realtoken_xyz",
                        "model": "mistralai/Mistral-7B"},
    })
    raw = json.loads(cfg._config_path().read_text(encoding="utf-8"))
    stored = raw["huggingface"]["token"]
    assert stored.startswith(("enc:", "b64:"))
    assert "hf_realtoken_xyz" not in stored


def test_save_preserves_existing_secret_when_blank():
    """If the form sends an empty token, we keep the prior encrypted one
    instead of clobbering it. UI convention: blank = unchanged."""
    from safecadence.reports import llm_config as cfg
    # First save with a real token
    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "first_token", "model": "m1"},
    })
    first = json.loads(cfg._config_path().read_text())["huggingface"]["token"]
    # Second save WITHOUT a token (just changing model)
    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "", "model": "m2"},
    })
    second = json.loads(cfg._config_path().read_text())["huggingface"]["token"]
    # The encrypted blob should be the same
    assert first == second
    assert cfg.decrypt_secret(second) == "first_token"


def test_save_accepts_round_tripped_encrypted_value():
    """If the caller passes back a value that's already prefixed (e.g.
    came from public_view, was edited, sent back), we keep it as-is
    instead of double-encrypting."""
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "openai",
        "openai": {"api_key": "sk-original"},
    })
    enc = json.loads(cfg._config_path().read_text())["openai"]["api_key"]
    # Now pretend the UI sent this back as-is
    cfg.save_config({
        "provider": "openai",
        "openai": {"api_key": enc},
    })
    enc2 = json.loads(cfg._config_path().read_text())["openai"]["api_key"]
    assert enc == enc2
    # Still decrypts to original
    assert cfg.decrypt_secret(enc2) == "sk-original"


# --------------------------------------------------------------------------
# public_view (UI safety)
# --------------------------------------------------------------------------


def test_public_view_masks_secrets():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "hf_supersecret_endswithabcd_1234"},
    })
    pv = cfg.public_view()
    hf = pv["providers"]["huggingface"]
    assert "token" not in hf                          # raw secret stripped
    assert hf["has_token"] is True
    assert hf["token_preview"] == "****1234"          # last 4


def test_public_view_with_no_secrets_set():
    from safecadence.reports import llm_config as cfg
    pv = cfg.public_view()
    assert pv["providers"]["huggingface"]["has_token"] is False
    assert pv["providers"]["openai"]["has_api_key"] is False


# --------------------------------------------------------------------------
# Resolver — store > env vars
# --------------------------------------------------------------------------


def test_get_active_provider_returns_none_when_env_mode():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({"provider": "env"})
    assert cfg.get_active_provider() is None


def test_get_active_provider_returns_explicit_choice():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({"provider": "ollama",
                     "ollama": {"host": "http://x:11434", "model": "m"}})
    assert cfg.get_active_provider() == "ollama"


def test_get_active_provider_none_means_disabled():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({"provider": "none"})
    assert cfg.get_active_provider() == "none"


def test_get_provider_settings_decrypts_secrets():
    from safecadence.reports import llm_config as cfg
    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "hf_xyz", "model": "m"},
    })
    s = cfg.get_provider_settings("huggingface")
    assert s["token"] == "hf_xyz"
    assert s["model"] == "m"


# --------------------------------------------------------------------------
# _try_ai integration
# --------------------------------------------------------------------------


def test_try_ai_uses_store_when_configured(monkeypatch):
    """When UI saved 'huggingface' with a token, _try_ai uses those
    credentials, not env vars."""
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({
        "provider": "huggingface",
        "huggingface": {"token": "hf_from_ui",
                        "model": "stored-model",
                        "base_url": "https://stored.example.com/v1"},
    })

    seen = {}
    def fake_call(prompt, **kw):
        seen.update(kw)
        return "from store"

    monkeypatch.setattr(ah, "_call_huggingface", fake_call)
    monkeypatch.setattr(ah, "_call_openai",
                        lambda *a, **kw: pytest.fail("should not be called"))

    out = ah._try_ai("hi")
    assert out == "from store"
    assert seen["token"] == "hf_from_ui"
    assert seen["model"] == "stored-model"
    assert seen["base_url"] == "https://stored.example.com/v1"


def test_try_ai_store_none_returns_none(monkeypatch):
    """Even if env vars are set, store=none short-circuits."""
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({"provider": "none"})
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(ah, "_call_ollama",
                        lambda *a, **kw: pytest.fail("should not be called"))
    assert ah._try_ai("hi") is None


def test_try_ai_env_mode_falls_through_to_env_vars(monkeypatch):
    """Default (store=env) preserves v11.3.x behavior."""
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({"provider": "env"})
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(ah, "_call_ollama", lambda *a, **kw: "from env")
    assert ah._try_ai("hi") == "from env"


def test_llm_status_reports_source_ui_when_store_active():
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({
        "provider": "ollama",
        "ollama": {"host": "http://custom:11434", "model": "custom-model"},
    })
    status = ah.llm_status()
    assert status["provider"] == "ollama"
    assert status["source"] == "ui"
    assert status["model"] == "custom-model"
    assert status["endpoint"] == "http://custom:11434"


def test_llm_status_reports_source_env_when_store_is_env(monkeypatch):
    """When store=env, status should reflect env-var detection."""
    from safecadence.reports import llm_config as cfg
    from safecadence.reports import ai_helpers as ah

    cfg.save_config({"provider": "env"})
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    status = ah.llm_status()
    assert status["provider"] == "ollama"
    assert status.get("source") == "env"
