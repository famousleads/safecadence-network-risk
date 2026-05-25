"""
v11.4.0 — Persistent UI-configurable LLM settings for the reports module.

Replaces the env-var-only configuration story from v11.3.x. The reports
module now consults this store first, then falls back to env vars,
then to deterministic stub mode. Operators can change LLM provider
from the /settings UI without restarting the service or touching
shell env vars.

Storage:
  ``~/.safecadence/llm_config.json``  — non-secret fields in plain text.

Security:
  API keys (HF token, OpenAI key, Anthropic key) are encrypted in-place
  using a Fernet key bootstrapped to
  ``~/.safecadence/.llm_vault.key`` on first save (chmod 600). The
  encrypted values are stored alongside the cleartext metadata with the
  ``_enc:`` prefix so the format is self-describing.

  If the ``cryptography`` package is not installed (it's optional via the
  ``[vault]`` extra), API keys fall back to base64-obfuscated storage.
  That's NOT encryption — it just keeps casual log/grep observers from
  seeing the literal token, and the file is chmod 600 either way.
  Operators who want real encryption should install
  ``pip install safecadence-netrisk[vault]``.

Threading:
  The store uses a process-local lock around the read-modify-write of
  ``llm_config.json``. Cross-process contention is rare (single FastAPI
  worker) but possible; tolerating last-write-wins is acceptable for a
  human-driven config UI.

Caller integration:
  ``ai_helpers._active_provider()`` consults ``get_active_provider()``
  from this module before falling through to env vars. When the UI
  saves a config, the running process picks up the change on the next
  call — no restart needed.
"""
from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def _safecadence_home() -> Path:
    home = Path(os.environ.get("SAFECADENCE_HOME") or (Path.home() / ".safecadence"))
    home.mkdir(parents=True, exist_ok=True)
    return home


def _config_path() -> Path:
    return _safecadence_home() / "llm_config.json"


def _vault_key_path() -> Path:
    return _safecadence_home() / ".llm_vault.key"


# --------------------------------------------------------------------------
# Encryption (Fernet preferred; base64 fallback)
# --------------------------------------------------------------------------


def _load_or_create_fernet_key() -> bytes | None:
    """Return the Fernet key bytes. Bootstrap if missing.

    Returns ``None`` if ``cryptography`` is not installed (caller should
    fall back to base64 obfuscation).
    """
    try:
        from cryptography.fernet import Fernet  # noqa: F401
    except Exception:
        return None
    path = _vault_key_path()
    if path.exists():
        try:
            return path.read_bytes().strip()
        except Exception:
            pass
    # Bootstrap a new key
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key


def encrypt_secret(plain: str) -> str:
    """Return an opaque string representing ``plain``, prefixed for clarity.

    ``enc:<fernet-token>`` when cryptography is installed.
    ``b64:<base64-value>`` as a fallback (NOT real encryption).
    Empty string returns empty string.
    """
    if not plain:
        return ""
    key = _load_or_create_fernet_key()
    if key is not None:
        from cryptography.fernet import Fernet
        token = Fernet(key).encrypt(plain.encode("utf-8")).decode("ascii")
        return f"enc:{token}"
    return "b64:" + base64.b64encode(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """Decrypt a value previously written by ``encrypt_secret``.

    Returns ``""`` if the input is empty or the format is unrecognized.
    Returns the original plaintext otherwise.
    """
    if not stored:
        return ""
    if stored.startswith("enc:"):
        key = _load_or_create_fernet_key()
        if key is None:
            return ""
        from cryptography.fernet import Fernet, InvalidToken
        try:
            return Fernet(key).decrypt(stored[4:].encode("ascii")).decode("utf-8")
        except (InvalidToken, Exception):
            return ""
    if stored.startswith("b64:"):
        try:
            return base64.b64decode(stored[4:].encode("ascii")).decode("utf-8")
        except Exception:
            return ""
    # Legacy: stored value is already plaintext (e.g. someone hand-edited
    # the JSON). Return as-is.
    return stored


# --------------------------------------------------------------------------
# Config schema + I/O
# --------------------------------------------------------------------------


# All known providers. ``"none"`` means "skip the AI step; use the
# deterministic stub". ``"env"`` means "ignore this store and read env
# vars" — useful for operators who want to manage config via container
# environment but still see the panel exists.
SUPPORTED_PROVIDERS = (
    "none", "env",
    "ollama", "huggingface",
    "gemini", "groq", "openrouter",      # v11.5.0 free-tier additions
    "openai", "anthropic",
)


def empty_config() -> dict:
    """Return the canonical empty config shape."""
    return {
        "provider": "env",   # default: don't override; read env vars
        "ollama": {
            "host": "http://127.0.0.1:11434",
            "model": "llama3.1",
        },
        "huggingface": {
            "token": "",        # encrypted on save
            "model": "meta-llama/Meta-Llama-3.1-8B-Instruct",
            "base_url": "https://api-inference.huggingface.co/v1",
        },
        "gemini": {
            "api_key": "",      # encrypted on save
            "model": "gemini-2.0-flash",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        },
        "groq": {
            "api_key": "",      # encrypted on save
            "model": "llama-3.1-70b-versatile",
            "base_url": "https://api.groq.com/openai/v1",
        },
        "openrouter": {
            "api_key": "",      # encrypted on save
            "model": "meta-llama/llama-3.1-8b-instruct:free",
            "base_url": "https://openrouter.ai/api/v1",
        },
        "openai": {
            "api_key": "",      # encrypted on save
            "base_url": "https://api.openai.com",
            "model": "gpt-4o-mini",
        },
        "anthropic": {
            "api_key": "",      # encrypted on save
            "model": "claude-haiku-4-5-20251001",
        },
    }


_LOCK = threading.Lock()


def load_config() -> dict:
    """Return the current config dict, merged with defaults for missing fields.

    Never raises — corrupt JSON returns the empty config.
    """
    path = _config_path()
    if not path.exists():
        return empty_config()
    try:
        with path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return empty_config()
    if not isinstance(raw, dict):
        return empty_config()
    # Merge: ensure all expected keys are present so callers can index freely
    out = empty_config()
    if raw.get("provider") in SUPPORTED_PROVIDERS:
        out["provider"] = raw["provider"]
    for prov in ("ollama", "huggingface", "gemini", "groq", "openrouter",
                 "openai", "anthropic"):
        sub = raw.get(prov) or {}
        if isinstance(sub, dict):
            out[prov].update({k: v for k, v in sub.items() if isinstance(k, str)})
    return out


def save_config(new_cfg: dict) -> dict:
    """Persist ``new_cfg``, encrypting secret fields in-place.

    Returns the resulting config (with secrets in encrypted form, NOT
    plaintext — that's by design, the caller should not log it).
    """
    with _LOCK:
        cfg = empty_config()
        if isinstance(new_cfg, dict):
            if new_cfg.get("provider") in SUPPORTED_PROVIDERS:
                cfg["provider"] = new_cfg["provider"]
            # Per-provider field merge with secret encryption
            for prov, secret_fields in (
                ("ollama", ()),
                ("huggingface", ("token",)),
                ("gemini", ("api_key",)),
                ("groq", ("api_key",)),
                ("openrouter", ("api_key",)),
                ("openai", ("api_key",)),
                ("anthropic", ("api_key",)),
            ):
                sub = new_cfg.get(prov) or {}
                if not isinstance(sub, dict):
                    continue
                # Non-secret fields: just copy across
                for k, v in sub.items():
                    if k in secret_fields:
                        continue
                    cfg[prov][k] = v
                # Secret fields: encrypt OR preserve existing if empty
                prior = load_config()
                for k in secret_fields:
                    new_val = sub.get(k)
                    if isinstance(new_val, str) and new_val:
                        # If caller passes an already-encrypted blob
                        # (round-trip case), keep it as-is.
                        if new_val.startswith(("enc:", "b64:")):
                            cfg[prov][k] = new_val
                        else:
                            cfg[prov][k] = encrypt_secret(new_val)
                    else:
                        # Empty string → preserve prior encrypted value
                        cfg[prov][k] = prior[prov].get(k, "")
        path = _config_path()
        with path.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, sort_keys=True)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return cfg


# --------------------------------------------------------------------------
# Public read helpers (used by ai_helpers.py resolver)
# --------------------------------------------------------------------------


def get_active_provider() -> str | None:
    """Return the provider the UI selected, or ``None`` to use env-var path.

    Returns:
      ``"ollama"`` / ``"huggingface"`` / ``"openai"`` / ``"anthropic"``
        — UI explicitly selected this provider; use stored credentials.
      ``"none"`` — UI explicitly disabled AI; reports should use the
        deterministic stub.
      ``None`` — UI is set to "env" (or no UI config exists); the
        caller should fall through to env-var detection.
    """
    cfg = load_config()
    p = cfg.get("provider")
    if p == "env" or p not in SUPPORTED_PROVIDERS:
        return None
    if p == "none":
        return "none"
    return p


def get_provider_settings(provider: str) -> dict:
    """Return the resolved (decrypted) settings dict for ``provider``.

    Secret fields are decrypted; the caller is responsible for not
    logging them.
    """
    cfg = load_config()
    sub = cfg.get(provider) or {}
    out = dict(sub)
    for secret in ("token", "api_key"):
        if secret in out and isinstance(out[secret], str) and out[secret]:
            out[secret] = decrypt_secret(out[secret])
    return out


def public_view() -> dict:
    """Return a config dict safe to render in the UI / API responses.

    Secret fields are replaced with a boolean ``has_*`` indicator and a
    masked suffix preview, never the actual secret.
    """
    cfg = load_config()
    out: dict = {"provider": cfg.get("provider", "env"), "providers": {}}
    for prov in ("ollama", "huggingface", "gemini", "groq", "openrouter", "openai", "anthropic"):
        sub = dict(cfg.get(prov) or {})
        for secret in ("token", "api_key"):
            if secret in sub:
                stored = sub.pop(secret) or ""
                plain = decrypt_secret(stored) if stored else ""
                sub[f"has_{secret}"] = bool(plain)
                sub[f"{secret}_preview"] = ("****" + plain[-4:]) if len(plain) >= 4 else ""
        out["providers"][prov] = sub
    return out
