"""
AI helpers for the report module.

The strategy (auto-detected; override with ``SC_AI_PROVIDER``):

  1. If ``OLLAMA_HOST`` is set, call a local Ollama instance
     (air-gap friendly, default model ``llama3.1``).
  2. Else if ``HF_TOKEN`` or ``HUGGINGFACE_API_TOKEN`` is set, call the
     Hugging Face Serverless Inference API (default endpoint
     ``api-inference.huggingface.co``, default model
     ``meta-llama/Meta-Llama-3.1-8B-Instruct``). HF as a first-class
     provider — no env-var contortions.
  3. Else if ``OPENAI_API_KEY`` is set, call OpenAI Chat Completions
     (stdlib-only HTTPS POST — no SDK dependency). If
     ``SAFECADENCE_AI_BASE_URL`` is also set, the OpenAI code path hits
     that URL instead of ``api.openai.com`` — works with any
     OpenAI-compatible local endpoint (LM Studio, vLLM,
     text-generation-inference, llama.cpp server, Together.ai, Groq,
     Fireworks).
  4. Else if ``ANTHROPIC_API_KEY`` is set, call Anthropic Messages API.
  5. Otherwise, fall back to deterministic templated prose that uses the
     actual data values, so an offline build still produces realistic
     consultant-grade copy (not a placeholder).

All helpers are pure functions and never raise — failure modes degrade
to a minimal but useful string.

v10.6 changes (May 2026):
  * Real LLM calls now live here directly (urllib + json), with a
    30-second timeout and a single retry on 5xx — no third-party SDK.
  * ``explain_cve`` and ``detect_quick_wins`` are LLM-aware on top of
    the existing deterministic fallbacks.

v11.3.1 changes (May 2026):
  * Ollama is now a first-class provider in the reports module (was
    previously only available via the CLI shim). ``OLLAMA_HOST`` and
    ``SAFECADENCE_LOCAL_LLM`` env vars activate it.
  * ``SAFECADENCE_AI_BASE_URL`` lets the OpenAI code path hit a custom
    base URL — unlocks LM Studio / vLLM / TGI / llama.cpp server / any
    OpenAI-compatible local endpoint, which in practice is how most
    Hugging Face models get exposed for inference.
  * ``SC_AI_PROVIDER`` env var lets the operator force a specific
    provider even when multiple keys are set.
"""

from __future__ import annotations

import json as _json
import os
import time as _time
from typing import Any, Iterable
from urllib import error as _urlerr
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# provider plumbing
# --------------------------------------------------------------------------


# Module-level model names — overridable by env for tests / future tuning.
OPENAI_MODEL = os.environ.get("SAFECADENCE_OPENAI_MODEL", "gpt-4o-mini")
ANTHROPIC_MODEL = os.environ.get(
    "SAFECADENCE_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"
)
# Default Ollama model — override with SAFECADENCE_LOCAL_LLM (e.g. mistral,
# llama3.1:8b, codellama, or any model your local ollama has pulled).
OLLAMA_MODEL_DEFAULT = "llama3.1"
OLLAMA_HOST_DEFAULT = "http://127.0.0.1:11434"

# OpenAI-compatible endpoint base URL. If unset, talks to api.openai.com.
# Set this to point at LM Studio (http://localhost:1234/v1),
# vLLM / text-generation-inference, llama.cpp server, or any hosted
# OpenAI-compatible API (Together.ai, Groq, Fireworks, etc.). This is also
# how Hugging Face models get used in practice — most HF inference runners
# expose the OpenAI Chat Completions shape.
OPENAI_BASE_URL = os.environ.get(
    "SAFECADENCE_AI_BASE_URL", "https://api.openai.com"
).rstrip("/")

LLM_TIMEOUT_SEC = 30


# Hugging Face Inference API. The HF "Serverless Inference" endpoint
# now speaks the OpenAI Chat Completions shape at /v1/chat/completions
# for chat-capable models, so under the hood we route HF through the
# OpenAI code path with this base URL — but we name "huggingface" as a
# first-class provider so the UI dropdown and the docs match what HF
# users expect to see.
HF_BASE_URL_DEFAULT = "https://api-inference.huggingface.co/v1"
HF_MODEL_DEFAULT = "meta-llama/Meta-Llama-3.1-8B-Instruct"


# --------------------------------------------------------------------------
# v11.5.0 — Free-tier OpenAI-compatible providers (Gemini / Groq / OpenRouter)
#
# All three speak the OpenAI Chat Completions API shape, so they share the
# generic `_call_openai_compatible` helper below. Adding a 9th provider is
# one table row + one wrapper function.
# --------------------------------------------------------------------------

GEMINI_BASE_URL_DEFAULT = "https://generativelanguage.googleapis.com/v1beta/openai"
GEMINI_MODEL_DEFAULT = "gemini-2.0-flash"

GROQ_BASE_URL_DEFAULT = "https://api.groq.com/openai/v1"
GROQ_MODEL_DEFAULT = "llama-3.1-70b-versatile"

OPENROUTER_BASE_URL_DEFAULT = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL_DEFAULT = "meta-llama/llama-3.1-8b-instruct:free"


def _gemini_token() -> str | None:
    """Honor both Google's preferred env-var names."""
    return (
        os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or None
    )


def _groq_token() -> str | None:
    return os.environ.get("GROQ_API_KEY") or None


def _openrouter_token() -> str | None:
    return os.environ.get("OPENROUTER_API_KEY") or None


def _hf_token() -> str | None:
    """HF's docs use both names interchangeably; honor both."""
    return (
        os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGINGFACE_API_TOKEN")
        or None
    )


def _active_provider() -> str | None:
    """Return the active provider name or ``None``.

    Precedence (auto-detect):
      1. ``SC_AI_PROVIDER`` explicit override.
      2. Ollama (``OLLAMA_HOST`` or ``SAFECADENCE_LOCAL_LLM``) — local-first
         wins by default.
      3. Hugging Face (``HF_TOKEN`` or ``HUGGINGFACE_API_TOKEN``).
      4. Gemini (``GEMINI_API_KEY`` or ``GOOGLE_API_KEY``) — generous free tier.
      5. Groq (``GROQ_API_KEY``) — fast inference, real free tier.
      6. OpenRouter (``OPENROUTER_API_KEY``) — 200+ models incl. free ones.
      7. OpenAI (``OPENAI_API_KEY``).
      8. Anthropic (``ANTHROPIC_API_KEY``).
      9. ``None`` → deterministic stub.

    Free local + free cloud win over paid by default — sensible because
    if the operator set up the free key, they probably want it used.
    """
    valid = {"ollama", "openai", "anthropic", "huggingface", "hf",
             "gemini", "groq", "openrouter"}
    forced = (os.environ.get("SC_AI_PROVIDER") or "").strip().lower()
    if forced in valid:
        return "huggingface" if forced == "hf" else forced
    if os.environ.get("OLLAMA_HOST") or os.environ.get("SAFECADENCE_LOCAL_LLM"):
        return "ollama"
    if _hf_token():
        return "huggingface"
    if _gemini_token():
        return "gemini"
    if _groq_token():
        return "groq"
    if _openrouter_token():
        return "openrouter"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


def _has_api_key() -> bool:
    """True if any LLM provider is configured (including Ollama, HF)."""
    return _active_provider() is not None


def _http_post_json(url: str, payload: dict, headers: dict,
                    timeout: float = LLM_TIMEOUT_SEC,
                    retry_on_5xx: bool = True) -> dict | None:
    """Stdlib JSON POST. Returns the parsed body on 2xx, ``None`` on failure.

    Retries once on transient 5xx so a single flake doesn't tank the
    report build. Never raises.
    """
    body = _json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **headers}
    attempts = 2 if retry_on_5xx else 1
    last_err: Exception | None = None
    for i in range(attempts):
        req = _urlreq.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with _urlreq.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return _json.loads(raw)
                except Exception:
                    return None
        except _urlerr.HTTPError as e:
            last_err = e
            if 500 <= e.code < 600 and i + 1 < attempts:
                _time.sleep(0.5)
                continue
            return None
        except Exception as e:                         # pragma: no cover
            last_err = e
            return None
    if last_err:
        return None
    return None


def _call_openai(prompt: str, *, system: str | None = None,
                 max_tokens: int = 400,
                 api_key: str | None = None,
                 base_url: str | None = None,
                 model: str | None = None) -> str | None:
    """Single Chat-Completions call. Returns assistant text or ``None``.

    All three of ``api_key`` / ``base_url`` / ``model`` are optional —
    when ``None`` we read the same env vars the module always has. The
    UI Settings panel passes resolved values to bypass env detection.
    """
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    payload = {
        "model": model or OPENAI_MODEL,
        "messages": msgs,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    # Honor SAFECADENCE_AI_BASE_URL — lets a local LM Studio / vLLM / TGI
    # endpoint (or any HF-model runner that speaks the OpenAI shape) handle
    # the request instead of OpenAI's cloud. Air-gap friendly.
    base = (base_url or OPENAI_BASE_URL).rstrip("/")
    url = f"{base}/v1/chat/completions"
    resp = _http_post_json(
        url,
        payload,
        {"Authorization": f"Bearer {key}"},
    )
    if not isinstance(resp, dict):
        return None
    try:
        text = resp["choices"][0]["message"]["content"]
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return None
    return None


def _call_anthropic(prompt: str, *, system: str | None = None,
                    max_tokens: int = 400,
                    api_key: str | None = None,
                    model: str | None = None) -> str | None:
    """Single Messages-API call. Returns assistant text or ``None``.

    ``api_key`` and ``model`` are optional; ``None`` falls back to env
    vars (same as before v11.4.0).
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    payload: dict[str, Any] = {
        "model": model or ANTHROPIC_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system
    resp = _http_post_json(
        "https://api.anthropic.com/v1/messages",
        payload,
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
    )
    if not isinstance(resp, dict):
        return None
    try:
        blocks = resp.get("content") or []
        # Standard shape: [{"type":"text","text":"..."}]
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text":
                t = b.get("text")
                if isinstance(t, str) and t.strip():
                    return t.strip()
    except Exception:
        return None
    return None


def _call_ollama(prompt: str, *, system: str | None = None,
                 max_tokens: int = 400,
                 host: str | None = None,
                 model: str | None = None) -> str | None:
    """Single Ollama /api/chat call. Returns assistant text or ``None``.

    Hits ``OLLAMA_HOST`` (default ``http://127.0.0.1:11434``) with the
    model from ``SAFECADENCE_LOCAL_LLM`` (default ``llama3.1``). Air-gap
    friendly — no outbound calls. ``host`` / ``model`` kwargs override
    the env vars (v11.4.0 UI passes resolved values).
    """
    host = (host or os.environ.get("OLLAMA_HOST", OLLAMA_HOST_DEFAULT)).rstrip("/")
    model = (
        model
        or os.environ.get("SAFECADENCE_LOCAL_LLM")
        or OLLAMA_MODEL_DEFAULT
    )
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    payload = {
        "model": model,
        "messages": msgs,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": max_tokens,
        },
    }
    resp = _http_post_json(
        f"{host}/api/chat",
        payload,
        headers={},  # Ollama doesn't require auth on localhost
    )
    if not isinstance(resp, dict):
        return None
    try:
        text = (resp.get("message") or {}).get("content")
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return None
    return None


def _call_huggingface(prompt: str, *, system: str | None = None,
                      max_tokens: int = 400,
                      token: str | None = None,
                      base_url: str | None = None,
                      model: str | None = None) -> str | None:
    """Single Hugging Face Inference call. Returns assistant text or ``None``.

    Routes through HF's OpenAI-compatible Chat Completions endpoint
    (``/v1/chat/completions``) for chat-capable models. ``token`` /
    ``base_url`` / ``model`` kwargs override the env vars; v11.4.0
    UI passes resolved values from the encrypted config store.
    """
    tok = token or _hf_token()
    if not tok:
        return None
    base = (base_url or os.environ.get("SAFECADENCE_HF_BASE_URL", HF_BASE_URL_DEFAULT)).rstrip("/")
    model = model or os.environ.get("SAFECADENCE_HF_MODEL") or HF_MODEL_DEFAULT
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    payload = {
        "model": model,
        "messages": msgs,
        "max_tokens": max_tokens,
        "temperature": 0.3,
        "stream": False,
    }
    resp = _http_post_json(
        f"{base}/chat/completions",
        payload,
        {"Authorization": f"Bearer {tok}"},
    )
    if not isinstance(resp, dict):
        return None
    try:
        text = resp["choices"][0]["message"]["content"]
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return None
    return None


def _call_openai_compatible(
    prompt: str,
    *,
    system: str | None,
    max_tokens: int,
    api_key: str,
    base_url: str,
    model: str,
    extra_headers: dict | None = None,
) -> str | None:
    """Generic OpenAI Chat Completions caller.

    Powers Gemini / Groq / OpenRouter (and anything else that speaks the
    OpenAI /v1/chat/completions shape). Returns assistant text or
    ``None`` on any failure mode (missing key, network error, empty
    response, parse error).
    """
    if not api_key:
        return None
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    payload = {
        "model": model,
        "messages": msgs,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    headers = {"Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)
    url = f"{base_url.rstrip('/')}/chat/completions"
    resp = _http_post_json(url, payload, headers)
    if not isinstance(resp, dict):
        return None
    try:
        text = resp["choices"][0]["message"]["content"]
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return None
    return None


def _call_gemini(prompt: str, *, system: str | None = None,
                 max_tokens: int = 400,
                 api_key: str | None = None,
                 base_url: str | None = None,
                 model: str | None = None) -> str | None:
    """Google Gemini via the OpenAI-compatible endpoint at
    ``generativelanguage.googleapis.com/v1beta/openai``.

    Default model ``gemini-2.0-flash`` — 1M tokens/day free indefinitely
    as of 2026. Override with ``SAFECADENCE_GEMINI_MODEL`` or pass
    ``model=`` directly from UI config.
    """
    return _call_openai_compatible(
        prompt, system=system, max_tokens=max_tokens,
        api_key=api_key or _gemini_token() or "",
        base_url=base_url or os.environ.get("SAFECADENCE_GEMINI_BASE_URL", GEMINI_BASE_URL_DEFAULT),
        model=model or os.environ.get("SAFECADENCE_GEMINI_MODEL") or GEMINI_MODEL_DEFAULT,
    )


def _call_groq(prompt: str, *, system: str | None = None,
               max_tokens: int = 400,
               api_key: str | None = None,
               base_url: str | None = None,
               model: str | None = None) -> str | None:
    """Groq Cloud — 300-500 tokens/sec inference, free tier no card.

    Default model ``llama-3.1-70b-versatile``. Other strong options:
    ``mixtral-8x7b-32768``, ``llama-3.2-90b-text-preview``.
    """
    return _call_openai_compatible(
        prompt, system=system, max_tokens=max_tokens,
        api_key=api_key or _groq_token() or "",
        base_url=base_url or os.environ.get("SAFECADENCE_GROQ_BASE_URL", GROQ_BASE_URL_DEFAULT),
        model=model or os.environ.get("SAFECADENCE_GROQ_MODEL") or GROQ_MODEL_DEFAULT,
    )


def _call_openrouter(prompt: str, *, system: str | None = None,
                     max_tokens: int = 400,
                     api_key: str | None = None,
                     base_url: str | None = None,
                     model: str | None = None) -> str | None:
    """OpenRouter — aggregator for 200+ models, several free.

    Default model ``meta-llama/llama-3.1-8b-instruct:free`` (the ``:free``
    suffix is OpenRouter's convention for zero-cost variants). Includes
    an optional ``HTTP-Referer`` header so SafeCadence shows up in
    OpenRouter's leaderboard — purely informational.
    """
    extra = {
        "HTTP-Referer": "https://safecadence.com",
        "X-Title": "SafeCadence NetRisk",
    }
    return _call_openai_compatible(
        prompt, system=system, max_tokens=max_tokens,
        api_key=api_key or _openrouter_token() or "",
        base_url=base_url or os.environ.get("SAFECADENCE_OPENROUTER_BASE_URL", OPENROUTER_BASE_URL_DEFAULT),
        model=model or os.environ.get("SAFECADENCE_OPENROUTER_MODEL") or OPENROUTER_MODEL_DEFAULT,
        extra_headers=extra,
    )


def _try_ai(prompt: str, *, system: str | None = None,
            max_tokens: int = 400) -> str | None:
    """Attempt a real LLM call honoring the auto-detected provider.

    v11.4.0 — checks the UI Settings store first. If the operator
    saved a provider via /settings, those credentials are used and
    we don't fall through to env vars (they made an explicit choice).
    If the store is set to "env" (default) or empty, falls back to
    the v11.3.x env-var auto-detection: Ollama → Hugging Face →
    OpenAI → Anthropic. Returns ``None`` when no provider is
    configured, on network failure, or on an empty response. Never
    raises — failures degrade to the caller's deterministic fallback.
    """
    # ---- UI store path (v11.4.0) ----
    try:
        from safecadence.reports import llm_config as _ui_cfg
        ui_provider = _ui_cfg.get_active_provider()
    except Exception:
        ui_provider = None

    if ui_provider == "none":
        # UI explicitly disabled AI — use the deterministic stub.
        return None

    if ui_provider:
        # UI explicitly selected — honor it, don't fall through to env.
        s = _ui_cfg.get_provider_settings(ui_provider)
        if ui_provider == "ollama":
            return _call_ollama(prompt, system=system, max_tokens=max_tokens,
                                host=s.get("host"), model=s.get("model"))
        if ui_provider == "huggingface":
            return _call_huggingface(prompt, system=system, max_tokens=max_tokens,
                                     token=s.get("token"), base_url=s.get("base_url"),
                                     model=s.get("model"))
        if ui_provider == "gemini":
            return _call_gemini(prompt, system=system, max_tokens=max_tokens,
                                api_key=s.get("api_key"), base_url=s.get("base_url"),
                                model=s.get("model"))
        if ui_provider == "groq":
            return _call_groq(prompt, system=system, max_tokens=max_tokens,
                              api_key=s.get("api_key"), base_url=s.get("base_url"),
                              model=s.get("model"))
        if ui_provider == "openrouter":
            return _call_openrouter(prompt, system=system, max_tokens=max_tokens,
                                    api_key=s.get("api_key"), base_url=s.get("base_url"),
                                    model=s.get("model"))
        if ui_provider == "openai":
            return _call_openai(prompt, system=system, max_tokens=max_tokens,
                                api_key=s.get("api_key"), base_url=s.get("base_url"),
                                model=s.get("model"))
        if ui_provider == "anthropic":
            return _call_anthropic(prompt, system=system, max_tokens=max_tokens,
                                   api_key=s.get("api_key"), model=s.get("model"))

    # ---- Env-var path (v11.5.0 — Ollama > HF > Gemini > Groq > OpenRouter > OpenAI > Anthropic) ----
    provider = _active_provider()
    # Each step: if I'm one of the providers that could fall through to
    # the next, AND the next provider's key is actually set, try it.
    # First success wins.
    if provider == "ollama":
        out = _call_ollama(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface") and _hf_token():
        out = _call_huggingface(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface", "gemini") and _gemini_token():
        out = _call_gemini(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface", "gemini", "groq") and _groq_token():
        out = _call_groq(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface", "gemini", "groq", "openrouter") and _openrouter_token():
        out = _call_openrouter(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface", "gemini", "groq", "openrouter", "openai") and os.environ.get("OPENAI_API_KEY"):
        out = _call_openai(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    if provider in ("ollama", "huggingface", "gemini", "groq", "openrouter", "openai", "anthropic") and os.environ.get("ANTHROPIC_API_KEY"):
        out = _call_anthropic(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
    return None


def llm_status() -> dict:
    """Return ``{provider, model, endpoint?}`` for the active LLM.

    When the operator is using an OpenAI-compatible local endpoint
    (LM Studio, vLLM, etc. — anything with ``SAFECADENCE_AI_BASE_URL``
    set), the ``endpoint`` key is included so the UI can show "OpenAI
    API at http://localhost:1234" instead of misleadingly claiming
    OpenAI cloud.
    """
    # v11.4.0 — UI-saved config wins.
    try:
        from safecadence.reports import llm_config as _ui_cfg
        ui_provider = _ui_cfg.get_active_provider()
        if ui_provider == "none":
            return {"provider": "none", "model": None, "source": "ui"}
        if ui_provider:
            s = _ui_cfg.get_provider_settings(ui_provider)
            out: dict = {"provider": ui_provider, "source": "ui"}
            if ui_provider == "ollama":
                out["model"] = s.get("model") or OLLAMA_MODEL_DEFAULT
                out["endpoint"] = s.get("host") or OLLAMA_HOST_DEFAULT
            elif ui_provider == "huggingface":
                out["model"] = s.get("model") or HF_MODEL_DEFAULT
                out["endpoint"] = s.get("base_url") or HF_BASE_URL_DEFAULT
            elif ui_provider == "gemini":
                out["model"] = s.get("model") or GEMINI_MODEL_DEFAULT
                out["endpoint"] = s.get("base_url") or GEMINI_BASE_URL_DEFAULT
            elif ui_provider == "groq":
                out["model"] = s.get("model") or GROQ_MODEL_DEFAULT
                out["endpoint"] = s.get("base_url") or GROQ_BASE_URL_DEFAULT
            elif ui_provider == "openrouter":
                out["model"] = s.get("model") or OPENROUTER_MODEL_DEFAULT
                out["endpoint"] = s.get("base_url") or OPENROUTER_BASE_URL_DEFAULT
            elif ui_provider == "openai":
                out["model"] = s.get("model") or OPENAI_MODEL
                out["endpoint"] = s.get("base_url") or "https://api.openai.com"
            elif ui_provider == "anthropic":
                out["model"] = s.get("model") or ANTHROPIC_MODEL
            return out
    except Exception:
        pass
    # Env-var path (v11.3.x — unchanged)
    p = _active_provider()
    if p == "ollama":
        host = os.environ.get("OLLAMA_HOST", OLLAMA_HOST_DEFAULT)
        model = os.environ.get("SAFECADENCE_LOCAL_LLM") or OLLAMA_MODEL_DEFAULT
        return {"provider": "ollama", "model": model, "endpoint": host, "source": "env"}
    if p == "huggingface":
        base = os.environ.get("SAFECADENCE_HF_BASE_URL", HF_BASE_URL_DEFAULT)
        model = os.environ.get("SAFECADENCE_HF_MODEL") or HF_MODEL_DEFAULT
        return {"provider": "huggingface", "model": model, "endpoint": base, "source": "env"}
    if p == "gemini":
        base = os.environ.get("SAFECADENCE_GEMINI_BASE_URL", GEMINI_BASE_URL_DEFAULT)
        model = os.environ.get("SAFECADENCE_GEMINI_MODEL") or GEMINI_MODEL_DEFAULT
        return {"provider": "gemini", "model": model, "endpoint": base, "source": "env"}
    if p == "groq":
        base = os.environ.get("SAFECADENCE_GROQ_BASE_URL", GROQ_BASE_URL_DEFAULT)
        model = os.environ.get("SAFECADENCE_GROQ_MODEL") or GROQ_MODEL_DEFAULT
        return {"provider": "groq", "model": model, "endpoint": base, "source": "env"}
    if p == "openrouter":
        base = os.environ.get("SAFECADENCE_OPENROUTER_BASE_URL", OPENROUTER_BASE_URL_DEFAULT)
        model = os.environ.get("SAFECADENCE_OPENROUTER_MODEL") or OPENROUTER_MODEL_DEFAULT
        return {"provider": "openrouter", "model": model, "endpoint": base, "source": "env"}
    if p == "openai":
        out: dict = {"provider": "openai", "model": OPENAI_MODEL}
        if OPENAI_BASE_URL != "https://api.openai.com":
            out["endpoint"] = OPENAI_BASE_URL
        return out
    if p == "anthropic":
        return {"provider": "anthropic", "model": ANTHROPIC_MODEL}
    return {"provider": None, "model": None}


# --------------------------------------------------------------------------
# 1. executive summary
# --------------------------------------------------------------------------


_TONE_OPENERS = {
    "professional": "This SafeCadence NetRisk report",
    "executive":    "Executive summary",
    "technical":    "Technical readout",
    "audit":        "Audit-ready summary",
    "forward-looking": "Quarter-over-quarter posture",
}


def _band_for_score(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "elevated"
    if score >= 40: return "moderate"
    if score >= 20: return "low"
    return "minimal"


def _ciso_part1(kev, crit, high, eol):
    if kev:
        return (f"{kev} CISA KEV-listed CVE{'s' if kev != 1 else ''} on assets in scope "
                "represent the highest residual risk — these are exploited in the wild now, "
                "not theoretically.")
    if crit >= 5:
        return (f"{crit} critical findings concentrate the bulk of residual risk; "
                "remediation is the most material lever available this quarter.")
    if eol >= 3:
        return (f"{eol} devices past vendor end-of-support cannot be patched and "
                "constitute durable, unmitigatable risk.")
    if high >= 10:
        return (f"{high} high-severity findings collectively raise the breach-likelihood "
                "envelope above acceptable thresholds.")
    return "Residual risk is within acceptable bounds — emphasis shifts to detection maturity."


def _engineer_part1(kev, crit, high):
    if kev:
        return (f"KEV catalog: {kev} CVE{'s' if kev != 1 else ''} match active exploitation entries — "
                "treat as P0 patch class, ship this week.")
    if crit:
        return (f"{crit} critical CVEs are ready for patch — cluster by vendor and "
                "deploy in a single change window.")
    if high:
        return (f"{high} high-severity items are next in the queue; group by host class.")
    return "No P0/P1 patch items. Focus shifts to baseline drift detection."


def _auditor_part1(kev, crit, eol):
    bits = []
    if kev:
        bits.append(f"{kev} KEV-listed CVE{'s' if kev != 1 else ''} trigger SI-2, RA-5, "
                    "and PCI 6.3.3 control failures")
    if crit:
        bits.append(f"{crit} critical findings inform CC7.1 and CIS 7.x evidence")
    if eol:
        bits.append(f"{eol} EOL device{'s' if eol != 1 else ''} fail SI-2(2) supportability")
    if bits:
        return "Control implications: " + "; ".join(bits) + "."
    return "No findings of audit consequence in the current scan window."


def generate_executive_summary(report_data: dict, *, tone: str = "professional") -> str:
    """Produce a three-part executive summary from a KPI dict.

    The structure is consistent across tones:
      1. Lead with the most actionable threat.
      2. Quantify the gap.
      3. One concrete this-week recommendation.
    The wording (and ordering of facts) changes per tone so each audience
    feels addressed in their own language.
    """
    kpi = report_data.get("kpi") or report_data
    hosts  = int(kpi.get("hosts") or 0)
    crit   = int(kpi.get("critical") or 0)
    high   = int(kpi.get("high") or 0)
    cves   = int(kpi.get("cves") or 0)
    kev    = int(kpi.get("kev") or 0)
    eol    = int(kpi.get("eol") or 0)
    eos    = int(kpi.get("eos_software") or 0)

    # heuristic risk score from KPIs (0..100)
    score = min(100, crit * 8 + high * 3 + kev * 6 + eol * 4 + eos * 2)
    band = _band_for_score(score)

    if hosts == 0:
        return ("No assets in scope. Add scans or widen the scope filter to surface "
                "fleet posture, CVE exposure, and compliance signals.")

    # ---- Part 1: lead with the most actionable threat (per tone) ----
    if tone == "ciso":
        p1 = _ciso_part1(kev, crit, high, eol)
    elif tone in ("engineer", "technical"):
        p1 = _engineer_part1(kev, crit, high)
    elif tone in ("auditor", "audit"):
        p1 = _auditor_part1(kev, crit, eol)
    elif tone == "forward-looking":
        if kev:
            p1 = (f"Quarter opens with {kev} KEV-listed CVE{'s' if kev != 1 else ''} carried over — "
                  "these set the immediate operating ceiling on risk.")
        else:
            p1 = (f"Quarter opens with no KEV-listed exposure on assets in scope — "
                  "a meaningful improvement over the prior quarter for organizations "
                  "tracking that metric.")
    else:  # executive / professional / default
        if kev:
            p1 = (f"{kev} CISA KEV-listed CVE{'s' if kev != 1 else ''} sit on critical "
                  "assets — these are exploited in the wild this week, not later.")
        elif crit >= 5:
            p1 = (f"{crit} critical CVEs are open across the fleet — they concentrate "
                  "the bulk of breach risk and are the single highest leverage move.")
        elif eol >= 3:
            p1 = (f"{eol} devices are past vendor end-of-support — they cannot be "
                  "patched and should be replaced before next quarter.")
        elif crit:
            p1 = (f"{crit} critical CVE{'s' if crit != 1 else ''} need attention this sprint.")
        else:
            p1 = ("No critical or KEV-listed vulnerabilities — the environment's "
                  "current security posture is solid.")

    # ---- Part 2: quantify the gap (per tone) ----
    if tone == "ciso":
        p2 = (f"Across {hosts} in-scope systems, the environment carries an overall "
              f"risk index of {score}/100 ({band}), composed of {crit} critical and "
              f"{high} high findings.")
    elif tone in ("engineer", "technical"):
        p2 = (f"Scope: {hosts} hosts, {cves} distinct CVE classes. Severity split: "
              f"critical={crit}, high={high}. Lifecycle drift: {eol} HW EOL, "
              f"{eos} SW EOS.")
    elif tone in ("auditor", "audit"):
        p2 = (f"Sample size: {hosts} in-scope assets. Open findings: {crit} critical, "
              f"{high} high. Lifecycle exceptions: {eol} HW past EOS, {eos} SW past EOS. "
              "Evidence per-host and per-control is appended.")
    elif tone == "forward-looking":
        p2 = (f"Across {hosts} assets the active risk index is {score}/100 ({band}); "
              f"{crit} critical and {high} high findings drive the number, with "
              f"{eol} EOL hardware items on a replacement clock.")
    else:  # executive / professional
        p2 = (f"Across {hosts} in-scope systems your environment carries an overall "
              f"risk index of {score}/100 ({band}), driven by {crit} critical and "
              f"{high} high findings.")

    # ---- Part 3: one concrete this-week recommendation (per tone) ----
    rec_bits = []
    if kev:
        rec_bits.append("patch the KEV-listed items")
    elif crit:
        rec_bits.append("close the critical CVE queue")
    if high and not kev:
        rec_bits.append("schedule high-severity patches")
    if eol >= 1:
        rec_bits.append(f"replace {eol} end-of-support device{'s' if eol != 1 else ''} before next quarter")
    if eos >= 1:
        rec_bits.append(f"upgrade {eos} EOS software stack{'s' if eos != 1 else ''}")
    if not rec_bits:
        rec_bits.append("maintain scan cadence and tighten identity hygiene")
    # Common shared move
    if kev or crit:
        rec_bits.append("rotate any admin accounts still on shared credentials")

    rec = ", ".join(rec_bits[:3])

    if tone == "ciso":
        p3 = (f"This week, prioritize: {rec}. The action plan in the report scopes each "
              "to a target date based on its priority class.")
    elif tone in ("engineer", "technical"):
        p3 = (f"Sprint backlog: {rec}. P0/P1 remediation snippets are inline against "
              "each finding in the action plan.")
    elif tone in ("auditor", "audit"):
        p3 = (f"Recommended remediation: {rec}. Each item maps back to one or more "
              "controls; tracking is in the risk register.")
    elif tone == "forward-looking":
        p3 = (f"Recommended this quarter: {rec}, with a posture re-snapshot in 30 days "
              "to confirm trend.")
    else:
        p3 = f"Recommended this week: {rec}."

    deterministic = " ".join((p1, p2, p3))
    # v10.6: pass the structured KPI data + tone hint so the LLM can shape
    # the narrative without inventing numbers. The fallback (deterministic)
    # is sent as a "preserve every number" anchor.
    kpi_blob = _json.dumps({
        "hosts": hosts, "critical": crit, "high": high, "cves": cves,
        "kev": kev, "eol": eol, "eos_software": eos, "risk_index": score,
    })
    ai = _try_ai(
        "Write a 2-3 sentence executive summary for a security report. "
        f"Tone: {tone}. "
        "Use exactly the numbers in this KPI JSON — do not invent new figures: "
        f"{kpi_blob}.\n\n"
        "For reference, here is the deterministic version (you may rephrase "
        "but keep every number identical):\n"
        f"{deterministic}",
        system="You are a senior security consultant. Concise, executive-grade prose.",
        max_tokens=300,
    )
    return ai or deterministic


# --------------------------------------------------------------------------
# 2. CVE plain-language explainer
# --------------------------------------------------------------------------


_SEVERITY_PHRASES = {
    "critical": "an unauthenticated remote attacker can fully compromise this system",
    "high":     "an attacker who reaches this host can escalate privileges or read data they shouldn't",
    "medium":   "an attacker with some foothold can chain this with other issues to widen impact",
    "low":      "this is a hygiene item — fix it during the next maintenance window",
}


def explain_cve_plain_language(cve_id: str, severity: str, host: str | None = None) -> str:
    """Three-sentence plain-English explainer for a CVE (legacy signature)."""
    out = explain_cve(cve_id, severity, host=host)
    return out["explanation"]


def explain_cve(cve_id: str, severity: str, *, kev: bool = False,
                host: str | None = None) -> dict:
    """Return ``{explanation: str, source: 'llm'|'stub'}`` for a CVE.

    With an LLM key set, asks the model for a 2-3 sentence non-technical
    explanation. Without, returns a deterministic templated message that
    plugs the severity into a stock phrase.
    """
    sev = (severity or "").lower()
    phrase = _SEVERITY_PHRASES.get(sev, "this issue requires investigation and a fix")
    where = f" on {host}" if host else ""
    kev_note = (
        " It is on the CISA Known Exploited Vulnerabilities list — exploitation has been "
        "observed in the wild, not theorized."
        if kev else ""
    )
    deterministic = (
        f"{cve_id}{where}: {phrase}.{kev_note} "
        f"Treat this as {sev or 'unrated'} priority. "
        "Apply the vendor patch or the configuration mitigation listed in the action plan; "
        "if patching is blocked, isolate the host on a management VLAN and add detection rules."
    )
    prompt_parts = [
        f"Vulnerability: {cve_id}",
        f"Severity: {sev or 'unknown'}",
    ]
    if kev:
        prompt_parts.append("KEV-listed: yes (actively exploited)")
    if host:
        prompt_parts.append(f"Affected host: {host}")
    prompt = (
        "\n".join(prompt_parts)
        + "\n\nDescribe in 2 sentences for a non-technical reader: what this CVE "
          "means in plain English and what one action a security team should take. "
          "Do not invent CVSS scores or vendor names. Keep it concise."
    )
    ai = _try_ai(prompt, system="You are a senior security analyst writing for executives.", max_tokens=200)
    if ai:
        return {"explanation": ai, "source": "llm"}
    return {"explanation": deterministic, "source": "stub"}


# --------------------------------------------------------------------------
# 3. quick wins
# --------------------------------------------------------------------------


def find_quick_wins(findings: list, max_results: int = 5) -> list[dict]:
    """Pick high-leverage findings = (risk_reduction / effort_minutes) high.

    Returns dicts with: title, host, risk_reduction, effort_minutes, why.
    Falls back to severity-ordered picks if those fields aren't present.
    """
    if not findings:
        return []

    def score(f: dict) -> float:
        rr = float(f.get("risk_reduction") or 0)
        eff = float(f.get("effort_minutes") or 0)
        if eff > 0 and rr > 0:
            return rr / eff
        # heuristic: severity weight / effort guess
        sev_w = {"critical": 40, "high": 20, "medium": 8, "low": 2}.get(
            (f.get("severity") or "").lower(), 1)
        e_guess = 30 if f.get("fix_snippet") else 90
        return sev_w / max(1, e_guess)

    ranked = sorted(findings, key=score, reverse=True)
    out: list[dict] = []
    for f in ranked[:max_results]:  # noqa: PERF401  (loop body is non-trivial)
        title = f.get("title") or f.get("rule_id") or f.get("id") or "Unnamed finding"
        host = f.get("host") or f.get("hostname") or ""
        rr = f.get("risk_reduction") or {"critical": 18, "high": 10, "medium": 4, "low": 1}.get(
            (f.get("severity") or "").lower(), 5)
        eff = f.get("effort_minutes") or (15 if f.get("fix_snippet") else 60)
        why = f.get("rationale") or (
            f"Cuts ~{rr} risk points for ~{eff} minutes of work — "
            f"high leverage."
        )
        out.append({
            "title": title,
            "host": host,
            "risk_reduction": rr,
            "effort_minutes": eff,
            "why": why,
            "severity": f.get("severity") or "high",
        })
    return out


def detect_quick_wins(actions: list[dict], *, top_n: int = 3) -> list[dict]:
    """Pick the top ``top_n`` actions by (risk_reduction / effort_minutes).

    With an LLM key set, sends the action list and asks the model to
    rank by leverage. Falls back to the deterministic heuristic on any
    error / missing key.

    Each input ``action`` should look like::

        {"id": "...", "title": "...", "risk_reduction": <num>,
         "effort_minutes": <num>, "severity": "..."}

    Returns ``[{id, score, source, ...}]`` sorted high → low. ``source``
    is ``'llm'`` or ``'heuristic'`` so the caller can label the badge.
    """
    if not actions:
        return []

    def _heuristic_score(a: dict) -> float:
        rr = float(a.get("risk_reduction") or 0)
        eff = float(a.get("effort_minutes") or 0)
        if rr > 0 and eff > 0:
            return rr / eff
        sev_w = {"critical": 40, "high": 20, "medium": 8, "low": 2}.get(
            (a.get("severity") or "").lower(), 1)
        e_guess = float(a.get("effort_minutes") or 60) or 60
        return sev_w / e_guess

    # --- LLM path -----------------------------------------------------
    if _has_api_key():
        # Build a small, structured payload so the model can rank without
        # hallucinating new actions. We pin to the ids supplied.
        try:
            compact = [
                {
                    "id": str(a.get("id") or a.get("title") or i),
                    "title": str(a.get("title") or ""),
                    "risk_reduction": a.get("risk_reduction"),
                    "effort_minutes": a.get("effort_minutes"),
                    "severity": a.get("severity"),
                }
                for i, a in enumerate(actions)
            ]
            prompt = (
                "Rank the following remediation actions by leverage "
                "(risk reduction per minute of effort). Return ONLY a JSON "
                f"array of the top {top_n} action ids, highest leverage first, "
                "no prose, no markdown. Allowed ids: "
                + ", ".join(a["id"] for a in compact)
                + "\n\nActions:\n" + _json.dumps(compact)
            )
            raw = _try_ai(
                prompt,
                system="You output JSON only. No prose. No code fences.",
                max_tokens=200,
            )
            if raw:
                # Strip fences if the model added them despite instructions.
                s = raw.strip()
                if s.startswith("```"):
                    s = s.strip("`")
                    if s.lower().startswith("json"):
                        s = s[4:]
                    s = s.strip()
                ids = _json.loads(s)
                if isinstance(ids, list) and ids:
                    by_id = {str(a.get("id") or a.get("title") or i): a
                             for i, a in enumerate(actions)}
                    ordered: list[dict] = []
                    seen: set[str] = set()
                    for raw_id in ids:
                        key = str(raw_id)
                        if key in by_id and key not in seen:
                            a = dict(by_id[key])
                            a["score"] = round(_heuristic_score(a), 3)
                            a["source"] = "llm"
                            ordered.append(a)
                            seen.add(key)
                        if len(ordered) >= top_n:
                            break
                    if ordered:
                        return ordered
        except Exception:
            pass  # fall through to heuristic

    # --- heuristic fallback ------------------------------------------
    ranked = sorted(actions, key=_heuristic_score, reverse=True)
    out: list[dict] = []
    for a in ranked[:top_n]:
        b = dict(a)
        b["score"] = round(_heuristic_score(a), 3)
        b["source"] = "heuristic"
        out.append(b)
    return out


# --------------------------------------------------------------------------
# 4. patch sequencing
# --------------------------------------------------------------------------


_TIER_ORDER = [
    ("identity", 0, "Identity providers — patch first; downstream auth depends on these."),
    ("firewall", 1, "Edge / firewall — patch before opening internal change windows."),
    ("network",  2, "Network gear — patch in maintenance windows after edge."),
    ("server",   3, "OS-level patches on servers — schedule rolling restarts."),
    ("cloud",    4, "Cloud control plane — apply after on-prem stabilizes."),
    ("backup",   5, "Backup infrastructure — patch last to keep recovery available."),
    ("app",      6, "Application patches — go last; verify against staging."),
]


def _tier_for(asset_type: str) -> tuple[int, str]:
    a = (asset_type or "").lower()
    for name, tier, note in _TIER_ORDER:
        if name in a:
            return tier, note
    return 9, "Patch alongside its peer tier."


def sequence_patches(findings: list) -> list[dict]:
    """Group findings into ordered patch waves based on asset role."""
    if not findings:
        return []
    waves: dict[int, dict] = {}
    for f in findings:
        atype = f.get("asset_type") or f.get("type") or ""
        tier, note = _tier_for(atype)
        wave = waves.setdefault(tier, {
            "wave": tier + 1, "tier_note": note, "items": [],
        })
        wave["items"].append({
            "title": f.get("title") or f.get("id") or f.get("rule_id") or "Patch",
            "host":  f.get("host") or f.get("hostname") or "",
            "severity": f.get("severity") or "high",
            "asset_type": atype,
        })
    return [waves[k] for k in sorted(waves.keys())]


# --------------------------------------------------------------------------
# 5. stakeholder narrative
# --------------------------------------------------------------------------


_AUDIENCE_TONE = {
    "ceo":          "executive",
    "ciso":         "executive",
    "engineer":     "technical",
    "auditor":      "audit",
    "soc-analyst":  "technical",
    "soc":          "technical",
}


def stakeholder_narrative(report_data: dict, *, audience: str) -> str:
    """Same data, different framing per audience."""
    tone = _AUDIENCE_TONE.get((audience or "").lower(), "professional")
    base = generate_executive_summary(report_data, tone=tone)
    a = (audience or "").lower()
    if a == "ceo":
        return ("For the board: " + base + " Business risk is concentrated in a "
                "small number of fixes; the action plan section lists the dollar-cheap, "
                "fast-to-execute ones first.")
    if a == "ciso":
        return ("Security leadership view: " + base + " Recommend pairing the KEV "
                "remediation list below with this quarter's patch SLO.")
    if a == "engineer":
        return ("Engineering readout: " + base + " Use the action plan's P0/P1 list as "
                "your sprint backlog; remediation snippets are inline per finding.")
    if a == "auditor":
        return ("Audit framing: " + base + " Evidence and control mappings are "
                "appended; sampling notes are in the host inventory section.")
    if a in ("soc-analyst", "soc"):
        return ("SOC analyst brief: " + base + " Detection rules for KEV CVEs are listed "
                "in the action plan; tune correlation accordingly.")
    return base


__all__ = [
    "generate_executive_summary",
    "explain_cve_plain_language",
    "explain_cve",
    "find_quick_wins",
    "detect_quick_wins",
    "sequence_patches",
    "stakeholder_narrative",
    "llm_status",
]
