"""
BYOK AI client.

Talks directly to OpenAI / Anthropic from the user's machine using their
own API key. Key never touches a SafeCadence server.

Optional dependency: requires `pip install safecadence-netrisk[ai]`
which pulls httpx. We import httpx lazily so users without the extra
get a clear error message rather than an ImportError on `safecadence scan`.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Optional

from safecadence.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from safecadence.core.schema import ScanResult


class AIError(RuntimeError):
    pass


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"     # local LLM via Ollama (or any OpenAI-compatible local API)
    NONE = "none"


def detect_provider(env: Optional[dict] = None) -> AIProvider:
    """Pick a provider based on which API key is set in the environment."""
    e = env if env is not None else os.environ
    # Prefer local LLM if explicitly configured (air-gapped friendly)
    if e.get("OLLAMA_HOST") or e.get("SAFECADENCE_LOCAL_LLM"):
        return AIProvider.OLLAMA
    if e.get("OPENAI_API_KEY"):
        return AIProvider.OPENAI
    if e.get("ANTHROPIC_API_KEY"):
        return AIProvider.ANTHROPIC
    return AIProvider.NONE


def _import_httpx():
    try:
        import httpx  # type: ignore
        return httpx
    except ImportError as exc:
        raise AIError(
            "AI features require httpx. Install with: "
            "pip install 'safecadence-netrisk[ai]'"
        ) from exc


def _call_openai(user_prompt: str, *, api_key: str, model: str, timeout: int) -> str:
    httpx = _import_httpx()
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    try:
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload, headers=headers, timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise AIError(f"OpenAI request failed: {exc}") from exc
    if r.status_code >= 400:
        raise AIError(f"OpenAI returned {r.status_code}: {r.text[:300]}")
    try:
        return r.json()["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, ValueError) as exc:
        raise AIError(f"Could not parse OpenAI response: {exc}") from exc


def _call_anthropic(user_prompt: str, *, api_key: str, model: str, timeout: int) -> str:
    httpx = _import_httpx()
    payload = {
        "model": model,
        "max_tokens": 1500,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            json=payload, headers=headers, timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise AIError(f"Anthropic request failed: {exc}") from exc
    if r.status_code >= 400:
        raise AIError(f"Anthropic returned {r.status_code}: {r.text[:300]}")
    try:
        body = r.json()
        # /v1/messages returns content as a list of blocks
        chunks = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
        return ("".join(chunks)).strip()
    except (KeyError, ValueError) as exc:
        raise AIError(f"Could not parse Anthropic response: {exc}") from exc


def explain_findings(
    result: ScanResult,
    *,
    provider: AIProvider | str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    timeout: int = 60,
) -> str:
    """
    Produce an executive remediation briefing.

    Returns a deterministic fallback string if no provider is available.
    """
    prov = provider if isinstance(provider, AIProvider) else (
        AIProvider(provider) if provider else detect_provider()
    )
    if prov == AIProvider.NONE:
        return _deterministic_fallback(result)

    if prov == AIProvider.OPENAI:
        key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
        if not key:
            raise AIError("OPENAI_API_KEY not set and no --api-key provided.")
        return _call_openai(
            build_user_prompt(result),
            api_key=key,
            model=model or "gpt-4o-mini",
            timeout=timeout,
        )

    if prov == AIProvider.ANTHROPIC:
        key = (api_key or os.environ.get("ANTHROPIC_API_KEY", "")).strip()
        if not key:
            raise AIError("ANTHROPIC_API_KEY not set and no --api-key provided.")
        return _call_anthropic(
            build_user_prompt(result),
            api_key=key,
            model=model or "claude-haiku-4-5-20251001",
            timeout=timeout,
        )

    if prov == AIProvider.OLLAMA:
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        return _call_ollama(
            build_user_prompt(result),
            host=host,
            model=model or os.environ.get("SAFECADENCE_LOCAL_LLM") or "llama3.1",
            timeout=timeout,
        )

    return _deterministic_fallback(result)


def _call_ollama(user_prompt: str, *, host: str, model: str, timeout: int) -> str:
    """Local LLM via Ollama's chat API. Air-gapped friendly."""
    httpx = _import_httpx()
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.2},
    }
    try:
        r = httpx.post(f"{host}/api/chat", json=payload, timeout=timeout)
    except httpx.HTTPError as exc:
        raise AIError(f"Ollama request failed ({host}): {exc}") from exc
    if r.status_code >= 400:
        raise AIError(f"Ollama returned {r.status_code}: {r.text[:300]}")
    try:
        body = r.json()
        return (body.get("message", {}).get("content", "")).strip()
    except (KeyError, ValueError) as exc:
        raise AIError(f"Could not parse Ollama response: {exc}") from exc


def _deterministic_fallback(result: ScanResult) -> str:
    """No-AI fallback — still useful, just rule-based."""
    if not result.findings:
        return (
            "No AI key detected. The deterministic engine found no findings on "
            "this device. Re-scan periodically and after every change."
        )
    crit = [f for f in result.findings if f.severity.value == "critical"]
    high = [f for f in result.findings if f.severity.value == "high"]
    top = (crit + high)[:5] or result.findings[:5]
    bullets = "\n".join(f"  - [{f.severity.value.upper()}] {f.title}" for f in top)
    return (
        "No AI key detected (set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable "
        "AI-generated remediation plans).\n\n"
        f"Top findings to address first:\n{bullets}\n\n"
        f"Risk score: {result.risk_score}/100 ({result.risk_band}). "
        f"Health: {result.health_score}/100 ({result.health_band})."
    )
