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


class AIRefusal(AIError):
    """The model declined to answer.

    For a security tool this is not exceptional. Asking a model to describe a
    vulnerability and how to fix it is exactly the shape of request a safety
    classifier may decline. Callers retry once on a fallback model, then drop to
    the deterministic engine — so the user always gets an explanation.
    """


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


# --------------------------------------------------------------------------- #
# Claude model selection (Fable 5)                                             #
# --------------------------------------------------------------------------- #
# Read at call time rather than import time, so flipping an env var takes effect
# without reimporting the module — and so tests can set it cleanly.
_DEFAULT_ANTHROPIC_MODEL = "claude-fable-5"
_FALLBACK_ANTHROPIC_MODEL = "claude-opus-4-8"

#: Fable 5 reasoning-effort levels, sent as ``output_config.effort``.
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")


def _anthropic_model() -> str:
    return (os.environ.get("SAFECADENCE_CLAUDE_MODEL") or _DEFAULT_ANTHROPIC_MODEL).strip()


def _anthropic_fallback_model() -> str:
    return (os.environ.get("SAFECADENCE_CLAUDE_FALLBACK") or _FALLBACK_ANTHROPIC_MODEL).strip()


def _require_text(text: str, provider: str, *, stop_reason: Optional[str] = None) -> str:
    """Never hand back an empty explanation in silence.

    Before this guard, a response carrying no text block — a refusal, a
    thinking-only turn, a tool_use block — collapsed to ``''`` with no error
    raised, so ``safecadence ai-explain`` printed nothing and never said why.
    """
    cleaned = (text or "").strip()
    if cleaned:
        return cleaned
    if stop_reason == "refusal":
        raise AIRefusal(f"{provider} declined to answer (stop_reason=refusal).")
    suffix = f" (stop_reason={stop_reason})" if stop_reason else ""
    raise AIError(f"{provider} returned no text content{suffix}.")


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
        message = r.json()["choices"][0]["message"]
    except (KeyError, IndexError, ValueError) as exc:
        raise AIError(f"Could not parse OpenAI response: {exc}") from exc
    if message.get("refusal"):
        raise AIRefusal(f"OpenAI ({model}) declined: {str(message['refusal'])[:200]}")
    return _require_text(message.get("content") or "", f"OpenAI ({model})")


def _call_anthropic(user_prompt: str, *, api_key: str, model: str, timeout: int,
                    effort: Optional[str] = None, max_tokens: int = 4096) -> str:
    httpx = _import_httpx()
    payload = {
        "model": model,
        # Fable 5 keeps adaptive thinking on, and thinking blocks share this
        # budget — 1500 was enough for text-only models and truncates here.
        "max_tokens": max_tokens,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    # Deliberately no `temperature` on the Claude path: adaptive thinking is
    # always on and the two don't mix.
    if effort:
        if effort not in EFFORT_LEVELS:
            raise AIError(
                f"Unknown effort {effort!r}. Choose one of: {', '.join(EFFORT_LEVELS)}."
            )
        payload["output_config"] = {"effort": effort}
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
    except ValueError as exc:
        raise AIError(f"Could not parse Anthropic response: {exc}") from exc

    # A refusal arrives as HTTP 200 with stop_reason="refusal" and no text block.
    stop_reason = body.get("stop_reason")
    if stop_reason == "refusal":
        raise AIRefusal(f"Anthropic ({model}) declined to answer (stop_reason=refusal).")

    # /v1/messages returns content as a list of blocks; thinking blocks are not
    # text and are skipped here by design.
    chunks = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
    return _require_text("".join(chunks), f"Anthropic ({model})", stop_reason=stop_reason)


def explain_findings(
    result: ScanResult,
    *,
    provider: AIProvider | str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    timeout: int = 60,
    effort: str | None = None,
) -> str:
    """
    Produce an executive remediation briefing.

    Returns a deterministic fallback string if no provider is available, or if
    the model declines to answer (see AIRefusal). `effort` is Fable 5's
    reasoning budget and is ignored by providers that don't support it.
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
        prompt = build_user_prompt(result)
        primary = model or _anthropic_model()
        try:
            return _call_anthropic(prompt, api_key=key, model=primary,
                                   timeout=timeout, effort=effort)
        except AIRefusal:
            fallback = _anthropic_fallback_model()
            if fallback and fallback != primary:
                try:
                    return _call_anthropic(prompt, api_key=key, model=fallback,
                                           timeout=timeout, effort=effort)
                except AIRefusal:
                    pass
            # Both declined. A security tool must still explain itself, so drop
            # to the rule-based engine rather than leaving the user with nothing.
            return _deterministic_fallback(
                result,
                header=(
                    f"The AI model declined to write a remediation narrative "
                    f"(tried {primary}, then {fallback}). That can happen when a "
                    "safety classifier sees vulnerability detail. Falling back to "
                    "the deterministic engine — the findings themselves are unchanged."
                ),
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
    except ValueError as exc:
        raise AIError(f"Could not parse Ollama response: {exc}") from exc
    return _require_text(body.get("message", {}).get("content", ""), f"Ollama ({model})")


def _deterministic_fallback(result: ScanResult, header: str | None = None) -> str:
    """Rule-based briefing. Used when there's no AI key, and when the model
    declines — in which case `header` explains what happened."""
    lead = header or (
        "No AI key detected (set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable "
        "AI-generated remediation plans)."
    )
    if not result.findings:
        return (
            f"{lead}\n\nThe deterministic engine found no findings on this "
            "device. Re-scan periodically and after every change."
        )
    crit = [f for f in result.findings if f.severity.value == "critical"]
    high = [f for f in result.findings if f.severity.value == "high"]
    top = (crit + high)[:5] or result.findings[:5]
    bullets = "\n".join(f"  - [{f.severity.value.upper()}] {f.title}" for f in top)
    return (
        f"{lead}\n\n"
        f"Top findings to address first:\n{bullets}\n\n"
        f"Risk score: {result.risk_score}/100 ({result.risk_band}). "
        f"Health: {result.health_score}/100 ({result.health_band})."
    )
