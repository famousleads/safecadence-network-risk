"""
v9.32 — AI-explain a finding (BYO-AI hook).

Trust posture (read this first):
  * BYO-AI: the operator's API key (OpenAI, Anthropic, Ollama) reads
    from env vars on the LOCAL machine and is sent ONLY to that
    provider. The key never touches a SafeCadence server, never
    appears in logs.
  * Air-gap mode: when SC_AI_DISABLED=1 or no provider key is set,
    we return a deterministic offline explanation instead of failing.
  * No outbound calls without an explicit env var. The function
    short-circuits with a "set $OPENAI_API_KEY to enable" message
    when no provider is configured.
  * The prompt + response are both returned to the caller so the
    operator can see exactly what we sent and exactly what came back.
    No hidden prompts, no hidden tools.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional


_PROVIDERS = ("openai", "anthropic", "ollama")
_MAX_TOKENS = 600
_MAX_FINDING_BYTES = 8000   # cap how much of a finding we send


@dataclass
class Explanation:
    finding_id: str
    provider: str           # offline | openai | anthropic | ollama
    model: str
    text: str
    prompt: str             # exact prompt we sent (transparency)
    network_used: bool      # was an outbound call made?
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "provider": self.provider,
            "model": self.model,
            "text": self.text,
            "prompt": self.prompt,
            "network_used": self.network_used,
            "error": self.error,
        }


# ---------------------------------------------------------- prompt builder


_SYSTEM_PROMPT = """You are a senior network/security engineer helping
explain a finding from SafeCadence — a multi-vendor security posture
tool — to another engineer.

Output rules:
  * Plain English, 4-8 sentences total. No markdown headers.
  * First sentence: what the problem actually is.
  * Then: why it matters (impact, threat model).
  * Then: a concrete remediation, vendor-specific if vendor is given.
  * Last: a one-line citation like 'Maps to NIST 800-53 AC-2 / CIS 6.1'.

Stay technically accurate. If the finding is ambiguous, say so.
Never invent CVE IDs, control IDs, or vendor commands you aren't
certain of.
"""


def _build_prompt(finding: dict) -> str:
    safe = {k: v for k, v in finding.items()
            if not isinstance(v, (bytes, bytearray))}
    payload = json.dumps(safe, default=str)[:_MAX_FINDING_BYTES]
    return (f"Explain this finding:\n```json\n{payload}\n```\n"
            "Follow the output rules above.")


# ---------------------------------------------------------- providers


def _provider_in_env() -> str:
    """Detect which BYO-AI provider has a key set, in priority order:
    Anthropic → OpenAI → Ollama → none. Operator can override with
    SC_AI_PROVIDER explicitly."""
    forced = (os.environ.get("SC_AI_PROVIDER") or "").lower().strip()
    if forced in _PROVIDERS:
        return forced
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    return ""


def _ai_disabled() -> bool:
    """Master kill switch. Set SC_AI_DISABLED=1 (or any truthy value)
    to force the offline path even when keys are present. Useful for
    air-gap deployments where nothing should leave the box."""
    v = (os.environ.get("SC_AI_DISABLED") or "").strip().lower()
    return v not in ("", "0", "false", "no", "off")


def _offline_explanation(finding: dict) -> str:
    """Deterministic, no-network explanation. Always available."""
    sev = (finding.get("severity") or "").lower()
    kind = finding.get("kind") or "issue"
    cid = finding.get("control_id") or ""
    asset = finding.get("asset_id") or ""
    title = finding.get("title") or kind
    msg = finding.get("message") or ""

    parts = [
        f"This is a {sev or 'medium'}-severity {kind} on "
        f"{asset or 'an asset'}: {title}."
    ]
    if msg:
        parts.append(f"Details: {msg[:240]}")
    if cid:
        parts.append(f"It's tied to SafeCadence control `{cid}`. "
                     f"See /api/compliance/control/{cid} for the full "
                     f"framework mapping.")
    parts.append("Remediate by reviewing the control's expected "
                 "posture against this asset's running config; the "
                 "policy translator can render the change for "
                 "your vendor.")
    parts.append("(Offline explanation — set ANTHROPIC_API_KEY or "
                 "OPENAI_API_KEY for an AI-generated walkthrough, "
                 "or keep SC_AI_DISABLED=1 to stay air-gap.)")
    return " ".join(parts)


def _try_anthropic(prompt: str) -> tuple[str, str, str]:
    """Returns (text, model, error). Empty text + error on failure."""
    try:
        import httpx
    except ImportError:
        return "", "", "httpx not installed"
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return "", "", "no ANTHROPIC_API_KEY"
    model = os.environ.get("SC_AI_MODEL") or "claude-haiku-4-5-20251001"
    try:
        with httpx.Client(timeout=20) as c:
            r = c.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": _MAX_TOKENS,
                    "system": _SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        if r.status_code != 200:
            return "", model, f"HTTP {r.status_code}: {r.text[:240]}"
        data = r.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        return text.strip(), model, ""
    except Exception as e:
        return "", model, f"{type(e).__name__}: {e}"


def _try_openai(prompt: str) -> tuple[str, str, str]:
    try:
        import httpx
    except ImportError:
        return "", "", "httpx not installed"
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return "", "", "no OPENAI_API_KEY"
    model = os.environ.get("SC_AI_MODEL") or "gpt-4o-mini"
    try:
        with httpx.Client(timeout=20) as c:
            r = c.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": _MAX_TOKENS,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
        if r.status_code != 200:
            return "", model, f"HTTP {r.status_code}: {r.text[:240]}"
        data = r.json()
        text = (data.get("choices", [{}])[0]
                  .get("message", {}).get("content", "") or "")
        return text.strip(), model, ""
    except Exception as e:
        return "", model, f"{type(e).__name__}: {e}"


def _try_ollama(prompt: str) -> tuple[str, str, str]:
    try:
        import httpx
    except ImportError:
        return "", "", "httpx not installed"
    host = os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
    model = os.environ.get("SC_AI_MODEL") or "llama3.2"
    try:
        with httpx.Client(timeout=30) as c:
            r = c.post(
                f"{host.rstrip('/')}/api/generate",
                json={
                    "model": model,
                    "system": _SYSTEM_PROMPT,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": _MAX_TOKENS},
                },
            )
        if r.status_code != 200:
            return "", model, f"HTTP {r.status_code}: {r.text[:240]}"
        data = r.json()
        return (data.get("response", "") or "").strip(), model, ""
    except Exception as e:
        return "", model, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------- public


def explain(finding: dict) -> Explanation:
    """Generate a plain-English explanation of one finding.

    Returns an :class:`Explanation` with the prompt + response + the
    `network_used` flag so the caller can show the operator exactly
    what happened. Honors SC_AI_DISABLED for air-gap deployments.
    """
    fid = (finding.get("id") or finding.get("finding_id")
            or finding.get("uid") or "")
    prompt = _build_prompt(finding)

    if _ai_disabled():
        return Explanation(
            finding_id=str(fid), provider="offline", model="rule-based",
            text=_offline_explanation(finding), prompt=prompt,
            network_used=False,
        )

    provider = _provider_in_env()
    if provider == "anthropic":
        text, model, err = _try_anthropic(prompt)
    elif provider == "openai":
        text, model, err = _try_openai(prompt)
    elif provider == "ollama":
        text, model, err = _try_ollama(prompt)
    else:
        return Explanation(
            finding_id=str(fid), provider="offline",
            model="rule-based",
            text=_offline_explanation(finding),
            prompt=prompt, network_used=False,
        )

    if not text:
        return Explanation(
            finding_id=str(fid), provider=provider, model=model,
            text=_offline_explanation(finding) +
                  f"\n\n(AI provider returned no usable text: {err})",
            prompt=prompt, network_used=True, error=err,
        )

    return Explanation(
        finding_id=str(fid), provider=provider, model=model,
        text=text, prompt=prompt,
        network_used=provider in ("openai", "anthropic"),
    )
