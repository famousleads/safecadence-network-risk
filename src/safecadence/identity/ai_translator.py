"""
v7.5 — Plain-English → UnifiedPolicyIR translator.

The AI is constrained to producing IR JSON. The IR → per-system change
preview is computed deterministically downstream so the model cannot
hallucinate changes that ship.

Flow:
  1. User provides intent (a sentence).
  2. We render a prompt that pins the IR schema and shows 2 few-shot
     examples (one allow, one deny+step-up).
  3. The AI client (BYO-key, existing safecadence.ai.client) returns a
     JSON blob.
  4. We strip code-fences, parse JSON, validate against the IR schema.
     Anything malformed is rejected — no silent acceptance.

If no AI key is configured, `translate()` raises AIError with an explicit
message pointing the user at the guided form fallback (CLI flag) so the
feature works air-gapped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from safecadence.ai.client import AIError, AIProvider, detect_provider
from safecadence.identity.ir import (
    IRValidationError, UnifiedPolicyIR, validate_ir,
)


# ---------------------------------------------------------------- prompt

_IR_SYSTEM_PROMPT = """You are SafeCadence's identity policy compiler.
Your only job is to translate a user's plain-English intent into a
JSON object matching the SafeCadence Unified Policy IR schema. You
must NEVER output prose, explanations, or commentary. Output JSON only.

Schema (all keys optional unless marked REQUIRED):

{
  "intent": "<verbatim user intent>",            // REQUIRED
  "subjects": {                                   // REQUIRED, at least one selector populated
    "principals":   [],
    "groups":       [],
    "roles":        [],
    "tags":         [],
    "nhi_subtypes": [],
    "exclude_principals": []
  },
  "resources": {
    "asset_ids":    [],
    "asset_types":  [],   // network | server | identity | storage | cloud
    "environments": [],   // prod | staging | dev | test | dr
    "criticalities":[],   // crown-jewel | high | medium | low
    "tags":         [],
    "sites":        []
  },
  "actions":  ["ssh"|"rdp"|"http"|"https"|"read"|"write"|"admin"|"login"], // REQUIRED, ≥1
  "conditions": [
    {"kind": "mfa_required", "value": null, "negate": false},
    {"kind": "posture_compliant", ...},
    {"kind": "device_trusted", ...},
    {"kind": "time_window", "value": "business_hours"}
  ],
  "effect":   "allow" | "deny" | "require_step_up",   // REQUIRED
  "severity": "advisory" | "warn" | "enforce",        // default "enforce"
  "targets":  ["okta"|"ise"|"clearpass"|"ad"|"entra"|"all"]   // default ["all"]
}

Rules:
- Output ONE JSON object, nothing else. No markdown fences. No prose.
- If the intent is unsafe or ambiguous, still produce IR but use
  "severity": "warn" so a human reviews it.
- "targets" reflects which systems the intent can be enforced in.
  Pick the smallest set, e.g. SSH access usually maps to ["okta", "ise"].
"""

_FEW_SHOT = [
    {
        "user": "contractors without MFA cannot SSH to prod",
        "ir": {
            "intent": "contractors without MFA cannot SSH to prod",
            "subjects": {"groups": ["Contractors"]},
            "resources": {"environments": ["prod"], "asset_types": ["server", "network"]},
            "actions": ["ssh"],
            "conditions": [{"kind": "mfa_required", "value": True, "negate": False}],
            "effect": "deny",
            "severity": "enforce",
            "targets": ["okta", "ise"],
        },
    },
    {
        "user": "engineers can RDP to staging only with a trusted device and MFA",
        "ir": {
            "intent": "engineers can RDP to staging only with a trusted device and MFA",
            "subjects": {"groups": ["Engineers"]},
            "resources": {"environments": ["staging"], "asset_types": ["server"]},
            "actions": ["rdp"],
            "conditions": [
                {"kind": "device_trusted", "value": True, "negate": False},
                {"kind": "mfa_required", "value": True, "negate": False},
            ],
            "effect": "allow",
            "severity": "enforce",
            "targets": ["entra", "okta"],
        },
    },
]


def _build_prompt(intent: str) -> str:
    examples = "\n\n".join([
        f"USER: {ex['user']}\nIR: {json.dumps(ex['ir'], sort_keys=True)}"
        for ex in _FEW_SHOT
    ])
    return f"{examples}\n\nUSER: {intent}\nIR:"


# ---------------------------------------------------------------- client


@dataclass
class TranslateResult:
    ir: UnifiedPolicyIR
    raw_response: str
    provider: str
    model: str


def translate(intent: str, *, provider: AIProvider | None = None,
              model: str | None = None,
              ai_call=None) -> TranslateResult:
    """NL → validated IR.

    Parameters
    ----------
    intent     The user's plain-English policy intent.
    provider   AIProvider override. If None, auto-detect from env.
    model      Model override (e.g. 'gpt-4o-mini', 'claude-3-5-sonnet-latest').
    ai_call    Test seam — callable(system_prompt, user_prompt, model) -> str.
               If given, used instead of the real AI client. Tests inject
               a stub here so unit tests don't make network calls.
    """
    if not intent or not intent.strip():
        raise ValueError("intent must be a non-empty string")

    chosen_provider = provider or detect_provider()
    if chosen_provider == AIProvider.NONE and ai_call is None:
        raise AIError(
            "No AI provider configured. Set OPENAI_API_KEY, "
            "ANTHROPIC_API_KEY, or OLLAMA_HOST — or use "
            "`safecadence identity translate --form` for the guided "
            "form fallback (no AI required).")

    user_prompt = _build_prompt(intent)
    chosen_model = model or _default_model_for(chosen_provider)

    if ai_call is not None:
        raw = ai_call(_IR_SYSTEM_PROMPT, user_prompt, chosen_model)
    else:
        raw = _call_real_ai(chosen_provider, chosen_model,
                             _IR_SYSTEM_PROMPT, user_prompt)

    # Strip common LLM noise — code fences, leading "IR:" labels.
    cleaned = _clean_json(raw)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise IRValidationError(
            f"AI returned non-JSON content. First 200 chars: {raw[:200]!r}"
        ) from exc

    # Stamp provenance before validation so a rejected IR still has author.
    parsed.setdefault("intent", intent)
    parsed["author"] = "ai"
    parsed["ai_model"] = chosen_model

    ir = validate_ir(parsed)
    return TranslateResult(
        ir=ir, raw_response=raw,
        provider=chosen_provider.value, model=chosen_model,
    )


# ---------------------------------------------------------------- helpers


def _default_model_for(p: AIProvider) -> str:
    return {
        AIProvider.OPENAI: "gpt-4o-mini",
        AIProvider.ANTHROPIC: "claude-3-5-sonnet-latest",
        AIProvider.OLLAMA: "llama3.1",
        AIProvider.NONE: "",
    }.get(p, "")


def _clean_json(raw: str) -> str:
    """Strip fenced code blocks and stray label prefixes."""
    s = (raw or "").strip()
    # ```json ... ``` or ``` ... ```
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", s, re.DOTALL)
    if fence:
        s = fence.group(1).strip()
    # "IR:" prefix from few-shot bleed
    if s.lower().startswith("ir:"):
        s = s[3:].lstrip()
    # Sometimes models prefix with "Output:" or similar
    for prefix in ("Output:", "Result:", "JSON:"):
        if s.startswith(prefix):
            s = s[len(prefix):].lstrip()
    return s


def _call_real_ai(provider: AIProvider, model: str,
                   system_prompt: str, user_prompt: str) -> str:
    """Bridge into the existing BYO-key AI client.

    The existing client wraps a different system prompt for vuln summaries.
    We bypass it to keep our IR system prompt clean. httpx is imported
    lazily so the module loads without the [ai] extra.
    """
    try:
        import httpx  # type: ignore
    except ImportError as exc:
        raise AIError(
            "AI features require httpx. Install with: "
            "pip install 'safecadence-netrisk[ai]'"
        ) from exc

    if provider == AIProvider.OPENAI:
        return _post_openai(httpx, model, system_prompt, user_prompt)
    if provider == AIProvider.ANTHROPIC:
        return _post_anthropic(httpx, model, system_prompt, user_prompt)
    if provider == AIProvider.OLLAMA:
        return _post_ollama(httpx, model, system_prompt, user_prompt)
    raise AIError(f"Unsupported provider: {provider}")


def _post_openai(httpx, model: str, system_prompt: str, user_prompt: str) -> str:
    import os
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        raise AIError("OPENAI_API_KEY not set")
    r = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
        json={"model": model, "temperature": 0.1,
               "response_format": {"type": "json_object"},
               "messages": [
                   {"role": "system", "content": system_prompt},
                   {"role": "user", "content": user_prompt},
               ]},
        timeout=60,
    )
    if r.status_code >= 400:
        raise AIError(f"OpenAI {r.status_code}: {r.text[:300]}")
    return r.json()["choices"][0]["message"]["content"]


def _post_anthropic(httpx, model: str, system_prompt: str, user_prompt: str) -> str:
    import os
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise AIError("ANTHROPIC_API_KEY not set")
    r = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"},
        json={"model": model, "max_tokens": 1024,
               "system": system_prompt,
               "messages": [{"role": "user", "content": user_prompt}]},
        timeout=60,
    )
    if r.status_code >= 400:
        raise AIError(f"Anthropic {r.status_code}: {r.text[:300]}")
    return r.json()["content"][0]["text"]


def _post_ollama(httpx, model: str, system_prompt: str, user_prompt: str) -> str:
    import os
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    r = httpx.post(
        f"{host}/api/chat",
        json={"model": model, "stream": False, "format": "json",
               "messages": [
                   {"role": "system", "content": system_prompt},
                   {"role": "user", "content": user_prompt},
               ]},
        timeout=120,
    )
    if r.status_code >= 400:
        raise AIError(f"Ollama {r.status_code}: {r.text[:300]}")
    return r.json()["message"]["content"]


# ---------------------------------------------------------------- form fallback


def from_form(*, intent: str, groups: list[str], actions: list[str],
              environments: list[str], effect: str = "deny",
              require_mfa: bool = True,
              targets: list[str] | None = None) -> UnifiedPolicyIR:
    """Air-gapped fallback. Produces a valid IR from CLI flags so the
    feature works without an AI key. Used by `safecadence identity
    translate --form ...`."""
    doc = {
        "intent": intent,
        "subjects": {"groups": groups},
        "resources": {"environments": environments,
                       "asset_types": ["server", "network"]},
        "actions": actions,
        "conditions": ([{"kind": "mfa_required", "value": True,
                          "negate": False}] if require_mfa else []),
        "effect": effect,
        "severity": "enforce",
        "targets": targets or ["all"],
        "author": "human-form",
    }
    return validate_ir(doc)
