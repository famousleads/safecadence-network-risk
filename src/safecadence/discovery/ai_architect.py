"""
AI Network Architect — analyzes the entire network architecture and recommends
structural improvements (segmentation, zero-trust posture, microsegmentation
gaps, VLAN organization).

Different from per-device AI analysis: this looks at the WHOLE network as a
system and asks "is this architecture sound?"

Returns prioritized architectural recommendations with effort estimates.
"""

from __future__ import annotations

import json
import re

from safecadence.ai.client import AIError, _call_anthropic, _call_ollama, _call_openai
from safecadence.discovery.ai_chat import _summarize_fleet


_ARCHITECT_PROMPT = """You are a senior network architect with 20 years of experience designing enterprise networks. You've been asked to review the network below and recommend structural improvements. Focus on architecture issues, not per-device tuning.

Analyze for:
- Network segmentation gaps (devices that should be on different VLANs)
- Microsegmentation opportunities (where east-west traffic should be controlled)
- Zero-trust posture (where implicit trust should be removed)
- Critical-asset isolation (crown jewels mixed with low-trust devices)
- Lateral movement risk (chains of trust that enable attacker pivots)
- Modernization opportunities (legacy patterns that should be retired)

Respond with VALID JSON ONLY:

{
  "architecture_grade": "A | B | C | D | F",
  "summary": "2-3 sentence executive view of the network's architecture",
  "segmentation_gaps": [
    {
      "issue": "what's wrong (1 sentence)",
      "evidence_devices": ["IP1", "IP2"],
      "recommendation": "specific architectural change",
      "effort": "hours | days | weeks",
      "risk_reduction": "low | medium | high | critical"
    }
  ],
  "zero_trust_recommendations": [
    {
      "principle": "name of zero-trust principle being violated",
      "current_state": "how the network does it today",
      "target_state": "what it should look like",
      "first_step": "smallest concrete first action"
    }
  ],
  "lateral_movement_risks": [
    {
      "scenario": "if attacker gains foothold on X, they could reach Y because Z",
      "break_the_chain": "single architectural fix that mitigates this"
    }
  ],
  "modernization_opportunities": [
    "specific legacy patterns to retire and what to replace them with"
  ],
  "prioritized_roadmap": [
    {
      "phase": 1,
      "timeframe": "30 days | 90 days | 6 months",
      "actions": ["action 1", "action 2"],
      "expected_outcome": "what improves"
    }
  ]
}

Begin response with { and end with }."""


def analyze_architecture(
    fleet: dict,
    *,
    provider: str = "openai",
    api_key: str = "",
    model: str = "",
    timeout: int = 90,
) -> dict:
    """Analyze the network architecture as a whole."""
    summary = _summarize_fleet(fleet, max_devices_inline=50)

    prompt = f"""{_ARCHITECT_PROMPT}

NETWORK DATA:
{summary}

Respond with JSON only."""

    default_models = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-haiku-4-5-20251001",
        "ollama": "llama3.1:8b",
    }
    model = model or default_models.get(provider, "")

    try:
        if provider == "openai":
            raw = _call_openai(prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "anthropic":
            raw = _call_anthropic(prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "ollama":
            raw = _call_ollama(prompt, host="http://localhost:11434", model=model, timeout=timeout)
        else:
            return {"error": f"unknown provider: {provider}"}
    except AIError as e:
        return {"error": f"AI provider error: {e}"}
    except Exception as e:
        return {"error": f"unexpected error: {e}"}

    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "AI returned invalid JSON", "raw": raw[:1500]}
