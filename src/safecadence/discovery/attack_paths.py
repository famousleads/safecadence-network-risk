"""
AI Attack Path Analysis — traces realistic attack chains across the fleet.

Given the discovered fleet, asks the LLM to model how an attacker would
move from initial access to a chosen objective, with each hop justified by
real findings/CVEs from the data.

Demo line: *"phisher gets to your Mac → your Mac has SSH key for that
Linux server → Linux server has telnet to the switch → attacker now owns
the network. Here's the ONE fix that breaks all 3 of those paths at once."*

Multi-LLM consensus mode (optional): runs the same analysis through
both OpenAI and Anthropic, returns the union + flags disagreements.
"""

from __future__ import annotations

import json
import re

from safecadence.ai.client import AIError, _call_anthropic, _call_ollama, _call_openai
from safecadence.discovery.ai_chat import _summarize_fleet


_ATTACK_PATH_PROMPT = """You are a senior penetration tester. Given the fleet below, identify the 3 most likely attack paths from initial access (e.g., a phished employee laptop) to a high-value objective (root on critical infrastructure, data exfiltration, ransomware staging). Each path must use REAL findings and CVEs from the data — do not invent vulnerabilities.

Respond with VALID JSON ONLY:

{
  "attack_paths": [
    {
      "rank": 1,
      "name": "short descriptive name",
      "objective": "what the attacker achieves",
      "likelihood": "trivial | requires-foothold | requires-credentials | hard",
      "impact": "critical | high | medium",
      "hops": [
        {
          "step": 1,
          "device_ip": "IP from the fleet",
          "vector": "how the attacker compromises this hop (cite real CVE/finding)",
          "outcome": "what the attacker gains here"
        }
      ],
      "estimated_time_to_compromise": "minutes | hours | days",
      "break_the_chain_action": "the SINGLE fix that breaks this entire path",
      "broken_chain_count": 1
    }
  ],
  "highest_leverage_fix": {
    "action": "the one fix across all paths that defuses the most attacks",
    "paths_affected": ["names of paths it breaks"],
    "rationale": "why this is the single best place to start"
  }
}

Begin response with { and end with }."""


def analyze_attack_paths(
    fleet: dict,
    *,
    provider: str = "openai",
    api_key: str = "",
    model: str = "",
    timeout: int = 90,
) -> dict:
    """Run attack-path analysis against a fleet."""
    summary = _summarize_fleet(fleet, max_devices_inline=40)

    prompt = f"""{_ATTACK_PATH_PROMPT}

FLEET DATA:
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


def consensus_analyze(
    fleet: dict,
    *,
    openai_key: str = "",
    anthropic_key: str = "",
    timeout: int = 90,
) -> dict:
    """
    Multi-LLM consensus: run the same analysis through both providers,
    return both results + a 'disagreements' field flagging where they diverge.
    Use for high-stakes findings where you want to verify the AI isn't hallucinating.
    """
    results = {}
    if openai_key:
        results["openai"] = analyze_attack_paths(fleet, provider="openai", api_key=openai_key, timeout=timeout)
    if anthropic_key:
        results["anthropic"] = analyze_attack_paths(fleet, provider="anthropic", api_key=anthropic_key, timeout=timeout)

    # Compare results — find paths both agree on, paths only one mentions
    disagreements = []
    if "openai" in results and "anthropic" in results:
        oa_paths = {p.get("name", ""): p for p in (results["openai"].get("attack_paths") or [])}
        an_paths = {p.get("name", ""): p for p in (results["anthropic"].get("attack_paths") or [])}
        only_openai = [name for name in oa_paths if name not in an_paths]
        only_anthropic = [name for name in an_paths if name not in oa_paths]
        if only_openai:
            disagreements.append({"finding_type": "only_openai_identified", "names": only_openai})
        if only_anthropic:
            disagreements.append({"finding_type": "only_anthropic_identified", "names": only_anthropic})

    return {
        "providers_consulted": list(results.keys()),
        "results": results,
        "disagreements": disagreements,
        "consensus_count": sum(1 for n in (set((p.get("name") for p in (results.get("openai", {}).get("attack_paths") or [])))
                                            & set((p.get("name") for p in (results.get("anthropic", {}).get("attack_paths") or []))))),
    }
