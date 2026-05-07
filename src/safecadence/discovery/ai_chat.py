"""
Conversational AI for the discovered fleet.

Lets users ask natural-language questions about their network and get
grounded answers based on actual scan data. The LLM only sees the fleet
summary + relevant device details — the user's prompt is constrained to
prevent hallucinated devices/CVEs.

Examples:
  "Which devices have telnet open?"
  "Show me all printers."
  "What's the riskiest device on the network?"
  "Which Apple devices haven't been seen in the last scan?"
  "Generate a 30-day remediation plan."
  "Compare today's scan to last week's."

Returns structured output so the UI can render filters / device cards /
playbooks based on the response.
"""

from __future__ import annotations

import json
import re

from safecadence.ai.client import AIError, _call_anthropic, _call_ollama, _call_openai


_CHAT_SYSTEM_PROMPT = """You are a network security analyst chatting with the operator of a small-to-medium enterprise network. You have access to live discovery data from the operator's local network. Answer their questions based ONLY on the data provided — do not invent devices, CVEs, or facts.

When the user asks for a list of devices, return them in a clear table format. When they ask for analysis, be concise and actionable. When they ask for recommendations, prioritize by risk impact and business criticality.

Respond with VALID JSON ONLY using this schema:
{
  "answer": "natural language answer to the user's question (max 400 words)",
  "matching_device_ips": ["list of IPs that match the question, if any — empty array if not relevant"],
  "suggested_followup": ["max 3 short followup questions the user might want to ask next"],
  "action_recommendation": "single concrete next action they should take, or null"
}

Begin response with { and end with }."""


def _summarize_fleet(fleet: dict, max_devices_inline: int = 30) -> str:
    """
    Build a compact text summary of the fleet for the LLM prompt.
    Keeps token usage low while preserving the data the LLM needs.
    """
    summary = fleet.get("summary", {})
    bands = summary.get("by_risk_band", {})
    cats = summary.get("by_category", {})
    cve_sum = summary.get("cves", {})

    lines = [
        f"FLEET OVERVIEW — subnet {fleet.get('cidr', '?')}, {fleet.get('count', 0)} devices",
        f"Risk distribution: {bands.get('critical',0)} critical / {bands.get('high',0)} high / {bands.get('medium',0)} medium / {bands.get('low',0)} low / {bands.get('safe',0)} safe",
        f"CVEs matched: {cve_sum.get('total_cves', 0)} total ({cve_sum.get('kev_cves', 0)} on CISA KEV)",
        f"Categories: " + ", ".join(f"{k}={v}" for k, v in cats.items()),
        "",
        "DEVICES (sorted by risk):",
    ]

    devices = fleet.get("results", [])
    for d in devices[:max_devices_inline]:
        cves = d.get("cves") or []
        cve_str = f" | CVEs: {len(cves)}" + (f" ({sum(1 for c in cves if c.get('kev'))} KEV)" if any(c.get('kev') for c in cves) else "")
        lines.append(
            f"  {d.get('ip','?'):<16} "
            f"risk={d.get('risk_score',0):>3} "
            f"vendor={d.get('vendor','-')[:18]:<18} "
            f"category={d.get('category','-')[:14]:<14} "
            f"ports={','.join(str(p) for p in (d.get('open_ports') or [])[:6])}"
            f"{cve_str}"
        )
    if len(devices) > max_devices_inline:
        lines.append(f"  ... and {len(devices) - max_devices_inline} more devices not shown")
    return "\n".join(lines)


def chat(message: str, fleet: dict, *, provider: str = "openai",
         api_key: str = "", model: str = "", timeout: int = 60,
         conversation_history: list | None = None) -> dict:
    """
    Send a user message + fleet context to the LLM.
    Returns dict matching the JSON schema above (with 'error' if it failed).
    """
    if not message or not message.strip():
        return {"error": "message required"}

    fleet_summary = _summarize_fleet(fleet)
    history_block = ""
    if conversation_history:
        # Last 4 exchanges for context, kept short
        for turn in conversation_history[-4:]:
            who = turn.get("role", "user")
            content = (turn.get("content") or "")[:400]
            history_block += f"\n{who.upper()}: {content}"

    full_prompt = f"""{_CHAT_SYSTEM_PROMPT}

DATA FROM THE OPERATOR'S LIVE NETWORK SCAN:
{fleet_summary}
{f'PRIOR CONVERSATION:{history_block}' if history_block else ''}

USER QUESTION: {message}

Respond with JSON only, conforming to the schema above."""

    default_models = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-haiku-4-5-20251001",
        "ollama": "llama3.1:8b",
    }
    model = model or default_models.get(provider, "")

    try:
        if provider == "openai":
            raw = _call_openai(full_prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "anthropic":
            raw = _call_anthropic(full_prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "ollama":
            raw = _call_ollama(full_prompt, host="http://localhost:11434", model=model, timeout=timeout)
        else:
            return {"error": f"unknown provider: {provider}"}
    except AIError as e:
        return {"error": f"AI provider error: {e}"}
    except Exception as e:
        return {"error": f"unexpected error: {e}"}

    # Strip code fences if the LLM wrapped the JSON
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: return the raw text as the answer
        return {
            "answer": raw[:1500],
            "matching_device_ips": [],
            "suggested_followup": [],
            "action_recommendation": None,
            "_raw_fallback": True,
        }

    return parsed


def bulk_analyze_fleet(fleet: dict, *, provider: str = "openai",
                       api_key: str = "", model: str = "", timeout: int = 90) -> dict:
    """
    One-shot AI analysis covering the entire fleet at once.
    Returns a structured executive summary + cross-device patterns +
    prioritized fleet-wide actions.
    """
    fleet_summary = _summarize_fleet(fleet, max_devices_inline=60)

    prompt = f"""You are a senior network security architect. Analyze this entire fleet at once and respond with VALID JSON ONLY:

{{
  "executive_summary": "3-4 sentences for the CISO — tone is direct, not alarmist",
  "fleet_health_grade": "A | B | C | D | F",
  "cross_device_patterns": [
    {{
      "pattern": "what you observed across multiple devices",
      "affected_devices": ["IP1", "IP2"],
      "recommendation": "what to do about it as a fleet, not per-device"
    }}
  ],
  "prioritized_fleet_actions": [
    {{
      "rank": 1,
      "action": "imperative — fleet-wide step",
      "estimated_impact": "X% risk reduction across N devices",
      "estimated_effort": "minutes | hours | days | weeks"
    }}
  ],
  "anomalies": [
    "things that look unusual or out-of-place across this fleet"
  ],
  "compliance_callouts": "1-2 sentences on the most relevant compliance gap"
}}

FLEET DATA:
{fleet_summary}

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
        return {"error": "AI returned invalid JSON", "raw": raw[:1000]}
