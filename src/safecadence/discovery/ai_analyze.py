"""
AI deep-analyze for a discovered device.

Sends the device's full fingerprint to the user's BYO LLM and asks for a
structured analysis: identification, threat model, recommended actions,
compliance impact. Forces JSON-schema output so we can render it cleanly.

Grounding strategy: we tell the LLM to only cite CVE IDs that exist in the
candidate list we provide (no hallucination) and validate every CVE-ID it
returns against our local CVE database before showing it to the user.

BYOK only — same as ai-explain. Key never persisted, never sent to SafeCadence.
"""

from __future__ import annotations

import json
import re
from typing import Any

from safecadence.ai.client import AIError, AIProvider, _call_anthropic, _call_ollama, _call_openai
from safecadence.discovery.cve_match import cves_for_device


_PROMPT_TEMPLATE = """You are a senior network security analyst. Analyze the device below and respond with VALID JSON ONLY (no markdown, no commentary). Use this exact schema:

{{
  "identification": {{
    "vendor": "string",
    "model": "string or null if unknown",
    "device_role": "string — what does this device DO in the network",
    "confidence": "high | medium | low",
    "reasoning": "1-2 sentence explanation of identification"
  }},
  "threat_assessment": {{
    "exposure": "internet | dmz | lan-only | unknown",
    "criticality": "low | medium | high | critical",
    "primary_concerns": ["max 3 short bullet points"]
  }},
  "vulnerabilities": [
    {{
      "cve_id": "must be from candidate list — do NOT invent CVE IDs",
      "why_it_applies": "1 sentence",
      "exploitability": "trivial | requires-auth | requires-position | hard"
    }}
  ],
  "recommended_actions": [
    {{
      "priority": "P0 | P1 | P2",
      "action": "specific imperative — e.g. 'Disable telnet on VTY 0-4 and use SSH only'",
      "command": "exact CLI command if applicable, else null",
      "estimated_effort": "minutes | hours | days"
    }}
  ],
  "compliance_impact": {{
    "frameworks": ["NIST 800-53", "CIS Controls v8", "PCI-DSS", "HIPAA"],
    "affected_controls": ["short identifiers like 'NIST AC-17', 'CIS 4.1', 'PCI 2.3'"]
  }},
  "summary": "2-3 sentence executive summary in plain English for a non-technical reader"
}}

DEVICE FINGERPRINT:
{fingerprint}

CANDIDATE CVES (you may only cite these IDs, or none):
{candidates}

Respond with JSON only. Begin response with {{ and end with }}."""


def _build_fingerprint_block(host: dict) -> str:
    """Format a discovered host into a compact text block for the prompt."""
    lines = [
        f"IP:            {host.get('ip','')}",
        f"Hostname:      {host.get('hostname','—')}",
        f"MAC:           {host.get('mac','—')}",
        f"Vendor:        {host.get('vendor','—')}",
        f"OS guess:      {host.get('os','—')}",
        f"Category:      {host.get('category','—')}",
        f"Open ports:    {', '.join(str(p) for p in host.get('open_ports', [])) or 'none'}",
        f"Risk score:    {host.get('risk_score', 0)}/100 ({host.get('risk_band','safe')})",
    ]
    if host.get("snmp_sysdescr"):
        lines.append(f"SNMP sysDescr: {host['snmp_sysdescr'][:300]}")
    banners = host.get("banners") or {}
    if banners:
        lines.append("Banners:")
        for port, b in list(banners.items())[:6]:
            lines.append(f"  port {port}: {str(b)[:120]}")
    findings = host.get("findings", [])
    if findings:
        lines.append("Existing findings:")
        for f in findings[:5]:
            lines.append(f"  - {f}")
    return "\n".join(lines)


def _build_candidates_block(host: dict) -> str:
    """Build a list of candidate CVEs the LLM may cite (no hallucination)."""
    cves = host.get("cves") or cves_for_device(host)
    if not cves:
        return "(none — vendor/version not identified or no matching CVEs in local DB)"
    lines = []
    for c in cves[:20]:  # cap context window usage
        kev = " [CISA KEV]" if c.get("kev") else ""
        lines.append(
            f"  {c.get('cve_id','?')}{kev}  CVSS={c.get('cvss','?')}  "
            f"{(c.get('title') or '')[:80]}"
        )
    return "\n".join(lines)


def _validate_against_known_cves(returned: list[dict], known_cve_ids: set[str]) -> list[dict]:
    """Strip any CVE IDs the LLM hallucinated."""
    valid = []
    for v in returned:
        cid = v.get("cve_id", "").upper()
        if cid in known_cve_ids:
            valid.append(v)
    return valid


def analyze_device(
    host: dict,
    *,
    provider: str = "openai",
    api_key: str = "",
    model: str = "",
    timeout: int = 60,
) -> dict:
    """
    Analyze a single discovered host with the user's BYO LLM.
    Returns a dict matching the JSON schema above, or {"error": "..."} on failure.
    """
    # Pre-compute candidate CVEs so we can validate the response
    candidate_cves = cves_for_device(host)
    candidate_ids = {c["cve_id"].upper() for c in candidate_cves if c.get("cve_id")}

    # Inject pre-computed candidates into the host dict for the prompt
    if "cves" not in host:
        host = {**host, "cves": candidate_cves}

    fingerprint = _build_fingerprint_block(host)
    candidates = _build_candidates_block(host)
    prompt = _PROMPT_TEMPLATE.format(fingerprint=fingerprint, candidates=candidates)

    # Default models per provider
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

    # Try to extract JSON from the response (LLMs sometimes wrap it in code fences)
    raw = raw.strip()
    if raw.startswith("```"):
        # Strip any ```json or ``` fences
        raw = re.sub(r"^```(?:json)?\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        return {"error": f"AI returned invalid JSON: {e}", "raw": raw[:1000]}

    # Validate cve_ids against known set — drop hallucinations
    if isinstance(parsed.get("vulnerabilities"), list):
        parsed["vulnerabilities"] = _validate_against_known_cves(
            parsed["vulnerabilities"], candidate_ids
        )

    return parsed


def generate_remediation_playbook(
    host: dict,
    *,
    provider: str = "openai",
    api_key: str = "",
    model: str = "",
    timeout: int = 60,
) -> str:
    """
    Generate a step-by-step vendor-specific remediation playbook for a device.
    Returns markdown text suitable for direct copy-paste to a runbook or ticket.
    """
    findings = host.get("findings", [])
    actions = host.get("recommended_actions", [])
    cves = host.get("cves", [])

    finding_lines = "\n".join(f"  - {f}" for f in findings) if findings else "  (none)"
    action_lines = "\n".join(f"  - {a}" for a in actions) if actions else "  (none)"
    cve_lines = "\n".join(
        f"  - {c.get('cve_id')} (CVSS {c.get('cvss')}{'  KEV' if c.get('kev') else ''}): {c.get('title','')}"
        for c in (cves[:10] or [])
    ) or "  (none)"

    prompt = f"""You are a senior network engineer. Write a practical, step-by-step remediation
playbook for the device below. The playbook will be executed by an on-call
engineer — assume they know the basics but need exact commands. Format as
Markdown with:
- A 1-line summary
- Numbered Pre-checks (verify the change won't break anything)
- Numbered Implementation steps with EXACT commands for the device's vendor/OS
- Numbered Verification steps
- Rollback section
- Time estimate

Be specific. If you don't know the exact command for this vendor/OS, say so —
do not invent commands.

DEVICE:
- Vendor: {host.get('vendor','?')}
- OS: {host.get('os','?')}
- IP: {host.get('ip','?')}
- Category: {host.get('category','?')}

FINDINGS TO REMEDIATE:
{finding_lines}

INITIAL RECOMMENDED ACTIONS:
{action_lines}

KNOWN CVES AFFECTING THIS DEVICE:
{cve_lines}

Respond with the Markdown playbook only. No preamble."""

    default_models = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-haiku-4-5-20251001",
        "ollama": "llama3.1:8b",
    }
    model = model or default_models.get(provider, "")

    try:
        if provider == "openai":
            return _call_openai(prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "anthropic":
            return _call_anthropic(prompt, api_key=api_key, model=model, timeout=timeout)
        elif provider == "ollama":
            return _call_ollama(prompt, host="http://localhost:11434", model=model, timeout=timeout)
        else:
            return f"# Error\n\nUnknown provider: {provider}"
    except AIError as e:
        return f"# Error\n\nAI provider error: {e}"
    except Exception as e:
        return f"# Error\n\nUnexpected: {e}"
