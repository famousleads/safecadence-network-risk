"""
Plain-English → SecurityPolicy translator.

Two paths:
  1. AI path — uses the existing BYO-AI httpx wiring in safecadence.ai
     to call the user's preferred provider (OpenAI, Anthropic, Ollama).
     Never sends data outside the user's network unless the user
     configured that provider.
  2. Pattern path — keyword matching against the registered control
     library. Always available, runs offline, used when no AI key is
     configured.

Output is a SecurityPolicy with controls and parameters extracted.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from safecadence.policy.controls import all_controls
from safecadence.policy.schema import (
    EnforcementMode, PolicyControl, SecurityPolicy, Severity,
)


# Synonym table — drives the offline pattern matcher and seeds the AI prompt.
_KEYWORDS: dict[str, list[str]] = {
    "disable_telnet":               ["telnet"],
    "enforce_ssh_v2":               ["ssh", "ssh v2", "sshv2", "ssh version 2"],
    "require_aaa":                  ["aaa", "tacacs", "radius"],
    "enforce_snmpv3":               ["snmpv3", "snmp v3", "snmp"],
    "enable_syslog":                ["syslog", "logging", "log forwarding",
                                     "send logs", "logs to ", "ship logs",
                                     "forward logs", "central log"],
    "enable_ntp":                   ["ntp", "time sync", "clock"],
    "block_insecure_crypto":        ["sslv3", "tls 1.0", "tls1.0", "rc4", "des", "md5", "weak crypto"],
    "restrict_management_access":   ["mgmt access", "management access", "vty acl", "ssh acl", "admin cidr"],
    "enforce_patch_level":          ["patch", "patches", "vulnerab", "cve", "update"],
    "enforce_encryption_at_rest":   ["encryption at rest", "rest encryption", "encrypt at rest"],
    "enforce_encryption_in_transit":["encryption in transit", "in-transit encryption", "tls", "https"],
    "restrict_default_creds":       ["default cred", "default password", "default account"],
    "enforce_password_policy":      ["password policy", "password complexity", "password length"],
    "enforce_mfa":                  ["mfa", "2fa", "multi-factor", "multifactor"],
    "enforce_least_privilege":      ["least privilege", "wildcard", "iam:*", "over-privileged"],
    "block_public_exposure":        ["public access", "publicly exposed", "open to internet", "0.0.0.0/0"],
    "enforce_cloud_iam":            ["iam role", "service account", "cloud iam"],
    "enforce_logging":              ["cloudtrail", "audit log", "activity log", "cloud audit"],
    "enforce_backup_retention":     ["backup retention", "retain backups"],
    "enforce_immutability":         ["immutab", "object lock", "worm"],
    "enforce_air_gap":              ["air gap", "offline backup", "tape"],
    "replication_enabled":          ["replicat"],
}


def _extract_parameters(text: str) -> dict[str, Any]:
    """Pull common parameters from the natural-language input."""
    out: dict[str, Any] = {}
    # syslog destination IP
    m = re.search(r"(?:syslog|logs?)\s+(?:to|server|target|host)?\s*(\d+\.\d+\.\d+\.\d+)", text, re.I)
    if m:
        out["syslog_target"] = m.group(1)
    # NTP server
    m = re.search(r"ntp\s+(?:server|host)?\s*([a-z0-9\.\-]+)", text, re.I)
    if m and "." in m.group(1):
        out["ntp_server"] = m.group(1)
    # CIDR
    cidrs = re.findall(r"(\d+\.\d+\.\d+\.\d+/\d{1,2})", text)
    if cidrs:
        out["allowed_cidrs"] = cidrs
    # password length
    m = re.search(r"(?:min|minimum|at least)\s+(\d+)\s*(?:char|character)", text, re.I)
    if m:
        out["min_length"] = int(m.group(1))
    # backup retention days
    m = re.search(r"retain.*?(\d+)\s*day", text, re.I)
    if m:
        out["min_retention_days"] = int(m.group(1))
    # TACACS host
    m = re.search(r"tacacs\s+(?:server|host)?\s*(\d+\.\d+\.\d+\.\d+)", text, re.I)
    if m:
        out["tacacs_host"] = m.group(1)
    return out


def interpret_offline(text: str, *, name: str = "") -> SecurityPolicy:
    """Pattern-match path. Always works, no AI required."""
    text_lower = text.lower()
    matched: list[PolicyControl] = []
    params = _extract_parameters(text)
    spec_by_id = {s.id: s for s in all_controls()}
    for cid, kws in _KEYWORDS.items():
        if any(k in text_lower for k in kws):
            spec = spec_by_id.get(cid)
            if not spec:
                continue
            # Apply only the relevant parameters for this control
            cparams: dict[str, Any] = {}
            for k in ("syslog_target", "ntp_server", "allowed_cidrs",
                      "min_length", "min_retention_days", "tacacs_host"):
                if k in params:
                    cparams[k] = params[k]
            matched.append(PolicyControl(
                control_id=cid, description=spec.description,
                parameters=cparams, severity=spec.severity,
                framework_refs=spec.frameworks,
            ))
    return SecurityPolicy(
        policy_id=f"pol_{uuid.uuid4().hex[:8]}",
        policy_name=name or _derive_name(text),
        description=text.strip(),
        controls=matched,
        severity=Severity.MEDIUM,
        enforcement_mode=EnforcementMode.OBSERVE,
        source="nl",
    )


def _derive_name(text: str) -> str:
    # First few words, title-cased.
    words = re.findall(r"[A-Za-z0-9]+", text)
    return " ".join(words[:4]).title() or "AI-Generated Policy"


def interpret(text: str, *, ai: bool = False, name: str = "",
              provider: str | None = None, api_key: str | None = None,
              model: str | None = None) -> SecurityPolicy:
    """Public entry. If ai=True we attempt the AI path with offline fallback.

    Safety contract: the offline matcher ALWAYS runs as a safety net. The AI
    can ADD controls and refine parameters but it can NEVER drop a control
    the offline matcher would have caught. Hallucinations are bounded to
    "added an extra control" never to "missed a real one".
    """
    if not ai:
        return interpret_offline(text, name=name)
    try:
        return _interpret_ai(text, name=name, provider=provider,
                             api_key=api_key, model=model)
    except Exception:
        return interpret_offline(text, name=name)


def _interpret_ai(text: str, *, name: str = "",
                  provider: str | None = None, api_key: str | None = None,
                  model: str | None = None) -> SecurityPolicy:
    """AI path — calls OpenAI / Anthropic / Ollama via the existing client."""
    # Always start with the offline result — that's our safety net.
    offline = interpret_offline(text, name=name)
    offline_ids = {c.control_id for c in offline.controls}

    # Lazy-import the BYO-AI client (only requires httpx)
    try:
        from safecadence.ai.client import (
            AIProvider, detect_provider, _import_httpx,
            _call_openai, _call_anthropic, _call_ollama,
        )
    except Exception:
        return offline

    # Resolve provider — explicit arg > env auto-detect
    import os
    if provider:
        try: prov = AIProvider(provider.lower())
        except ValueError: return offline
    else:
        prov = detect_provider()
    if prov == AIProvider.NONE:
        return offline

    # Build a JSON-asking prompt that lists our control library
    catalog = "\n".join(f"  - {s.id}: {s.description}" for s in all_controls())
    prompt = (
        "You are a security policy interpreter. Given a plain-English security "
        "intent, output STRICT JSON with this shape:\n"
        '  {"controls": [{"control_id": "...", "parameters": {...}, '
        '"severity": "low|medium|high|critical"}]}\n'
        "Use ONLY control_id values from this catalog (no inventions):\n"
        f"{catalog}\n\n"
        "Common parameters: syslog_target (IPv4), ntp_server, allowed_cidrs (list), "
        "min_length (int), tacacs_host (IPv4), min_retention_days (int).\n"
        f"INPUT:\n{text}\n\n"
        "Respond with the JSON object only. No prose, no markdown fences."
    )

    raw_response = ""
    try:
        if prov == AIProvider.OPENAI:
            key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
            if not key: return offline
            raw_response = _call_openai(prompt, api_key=key,
                                        model=model or "gpt-4o-mini", timeout=30)
        elif prov == AIProvider.ANTHROPIC:
            key = (api_key or os.environ.get("ANTHROPIC_API_KEY", "")).strip()
            if not key: return offline
            raw_response = _call_anthropic(prompt, api_key=key,
                                           model=model or "claude-haiku-4-5-20251001",
                                           timeout=30)
        elif prov == AIProvider.OLLAMA:
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            raw_response = _call_ollama(prompt, host=host,
                                        model=model or "llama3.1", timeout=60)
    except Exception:
        return offline

    # Parse the JSON; tolerate prose wrappers + code fences
    import json
    body = (raw_response or "").strip()
    # strip ```json ... ``` wrappers if the model added them
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", body, flags=re.MULTILINE).strip()
    # extract the first JSON object
    m = re.search(r"\{.*\}", body, re.DOTALL)
    if not m:
        return offline
    try:
        parsed = json.loads(m.group(0))
    except Exception:
        return offline

    spec_by_id = {s.id: s for s in all_controls()}
    sev_map = {s.value: s for s in Severity}
    ai_controls: list[PolicyControl] = []
    for c in parsed.get("controls") or []:
        cid = c.get("control_id")
        spec = spec_by_id.get(cid)
        if not spec:                          # ignore hallucinated control_ids
            continue
        sev = sev_map.get((c.get("severity") or "").lower(), spec.severity)
        params = c.get("parameters") or {}
        if not isinstance(params, dict): params = {}
        ai_controls.append(PolicyControl(
            control_id=cid, description=spec.description,
            parameters=params, severity=sev, framework_refs=spec.frameworks,
        ))

    # Union: keep every offline control (safety net), add any AI-only control
    ai_ids = {c.control_id for c in ai_controls}
    extra = [c for c in ai_controls if c.control_id not in offline_ids]
    # For overlap: prefer AI's parameters (the AI may pull values offline missed)
    overlap_by_id = {c.control_id: c for c in ai_controls if c.control_id in offline_ids}
    merged_controls = []
    for off in offline.controls:
        ai_match = overlap_by_id.get(off.control_id)
        if ai_match and ai_match.parameters:
            merged = PolicyControl(
                control_id=off.control_id, description=off.description,
                parameters={**off.parameters, **ai_match.parameters},
                severity=off.severity, framework_refs=off.framework_refs,
            )
            merged_controls.append(merged)
        else:
            merged_controls.append(off)
    merged_controls.extend(extra)
    offline.controls = merged_controls
    offline.source = f"nl+ai:{prov.value}"
    return offline
