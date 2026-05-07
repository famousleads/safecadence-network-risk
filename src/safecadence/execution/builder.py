"""AI Command Builder — natural language → per-vendor command sets.

Operator types::

    "Check BGP and interface errors on all Cisco routers in DC East"

We:
  1. Parse intent (read-only diagnostic vs config vs remediation).
  2. Pick the matching command pack(s) from the built-in catalog.
  3. Resolve targets (asset_ids, asset_groups, or filter spec).
  4. Render per-vendor commands using the existing translator family.
  5. Return a structured ExecutionPlan that the workflow + executor
     can take through approval and dry-run without further parsing.

Two modes:
  * **offline** (default): rule-based intent matcher. Always works,
    no API key. Covers the ~30 most-common diagnostic + remediation
    intents enterprise operators ask for.
  * **ai**: when the [ai] extra is installed and a provider is
    configured, calls OpenAI/Anthropic/Ollama for richer extraction.
    Falls back to offline silently if the provider call fails.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from safecadence.execution.guardrails import preflight
from safecadence.execution.schema import (
    CommandJob, CommandMode, ExecutionMethod, RiskLevel,
)


# --------------------------------------------------------------------------
# Built-in command catalog — pre-vetted, per-vendor command packs
# --------------------------------------------------------------------------

# Each pack maps vendor → list of commands. The operator never has to
# remember vendor syntax: we offer the common diagnostic / remediation
# intents and translate. New packs go here so the security review for
# "what can SafeCadence make my devices do" stays auditable.
_PACKS: dict[str, dict[str, list[str]]] = {
    "bgp_health": {
        "cisco_ios":     ["show ip bgp summary", "show ip bgp neighbors"],
        "cisco_nxos":    ["show bgp summary", "show bgp neighbors"],
        "arista_eos":    ["show ip bgp summary", "show ip bgp neighbors"],
        "juniper_junos": ["show bgp summary", "show bgp neighbor"],
    },
    "interface_errors": {
        "cisco_ios":     ["show interfaces counters errors",
                          "show interfaces | include error|drop"],
        "cisco_nxos":    ["show interface counters errors"],
        "arista_eos":    ["show interfaces counters errors"],
        "juniper_junos": ["show interfaces extensive | match input"],
        "fortinet_fortios": ["diagnose hardware deviceinfo nic"],
        "linux":         ["ip -s link", "ethtool -S eth0 | grep -i error"],
    },
    "memory_cpu": {
        "cisco_ios":  ["show processes cpu sorted",
                       "show memory statistics"],
        "cisco_nxos": ["show system resources",
                       "show processes cpu sort"],
        "linux":      ["top -bn1 | head -20", "free -h"],
        "windows":    ["Get-Counter '\\Processor(_Total)\\% Processor Time'",
                       "Get-Counter '\\Memory\\Available MBytes'"],
    },
    "version_inventory": {
        "cisco_ios":     ["show version | include uptime|Version|Software"],
        "cisco_nxos":    ["show version"],
        "arista_eos":    ["show version"],
        "juniper_junos": ["show version"],
        "fortinet_fortios": ["get system status"],
        "paloalto_panos": ["show system info"],
        "linux":         ["uname -a", "cat /etc/os-release"],
        "windows":       ["[System.Environment]::OSVersion.VersionString"],
    },
    "logging_check": {
        "cisco_ios":     ["show logging | include host"],
        "cisco_nxos":    ["show logging server"],
        "arista_eos":    ["show logging | include host"],
        "juniper_junos": ["show configuration system syslog"],
        "linux":         ["systemctl status rsyslog",
                          "ss -lnp | grep ':514'"],
    },
    "aaa_health": {
        "cisco_ios":  ["show aaa servers", "show aaa method-lists"],
        "cisco_nxos": ["show aaa authentication", "show tacacs-server"],
    },
    "config_backup": {
        "cisco_ios":  ["copy running-config startup-config"],
        "cisco_nxos": ["copy running-config startup-config"],
        "arista_eos": ["copy running-config startup-config"],
    },
    "uptime": {
        "cisco_ios":  ["show version | include uptime"],
        "linux":      ["uptime"],
        "windows":    ["(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"],
    },
    "interface_status": {
        "cisco_ios":     ["show ip interface brief"],
        "cisco_nxos":    ["show interface brief"],
        "arista_eos":    ["show interfaces status"],
        "juniper_junos": ["show interfaces terse"],
    },
    "kev_inventory": {
        "linux":         ["dpkg -l 2>/dev/null || rpm -qa"],
        "windows":       ["Get-HotFix"],
    },
}


# Plain-English keyword → pack id. Multiple keywords can match; we
# add every matching pack to the plan.
_INTENT_RULES: list[tuple[re.Pattern, str, CommandMode, RiskLevel]] = [
    (re.compile(r"\bbgp\b", re.I),                    "bgp_health",
     CommandMode.DIAGNOSTIC, RiskLevel.SAFE),
    (re.compile(r"\binterface\s*(error|drop|crc)", re.I), "interface_errors",
     CommandMode.DIAGNOSTIC, RiskLevel.SAFE),
    (re.compile(r"\b(cpu|memory|ram)\b", re.I),       "memory_cpu",
     CommandMode.DIAGNOSTIC, RiskLevel.SAFE),
    (re.compile(r"\bversion|software|firmware\b", re.I), "version_inventory",
     CommandMode.READ_ONLY, RiskLevel.SAFE),
    (re.compile(r"\b(syslog|logging|log\s+host)\b", re.I), "logging_check",
     CommandMode.READ_ONLY, RiskLevel.SAFE),
    (re.compile(r"\b(aaa|tacacs|radius)\b", re.I),    "aaa_health",
     CommandMode.READ_ONLY, RiskLevel.SAFE),
    (re.compile(r"\bbackup\s+config|save\s+config\b", re.I), "config_backup",
     CommandMode.CONFIG, RiskLevel.MEDIUM),
    (re.compile(r"\buptime|reboot\s+history\b", re.I),  "uptime",
     CommandMode.READ_ONLY, RiskLevel.SAFE),
    (re.compile(r"\binterface\s*(status|brief|up|down)", re.I),
     "interface_status", CommandMode.READ_ONLY, RiskLevel.SAFE),
    (re.compile(r"\b(patch|vulnerab|kev|cve)\b", re.I), "kev_inventory",
     CommandMode.DIAGNOSTIC, RiskLevel.SAFE),
]


# Vendor keyword detection — drives target filtering when the operator
# says "all Cisco routers" instead of picking an explicit asset group.
_VENDOR_HINTS: dict[str, list[str]] = {
    "cisco":     ["cisco", "ios-xe", "nx-os", "asa"],
    "arista":    ["arista", "eos"],
    "juniper":   ["juniper", "junos"],
    "fortinet":  ["fortinet", "fortigate"],
    "palo-alto": ["palo alto", "panos", "pan-os"],
    "linux":     ["linux", "ubuntu", "rhel", "debian", "centos"],
    "microsoft": ["windows", "server 20"],
    "aws":       ["aws", "ec2", "s3"],
    "azure":     ["azure"],
    "gcp":       ["gcp", "google cloud"],
}


_TYPE_HINTS: dict[str, list[str]] = {
    "network":  ["router", "switch", "firewall"],
    "server":   ["server", "host", "vm"],
    "cloud":    ["cloud", "vpc", "subscription"],
    "identity": ["ad", "okta", "entra", "ldap"],
    "backup":   ["backup", "veeam", "rubrik", "cohesity"],
    "storage":  ["storage", "netapp", "pure"],
}


# --------------------------------------------------------------------------
# Build plan
# --------------------------------------------------------------------------

@dataclass
class ExecutionPlan:
    """Output of the builder — ready to be persisted as a CommandJob."""

    intent: str
    matched_packs: list[str] = field(default_factory=list)
    target_filter: dict[str, Any] = field(default_factory=dict)
    target_asset_ids: list[str] = field(default_factory=list)
    target_asset_group_ids: list[str] = field(default_factory=list)
    commands_by_vendor: dict[str, list[str]] = field(default_factory=dict)
    mode: CommandMode = CommandMode.READ_ONLY
    risk: RiskLevel = RiskLevel.SAFE
    risk_reasons: list[str] = field(default_factory=list)
    blocked: bool = False
    block_reasons: list[str] = field(default_factory=list)
    summary: str = ""
    method: ExecutionMethod = ExecutionMethod.MANUAL


def _detect_vendor_filter(text: str) -> dict[str, Any]:
    text_l = text.lower()
    vendors: list[str] = []
    types: list[str] = []
    for v, hints in _VENDOR_HINTS.items():
        if any(h in text_l for h in hints):
            vendors.append(v)
    for t, hints in _TYPE_HINTS.items():
        if any(h in text_l for h in hints):
            types.append(t)
    if not vendors and not types:
        return {}
    clauses: list[dict] = []
    if vendors:
        clauses.append({"field": "vendor", "op": "in", "value": vendors})
    if types:
        clauses.append({"field": "asset_type", "op": "in", "value": types})
    return {"all": clauses}


# v9.35 #5 — AI fallback. The offline packs cover ~30 well-known
# intents; for everything else, ask the configured BYO-AI provider
# to translate the intent into per-vendor commands. The result still
# goes through the same guardrail preflight + approval workflow as a
# pack-driven plan. AI is a translator, never a bypass.
_AI_BUILDER_SYSTEM_PROMPT = (
    "You are a network operations command translator. Given a "
    "plain-English intent, return ONLY a JSON object mapping vendor "
    "key to a list of CLI commands that accomplish the intent on that "
    "vendor's platform. Vendor keys to use: cisco_ios, cisco_nxos, "
    "arista_eos, juniper_junos, palo_alto, fortinet, hpe_aruba. Use "
    "ONLY commands you are sure exist on that vendor's CLI. Do not "
    "include destructive commands like 'erase startup-config' or "
    "'rm -rf'. Do not include AAA disablement or transport-input "
    "removal. If you can't translate the intent safely, return an "
    "empty JSON object. Do not include any prose, only the JSON. "
    "Example output: "
    '{"cisco_ios": ["show version", "show ip interface brief"]}'
)


def _try_ai_fallback(intent: str,
                       plan: "ExecutionPlan") -> "ExecutionPlan | None":
    """Try the BYO-AI provider when offline packs miss. Returns the
    enriched plan on success, None on any failure. Best-effort:
    failures fall back to the no-match summary upstream."""
    import os as _os
    if _os.environ.get("SC_AI_DISABLED") == "1":
        return None
    try:
        from safecadence.ai.client import (
            AIProvider, detect_provider,
            _call_openai, _call_anthropic, _call_ollama,
        )
    except Exception:
        return None
    provider = detect_provider()
    if provider == AIProvider.NONE:
        return None
    user_prompt = f"Intent: {intent}\n\nReturn the JSON now."
    raw = ""
    try:
        if provider == AIProvider.OPENAI:
            raw = _call_openai(
                user_prompt,
                api_key=_os.environ.get("OPENAI_API_KEY", ""),
                model=_os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                timeout=20,
            )
        elif provider == AIProvider.ANTHROPIC:
            raw = _call_anthropic(
                user_prompt,
                api_key=_os.environ.get("ANTHROPIC_API_KEY", ""),
                model=_os.environ.get("ANTHROPIC_MODEL",
                                         "claude-3-5-sonnet-20241022"),
                timeout=20,
            )
        elif provider == AIProvider.OLLAMA:
            raw = _call_ollama(
                user_prompt,
                host=_os.environ.get("OLLAMA_HOST",
                                       "http://localhost:11434"),
                model=_os.environ.get("OLLAMA_MODEL", "llama3.1"),
                timeout=30,
            )
    except Exception:
        return None
    if not raw:
        return None
    # Extract JSON from the response. The system prompt asks for pure
    # JSON but models occasionally wrap it in code fences.
    import json as _json, re as _re
    raw = raw.strip()
    if raw.startswith("```"):
        m = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, _re.S)
        if m:
            raw = m.group(1)
    try:
        cmds_by_vendor = _json.loads(raw)
    except Exception:
        return None
    if not isinstance(cmds_by_vendor, dict) or not cmds_by_vendor:
        return None
    # Filter out non-list values and empty lists.
    by_vendor: dict[str, list[str]] = {}
    for k, v in cmds_by_vendor.items():
        if isinstance(v, list) and v and all(isinstance(c, str) for c in v):
            by_vendor[str(k).lower()] = [c.strip() for c in v if c.strip()]
    if not by_vendor:
        return None
    # Run the same guardrails the pack-driven path runs.
    plan.commands_by_vendor = by_vendor
    plan.matched_packs = ["ai_fallback"]
    plan.mode = CommandMode.CONFIG
    flat: list[str] = []
    for cmds in by_vendor.values():
        flat.extend(cmds)
    pf = preflight(flat)
    plan.risk = pf.risk
    plan.risk_reasons = pf.reasons
    plan.blocked = pf.blocked
    plan.block_reasons = [r for r in pf.reasons if r.startswith("BLOCKED")]
    plan.summary = (
        f"AI-translated intent ({provider.value}). Produced commands "
        f"for {len(by_vendor)} vendor target(s). "
        f"Risk: {plan.risk.value}. "
        f"{'BLOCKED — review block_reasons.' if plan.blocked else 'Review carefully before approving — AI output is unverified.'}"
    )
    return plan


def build_plan(intent: str, *, asset_ids: list[str] | None = None,
                asset_group_ids: list[str] | None = None,
                target_filter: dict | None = None) -> ExecutionPlan:
    """Translate plain-English intent into a structured ExecutionPlan.

    Targeting precedence:
      explicit asset_ids > asset_group_ids > target_filter override
      > vendor/type sniffed from the intent text.
    """
    intent_l = (intent or "").strip()
    plan = ExecutionPlan(intent=intent_l)

    # 1) Match command packs
    matched: list[str] = []
    for pattern, pack_id, mode, risk in _INTENT_RULES:
        if pattern.search(intent_l):
            matched.append(pack_id)
            # The strictest mode/risk wins for the overall job
            if mode == CommandMode.CONFIG:
                plan.mode = CommandMode.CONFIG
            elif (plan.mode == CommandMode.READ_ONLY
                  and mode == CommandMode.DIAGNOSTIC):
                plan.mode = CommandMode.DIAGNOSTIC
    plan.matched_packs = matched

    if not matched:
        # v9.35 #5 — when offline packs miss, try the BYO-AI provider.
        # Fall back to manual mode if AI is disabled or fails.
        # Trust property: AI suggestions go through the same preflight
        # guardrails + approval workflow as any other job. The AI is
        # a translator, never a bypass.
        ai_plan = _try_ai_fallback(intent_l, plan)
        if ai_plan is not None:
            return ai_plan
        plan.summary = (
            "No built-in command pack matched and AI fallback was "
            "unavailable. Try wording like 'check BGP', 'show "
            "interface errors', 'check version', 'check AAA', or "
            "paste explicit commands instead. Set ANTHROPIC_API_KEY "
            "or OPENAI_API_KEY to enable AI translation."
        )
        return plan

    # 2) Aggregate commands by vendor across all matched packs
    by_vendor: dict[str, list[str]] = {}
    for pack_id in matched:
        for vendor, cmds in _PACKS[pack_id].items():
            by_vendor.setdefault(vendor, []).extend(cmds)
    plan.commands_by_vendor = by_vendor

    # 3) Resolve targeting
    if asset_ids:
        plan.target_asset_ids = list(asset_ids)
    if asset_group_ids:
        plan.target_asset_group_ids = list(asset_group_ids)
    if target_filter is not None:
        plan.target_filter = dict(target_filter)
    elif not (asset_ids or asset_group_ids):
        plan.target_filter = _detect_vendor_filter(intent_l)

    # 4) Run the unified guardrails over every command we'd emit
    flat_cmds: list[str] = []
    for cmds in by_vendor.values():
        flat_cmds.extend(cmds)
    pf = preflight(flat_cmds)
    plan.risk = pf.risk
    plan.risk_reasons = pf.reasons
    plan.blocked = pf.blocked
    plan.block_reasons = [r for r in pf.reasons if r.startswith("BLOCKED")]

    # 5) Method hint — read-only / diagnostic stays MANUAL because the
    #    operator runs them in their own session; CONFIG mode hints SSH
    #    so the Ansible exporter knows what `connection:` to render.
    if plan.mode in (CommandMode.CONFIG, CommandMode.REMEDIATION):
        plan.method = ExecutionMethod.SSH

    plan.summary = (
        f"Matched {len(matched)} command pack{'s' if len(matched)!=1 else ''} "
        f"across {len(by_vendor)} vendor target{'s' if len(by_vendor)!=1 else ''}. "
        f"Risk: {plan.risk.value}. "
        f"{'BLOCKED — see block_reasons.' if plan.blocked else 'OK to submit for review.'}"
    )
    return plan


def plan_to_job(plan: ExecutionPlan, *, name: str = "",
                description: str = "", created_by: str = "",
                tenant: str = "local") -> CommandJob:
    """Turn an ExecutionPlan into a draft CommandJob ready to save."""
    return CommandJob(
        name=name or f"AI: {plan.intent[:60]}",
        description=description or plan.intent,
        mode=plan.mode,
        risk=plan.risk,
        target_asset_ids=list(plan.target_asset_ids),
        target_asset_group_ids=list(plan.target_asset_group_ids),
        target_filter=dict(plan.target_filter),
        inline_commands=dict(plan.commands_by_vendor),
        method=plan.method,
        created_by=created_by,
        tenant=tenant,
    )
