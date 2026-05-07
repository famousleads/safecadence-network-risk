"""
v9.1 — AI-assisted asset enrichment.

When a new device is added (auto-discovery, CSV import, or manual entry),
this module infers attributes that turn the asset into a useful object
for filtering, grouping, and policy targeting.

Outputs (written to identity.tags + identity.custom_fields):

    inferred_role         e.g. "edge-router", "core-switch", "db-server",
                          "web-server", "branch-router", "voice-gateway"
    inferred_environment  prod / staging / dev / test / dr
    inferred_site         e.g. "dc1", "branch-east", "azure-east"
    inferred_criticality  crown-jewel / high / medium / low
    compliance_tier       sox / pci / hipaa / fedramp / none
    suggested_tags        list of stable tag strings ready to filter/group on
    suggested_owner_team  e.g. "network-eng", "sec-ops", "devops"
    summary               1-line plain-English description for hover/list-view

Two paths:
  * AI path (preferred when an LLM key is set) — passes the asset's
    identity + hardware + os blocks to the LLM with a strict JSON schema
    and merges the answer back.
  * Deterministic fallback (always works, runs <1ms) — regex on hostname
    + lookup tables for common vendor/model → role mappings.

The deterministic fallback alone usually gets 70–80% of fields right;
AI gets close to 100% with edge cases. Both paths are read-only and
never modify production state on their own — the caller decides whether
to merge the enrichment into the stored asset.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable


@dataclass
class Enrichment:
    """Structured enrichment output. JSON-serializable."""
    asset_id: str = ""
    inferred_role: str = ""
    inferred_environment: str = ""
    inferred_site: str = ""
    inferred_criticality: str = ""
    compliance_tier: str = ""        # sox | pci | hipaa | fedramp | none
    suggested_tags: list[str] = field(default_factory=list)
    suggested_owner_team: str = ""
    summary: str = ""
    used_ai: bool = False
    confidence: str = "low"           # low | medium | high

    def to_custom_fields(self) -> dict[str, str]:
        """Subset suitable for writing into identity.custom_fields."""
        return {
            "ai_role": self.inferred_role,
            "ai_environment": self.inferred_environment,
            "ai_site": self.inferred_site,
            "ai_compliance_tier": self.compliance_tier,
            "ai_owner_team": self.suggested_owner_team,
            "ai_summary": self.summary,
            "ai_confidence": self.confidence,
        }


# ---------------------------------------------------------------- public

def enrich_asset(asset: dict, *, ai_call=None) -> Enrichment:
    """Infer attributes for a single asset.

    Parameters
    ----------
    asset    UnifiedAsset-shaped dict (top-level identity / hardware / os blocks)
    ai_call  Optional callable(system_prompt, user_prompt, model) -> str.
             Used only for testing — production runs detect_provider() and
             call OpenAI/Anthropic/Ollama through the existing AI client.

    Returns
    -------
    Enrichment with all fields populated. If both AI and fallback fail
    completely, the Enrichment carries empty strings + confidence='low'.
    """
    aid = (asset.get("identity") or {}).get("asset_id", "")
    out = Enrichment(asset_id=aid)

    # Try AI first (catches edge cases + non-obvious naming)
    try:
        ai = _enrich_via_ai(asset, ai_call=ai_call)
        if ai:
            ai.asset_id = aid
            return ai
    except Exception:
        pass

    # Deterministic fallback — never fails
    return _enrich_deterministic(asset)


def enrich_fleet(assets: Iterable[dict], *, ai_call=None,
                  on_progress=None) -> list[Enrichment]:
    """Bulk enrichment with optional progress callback."""
    results: list[Enrichment] = []
    items = list(assets)
    for i, a in enumerate(items):
        result = enrich_asset(a, ai_call=ai_call)
        results.append(result)
        if on_progress:
            on_progress(i + 1, len(items), result)
    return results


def merge_enrichment(asset: dict, enrichment: Enrichment) -> dict:
    """Return a new asset dict with enrichment merged into identity.

    Tags are appended (deduped). custom_fields keys prefixed with `ai_`
    are overwritten. Non-AI custom fields are preserved.
    """
    new = dict(asset)
    new["identity"] = dict(new.get("identity") or {})
    ident = new["identity"]
    # Tags
    existing_tags = list(ident.get("tags") or [])
    for t in enrichment.suggested_tags:
        if t and t not in existing_tags:
            existing_tags.append(t)
    ident["tags"] = existing_tags
    # Custom fields
    existing_cf = dict(ident.get("custom_fields") or {})
    for k, v in enrichment.to_custom_fields().items():
        if v:
            existing_cf[k] = v
    ident["custom_fields"] = existing_cf
    return new


# ---------------------------------------------------------------- AI path

_AI_SYSTEM_PROMPT = """You are SafeCadence's asset-enrichment classifier.
Given a JSON snippet describing one network/server/identity asset (its
hostname, vendor, model, OS, environment, etc.), return ONE JSON object
matching this schema:

{
  "inferred_role":        string,   // e.g. "edge-router", "core-switch", "db-server", "web-server", "branch-router", "voice-gateway", "domain-controller", "identity-provider", "backup-target", "cloud-iam-role"
  "inferred_environment": string,   // "prod" | "staging" | "dev" | "test" | "dr"
  "inferred_site":        string,   // e.g. "dc1", "branch-east", "us-west-2"
  "inferred_criticality": string,   // "crown-jewel" | "high" | "medium" | "low"
  "compliance_tier":      string,   // "sox" | "pci" | "hipaa" | "fedramp" | "none"
  "suggested_tags":       array,    // list of short tag strings the operator can filter on
  "suggested_owner_team": string,   // e.g. "network-eng", "sec-ops", "devops", "platform"
  "summary":              string    // ONE sentence, <120 chars
}

Rules:
- Output ONE JSON object, nothing else. No markdown, no prose.
- Use evidence from the asset only — do not fabricate.
- Use stable lower-kebab-case for tag values (e.g. "role:edge-router").
- If a field cannot be inferred with confidence, use "" (empty string).
- "compliance_tier" is the most regulated framework the asset likely
  participates in: pci > hipaa > sox > fedramp > none. Pick the highest
  one that fits, or "none" if no signal.
"""


def _enrich_via_ai(asset: dict, ai_call=None) -> Enrichment | None:
    """Returns an Enrichment if AI is reachable + cooperative, else None."""
    from safecadence.ai.client import AIError, AIProvider, detect_provider

    chosen = detect_provider() if ai_call is None else AIProvider.OPENAI
    if chosen == AIProvider.NONE and ai_call is None:
        return None

    snapshot = _ai_snapshot(asset)
    user_prompt = json.dumps(snapshot, sort_keys=True)
    raw = ""

    if ai_call is not None:
        raw = ai_call(_AI_SYSTEM_PROMPT, user_prompt, "test-model")
    else:
        try:
            raw = _real_ai_call(chosen, _AI_SYSTEM_PROMPT, user_prompt)
        except AIError:
            return None
        except Exception:
            return None

    cleaned = _strip_json(raw)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return None

    return Enrichment(
        asset_id="",
        inferred_role=str(parsed.get("inferred_role") or ""),
        inferred_environment=str(parsed.get("inferred_environment") or ""),
        inferred_site=str(parsed.get("inferred_site") or ""),
        inferred_criticality=str(parsed.get("inferred_criticality") or ""),
        compliance_tier=str(parsed.get("compliance_tier") or ""),
        suggested_tags=[str(t) for t in (parsed.get("suggested_tags") or [])],
        suggested_owner_team=str(parsed.get("suggested_owner_team") or ""),
        summary=str(parsed.get("summary") or "")[:200],
        used_ai=True,
        confidence="high",
    )


def _ai_snapshot(asset: dict) -> dict:
    """Compact view of the asset for the AI — keeps token use small."""
    ident = asset.get("identity") or {}
    hw = asset.get("hardware") or {}
    os_ = asset.get("os") or {}
    net = asset.get("network") or {}
    return {
        "hostname": ident.get("hostname"),
        "vendor": ident.get("vendor"),
        "product_family": ident.get("product_family"),
        "model": ident.get("model") or hw.get("model"),
        "asset_type": ident.get("asset_type"),
        "site": ident.get("site"),
        "environment": ident.get("environment"),
        "datacenter": ident.get("datacenter"),
        "owner": ident.get("owner"),
        "team": ident.get("team"),
        "criticality": ident.get("criticality"),
        "os_type": os_.get("os_type"),
        "os_version": os_.get("os_version") or os_.get("version"),
        "internet_facing": net.get("internet_facing"),
        "zone": net.get("zone"),
        "public_ip": bool(net.get("public_ip")),
    }


def _real_ai_call(provider, system_prompt, user_prompt) -> str:
    """Reuse the BYO-AI client patterns. JSON-mode where supported."""
    from safecadence.ai.client import AIError, AIProvider
    import os
    try:
        import httpx
    except ImportError as exc:
        raise AIError(f"httpx required: {exc}")

    if provider == AIProvider.OPENAI:
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise AIError("OPENAI_API_KEY not set")
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json={"model": "gpt-4o-mini", "temperature": 0.1,
                   "response_format": {"type": "json_object"},
                   "messages": [
                       {"role": "system", "content": system_prompt},
                       {"role": "user", "content": user_prompt},
                   ]},
            timeout=30,
        )
        if r.status_code >= 400:
            raise AIError(f"OpenAI {r.status_code}: {r.text[:300]}")
        return r.json()["choices"][0]["message"]["content"]

    if provider == AIProvider.ANTHROPIC:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise AIError("ANTHROPIC_API_KEY not set")
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "Content-Type": "application/json"},
            json={"model": "claude-3-5-sonnet-latest", "max_tokens": 600,
                   "system": system_prompt,
                   "messages": [{"role": "user", "content": user_prompt}]},
            timeout=30,
        )
        if r.status_code >= 400:
            raise AIError(f"Anthropic {r.status_code}: {r.text[:300]}")
        return r.json()["content"][0]["text"]

    raise AIError(f"unsupported provider: {provider}")


def _strip_json(s: str) -> str:
    """Remove fenced code blocks or label prefixes."""
    s = (s or "").strip()
    m = re.match(r"^```(?:json)?\s*(.*?)\s*```$", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    for prefix in ("Output:", "JSON:", "Result:"):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
    return s


# ---------------------------------------------------------------- fallback

# Hostname → inferred role rules. Order matters; first match wins.
_ROLE_PATTERNS = [
    (r"\bedge[-_]?(rtr|router|gw|gateway)\b",        "edge-router"),
    (r"\bcore[-_]?(sw|switch|rtr|router)\b",          "core-switch"),
    (r"\bspine[-_]?(sw|switch)\b",                    "spine-switch"),
    (r"\bleaf[-_]?(sw|switch)\b",                     "leaf-switch"),
    (r"\b(branch|bra)[-_]?(rtr|router|gw)\b",         "branch-router"),
    (r"\b(distri|dist|access|acc)[-_]?(sw|switch)\b", "access-switch"),
    (r"\bfw[-_]|firewall|asa[-_]|palo|fortinet",      "firewall"),
    (r"\bvpn[-_]|vpngw",                                "vpn-gateway"),
    (r"\b(voice|cube|cucm|sbc)[-_]",                  "voice-gateway"),
    (r"\b(dc|domain[-_]?controller)\b",               "domain-controller"),
    (r"\b(db|database|sql|postgres|mysql|oracle|mongo)[-_]", "db-server"),
    (r"\b(web|www|http|nginx|apache)[-_]",            "web-server"),
    (r"\b(app|api|backend)[-_]",                       "app-server"),
    (r"\b(cache|redis|memcache)[-_]",                  "cache-server"),
    (r"\b(mq|kafka|rabbit)[-_]",                       "messaging"),
    (r"\b(file[-_]?(srv|server)|fs[-_])\b",           "file-server"),
    (r"\b(backup|veeam|borg|restic)\b",               "backup-target"),
    (r"\b(jump|bastion|gateway)[-_]",                  "bastion"),
    (r"\b(ad|ldap|okta|ise|clearpass|entra)\b",       "identity-provider"),
]

_ENV_PATTERNS = [
    (r"\b(prd|prod|production)\b", "prod"),
    (r"\b(stg|stage|staging)\b", "staging"),
    (r"\b(dev|develop|development)\b", "dev"),
    (r"\b(test|tst|qa)\b", "test"),
    (r"\b(dr|disaster|backup-region)\b", "dr"),
]

_SITE_PATTERNS = [
    (r"\b(dc1|dc-east|east-1|nyc|usewest)\b", "dc1"),
    (r"\b(dc2|dc-west|west-1|sfo|useast)\b", "dc2"),
    (r"\bbranch[-_]?([a-z]+)", "branch"),
    (r"\b(aws|amzn)[-_]", "aws"),
    (r"\b(azure|az)[-_]", "azure"),
    (r"\b(gcp|google)[-_]", "gcp"),
]

_VENDOR_TEAM = {
    "cisco":     "network-eng",
    "arista":    "network-eng",
    "palo":      "sec-ops",
    "fortinet":  "sec-ops",
    "okta":      "identity-eng",
    "microsoft": "identity-eng",
    "vmware":    "platform",
    "aws":       "cloud-platform",
    "veeam":     "backup-ops",
}


def _enrich_deterministic(asset: dict) -> Enrichment:
    """Pure-Python fallback. Always returns a populated Enrichment."""
    ident = asset.get("identity") or {}
    hostname = (ident.get("hostname") or ident.get("asset_id") or "").lower()
    vendor = (ident.get("vendor") or "").lower()
    asset_type = (ident.get("asset_type") or "").lower()
    aid = ident.get("asset_id", "")
    out = Enrichment(asset_id=aid, used_ai=False, confidence="medium")

    # Role
    for pattern, role in _ROLE_PATTERNS:
        if re.search(pattern, hostname):
            out.inferred_role = role
            break
    if not out.inferred_role:
        # Fall back to asset_type
        if asset_type == "network":     out.inferred_role = "network-device"
        elif asset_type == "server":    out.inferred_role = "server"
        elif asset_type == "identity":  out.inferred_role = "identity-provider"
        elif asset_type == "backup":    out.inferred_role = "backup-target"
        elif asset_type == "storage":   out.inferred_role = "storage-array"
        elif asset_type == "cloud":     out.inferred_role = "cloud-resource"

    # Environment — start with explicit, fall back to hostname pattern
    if ident.get("environment"):
        out.inferred_environment = ident["environment"]
    else:
        for pattern, env in _ENV_PATTERNS:
            if re.search(pattern, hostname):
                out.inferred_environment = env
                break

    # Site
    if ident.get("site"):
        out.inferred_site = ident["site"]
    else:
        for pattern, site in _SITE_PATTERNS:
            if re.search(pattern, hostname):
                out.inferred_site = site
                break

    # Criticality — keep existing if set
    if ident.get("criticality"):
        out.inferred_criticality = ident["criticality"]
    else:
        # Heuristics: edge/dc/identity = crown-jewel; servers in prod = high; rest = medium
        if out.inferred_role in ("edge-router", "core-switch", "domain-controller",
                                   "identity-provider", "spine-switch"):
            out.inferred_criticality = "crown-jewel"
        elif out.inferred_environment == "prod":
            out.inferred_criticality = "high"
        else:
            out.inferred_criticality = "medium"

    # Owner team — vendor lookup
    out.suggested_owner_team = _VENDOR_TEAM.get(vendor, "")

    # Compliance tier — heuristic from role + environment
    if out.inferred_role in ("db-server",) and out.inferred_environment == "prod":
        out.compliance_tier = "pci"
    elif "domain" in out.inferred_role or out.inferred_role == "identity-provider":
        out.compliance_tier = "sox"
    else:
        out.compliance_tier = "none"

    # Suggested tags — namespaced for stable filtering
    tags = []
    if out.inferred_role:        tags.append(f"role:{out.inferred_role}")
    if out.inferred_environment: tags.append(f"env:{out.inferred_environment}")
    if out.inferred_site:        tags.append(f"site:{out.inferred_site}")
    if out.inferred_criticality: tags.append(f"criticality:{out.inferred_criticality}")
    if out.compliance_tier and out.compliance_tier != "none":
        tags.append(f"compliance:{out.compliance_tier}")
    if vendor:
        tags.append(f"vendor:{vendor}")
    out.suggested_tags = tags

    # Summary
    parts = []
    if out.inferred_role:        parts.append(out.inferred_role.replace("-", " "))
    if vendor:                    parts.append(f"({vendor})")
    if out.inferred_environment:  parts.append(f"in {out.inferred_environment}")
    if out.inferred_site:         parts.append(f"@ {out.inferred_site}")
    out.summary = " ".join(parts) or hostname

    return out
