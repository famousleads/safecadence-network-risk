"""
Natural-language query (v11.0).

Pattern-based parser that turns English questions into filter dicts
against the platform_assets / findings store. When ``OPENAI_API_KEY``
or ``ANTHROPIC_API_KEY`` is set, queries that don't match any rule
get a second pass through the LLM (which is asked to return *only*
the same filter-dict shape). LLM is a strict enhancement — the base
parser ships everything it needs to be useful on its own.

Filter dict shape (open-ended; consumers ignore unknown keys):

    {
      "public_exposure": bool,
      "kev": bool,
      "eol": bool,
      "mfa_missing": bool,
      "cvss_min": float,
      "cvss_max": float,
      "severity_min": "low|medium|high|critical",
      "asset_type": str,
      "site": str,
      "vendor": str,
      "criticality": str,
      "tag": str,
      "hostname_contains": str,
    }
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from typing import Any


# --------------------------------------------------------------------------
# Dataclass
# --------------------------------------------------------------------------


@dataclasses.dataclass
class ParsedQuery:
    text: str
    filter: dict
    matched_patterns: list[str]
    source: str  # "rules" | "llm" | "parse_failed"
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "filter": self.filter,
            "matched_patterns": self.matched_patterns,
            "source": self.source,
            "note": self.note,
        }


# --------------------------------------------------------------------------
# Rule-based parser
# --------------------------------------------------------------------------


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _add(filt: dict, key: str, val, matched: list[str], name: str) -> None:
    filt[key] = val
    matched.append(name)


def _parse_rules(text: str) -> tuple[dict, list[str]]:
    t = (text or "").lower().strip()
    filt: dict = {}
    matched: list[str] = []
    if not t:
        return filt, matched

    # public exposure
    if re.search(r"\b(internet[- ]facing|public(ly)?[- ]exposed|publicly accessible|exposed to (the )?internet)\b", t):
        _add(filt, "public_exposure", True, matched, "public_exposure")

    # KEV
    if re.search(r"\bkev\b", t) or "known exploited" in t:
        _add(filt, "kev", True, matched, "kev")

    # EOL
    if re.search(r"\b(eol|end[- ]of[- ]life|end of life|unsupported)\b", t):
        _add(filt, "eol", True, matched, "eol")

    # MFA
    if re.search(r"\b(missing mfa|no mfa|mfa[- ]?(missing|disabled|off))\b", t):
        _add(filt, "mfa_missing", True, matched, "mfa_missing")
    elif "without mfa" in t:
        _add(filt, "mfa_missing", True, matched, "mfa_missing")

    # CVSS over/under — accept both orderings:
    #   "cvss over 8" / "cvss >= 8"
    #   "over cvss 8" / "above cvss 8"
    m = re.search(
        r"\bcvss\s*(?:>=|over|above|>|greater than)\s*([0-9]+(?:\.[0-9]+)?)\b",
        t,
    )
    if not m:
        m = re.search(
            r"\b(?:over|above|greater than|>=|>)\s*cvss\s*([0-9]+(?:\.[0-9]+)?)\b",
            t,
        )
    if m:
        _add(filt, "cvss_min", float(m.group(1)), matched, "cvss_min")
    m = re.search(
        r"\bcvss\s*(?:<=|under|below|<|less than)\s*([0-9]+(?:\.[0-9]+)?)\b",
        t,
    )
    if not m:
        m = re.search(
            r"\b(?:under|below|less than|<=|<)\s*cvss\s*([0-9]+(?:\.[0-9]+)?)\b",
            t,
        )
    if m:
        _add(filt, "cvss_max", float(m.group(1)), matched, "cvss_max")

    # severity threshold
    m = re.search(
        r"\b(critical|high|medium|low)(?:\s+severity)?\s+(or above|or higher|and above|plus)\b",
        t,
    )
    if m:
        _add(filt, "severity_min", m.group(1), matched, "severity_min")
    elif re.search(r"\bcritical (cves?|vulns?|findings?|severity)\b", t):
        _add(filt, "severity_min", "critical", matched, "severity_min")
    elif re.search(r"\bhigh[- ]severity\b", t):
        _add(filt, "severity_min", "high", matched, "severity_min")
    elif re.search(r"\bhigh\s+severity\b", t):
        _add(filt, "severity_min", "high", matched, "severity_min")

    # asset type
    for kw, val in [
        ("server", "server"),
        ("workstation", "workstation"),
        ("laptop", "workstation"),
        ("firewall", "firewall"),
        ("switch", "switch"),
        ("router", "router"),
        ("load balancer", "load_balancer"),
        ("access point", "wireless_ap"),
        ("printer", "printer"),
        ("iot", "iot"),
        ("camera", "camera"),
    ]:
        if re.search(rf"\b{re.escape(kw)}s?\b", t):
            _add(filt, "asset_type", val, matched, "asset_type")
            break

    # site / location ("in dc-east-1", "at site hq")
    m = re.search(r"\b(?:in|at)\s+(?:site\s+)?([a-z0-9][a-z0-9_\-]{1,40})\b", t)
    if m:
        candidate = m.group(1)
        # Filter false positives like "in the", "in this"
        if candidate not in {
            "the",
            "this",
            "that",
            "our",
            "all",
            "any",
            "us",
            "use",
            "with",
        }:
            _add(filt, "site", candidate, matched, "site")

    # vendor
    for v in [
        "cisco",
        "arista",
        "juniper",
        "aruba",
        "palo alto",
        "fortinet",
        "checkpoint",
        "microsoft",
        "vmware",
        "ubiquiti",
        "meraki",
        "dell",
        "hp",
    ]:
        if re.search(rf"\b{re.escape(v)}\b", t):
            _add(filt, "vendor", v, matched, "vendor")
            break

    # criticality
    for c in ["crown jewel", "tier 1", "tier 2", "tier 3"]:
        if c in t:
            _add(filt, "criticality", c.replace(" ", "_"), matched, "criticality")
            break

    # hostname contains
    m = re.search(r"\bhost(?:name)?\s+(?:contains|matching|like)\s+['\"]?([a-z0-9_\-\.]+)['\"]?", t)
    if m:
        _add(filt, "hostname_contains", m.group(1), matched, "hostname_contains")

    # tag
    m = re.search(r"\btag(?:ged)?\s+(?:as\s+)?['\"]?([a-z0-9_\-]+)['\"]?", t)
    if m:
        _add(filt, "tag", m.group(1), matched, "tag")

    return filt, matched


# --------------------------------------------------------------------------
# Optional LLM enhancement
# --------------------------------------------------------------------------


def _llm_available() -> bool:
    return bool(
        os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    )


def _llm_parse(text: str) -> dict | None:
    """Ask an LLM to return a filter dict. Best-effort; returns None on any error."""
    try:
        # Use the existing safecadence.ai.client if available.
        from safecadence.ai import client as ai_client

        prompt = (
            "Convert this natural-language query into a JSON filter dict for a "
            "security asset inventory. Allowed keys: public_exposure (bool), "
            "kev (bool), eol (bool), mfa_missing (bool), cvss_min (float), "
            "cvss_max (float), severity_min (one of info/low/medium/high/critical), "
            "asset_type (string), site (string), vendor (string), criticality "
            "(string), tag (string), hostname_contains (string). "
            f"Return ONLY a JSON object, no prose.\n\nQuery: {text}"
        )
        # We don't depend on a specific client signature — try a few.
        for name in ("complete", "chat", "ask"):
            fn = getattr(ai_client, name, None)
            if callable(fn):
                try:
                    raw = fn(prompt)
                except Exception:
                    continue
                if isinstance(raw, dict) and "text" in raw:
                    raw = raw["text"]
                if not isinstance(raw, str):
                    continue
                m = re.search(r"\{.*\}", raw, re.DOTALL)
                if not m:
                    continue
                try:
                    parsed = json.loads(m.group(0))
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    return parsed
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def parse_query(text: str) -> ParsedQuery:
    """Parse a natural-language query into a structured filter.

    Returns a :class:`ParsedQuery`. ``source`` indicates which engine
    answered (``"rules"`` | ``"llm"`` | ``"parse_failed"``).
    """
    text = (text or "").strip()
    if not text:
        return ParsedQuery(text="", filter={}, matched_patterns=[], source="parse_failed", note="empty query")
    filt, matched = _parse_rules(text)
    if matched:
        return ParsedQuery(text=text, filter=filt, matched_patterns=matched, source="rules")
    if _llm_available():
        llm = _llm_parse(text)
        if llm:
            return ParsedQuery(
                text=text,
                filter=llm,
                matched_patterns=["llm"],
                source="llm",
            )
    return ParsedQuery(
        text=text,
        filter={},
        matched_patterns=[],
        source="parse_failed",
        note="No rules matched and no LLM key configured (OPENAI_API_KEY / ANTHROPIC_API_KEY).",
    )


# --------------------------------------------------------------------------
# Execute
# --------------------------------------------------------------------------


def _asset_field(asset: dict, key: str, default: Any = "") -> Any:
    ident = asset.get("identity") or {}
    return ident.get(key) or asset.get(key, default)


def _asset_matches(asset: dict, filt: dict) -> bool:
    if not filt:
        return True
    if filt.get("public_exposure") and not (
        asset.get("public_exposure") or _asset_field(asset, "public_exposure")
    ):
        return False
    if filt.get("eol") and not (asset.get("eol") or _asset_field(asset, "eol")):
        return False
    if filt.get("mfa_missing") and not (
        asset.get("mfa_missing") or _asset_field(asset, "mfa_missing")
    ):
        return False
    if filt.get("asset_type"):
        if (str(_asset_field(asset, "asset_type")).lower() != str(filt["asset_type"]).lower()):
            return False
    if filt.get("site"):
        if str(_asset_field(asset, "site")).lower() != str(filt["site"]).lower():
            return False
    if filt.get("vendor"):
        if str(_asset_field(asset, "vendor")).lower() != str(filt["vendor"]).lower():
            return False
    if filt.get("criticality"):
        if (
            str(_asset_field(asset, "criticality")).lower()
            != str(filt["criticality"]).lower()
        ):
            return False
    if filt.get("hostname_contains"):
        sub = str(filt["hostname_contains"]).lower()
        host = str(_asset_field(asset, "hostname")).lower()
        if sub not in host:
            return False
    if filt.get("tag"):
        tags = asset.get("tags") or _asset_field(asset, "tags") or []
        if filt["tag"] not in tags:
            return False
    # CVSS / KEV / severity filter against this asset's CVEs
    cves = asset.get("cves") or asset.get("vulnerabilities") or []
    if filt.get("kev"):
        if not any(c.get("kev") for c in cves if isinstance(c, dict)):
            return False
    if "cvss_min" in filt:
        thresh = float(filt["cvss_min"])
        if not any(
            float(c.get("cvss") or c.get("cvss_score") or 0) >= thresh
            for c in cves
            if isinstance(c, dict)
        ):
            return False
    if "cvss_max" in filt:
        thresh = float(filt["cvss_max"])
        if not any(
            float(c.get("cvss") or c.get("cvss_score") or 0) <= thresh
            for c in cves
            if isinstance(c, dict)
        ):
            return False
    if filt.get("severity_min"):
        try:
            mn = _SEVERITY_ORDER.index(str(filt["severity_min"]).lower())
        except ValueError:
            mn = 0
        sevs = [
            _SEVERITY_ORDER.index(str(c.get("severity") or "low").lower())
            if (str(c.get("severity") or "").lower() in _SEVERITY_ORDER)
            else 0
            for c in cves
            if isinstance(c, dict)
        ]
        if not any(s >= mn for s in sevs):
            return False
    return True


def execute_query(
    parsed: ParsedQuery,
    store=None,
    org_id: str | None = None,
) -> list[dict]:
    """Run ``parsed`` against the asset store.

    ``store`` may be a list of asset dicts (test injection). When None,
    reads from the org's ``platform_assets/*.json``.
    """
    if parsed.source == "parse_failed":
        return []
    assets: list[dict] = []
    if isinstance(store, list):
        assets = store
    else:
        try:
            from safecadence.storage.org_store import org_data_dir

            base = (
                (org_data_dir(org_id) if org_id else None)
                or _default_base()
            ) / "platform_assets"
        except Exception:
            base = _default_base() / "platform_assets"
        if base.exists():
            for f in base.glob("*.json"):
                try:
                    assets.append(json.loads(f.read_text(encoding="utf-8")))
                except Exception:
                    continue
    return [a for a in assets if _asset_matches(a, parsed.filter)]


def _default_base():
    from pathlib import Path

    root = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME")
    return Path(root) if root else Path.home() / ".safecadence"


__all__ = ["ParsedQuery", "parse_query", "execute_query"]
