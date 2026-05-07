"""
v9.26 — vendor best-practice config evaluator.

Reads vendor-specific YAML packs (e.g. best_practice_cisco_ios.yaml)
and runs each check against an asset's running config. Returns a list
of (passed, failed, optional-skipped) findings + a credit number that
feeds the Posture Credit half of Safe Score 2.0.

Why YAML packs per vendor instead of one giant file:
  * Each vendor's config syntax is different — section detection
    for `line vty` (Cisco) vs `set system services ssh` (Junos) needs
    vendor-aware logic.
  * Operators can drop in a custom pack for an in-house OS without
    touching the engine.
  * Easier to keep a pack aligned with a moving CIS Benchmark version.

Pack schema (one per vendor; see best_practice_cisco_ios.yaml):
  - id, weight, description, reference, match{...}

The match clause supports four shapes:
  1. ``regex`` — single line in the running config matches.
  2. ``absent_regex`` — pattern must NOT appear (passes when missing).
  3. ``line_regex`` + ``section_regex`` — find a section header (e.g.
     ``^line vty 0 4``), then require ``section_regex`` to match
     somewhere in that section.
  4. ``...`` + ``section_must_not_match`` — additional negative
     constraint inside the same section.

Optional flag: ``optional: true`` means "don't penalize when missing
— this is a context-dependent recommendation."
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Map asset vendor → pack filename. Easy to extend.
_VENDOR_PACKS = {
    "cisco-ios":  "best_practice_cisco_ios.yaml",
    "cisco-iosxe": "best_practice_cisco_ios.yaml",
    "cisco-ios-xe": "best_practice_cisco_ios.yaml",
    "cisco_ios":  "best_practice_cisco_ios.yaml",
    "cisco":      "best_practice_cisco_ios.yaml",
}


@dataclass
class BestPracticeResult:
    asset_id: str
    vendor_key: str
    passed: list[dict] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    skipped_optional: list[dict] = field(default_factory=list)
    credit: int = 0
    max_credit: int = 0

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "vendor_key": self.vendor_key,
            "passed": self.passed,
            "failed": self.failed,
            "skipped_optional": self.skipped_optional,
            "credit": self.credit,
            "max_credit": self.max_credit,
            "compliance_pct": (
                round(100.0 * self.credit / self.max_credit, 1)
                if self.max_credit else 0.0
            ),
        }


# ---------------------------------------------------------- pack loader


_PACK_CACHE: dict[str, list[dict]] = {}


def _data_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data"


def load_pack(vendor_key: str) -> list[dict]:
    key = (vendor_key or "").lower()
    fname = _VENDOR_PACKS.get(key)
    if not fname:
        return []
    if fname in _PACK_CACHE:
        return _PACK_CACHE[fname]
    try:
        import yaml
    except ImportError:                                    # pragma: no cover
        return []
    p = _data_dir() / fname
    if not p.exists():
        _PACK_CACHE[fname] = []
        return []
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    _PACK_CACHE[fname] = raw
    return raw


def supported_vendors() -> list[str]:
    """Vendor keys we ship packs for. Used by the cockpit to decide
    whether to render the 'Best Practice' section at all."""
    return sorted(set(_VENDOR_PACKS.keys()))


# ---------------------------------------------------------- helpers


def _running_config(asset: dict) -> str:
    """Pull the running config text out of the asset's raw_collection.
    The shape is normalized across adapters."""
    raw = asset.get("raw_collection") or {}
    if isinstance(raw, dict):
        for key in ("running", "running_config", "running-config", "config"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                return v
    elif isinstance(raw, str):
        return raw
    return ""


def _vendor_key(asset: dict) -> str:
    ident = asset.get("identity") or {}
    v = (ident.get("vendor") or "").lower().strip()
    family = (ident.get("product_family") or "").lower().strip()
    if "ios" in family or "ios-xe" in family or "iosxe" in family:
        return "cisco-ios"
    if v == "cisco":
        return "cisco-ios"
    return v


def _section_lines(config: str, header_regex: str) -> list[str]:
    """Return lines belonging to a config section that starts with a
    header matching ``header_regex``. Section ends at the next
    non-indented top-level line (Cisco-style 'no leading space' rule).
    """
    if not config:
        return []
    lines = config.splitlines()
    out: list[str] = []
    in_section = False
    pat = re.compile(header_regex, re.MULTILINE)
    for line in lines:
        if pat.search(line):
            in_section = True
            out.append(line)
            continue
        if in_section:
            # End of section: a new top-level (non-indented) line
            # that isn't a comment and isn't blank.
            if line and not line.startswith((" ", "\t", "!")):
                in_section = False
                continue
            out.append(line)
    return out


def _check(rule: dict, config: str) -> bool:
    """Evaluate a single match clause."""
    m = rule.get("match") or {}

    if "absent_regex" in m:
        try:
            return not bool(re.search(m["absent_regex"], config,
                                        re.MULTILINE))
        except re.error:
            return False

    if "line_regex" in m and "section_regex" in m:
        section = "\n".join(_section_lines(config, m["line_regex"]))
        try:
            ok = bool(re.search(m["section_regex"], section,
                                  re.MULTILINE))
        except re.error:
            return False
        if "section_must_not_match" in m:
            try:
                if re.search(m["section_must_not_match"], section,
                                re.MULTILINE):
                    ok = False
            except re.error:
                return False
        return ok

    if "regex" in m:
        try:
            return bool(re.search(m["regex"], config, re.MULTILINE))
        except re.error:
            return False

    return False


# ---------------------------------------------------------- public


def evaluate_asset(asset: dict) -> BestPracticeResult:
    """Run vendor-specific best-practice checks against an asset.

    Returns an empty result (vendor_key=='') if we don't ship a pack
    for the asset's vendor. The cockpit hides the section in that case.
    """
    vk = _vendor_key(asset)
    pack = load_pack(vk)
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ident.get("hostname") or ""
    if not pack:
        return BestPracticeResult(asset_id=aid, vendor_key=vk)

    config = _running_config(asset)
    passed: list[dict] = []
    failed: list[dict] = []
    skipped: list[dict] = []
    credit = 0
    max_credit = 0

    for rule in pack:
        rid = rule.get("id", "")
        weight = int(rule.get("weight", 1))
        is_optional = bool(rule.get("optional", False))
        row = {"id": rid, "weight": weight,
                "description": rule.get("description", rid),
                "reference": rule.get("reference", "")}

        ok = _check(rule, config) if config else False
        if ok:
            passed.append(row)
            credit += weight
            max_credit += weight
        elif is_optional:
            skipped.append(row)
        else:
            failed.append(row)
            max_credit += weight

    return BestPracticeResult(
        asset_id=aid, vendor_key=vk,
        passed=passed, failed=failed, skipped_optional=skipped,
        credit=credit, max_credit=max_credit,
    )
