"""
Config audit engine.

Loads YAML rule packs from safecadence/data/rules/<vendor>/*.yaml and applies
them against a ParsedConfig. Three rule types are supported in v0.1:

  match_regex:    "any of these regexes present in raw_config => finding"
  absent_regex:   "none of these regexes present => finding"
  custom:         "Python expression evaluated against parsed (advanced)"

Rule schema (YAML):
  id: cisco-ios-telnet-enabled
  title: Telnet management enabled
  severity: critical | high | medium | low | info
  vendor: cisco-ios | * (any)
  domain: config | security | availability | performance
  description: |
      ...
  remediation: |
      ...
  fix_snippet: |
      no transport input telnet
      transport input ssh
  references:
      - https://...
  match_regex:
      - "(?im)^line\\s+vty[\\s\\S]+?transport\\s+input\\s+(?:.*?\\btelnet\\b)"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from safecadence.core.schema import Finding, ParsedConfig, Severity


# ----------------------------------------------------------------- #
# Compliance auto-tagging — derives NIST 800-53 / CIS / PCI / HIPAA #
# control IDs from the rule's id keywords. Vendor rules don't have  #
# to spell these out; the keyword-based mapper covers ~95%.         #
# ----------------------------------------------------------------- #
_COMPLIANCE_KEYWORDS = (
    # (keyword, NIST 800-53, CIS Benchmark, PCI-DSS v4, HIPAA)
    ("telnet",          ["AC-17", "SC-8"],   ["1.1.1"], ["2.2.4", "2.2.7"], ["164.312(a)(2)(iv)"]),
    ("ssh",             ["AC-17", "IA-2"],   ["1.1.2"], ["2.2.7", "8.3"],   ["164.312(a)(2)(iv)"]),
    ("snmp",            ["AC-17", "SC-8"],   ["3.4.1"], ["2.2.4"],          []),
    ("aaa",             ["IA-2",  "AC-2"],   ["1.4.1"], ["7.1", "8.2"],     ["164.308(a)(4)"]),
    ("password",        ["IA-5"],            ["1.4.2"], ["8.3"],            ["164.308(a)(5)"]),
    ("default-",        ["CM-6", "IA-5"],    ["1.4.4"], ["2.1"],            ["164.308(a)(5)"]),
    ("admin",           ["AC-2", "IA-2"],    ["1.4"],   ["8.2"],            ["164.308(a)(4)"]),
    ("syslog",          ["AU-2", "AU-12"],   ["3.5.1"], ["10.2"],           ["164.312(b)"]),
    ("logging",         ["AU-2", "AU-12"],   ["3.5"],   ["10.2"],           ["164.312(b)"]),
    ("ntp",             ["AU-8"],            ["3.6"],   ["10.4"],           []),
    ("acl",             ["AC-3", "AC-4"],    ["3.3.1"], ["1.2", "1.3"],     ["164.312(a)"]),
    ("management",      ["AC-3", "AC-17"],   ["1.1"],   ["2.2.7"],          ["164.312(a)"]),
    ("http",            ["AC-17", "SC-8"],   ["1.1.4"], ["4.1"],            []),
    ("https",           ["SC-8"],            ["1.1.4"], ["4.1"],            []),
    ("vlan",            ["AC-4", "SC-7"],    ["2.1"],   ["1.2", "1.3"],     []),
    ("bpdu",            ["SC-5"],            ["2.4"],   [],                 []),
    ("dhcp-snoop",      ["SC-7"],            ["2.5"],   [],                 []),
    ("trunk",           ["AC-4"],            ["2.2"],   [],                 []),
    ("cdp",             ["SC-7"],            ["2.6"],   [],                 []),
    ("source-route",    ["SC-7"],            ["3.1"],   [],                 []),
    ("proxy-arp",       ["SC-7"],            ["3.2"],   [],                 []),
    ("redirect",        ["SC-7"],            ["3.3"],   [],                 []),
    ("bootp",           ["CM-7"],            ["3.4"],   [],                 []),
    ("vty",             ["AC-17"],           ["1.1.5"], ["2.2.7"],          []),
    ("console",         ["AC-17"],           ["1.1.6"], [],                 []),
    ("encryption",      ["SC-13"],           [],        ["3.5", "4.1"],     ["164.312(a)(2)(iv)"]),
    ("crypto",          ["SC-13"],           [],        ["4.1"],            ["164.312(e)(1)"]),
    ("vpn",             ["SC-8", "AC-17"],   [],        ["4.1"],            ["164.312(e)(1)"]),
    ("permit-any",      ["AC-3", "AC-4"],    ["3.3"],   ["1.2"],            []),
    ("2fa",             ["IA-2(1)"],         ["1.5"],   ["8.4"],            ["164.308(a)(5)(ii)(D)"]),
    ("mfa",             ["IA-2(1)"],         ["1.5"],   ["8.4"],            ["164.308(a)(5)(ii)(D)"]),
    ("trusthost",       ["AC-3"],            [],        ["1.2"],            []),
    ("port-security",   ["SC-7"],            ["2.4"],   [],                 []),
    ("loop-protect",    ["SC-5"],            ["2.4"],   [],                 []),
    ("storm-control",   ["SC-5"],            [],        [],                 []),
    ("cve-",            ["SI-2"],            ["1.1.7"], ["6.3", "11.3"],    ["164.308(a)(1)(ii)(B)"]),
    ("eol",             ["SA-22"],           [],        ["6.3"],            []),
    ("vty-no-acl",      ["AC-3", "AC-17"],   [],        ["1.2"],            []),
    ("backup",          ["CP-9"],            ["3.7"],   ["12.10"],          ["164.308(a)(7)"]),
    ("archive",         ["AU-9", "CP-9"],    [],        ["10.5"],           []),
    ("banner",          ["AC-8"],            ["1.6"],   [],                 []),
    ("vrf",             ["SC-7"],            [],        [],                 []),
)


def _autotag_compliance(rule_id: str) -> dict:
    """Match a rule id against keyword table → control-ID lists."""
    rid = rule_id.lower()
    nist, cis, pci, hipaa = set(), set(), set(), set()
    for kw, n, c, p, h in _COMPLIANCE_KEYWORDS:
        if kw in rid:
            nist.update(n); cis.update(c); pci.update(p); hipaa.update(h)
    return {
        "nist_800_53":   sorted(nist),
        "cis_benchmark": sorted(cis),
        "pci_dss":       sorted(pci),
        "hipaa":         sorted(hipaa),
    }


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    description: str = ""
    remediation: str = ""
    fix_snippet: str = ""
    references: list[str] = field(default_factory=list)
    vendor: str = "*"
    domain: str = "config"
    match_regex: list[str] = field(default_factory=list)
    absent_regex: list[str] = field(default_factory=list)
    custom: str = ""
    # Compliance — auto-derived from id keywords if not present in YAML
    nist_800_53: list[str] = field(default_factory=list)
    cis_benchmark: list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    hipaa: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        sev_raw = str(d.get("severity", "medium")).lower()
        try:
            sev = Severity(sev_raw)
        except ValueError:
            sev = Severity.MEDIUM
        rid = str(d["id"])
        autotag = _autotag_compliance(rid)
        return cls(
            id=rid,
            title=str(d.get("title", rid)),
            severity=sev,
            description=str(d.get("description", "")).strip(),
            remediation=str(d.get("remediation", "")).strip(),
            fix_snippet=str(d.get("fix_snippet", "")).strip(),
            references=[str(x) for x in d.get("references", [])],
            vendor=str(d.get("vendor", "*")),
            domain=str(d.get("domain", "config")),
            match_regex=[str(x) for x in d.get("match_regex", [])],
            absent_regex=[str(x) for x in d.get("absent_regex", [])],
            custom=str(d.get("custom", "")),
            nist_800_53=[str(x) for x in d.get("nist_800_53") or autotag["nist_800_53"]],
            cis_benchmark=[str(x) for x in d.get("cis_benchmark") or autotag["cis_benchmark"]],
            pci_dss=[str(x) for x in d.get("pci_dss") or autotag["pci_dss"]],
            hipaa=[str(x) for x in d.get("hipaa") or autotag["hipaa"]],
        )


def _rules_root() -> Path:
    """Root directory of the rule packs (sits inside the installed package)."""
    # Package layout: safecadence/data/rules/<vendor>/*.yaml
    import safecadence
    pkg_root = Path(safecadence.__file__).resolve().parent
    return pkg_root / "data" / "rules"


def _iter_rule_files(vendor: str | None = None) -> Iterable[Path]:
    """
    Yield every rule YAML file shipped with the package.

    Vendor folder names use underscores on disk (cisco_ios) but rules carry
    a `vendor` slug with hyphens (cisco-ios). We translate when filtering.
    """
    root = _rules_root()
    if not root.is_dir():
        return
    folder_filter = vendor.replace("-", "_") if vendor else None
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if folder_filter and child.name != folder_filter:
            continue
        for f in sorted(child.iterdir()):
            if f.suffix in (".yaml", ".yml") and f.is_file():
                yield f


def load_rules(vendor: str | None = None) -> list[Rule]:
    """Load every rule applicable to `vendor` (None => all)."""
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for path in _iter_rule_files(vendor):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except Exception:
            continue
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not data:
            continue
        items = data if isinstance(data, list) else [data]
        for raw in items:
            if not isinstance(raw, dict) or "id" not in raw:
                continue
            try:
                rule = Rule.from_dict(raw)
            except Exception:
                continue
            if rule.id in seen_ids:
                continue
            if vendor and rule.vendor not in (vendor, "*"):
                continue
            seen_ids.add(rule.id)
            rules.append(rule)
    return rules


def _evaluate_rule(rule: Rule, parsed: ParsedConfig) -> Finding | None:
    text = parsed.raw_config or ""

    matched_evidence = ""

    if rule.match_regex:
        for pattern in rule.match_regex:
            try:
                m = re.search(pattern, text, re.MULTILINE)
            except re.error:
                continue
            if m:
                evidence = m.group(0)
                if len(evidence) > 200:
                    evidence = evidence[:197] + "..."
                matched_evidence = evidence
                break
        else:
            return None  # no match_regex hit => rule doesn't fire

    if rule.absent_regex:
        for pattern in rule.absent_regex:
            try:
                if re.search(pattern, text, re.MULTILINE):
                    return None  # presence found => rule doesn't fire
            except re.error:
                continue
        if not matched_evidence:
            matched_evidence = "(absent)"

    if rule.custom:
        try:
            namespace = {"parsed": parsed, "text": text, "re": re}
            if not bool(eval(rule.custom, {"__builtins__": {}}, namespace)):  # noqa: S307
                return None
            if not matched_evidence:
                matched_evidence = "(custom)"
        except Exception:
            return None

    if not (rule.match_regex or rule.absent_regex or rule.custom):
        return None

    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        description=rule.description,
        remediation=rule.remediation,
        fix_snippet=rule.fix_snippet,
        references=list(rule.references),
        evidence=matched_evidence,
        domain=rule.domain,
        nist_800_53=list(rule.nist_800_53),
        cis_benchmark=list(rule.cis_benchmark),
        pci_dss=list(rule.pci_dss),
        hipaa=list(rule.hipaa),
    )


@dataclass
class ConfigAuditEngine:
    """Runs a list of rules against a ParsedConfig."""

    vendor: str | None = None
    rules: list[Rule] = field(default_factory=list)

    def __post_init__(self):
        if not self.rules:
            self.rules = load_rules(vendor=self.vendor)

    def run(self, parsed: ParsedConfig) -> list[Finding]:
        out: list[Finding] = []
        for rule in self.rules:
            finding = _evaluate_rule(rule, parsed)
            if finding is not None:
                out.append(finding)
        # stable sort: critical first, then high, then medium, then low, then info
        out.sort(key=lambda f: -f.severity.weight)
        return out
