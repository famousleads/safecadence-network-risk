"""
CVE matching engine.

Loads bundled YAML datasets at safecadence/data/cves/<vendor>.yaml and
matches them to (vendor_slug, os, version). Version matching supports:

  - exact:        "15.2(7)E5"
  - range:        ">=15.0,<15.7"  (semantic-style ranges, vendor-aware)
  - prefix glob:  "15.2.*"
  - "any":        applies to all versions of that os
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml


@dataclass
class CVE:
    """One matched CVE record."""
    cve_id: str                              # "CVE-2023-20269"
    severity: str                            # "critical" | "high" | "medium" | "low"
    cvss: float = 0.0                        # 0.0 - 10.0
    title: str = ""
    description: str = ""
    affected_versions: str = ""              # human-readable range
    fixed_in: str = ""                       # version that ships the fix
    references: list[str] = field(default_factory=list)
    workaround: str = ""
    published: str = ""                      # YYYY-MM-DD
    kev: bool = False                        # in CISA Known-Exploited-Vulnerabilities catalog?

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss": self.cvss,
            "title": self.title,
            "description": self.description,
            "affected_versions": self.affected_versions,
            "fixed_in": self.fixed_in,
            "references": list(self.references),
            "workaround": self.workaround,
            "published": self.published,
            "kev": self.kev,
        }


# ----------------------------------------------------------------- #
# Loader                                                            #
# ----------------------------------------------------------------- #
def _cve_root() -> Path:
    import safecadence
    return Path(safecadence.__file__).resolve().parent / "data" / "cves"


def load_cve_db(vendor: str | None = None) -> dict[str, list[dict]]:
    """
    Load the bundled CVE database. Returns {vendor_slug: [cve_dict, …]}.
    Filtering by vendor (e.g. "cisco-ios") returns only that key.
    """
    root = _cve_root()
    if not root.is_dir():
        return {}
    out: dict[str, list[dict]] = {}
    folder_filter = vendor.replace("-", "_") if vendor else None
    for f in sorted(root.iterdir()):
        if f.suffix not in (".yaml", ".yml") or not f.is_file():
            continue
        slug = f.stem.replace("_", "-")
        if folder_filter and f.stem != folder_filter:
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if isinstance(data, list):
            out[slug] = data
    return out


# ----------------------------------------------------------------- #
# Version matcher                                                   #
# ----------------------------------------------------------------- #
def _version_tuple(v: str) -> tuple:
    """
    Loose version → tuple converter.  '15.2(7)E5' -> (15, 2, 7, 5).
    Used for >= / <= comparisons when versions look numeric.
    """
    if not v:
        return (0,)
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _matches_version(rule: str, actual: str) -> bool:
    """
    Returns True if `actual` falls inside `rule`. Supports:
      - "any"
      - exact equality
      - prefix glob ("15.2.*")
      - range ">=X" / "<=X" / "<X" / ">X" / "==X" combined with commas
    """
    rule = (rule or "").strip().lower()
    actual_low = (actual or "").lower()
    if not rule or rule == "any":
        return True
    if rule == actual_low:
        return True
    if rule.endswith(".*"):
        return actual_low.startswith(rule[:-2])
    # comma-separated multi-condition (AND)
    if any(op in rule for op in (">=", "<=", "<", ">", "==")):
        try:
            actual_t = _version_tuple(actual)
        except Exception:
            return False
        for cond in rule.split(","):
            cond = cond.strip()
            for op in (">=", "<=", "==", ">", "<"):
                if cond.startswith(op):
                    bound = _version_tuple(cond[len(op):].strip())
                    if op == ">="  and not (actual_t >= bound): return False
                    if op == "<="  and not (actual_t <= bound): return False
                    if op == ">"   and not (actual_t >  bound): return False
                    if op == "<"   and not (actual_t <  bound): return False
                    if op == "=="  and not (actual_t == bound): return False
                    break
        return True
    return False


# ----------------------------------------------------------------- #
# Match API                                                         #
# ----------------------------------------------------------------- #
def find_cves(*, vendor: str, os: str = "", version: str = "") -> list[CVE]:
    """
    Return every CVE in the bundled DB that affects the given vendor + os + version.
    """
    db = load_cve_db(vendor=vendor)
    candidates = db.get(vendor, [])
    out: list[CVE] = []
    for raw in candidates:
        if not isinstance(raw, dict) or "cve_id" not in raw:
            continue
        rule_os = (raw.get("os") or "").lower()
        if rule_os and os and rule_os != os.lower():
            continue
        rule_ver = raw.get("affects", "any")
        if not _matches_version(str(rule_ver), version):
            continue
        try:
            out.append(CVE(
                cve_id=str(raw["cve_id"]),
                severity=str(raw.get("severity", "medium")).lower(),
                cvss=float(raw.get("cvss", 0)),
                title=str(raw.get("title", "")),
                description=str(raw.get("description", "")).strip(),
                affected_versions=str(rule_ver),
                fixed_in=str(raw.get("fixed_in", "")),
                references=[str(x) for x in raw.get("references", [])],
                workaround=str(raw.get("workaround", "")).strip(),
                published=str(raw.get("published", "")),
                kev=bool(raw.get("kev", False)),
            ))
        except (TypeError, ValueError):
            continue
    # Sort: KEV first, then CVSS desc
    out.sort(key=lambda c: (-int(c.kev), -c.cvss))
    return out
