"""
End-of-Life / End-of-Support tracking.

Bundled YAML datasets (see safecadence/data/eol/*.yaml) map vendor + os
+ version-prefix to support dates. Sourced from vendor announcements and
endoflife.date.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml


@dataclass
class EOLRecord:
    """One support-lifecycle record."""
    vendor: str
    os: str
    version_prefix: str           # "15.2", "9.3", "10.10", etc.
    end_of_sale: str = ""         # YYYY-MM-DD
    end_of_software: str = ""     # YYYY-MM-DD — last maintenance release
    end_of_support: str = ""      # YYYY-MM-DD — full last day of support
    notes: str = ""

    def status_today(self, today: date | None = None) -> str:
        """Return one of: supported | end-of-software | end-of-support | unknown."""
        d = today or date.today()
        eos = _parse(self.end_of_support)
        eosw = _parse(self.end_of_software)
        if eos and d >= eos:
            return "end-of-support"
        if eosw and d >= eosw:
            return "end-of-software"
        if eos or eosw or self.end_of_sale:
            return "supported"
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse(s: str) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def _eol_root() -> Path:
    import safecadence
    return Path(safecadence.__file__).resolve().parent / "data" / "eol"


def load_eol_db(vendor: str | None = None) -> list[EOLRecord]:
    """Load all bundled EOL records, optionally filtered by vendor slug."""
    root = _eol_root()
    if not root.is_dir():
        return []
    out: list[EOLRecord] = []
    folder_filter = vendor.replace("-", "_") if vendor else None
    for f in sorted(root.iterdir()):
        if f.suffix not in (".yaml", ".yml") or not f.is_file():
            continue
        if folder_filter and f.stem != folder_filter:
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except (yaml.YAMLError, OSError):
            continue
        slug = f.stem.replace("_", "-")
        for raw in data if isinstance(data, list) else []:
            if not isinstance(raw, dict) or "version_prefix" not in raw:
                continue
            try:
                out.append(EOLRecord(
                    vendor=slug,
                    os=str(raw.get("os", "")),
                    version_prefix=str(raw["version_prefix"]),
                    end_of_sale=str(raw.get("end_of_sale", "") or ""),
                    end_of_software=str(raw.get("end_of_software", "") or ""),
                    end_of_support=str(raw.get("end_of_support", "") or ""),
                    notes=str(raw.get("notes", "")).strip(),
                ))
            except (TypeError, ValueError):
                continue
    return out


def eol_status(*, vendor: str, os: str = "", version: str = "",
               today: date | None = None) -> EOLRecord | None:
    """
    Return the best-matching EOLRecord for (vendor, os, version), or None.
    Picks the longest prefix match (e.g. version='15.2.7' prefers prefix
    '15.2' over '15').
    """
    db = load_eol_db(vendor=vendor)
    candidates = [r for r in db if not os or not r.os or r.os.lower() == os.lower()]
    matches = [
        r for r in candidates
        if version and version.lower().startswith(r.version_prefix.lower())
    ]
    if not matches:
        return None
    matches.sort(key=lambda r: -len(r.version_prefix))
    return matches[0]
