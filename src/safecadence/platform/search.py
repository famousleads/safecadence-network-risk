"""
Fleet-wide search.

Single search box that queries the entire UnifiedAsset inventory across
all 6 domains. Supports facet syntax:

    cisco prod                    → free-text + bare keywords
    vendor:cisco env:prod         → exact-match facets
    type:server cve:CVE-2025-9999 → control which fields are searched
    grade:F                       → assets with composite grade F
    kev:true                      → assets carrying KEV-listed CVEs
    site:dc1                      → asset.identity.site / datacenter

Returns ranked results: facet-matches outrank free-text, more-recent
collection wins ties.

Pure Python, no extra deps. Cross-platform.
"""

from __future__ import annotations

import re
from typing import Any


_FACET_RE = re.compile(r"(\w+):([^\s]+)")


def _parse_query(q: str) -> tuple[dict[str, list[str]], list[str]]:
    """Split a query into (facets, free_terms)."""
    facets: dict[str, list[str]] = {}
    free: list[str] = []
    if not q:
        return facets, free
    pos = 0
    for m in _FACET_RE.finditer(q):
        # everything before the match is free text
        free.extend(q[pos:m.start()].split())
        facets.setdefault(m.group(1).lower(), []).append(m.group(2).lower())
        pos = m.end()
    free.extend(q[pos:].split())
    return facets, [f.lower() for f in free if f]


def _matches_facet(asset: dict, facet: str, values: list[str]) -> bool:
    """Return True if any value matches the named facet."""
    ident = asset.get("identity") or {}
    f = facet.lower()
    if f == "vendor":
        return any(v in (ident.get("vendor", "") or "").lower() for v in values)
    if f in ("type", "asset_type"):
        return any(v == (ident.get("asset_type", "") or "").lower() for v in values)
    if f in ("env", "environment"):
        return any(v == (ident.get("environment", "") or "").lower() for v in values)
    if f in ("site", "datacenter", "dc"):
        return any(v in (ident.get("site", "") or ident.get("datacenter", "") or "").lower()
                   for v in values)
    if f == "model":
        return any(v in (ident.get("model", "") or "").lower() for v in values)
    if f in ("hostname", "host", "name"):
        return any(v in (ident.get("hostname", "") or "").lower() for v in values)
    if f == "id":
        return any(v == (ident.get("asset_id", "") or "").lower() for v in values)
    if f == "tag":
        tags = [t.lower() for t in (asset.get("tags") or [])]
        return any(v in tags for v in values)
    if f == "owner":
        return any(v in (ident.get("owner", "") or "").lower() for v in values)
    if f == "criticality":
        return any(v == (ident.get("criticality", "") or "").lower() for v in values)
    if f == "grade":
        g = ((asset.get("health") or {}).get("grade") or "").upper()
        return any(v.upper() == g for v in values)
    if f == "kev":
        wants_kev = any(v in ("true", "yes", "1") for v in values)
        kev_count = (asset.get("security") or {}).get("kev_cves", 0)
        return wants_kev == (kev_count > 0)
    if f == "cve":
        cves = (asset.get("security") or {}).get("vulnerabilities") or []
        ids = " ".join((c.get("cve_id") or c.get("id") or "").lower() for c in cves)
        return any(v in ids for v in values)
    if f == "framework":
        # any policy violation referencing this framework
        sec = asset.get("security") or {}
        viols = sec.get("findings") or []
        joined = " ".join(viols).lower()
        return any(v in joined for v in values)
    # Unknown facet → don't match (avoid false positives)
    return False


def _free_text_score(asset: dict, terms: list[str]) -> int:
    """Count how many free-text terms appear anywhere in the asset's stringified data."""
    if not terms:
        return 0
    blob = ""
    ident = asset.get("identity") or {}
    blob += " ".join(str(v) for v in ident.values())
    if asset.get("os"):
        blob += " " + " ".join(str(v) for v in (asset["os"] or {}).values())
    blob = blob.lower()
    # Plus the raw_collection — bounded to first 4KB to keep search fast
    raw_str = str(asset.get("raw_collection", ""))[:4096].lower()
    return sum(1 for t in terms if t in blob) * 3 + sum(1 for t in terms if t in raw_str)


def search(assets: list[dict], q: str, *, limit: int = 200) -> dict[str, Any]:
    """Run a query against an asset list. Returns {results, facets, count}."""
    facets, free = _parse_query(q or "")
    out: list[tuple[int, dict]] = []
    for a in assets:
        # Every facet must match (AND across facets, OR within values)
        if not all(_matches_facet(a, f, vs) for f, vs in facets.items()):
            continue
        text_score = _free_text_score(a, free)
        # If a query has free terms, require at least one to hit unless facets matched
        if free and text_score == 0 and not facets:
            continue
        # Prioritization: facet match worth a lot, free text adds, KEV count adds
        score = (100 if facets else 0) + text_score
        sec = a.get("security") or {}
        score += sec.get("kev_cves", 0) * 5
        score += sec.get("critical_cves", 0) * 2
        out.append((score, a))
    out.sort(key=lambda t: -t[0])
    return {
        "query": q, "facets": facets, "free_terms": free,
        "count": len(out),
        "results": [{
            "score": s,
            "asset_id": (a.get("identity") or {}).get("asset_id"),
            "vendor": (a.get("identity") or {}).get("vendor"),
            "asset_type": (a.get("identity") or {}).get("asset_type"),
            "hostname": (a.get("identity") or {}).get("hostname"),
            "environment": (a.get("identity") or {}).get("environment"),
            "grade": (a.get("health") or {}).get("grade"),
            "kev_cves": (a.get("security") or {}).get("kev_cves", 0),
            "critical_cves": (a.get("security") or {}).get("critical_cves", 0),
        } for s, a in out[:limit]],
    }
