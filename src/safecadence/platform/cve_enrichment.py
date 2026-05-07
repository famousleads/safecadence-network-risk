"""
Platform CVE auto-matching with KEV + EPSS + exploit-availability prioritization.

Beats Tenable / Qualys default CVE prioritization (which usually just sorts
by CVSS) by combining four signals:

  1. CISA KEV listed   — strongest signal: actively exploited in the wild
  2. EPSS score        — exploitation probability prediction (FIRST.org)
  3. Public exploit    — Exploit-DB or GitHub PoC available
  4. CVSS base score   — traditional severity

The composite priority score prefers KEV-listed CVEs even at moderate CVSS
because real-world exploitation matters more than theoretical severity.

Cross-platform: works on Windows / Linux / macOS. Pure Python. Air-gappable —
EPSS data ships bundled (with refresh_epss() to update).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# EPSS bundle — periodically refreshed; falls back to bundled snapshot.
# --------------------------------------------------------------------------

def _epss_bundle_path() -> Path:
    """User-writable EPSS cache. Falls back to bundled snapshot."""
    p = Path.home() / ".safecadence" / "epss_scores.json"
    if p.exists():
        return p
    # Bundled fallback (empty if not refreshed yet)
    bundled = Path(__file__).resolve().parent.parent / "data" / "epss_scores.json"
    return bundled if bundled.exists() else p


_EPSS_CACHE: dict[str, float] | None = None


def _load_epss() -> dict[str, float]:
    global _EPSS_CACHE
    if _EPSS_CACHE is not None:
        return _EPSS_CACHE
    p = _epss_bundle_path()
    if not p.exists():
        _EPSS_CACHE = {}
        return _EPSS_CACHE
    try:
        _EPSS_CACHE = {k.upper(): float(v) for k, v in
                       json.loads(p.read_text(encoding="utf-8")).items()}
    except Exception:
        _EPSS_CACHE = {}
    return _EPSS_CACHE


def epss_score(cve_id: str) -> float:
    """Return EPSS probability [0,1] for a CVE id, or 0 if unknown."""
    return _load_epss().get(cve_id.upper(), 0.0)


def refresh_epss() -> dict[str, Any]:
    """
    Pull the latest EPSS scores from FIRST.org and write to the local cache.
    Network call — only fires when explicitly invoked.
    Returns {fetched: int, path: str, ok: bool}.
    """
    try:
        import httpx
    except ImportError:
        return {"ok": False, "error": "httpx not installed"}
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        import gzip
        r = httpx.get(url, timeout=60.0)
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        text = gzip.decompress(r.content).decode("utf-8", errors="replace")
    except Exception as e:                    # pragma: no cover — network
        return {"ok": False, "error": str(e)}
    out: dict[str, float] = {}
    for line in text.splitlines():
        # CSV: cve,epss,percentile (skip the model-version comment + header)
        if line.startswith("#") or "cve," in line.lower() or not line.strip():
            continue
        parts = line.split(",")
        if len(parts) < 2: continue
        try:
            out[parts[0].strip().upper()] = float(parts[1])
        except ValueError:
            continue
    p = Path.home() / ".safecadence" / "epss_scores.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    global _EPSS_CACHE
    _EPSS_CACHE = out
    return {"ok": True, "fetched": len(out), "path": str(p)}


# --------------------------------------------------------------------------
# Triple-weighted prioritization — beats CVSS-only ranking
# --------------------------------------------------------------------------

def priority_score(cve: dict) -> float:
    """
    Combined priority score [0, 1000+].

    Weights:
      KEV          → +400  (actively exploited in the wild)
      Public PoC   → +200  (lower bar to attack)
      EPSS * 200   → 0..200 (probability of exploitation in next 30 days)
      CVSS         → 0..10  (traditional severity, normalized)
    """
    s = 0.0
    if cve.get("kev"):
        s += 400
    if cve.get("public_exploit") or cve.get("exploit_db_id") or cve.get("github_poc_url"):
        s += 200
    epss = float(cve.get("epss", cve.get("epss_score", 0)) or 0)
    s += epss * 200
    cvss = float(cve.get("cvss", cve.get("cvss_score", 0)) or 0)
    s += cvss
    return round(s, 2)


def priority_band(score: float) -> str:
    if score >= 600: return "critical"     # KEV + exploit + high EPSS
    if score >= 400: return "high"          # KEV alone OR exploit + medium EPSS
    if score >= 200: return "medium"
    if score >= 50:  return "low"
    return "info"


def enrich_cve(cve: dict) -> dict:
    """Return a copy of the CVE dict with priority_score + band added."""
    out = dict(cve)
    cid = (cve.get("cve_id") or cve.get("id") or "").upper()
    if cid and "epss" not in out:
        out["epss"] = epss_score(cid)
    out["priority_score"] = priority_score(out)
    out["priority_band"] = priority_band(out["priority_score"])
    return out


# --------------------------------------------------------------------------
# Per-asset enrichment
# --------------------------------------------------------------------------

def match_cves_for_asset(asset: dict) -> list[dict]:
    """
    Match every collected platform asset against the bundled CVE DB and
    enrich each match with KEV + EPSS + priority. Returns the sorted list
    (highest priority first).
    """
    try:
        from safecadence.discovery.cve_match import cves_for_device
    except Exception:
        return []
    # cves_for_device works on a discovery-shaped host dict; build that.
    ident = asset.get("identity") or {}
    raw = asset.get("raw_collection") or {}
    discover = raw.get("discover", {}) if isinstance(raw, dict) else {}
    fake_host = {
        "vendor_guess": ident.get("vendor", ""),
        "os_guess": ident.get("product_family") or ((asset.get("os") or {}).get("os_type") or ""),
        "snmp_sysdescr": ((asset.get("os") or {}).get("os_version") or ""),
        "banners": discover.get("banners", {}),
        "open_ports": discover.get("open_ports", []),
    }
    cves = cves_for_device(fake_host) or []
    enriched = [enrich_cve(c) for c in cves]
    enriched.sort(key=lambda c: -c.get("priority_score", 0))
    return enriched


def enrich_asset_with_cves(asset: dict) -> dict:
    """In-place enrich the Security block of a UnifiedAsset dict with CVE data."""
    matches = match_cves_for_asset(asset)
    sec = asset.setdefault("security", {})
    sec["vulnerabilities"] = matches
    sec["critical_cves"] = sum(1 for c in matches if c["priority_band"] == "critical")
    sec["high_cves"] = sum(1 for c in matches if c["priority_band"] == "high")
    sec["kev_cves"] = sum(1 for c in matches if c.get("kev"))
    return asset


def enrich_fleet(assets: list[dict]) -> dict[str, Any]:
    """Bulk-enrich an entire fleet. Returns aggregate counts."""
    total_kev = total_critical = total_high = 0
    enriched_count = 0
    for a in assets:
        enrich_asset_with_cves(a)
        sec = a.get("security") or {}
        total_kev += sec.get("kev_cves", 0)
        total_critical += sec.get("critical_cves", 0)
        total_high += sec.get("high_cves", 0)
        if sec.get("vulnerabilities"):
            enriched_count += 1
    return {
        "asset_count": len(assets),
        "assets_with_cves": enriched_count,
        "total_kev_matches": total_kev,
        "total_critical_priority": total_critical,
        "total_high_priority": total_high,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
