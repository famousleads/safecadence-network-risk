"""
Live refresh of CVE/EOL feeds.

Two sources, both free + public:
  - CISA KEV catalog (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
  - endoflife.date REST API per product (https://endoflife.date/api/<product>.json)

For air-gapped sites: download the JSON manually and feed via --kev-file /
--eol-file. The internet path is opt-in (--online).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def _import_httpx():
    try:
        import httpx
        return httpx
    except ImportError as exc:
        raise RuntimeError(
            "Online refresh requires httpx. "
            "Install with: pip install 'safecadence-network-risk[ai]'"
        ) from exc


_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# Map our adapter slugs → (endoflife.date product ID, os value the parser emits)
# The os value MUST match what the adapter's parser writes into ParsedConfig.os,
# otherwise eol_status() lookup fails to match.
_EOL_PRODUCTS = {
    # adapter slug              endoflife.date product   ParsedConfig.os
    "cisco-ios":          ("cisco-ios",                  "ios"),
    "cisco-nxos":         ("cisco-nxos",                 "nxos"),
    "cisco-asa":          ("cisco-asa",                  "asa"),
    "aruba-cx":           ("arubaos-cx",                 "aos-cx"),
    "arista-eos":         ("arista-eos",                 "eos"),
    "juniper-junos":      ("junos",                      "junos"),
    "fortinet-fortigate": ("fortios",                    "fortios"),
    "palo-alto-panos":    ("panos",                      "panos"),
    "vmware-esxi":        ("esxi",                       "esxi"),
    "windows-server":     ("windows-server",             "windows"),
    "linux-server":       ("ubuntu",                     "linux"),
}


def refresh_kev(*, online: bool = False, kev_file: Optional[str] = None,
                cves_dir: Optional[str] = None) -> dict:
    """
    Refresh KEV (Known Exploited Vulnerabilities) flags on the bundled CVE DB.

    online=True   → pull from CISA KEV JSON feed
    kev_file=path → use a previously-downloaded KEV JSON file
    """
    if not (online or kev_file):
        raise ValueError("Pass --online or --kev-file <path>")

    if online:
        httpx = _import_httpx()
        r = httpx.get(_KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
    else:
        data = json.loads(Path(kev_file).read_text(encoding="utf-8"))

    kev_ids = {entry["cveID"] for entry in data.get("vulnerabilities", [])}

    # Walk our bundled CVE files and flag matches
    if cves_dir:
        root = Path(cves_dir)
    else:
        import safecadence
        root = Path(safecadence.__file__).resolve().parent / "data" / "cves"

    import yaml
    flagged = 0
    files_touched = 0
    for f in root.iterdir():
        if f.suffix not in (".yaml", ".yml") or not f.is_file():
            continue
        try:
            items = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except yaml.YAMLError:
            continue
        if not isinstance(items, list):
            continue
        changed = False
        for entry in items:
            if not isinstance(entry, dict) or "cve_id" not in entry:
                continue
            should_be_kev = entry["cve_id"] in kev_ids
            if bool(entry.get("kev")) != should_be_kev:
                entry["kev"] = should_be_kev
                flagged += 1
                changed = True
        if changed:
            f.write_text(yaml.safe_dump(items, sort_keys=False), encoding="utf-8")
            files_touched += 1

    return {
        "kev_total":       len(kev_ids),
        "rules_updated":   flagged,
        "files_touched":   files_touched,
    }


def refresh_eol(*, online: bool = False, eol_dir: Optional[str] = None,
                products: Optional[list] = None) -> dict:
    """
    Refresh end-of-life data from endoflife.date for every product we map.

    online=True → fetch JSON from https://endoflife.date/api/<product>.json
    Otherwise   → no-op (stubbed; v2.2 will support local snapshot import).
    """
    if not online:
        return {"updated": 0, "note": "no-op (pass --online to fetch from endoflife.date)"}

    httpx = _import_httpx()
    if eol_dir:
        out_root = Path(eol_dir)
    else:
        import safecadence
        out_root = Path(safecadence.__file__).resolve().parent / "data" / "eol"
    out_root.mkdir(parents=True, exist_ok=True)

    import yaml
    requested = products or list(_EOL_PRODUCTS)
    updated = 0
    for slug in requested:
        mapping = _EOL_PRODUCTS.get(slug)
        if not mapping:
            continue
        product, os_value = mapping
        url = f"https://endoflife.date/api/{product}.json"
        try:
            r = httpx.get(url, timeout=30)
            if r.status_code != 200:
                continue
            cycles = r.json()
        except Exception:
            continue

        records = []
        for c in cycles:
            cycle = str(c.get("cycle", "")).strip()
            if not cycle:
                continue
            records.append({
                "os":             os_value,           # use the os value the parser emits
                "version_prefix": cycle,
                "end_of_software": str(c.get("support") or c.get("releaseDate") or ""),
                "end_of_support":  str(c.get("eol") or ""),
                "notes":           c.get("latest", "") and f"latest={c.get('latest')}",
            })
        if records:
            target = out_root / (slug.replace("-", "_") + ".yaml")
            target.write_text("---\n" + yaml.safe_dump(records, sort_keys=False),
                              encoding="utf-8")
            updated += 1

    return {"updated": updated, "products": requested}
