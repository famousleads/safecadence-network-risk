"""
Enrichment engines: CVE matching + EOL tracking.

Both are 100% local — bundled YAML datasets, no network calls. Update
cadence is per-release; v0.2 will add `safecadence enrich --refresh` to
pull updated NVD/endoflife.date snapshots.
"""

from safecadence.enrichment.cve import CVE, find_cves, load_cve_db
from safecadence.enrichment.eol import EOLRecord, eol_status, load_eol_db
from safecadence.enrichment.refresh import refresh_eol, refresh_kev

__all__ = [
    "CVE", "find_cves", "load_cve_db",
    "EOLRecord", "eol_status", "load_eol_db",
    "refresh_eol", "refresh_kev",
]
