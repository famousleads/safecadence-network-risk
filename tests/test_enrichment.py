"""CVE matching + EOL tracking tests."""

from datetime import date

import pytest

from safecadence.enrichment import find_cves, eol_status, load_cve_db, load_eol_db
from safecadence.enrichment.cve import _matches_version


# ---------------------------------------------------------- #
# CVE matcher
# ---------------------------------------------------------- #
class TestVersionMatcher:
    def test_any(self):
        assert _matches_version("any", "15.2.7")
        assert _matches_version("ANY", "anything")

    def test_exact(self):
        assert _matches_version("15.2", "15.2")
        assert not _matches_version("15.2", "15.3")

    def test_glob(self):
        assert _matches_version("15.2.*", "15.2.7")
        assert not _matches_version("15.2.*", "15.3.0")

    def test_range(self):
        assert _matches_version(">=16.0,<17.10", "16.5")
        assert _matches_version(">=16.0,<17.10", "17.9.4")
        assert not _matches_version(">=16.0,<17.10", "17.10")
        assert not _matches_version(">=16.0,<17.10", "15.9")

    def test_range_lt(self):
        assert _matches_version("<9.10", "9.8")
        assert not _matches_version("<9.10", "9.10")


class TestCVELookup:
    def test_db_loads(self):
        db = load_cve_db()
        assert "cisco-ios" in db
        assert "cisco-asa" in db
        assert "cisco-nxos" in db
        assert "aruba-cx" in db
        assert "arista-eos" in db

    def test_known_cisco_ios_cve_matches(self):
        # CVE-2017-3881 affects "any" version of Cisco IOS
        cves = find_cves(vendor="cisco-ios", os="ios", version="15.2")
        assert any(c.cve_id == "CVE-2017-3881" for c in cves)

    def test_ios_xe_specific_cve(self):
        # CVE-2023-20198 affects ios-xe versions 16.0 through <17.10
        cves = find_cves(vendor="cisco-ios", os="ios-xe", version="17.9.3")
        ids = {c.cve_id for c in cves}
        assert "CVE-2023-20198" in ids

    def test_ios_xe_cve_not_for_fixed_version(self):
        # 17.10 is fixed for CVE-2023-20198
        cves = find_cves(vendor="cisco-ios", os="ios-xe", version="17.10")
        ids = {c.cve_id for c in cves}
        assert "CVE-2023-20198" not in ids

    def test_kev_marker_present(self):
        cves = find_cves(vendor="cisco-asa", os="asa", version="9.8")
        assert any(c.kev for c in cves)

    def test_sort_kev_first(self):
        cves = find_cves(vendor="cisco-asa", os="asa", version="9.8")
        kev_first = True
        seen_non_kev = False
        for c in cves:
            if not c.kev:
                seen_non_kev = True
            elif seen_non_kev:
                kev_first = False
        assert kev_first, "KEV-flagged CVEs should sort first"


# ---------------------------------------------------------- #
# EOL lookup
# ---------------------------------------------------------- #
class TestEOL:
    def test_db_loads(self):
        db = load_eol_db()
        assert len(db) > 10
        assert any(r.vendor == "cisco-ios" for r in db)
        assert any(r.vendor == "arista-eos" for r in db)

    def test_eol_for_old_ios(self):
        rec = eol_status(vendor="cisco-ios", os="ios", version="12.4(15)T")
        assert rec is not None
        assert rec.version_prefix == "12.4"
        # 12.4 EoL was 2019, so today (>2019) = end-of-support
        assert rec.status_today() == "end-of-support"

    def test_eol_for_current_iosxe(self):
        rec = eol_status(vendor="cisco-ios", os="ios-xe", version="17.9.4a")
        assert rec is not None
        assert rec.version_prefix == "17.9"
        # 17.9 EOS is 2031; today is 2026 → still supported
        assert rec.status_today() == "supported"

    def test_eol_prefix_match_prefers_longest(self):
        # Both "9.8" and "9.1" exist for asa; 9.8 should win for "9.8(4)"
        rec = eol_status(vendor="cisco-asa", os="asa", version="9.8(4)")
        assert rec.version_prefix == "9.8"

    def test_no_match_for_unknown_vendor(self):
        rec = eol_status(vendor="nonexistent-vendor", os="x", version="1.0")
        assert rec is None
