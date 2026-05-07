"""
v9.26 — software currency check.

Compares an asset's running OS/firmware version against the
``data/software_currency.yaml`` reference table and classifies it:

  current          on the recommended version (or newer)
  supported        within the supported window but not on recommended
  behind           older than min_supported
  eol              past end-of-life
  kev_vulnerable   running a version with a known-exploited CVE
  unknown          we don't ship a reference for this vendor/family
                   OR the asset doesn't expose its version

The classification feeds two places:
  * Posture credit  — bumps when status == 'current'
  * Risk            — extra deduction when status in ('eol','kev_vulnerable')

Version comparison is "semver-ish lite" — splits on dots and the first
non-numeric character, compares numeric segments left-to-right. This
handles real-world strings like ``17.12.4``, ``15.9(3)M9``, ``9.20.3``,
``11.1.4-h7``. Vendor schemes that need bespoke ordering get an
explicit ``known_kev_versions`` list as a safety net.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SoftwareCurrencyResult:
    asset_id: str
    vendor_key: str
    running_version: str
    recommended: str
    status: str           # current|supported|behind|eol|kev_vulnerable|unknown
    posture_credit: int   # +N if status == 'current'
    risk_deduction: int   # extra deduction if eol or KEV-vulnerable
    notes: list[str]

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "vendor_key": self.vendor_key,
            "running_version": self.running_version,
            "recommended": self.recommended,
            "status": self.status,
            "posture_credit": self.posture_credit,
            "risk_deduction": self.risk_deduction,
            "notes": self.notes,
        }


# ---------------------------------------------------------- pack loader


_PACK: dict | None = None


def _data_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / \
        "software_currency.yaml"


def load_pack(force: bool = False) -> dict:
    global _PACK
    if _PACK is not None and not force:
        return _PACK
    try:
        import yaml
    except ImportError:                                   # pragma: no cover
        _PACK = {}
        return _PACK
    p = _data_path()
    if not p.exists():
        _PACK = {}
        return _PACK
    _PACK = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return _PACK


# ---------------------------------------------------------- helpers


_SEG_RE = re.compile(r"(\d+)")


def _normalize_version(v: str) -> tuple[int, ...]:
    """Extract a comparable numeric tuple from a version string.

    Examples:
      '17.12.4'      -> (17, 12, 4)
      '15.9(3)M9'    -> (15, 9, 3, 9)
      '11.1.4-h7'    -> (11, 1, 4, 7)
      '7.4.4'        -> (7, 4, 4)
    """
    nums = [int(x) for x in _SEG_RE.findall(v or "")]
    return tuple(nums)


def _cmp(a: str, b: str) -> int:
    """Return -1/0/1 like cmp() based on normalized versions.

    Pads the shorter tuple with zeros so '17.12' and '17.12.0' compare
    equal. Empty strings sort lowest.
    """
    ta, tb = _normalize_version(a), _normalize_version(b)
    n = max(len(ta), len(tb))
    pa = ta + (0,) * (n - len(ta))
    pb = tb + (0,) * (n - len(tb))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def _in_train_or_below(running: str, train_marker: str) -> bool:
    """Compare on major.minor only — matches "16.6.1 is in the 16.6 train".

    Used for the EOL check: an `eol: "16.6"` entry means *the entire
    16.6 train and below*. Without this, a literal compare puts 16.6.1
    > 16.6 and we miss the EOL.
    """
    rt = _normalize_version(running)[:2]
    mt = _normalize_version(train_marker)[:2]
    n = max(len(rt), len(mt))
    pa = rt + (0,) * (n - len(rt))
    pb = mt + (0,) * (n - len(mt))
    return pa <= pb


def _vendor_key_for(asset: dict) -> str:
    """Match an asset to a vendor key in the pack.

    Looks at identity.product_family first (e.g. "Cisco IOS XE Software"),
    then falls back to identity.vendor + asset_type heuristics.
    """
    ident = asset.get("identity") or {}
    family = (ident.get("product_family") or "").strip()
    vendor = (ident.get("vendor") or "").strip().lower()

    # Score every product_family entry by match-length so a long,
    # specific match like "Cisco IOS XE Software" wins over the
    # short, ambiguous "Cisco IOS" prefix. Without this, IOS-XE
    # devices get classified as plain IOS.
    pack = load_pack()
    best_key, best_len = "", 0
    fam_lower = family.lower()
    for key, entry in pack.items():
        for fam in entry.get("product_families", []) or []:
            f = (fam or "").lower()
            if not f:
                continue
            if f == vendor and best_len == 0:
                best_key = key   # weak match — keep looking for a stronger one
                continue
            if family and f in fam_lower and len(f) > best_len:
                best_key, best_len = key, len(f)
    if best_key:
        return best_key

    # Fallback heuristics
    if vendor == "cisco":
        if "asa" in family.lower(): return "cisco-asa"
        if "nx" in family.lower(): return "cisco-nxos"
        if "xe" in family.lower(): return "cisco-ios-xe"
        return "cisco-ios"
    if vendor == "juniper": return "juniper-junos"
    if vendor == "arista": return "arista-eos"
    if vendor in ("palo alto", "paloalto", "palo-alto"): return "paloalto-panos"
    if vendor == "fortinet": return "fortinet-fortios"
    if vendor == "aruba" and "cx" in family.lower(): return "aruba-aoscx"
    return ""


def _running_version(asset: dict) -> str:
    """Pull running OS / firmware version from the asset.

    Adapters store version under varied keys; we check the most common
    locations.
    """
    os_ = asset.get("os") or {}
    for k in ("version", "os_version", "running_version", "firmware_version"):
        if os_.get(k):
            return str(os_[k])
    hw = asset.get("hardware") or {}
    if hw.get("firmware_version"):
        return str(hw["firmware_version"])
    ident = asset.get("identity") or {}
    if ident.get("version"):
        return str(ident["version"])
    return ""


# ---------------------------------------------------------- public


def evaluate_asset(asset: dict) -> SoftwareCurrencyResult:
    """Classify an asset's running version against the reference table."""
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ident.get("hostname") or ""

    vk = _vendor_key_for(asset)
    pack = load_pack()
    entry = pack.get(vk) if vk else None
    running = _running_version(asset)

    if not vk or not entry:
        return SoftwareCurrencyResult(
            asset_id=aid, vendor_key=vk, running_version=running,
            recommended="", status="unknown", posture_credit=0,
            risk_deduction=0,
            notes=["No software-currency reference for this vendor."],
        )

    if not running:
        return SoftwareCurrencyResult(
            asset_id=aid, vendor_key=vk, running_version="",
            recommended=entry.get("recommended", ""),
            status="unknown", posture_credit=0, risk_deduction=0,
            notes=["Asset doesn't expose a version string yet."],
        )

    # KEV check first — strongest signal.
    kev_versions = entry.get("known_kev_versions") or []
    for kv in kev_versions:
        try:
            if re.match(rf"^{re.escape(kv)}", running):
                return SoftwareCurrencyResult(
                    asset_id=aid, vendor_key=vk,
                    running_version=running,
                    recommended=entry.get("recommended", ""),
                    status="kev_vulnerable",
                    posture_credit=0,
                    risk_deduction=12,
                    notes=[f"Version {running} matches a CISA KEV entry — "
                           f"upgrade is the highest-priority action."],
                )
        except re.error:
            continue

    rec = entry.get("recommended", "")
    minsup = entry.get("min_supported", "")
    eol = entry.get("eol", "")

    notes: list[str] = []
    status = "supported"
    posture = 0
    risk = 0

    if eol and _in_train_or_below(running, eol):
        status = "eol"
        risk = 8
        notes.append(f"{running} is in the {eol} train (vendor EOL).")
    elif minsup and _cmp(running, minsup) < 0:
        status = "behind"
        risk = 4
        notes.append(f"{running} is older than the supported floor ({minsup}).")
    elif rec and _cmp(running, rec) >= 0:
        status = "current"
        posture = 5
        notes.append(f"{running} is at or newer than recommended ({rec}).")
    else:
        notes.append(
            f"{running} is in the supported window (recommended {rec}).")

    return SoftwareCurrencyResult(
        asset_id=aid, vendor_key=vk, running_version=running,
        recommended=rec, status=status,
        posture_credit=posture, risk_deduction=risk, notes=notes,
    )
