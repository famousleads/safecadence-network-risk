"""
v9.7 — Asset deduplication across discovery sources.

Take asset records from N sources (LAN scan, SNMP harvest, AD, Entra,
DHCP, AWS, Azure, GCP, manual) and produce ONE canonical record per
real device with a sources[] list of provenance.

Match cascade:
  1. MAC address — most reliable (L2 identity)
  2. Management IP — second-best (assuming DHCP doesn't shuffle)
  3. Hostname (case-insensitive, with FQDN/short-form normalization)
  4. Asset ID

Every match record carries `match_reason` so the operator can audit why
two records were collapsed (or why two near-identical records weren't).

Shadow-IT detection:
  Anything seen by an active source (LAN scan, SNMP) but missing from a
  declarative source (AD, CMDB, Entra) is flagged. Useful for catching
  rogue devices, unmanaged BYOD, and forgotten lab gear.

The `merge_asset_groups` function is intentionally deterministic — AI
is not needed for the matching itself. AI gets used to *summarize* the
result in plain English (`describe_dedup_result`) so an operator can
glance at the page and understand what happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional


# ----------------------------------------------------------- types

@dataclass
class CanonicalAsset:
    """One real device, possibly seen by multiple sources."""
    asset_id: str                  # canonical (chosen from inputs)
    hostname: str = ""
    mac: str = ""
    primary_ip: str = ""
    asset_type: str = ""
    vendor: str = ""
    sources: list[str] = field(default_factory=list)   # ['lan', 'ad', 'aws']
    match_reasons: list[str] = field(default_factory=list)
    raw_inputs: list[dict] = field(default_factory=list)


@dataclass
class DedupResult:
    canonical: list[CanonicalAsset] = field(default_factory=list)
    shadow_it: list[CanonicalAsset] = field(default_factory=list)
    counts_by_source: dict[str, int] = field(default_factory=dict)
    summary_text: str = ""


# ----------------------------------------------------- normalizers

def _norm_mac(s: str) -> str:
    """Lowercase, drop separators. '00:11:22:33:44:55' → '001122334455'."""
    if not s:
        return ""
    return "".join(c for c in s.lower() if c in "0123456789abcdef")


def _norm_host(s: str) -> str:
    """Lowercase, strip domain and trailing dot. 'PC-01.acme.local' → 'pc-01'."""
    if not s:
        return ""
    s = s.strip().rstrip(".").lower()
    return s.split(".")[0]


def _pick_primary_ip(record: dict) -> str:
    """Prefer mgmt_ip → public_ip → private_ip → ip → first interface."""
    ident = record.get("identity") or record
    for k in ("mgmt_ip", "primary_ip", "public_ip", "private_ip", "ip"):
        v = ident.get(k) if isinstance(ident, dict) else None
        if v:
            return str(v)
    # Try interfaces[]
    ifaces = record.get("interfaces") if isinstance(record, dict) else None
    for i in (ifaces or []):
        v = i.get("ip_address") or i.get("ip")
        if v:
            return str(v)
    return ""


def _extract_keys(record: dict) -> tuple[str, str, str, str]:
    """Return (mac, ip, host, asset_id) — all normalized."""
    ident = record.get("identity") if isinstance(record, dict) else None
    if not ident or not isinstance(ident, dict):
        ident = record if isinstance(record, dict) else {}
    mac = _norm_mac(ident.get("mac_address") or ident.get("mac") or "")
    ip = _pick_primary_ip(record)
    host = _norm_host(ident.get("hostname") or ident.get("name") or "")
    aid = (ident.get("asset_id") or "").strip().lower()
    return mac, ip, host, aid


# -------------------------------------------------------------- merger

def _make_canonical(record: dict, source: str, reason: str) -> CanonicalAsset:
    ident = record.get("identity") if isinstance(record, dict) else {}
    if not isinstance(ident, dict):
        ident = {}
    mac, ip, host, aid = _extract_keys(record)
    return CanonicalAsset(
        asset_id=aid or host or ip or mac or "unknown",
        hostname=ident.get("hostname") or "",
        mac=ident.get("mac_address") or ident.get("mac") or "",
        primary_ip=ip,
        asset_type=ident.get("asset_type") or "",
        vendor=ident.get("vendor") or "",
        sources=[source],
        match_reasons=[reason],
        raw_inputs=[record],
    )


def _absorb(canonical: CanonicalAsset, record: dict, source: str,
            reason: str) -> None:
    """Merge a new record into an existing canonical asset."""
    canonical.raw_inputs.append(record)
    if source not in canonical.sources:
        canonical.sources.append(source)
    canonical.match_reasons.append(reason)
    # Fill in any gaps (don't overwrite existing data)
    ident = record.get("identity") or {}
    if not canonical.hostname and ident.get("hostname"):
        canonical.hostname = ident["hostname"]
    if not canonical.mac and (ident.get("mac_address") or ident.get("mac")):
        canonical.mac = ident.get("mac_address") or ident.get("mac")
    if not canonical.primary_ip:
        canonical.primary_ip = _pick_primary_ip(record)
    if not canonical.asset_type and ident.get("asset_type"):
        canonical.asset_type = ident["asset_type"]
    if not canonical.vendor and ident.get("vendor"):
        canonical.vendor = ident["vendor"]


# ----------------------------------------------------- main reconciliation

def merge_asset_groups(groups: dict[str, Iterable[dict]]) -> DedupResult:
    """Reconcile multiple sources of asset records.

    Args:
        groups: {source_name: iterable_of_asset_records}, e.g.
                {'lan': [...], 'ad': [...], 'aws': [...]}

    Returns:
        DedupResult with one canonical record per real device.
    """
    result = DedupResult()
    by_mac: dict[str, CanonicalAsset] = {}
    by_ip: dict[str, CanonicalAsset] = {}
    by_host: dict[str, CanonicalAsset] = {}
    by_aid: dict[str, CanonicalAsset] = {}
    canonical_list: list[CanonicalAsset] = []

    for source, records in groups.items():
        records_list = list(records)
        result.counts_by_source[source] = len(records_list)
        for rec in records_list:
            mac, ip, host, aid = _extract_keys(rec)
            existing: Optional[CanonicalAsset] = None
            reason = ""
            # 1. MAC match
            if mac and mac in by_mac:
                existing = by_mac[mac]; reason = f"mac={mac}"
            # 2. IP match
            elif ip and ip in by_ip:
                existing = by_ip[ip]; reason = f"ip={ip}"
            # 3. Hostname match
            elif host and host in by_host:
                existing = by_host[host]; reason = f"hostname={host}"
            # 4. Asset id match
            elif aid and aid in by_aid:
                existing = by_aid[aid]; reason = f"asset_id={aid}"

            if existing is None:
                ca = _make_canonical(rec, source, "first-seen")
                canonical_list.append(ca)
                if mac: by_mac[mac] = ca
                if ip: by_ip[ip] = ca
                if host: by_host[host] = ca
                if aid: by_aid[aid] = ca
            else:
                _absorb(existing, rec, source, reason)
                # Re-key under any newly known identifiers
                if mac and mac not in by_mac: by_mac[mac] = existing
                if ip and ip not in by_ip: by_ip[ip] = existing
                if host and host not in by_host: by_host[host] = existing
                if aid and aid not in by_aid: by_aid[aid] = existing

    result.canonical = canonical_list
    return result


# ---------------------------------------------------------- shadow IT

# What counts as a "declarative" source — i.e. the org tracks this gear
# on purpose. Anything in active scan / SNMP / cloud / DHCP that doesn't
# show up here is shadow IT.
DECLARATIVE_SOURCES = ("ad", "entra", "cmdb", "manual", "import")


def find_shadow_it(result: DedupResult,
                   *,
                   declarative: tuple[str, ...] = DECLARATIVE_SOURCES,
                   ) -> list[CanonicalAsset]:
    """Return canonical assets that were NOT seen by any declarative source."""
    decl_set = set(declarative)
    shadow: list[CanonicalAsset] = []
    for ca in result.canonical:
        if not (set(ca.sources) & decl_set):
            shadow.append(ca)
    return shadow


# ---------------------------------------------------------- AI summary

AICall = Callable[[str, str, str], str]   # (system, user, model) -> response


def describe_dedup_result(result: DedupResult,
                          *,
                          ai_call: Optional[AICall] = None,
                          ) -> str:
    """One-paragraph human summary. Falls back to deterministic template
    if no AI is configured."""
    n = len(result.canonical)
    sources = sorted(result.counts_by_source.keys())
    multi = sum(1 for ca in result.canonical if len(ca.sources) > 1)
    shadow = find_shadow_it(result)

    template = (
        f"Reconciled {n} canonical assets across "
        f"{len(sources)} source{'s' if len(sources) != 1 else ''} "
        f"({', '.join(sources) or 'none'}). "
        f"{multi} asset{'s' if multi != 1 else ''} "
        f"appear in 2 or more sources (high confidence). "
        f"{len(shadow)} appear only in active probes — these are shadow-IT "
        f"candidates worth investigating."
    )

    if ai_call is None:
        return template

    counts = ", ".join(f"{src}={result.counts_by_source[src]}"
                       for src in sources)
    user_prompt = (
        f"Summarize a network-discovery dedup result in 2-3 sentences for a "
        f"network engineer.\n\n"
        f"- {n} canonical devices after dedup\n"
        f"- input sources & counts: {counts}\n"
        f"- {multi} devices in 2+ sources\n"
        f"- {len(shadow)} shadow-IT candidates "
        f"(in active scan, missing from AD/Entra/CMDB)\n\n"
        f"Be specific. Don't recommend tools we don't have. Don't pad."
    )
    try:
        return ai_call("You are a precise infrastructure analyst.",
                       user_prompt, "claude-haiku")
    except Exception:
        return template
