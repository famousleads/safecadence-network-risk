"""
v9.17 — Discovery coverage health.

Score how much of the environment SafeCadence actually sees.

For each known source (lan-scan / snmp / ad / entra / dhcp / cloud /
manual / csv-import / unknown), report:
  - connected:        any asset attributed to this source
  - asset_count:      how many assets came from here
  - last_seen_at:     newest last_seen / first_seen across those assets
  - estimated_gap:    qualitative health: ok / stale / never-connected

Then add a punch list of recommended next connectors based on what's
*missing* — e.g. no AD = "you're probably blind to most Windows endpoints",
no SNMP = "you're probably blind to network gear neighbors and MAC tables".

This is intentionally heuristic — it can't tell you "what should be
there" without external context. It's an operator's prompt: a Monday-
morning *"what should I look at first"* page, not a precision tool.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Iterable


# Canonical sources we know how to detect, in priority order. The first
# match wins when an asset has multiple hints. The label is what the UI
# shows; the icon is the same family used elsewhere in the product.
_SOURCES = [
    ("lan-scan",   "🛰️ LAN scan",          "ARP / mDNS / TLS / HTTP probe"),
    ("snmp",       "📡 SNMP harvest",      "LLDP / CDP / MAC table"),
    ("ad",         "🪪 Active Directory",  "Domain-joined endpoints"),
    ("entra",      "☁️ Entra ID",          "Microsoft Graph devices"),
    ("dhcp",       "📋 DHCP leases",       "Sleeping laptops + IoT"),
    ("aws",        "🌩 AWS",               "EC2 describe-instances"),
    ("azure",      "🌩 Azure",             "VM list"),
    ("gcp",        "🌩 GCP",               "Compute instances"),
    ("manual",     "✏️ Manual",            "Crown-jewels added by hand"),
    ("import",     "📥 CSV import",        "CMDB exports"),
    ("unknown",    "❓ Unknown source",   "Source not recorded"),
]


# Coarse pattern matching from the discovery_source string the various
# adapters write into asset.identity.discovery_source.
_SOURCE_PATTERNS = {
    "lan-scan":   ("lan", "arp", "discover", "scan"),
    "snmp":       ("snmp", "lldp", "cdp", "harvest"),
    "ad":         ("ad", "ldap", "domain"),
    "entra":      ("entra", "azuread", "graph"),
    "dhcp":       ("dhcp", "lease"),
    "aws":        ("aws", "ec2"),
    "azure":      ("azure", "vm-list"),
    "gcp":        ("gcp", "compute", "gcloud"),
    "manual":     ("manual",),
    "import":     ("import", "csv", "cmdb"),
}


def _classify_source(raw: str) -> str:
    s = (raw or "").strip().lower()
    if not s:
        return "unknown"
    for key, hints in _SOURCE_PATTERNS.items():
        if any(h in s for h in hints):
            return key
    return "unknown"


def _parse_dt(s) -> datetime | None:
    if not s:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    try:
        # Accept ISO 8601 with or without tz
        s = str(s).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def compute_coverage(assets: Iterable[dict]) -> dict:
    """Build the coverage health report.

    Returns:
      {
        sources: [
          {key, label, hint, connected, asset_count, last_seen_at,
           estimated_gap, status_color},
          ...
        ],
        totals: {fleet_size, distinct_sources, hours_since_freshest_source},
        recommendations: [
          {priority, title, body, cta_url, cta_label},
          ...
        ],
        score: 0..100  (heuristic confidence we're seeing the fleet)
      }
    """
    assets = list(assets or [])
    fleet_size = len(assets)
    counts: dict[str, int] = defaultdict(int)
    last_seen: dict[str, datetime] = {}

    for a in assets:
        ident = a.get("identity") or {}
        src = _classify_source(ident.get("discovery_source"))
        counts[src] += 1
        # Pick the freshest of last_seen / last_collected_at / last_modified
        for field in ("last_seen", "last_collected_at", "last_modified",
                      "first_seen"):
            dt = _parse_dt(ident.get(field))
            if dt and (src not in last_seen or dt > last_seen[src]):
                last_seen[src] = dt
                break

    now = datetime.now(timezone.utc)
    sources_out: list[dict] = []
    for key, label, hint in _SOURCES:
        n = counts.get(key, 0)
        last = last_seen.get(key)
        if n == 0:
            gap = "never-connected"
            color = "#9ca3af"        # gray
        elif last is None:
            gap = "no-timestamp"
            color = "#f59e0b"        # yellow
        else:
            age_hours = (now - last).total_seconds() / 3600.0
            if age_hours < 24:
                gap = "fresh"; color = "#10b981"     # green
            elif age_hours < 24 * 7:
                gap = "stale"; color = "#f59e0b"     # yellow
            else:
                gap = "very-stale"; color = "#ef4444" # red
        sources_out.append({
            "key": key, "label": label, "hint": hint,
            "connected": n > 0,
            "asset_count": n,
            "last_seen_at": last.isoformat() if last else "",
            "hours_since": round((now - last).total_seconds() / 3600.0, 1)
                            if last else None,
            "estimated_gap": gap,
            "status_color": color,
        })

    # Build recommendations from missing or stale sources, ordered by
    # estimated impact (which sources are biggest visibility multipliers).
    rec: list[dict] = []
    # v9.20.1 — each source has a deep-link key the UI uses to auto-open
    # the right hero-card slide-over on /inventory (?open=<key>).
    impact_order = [
        ("snmp", "Connect SNMP harvest",
            "Each network device you harvest contributes its full LLDP/CDP "
            "neighbor list and MAC forwarding table — typically 50–500 "
            "additional devices per router. This is the single highest-"
            "impact source for network gear.",
            "snmp"),
        ("ad", "Connect Active Directory / LDAP",
            "AD is the single biggest source of endpoints in any enterprise "
            "— every domain-joined Windows / Mac / Linux host appears here "
            "with OS, OU, last-logon, and enabled state. Without it, you're "
            "probably blind to most user endpoints.",
            "ad"),
        ("entra", "Connect Entra ID",
            "Catches Intune-enrolled phones, BYOD laptops, and managed Macs "
            "that on-prem AD never sees. Required for any hybrid org.",
            "entra"),
        ("dhcp", "Pull DHCP leases",
            "Sleeping laptops, phones, and IoT devices that aren't responding "
            "to ARP right now still appear in DHCP — gold for catching "
            "intermittent assets.",
            "dhcp"),
        ("aws", "Connect AWS",
            "Cloud assets are invisible to LAN scans by definition. Pull "
            "EC2 instances directly via the AWS CLI.",
            "aws"),
        ("azure", "Connect Azure",
            "Azure VMs are invisible to LAN scans. Use az CLI auth chain.",
            "azure"),
        ("gcp", "Connect GCP",
            "GCP compute instances are invisible to LAN scans. Use gcloud "
            "CLI auth chain.",
            "gcp"),
    ]
    # v9.36 — explicit `reason` per recommendation so the operator can
    # see WHY one item ranks higher than another. The priority bucket is
    # derived from the source's estimated visibility impact (snmp + ad
    # are biggest multipliers), not a magic number. Surface the reason
    # in the UI under the title.
    PRIORITY_REASON = {
        "snmp": ("high",
                  "SNMP harvest is the highest-impact missing source — "
                  "each network device contributes 50–500 neighbor + "
                  "MAC table entries."),
        "ad":   ("high",
                  "AD/LDAP is typically the largest source of endpoint "
                  "visibility in an enterprise; missing it usually means "
                  "you're blind to most user devices."),
        "entra": ("medium",
                  "Entra catches devices on-prem AD never sees — required "
                  "for hybrid orgs and BYOD."),
        "dhcp":  ("medium",
                  "DHCP leases catch sleeping / intermittent devices "
                  "that ARP scans miss."),
        "aws":   ("medium",
                  "Cloud workloads are invisible to LAN scans by design."),
        "azure": ("medium",
                  "Cloud workloads are invisible to LAN scans by design."),
        "gcp":   ("medium",
                  "Cloud workloads are invisible to LAN scans by design."),
    }
    src_by_key = {s["key"]: s for s in sources_out}
    for key, title, body, open_key in impact_order:
        s = src_by_key.get(key, {})
        prio, reason = PRIORITY_REASON.get(key, ("medium", ""))
        if not s.get("connected"):
            rec.append({
                "priority": prio,
                "title": title, "body": body,
                "reason": reason,
                "cta_url": f"/inventory?open={open_key}",
                "cta_label": f"Open {key} setup",
                "source_key": key,
            })
        elif s.get("estimated_gap") in ("very-stale", "stale"):
            rec.append({
                "priority": "low",
                "title": f"Refresh {s['label']}",
                "body": f"Last run was {s['hours_since']:.1f}h ago. "
                        f"Stale data drifts away from reality.",
                "reason": (
                    "Connected sources still drift — staleness is "
                    "ranked LOW because the connector exists; refresh "
                    "is one click."
                ),
                "cta_url": f"/inventory?open={open_key}",
                "cta_label": "Re-run now",
                "source_key": key,
            })

    distinct_sources = sum(1 for s in sources_out if s["connected"])
    fresh_sources = sum(1 for s in sources_out
                        if s["estimated_gap"] == "fresh")
    # Heuristic score:
    #   30 base for any data + 40 for source diversity (≥3 connected)
    #   + 30 for any source being fresh.
    score = 0
    if fleet_size > 0:
        score += 30
        score += min(40, distinct_sources * 10)
        score += 30 if fresh_sources > 0 else 0
    score = min(100, score)

    fresh_hours = None
    if last_seen:
        fresh = max(last_seen.values())
        fresh_hours = round((now - fresh).total_seconds() / 3600.0, 1)

    return {
        "sources": sources_out,
        "totals": {
            "fleet_size": fleet_size,
            "distinct_sources": distinct_sources,
            "hours_since_freshest_source": fresh_hours,
        },
        "recommendations": rec,
        "score": score,
    }
