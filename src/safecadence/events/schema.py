"""
Canonical event schema (DESAT §6) + normalizers for the two classic
network transports: syslog (RFC3164 / RFC5424) and SNMPv2c traps.

Every ingest path (syslog, trap, webhook) converges on ``Event`` so
dedup, correlation, incidents, and the UI operate on one shape.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# RFC3164 severity levels (PRI % 8), mapped onto NetRisk's bands.
_SYSLOG_SEVERITY = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "info", 7: "info",
}

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    """One normalized inbound event."""
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    received_at: str = field(default_factory=_now)
    occurred_at: str = ""              # source-claimed time, if parseable
    source: str = ""                   # syslog | snmp_trap | webhook
    source_ip: str = ""                # sender address
    event_type: str = ""               # e.g. syslog.auth, trap.linkDown, webhook.custom
    severity: str = "info"             # critical | high | medium | low | info
    confidence: str = "reported"       # reported | corroborated | inferred
    description: str = ""
    # Asset linkage — filled by store.link_asset_by_ip when resolvable.
    asset_id: str = ""
    hostname: str = ""
    site: str = ""
    agency: str = ""
    related_assets: list[str] = field(default_factory=list)
    mission_impact: str = ""           # filled by correlation/incidents later
    correlation_id: str = ""           # dedup/grouping key
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def dedup_key(self) -> str:
        """Stable key for collapsing repeats of the same condition from
        the same source (independent of timestamps)."""
        basis = f"{self.source}|{self.source_ip}|{self.event_type}|{self.description[:160]}"
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------- syslog

# RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$")

# RFC3164: <PRI>TIMESTAMP HOSTNAME MSG   (timestamp = "Aug 17 12:01:02")
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$")


def normalize_syslog(raw_line: str, source_ip: str = "") -> Event:
    """Parse one syslog datagram into an Event. Never raises — an
    unparseable line still becomes an event (severity=info,
    event_type=syslog.unparsed) so nothing is silently dropped."""
    line = (raw_line or "").strip()

    m = _RFC5424.match(line) or _RFC3164.match(line)
    if not m:
        return Event(source="syslog", source_ip=source_ip,
                      event_type="syslog.unparsed", severity="info",
                      description=line[:500], raw={"line": line[:2000]})

    pri = int(m.group("pri"))
    severity = _SYSLOG_SEVERITY.get(pri % 8, "info")
    facility = _FACILITY_NAMES.get(pri // 8, str(pri // 8))
    rest = m.group("rest").strip()
    host = m.group("host")
    occurred = ""
    ts = m.group("ts")
    if "ver" in m.groupdict() and m.groupdict().get("ver"):
        # RFC5424 timestamps are ISO-ish already.
        if ts not in ("-", ""):
            occurred = ts

    return Event(
        source="syslog", source_ip=source_ip,
        occurred_at=occurred,
        event_type=f"syslog.{facility}",
        severity=severity,
        hostname="" if host in ("-",) else host,
        description=rest[:500],
        raw={"line": line[:2000], "pri": pri, "facility": facility},
    )


# ---------------------------------------------------------------- traps

# Well-known trap OIDs → friendly names.
_TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

_TRAP_SEVERITY = {
    "linkDown": "high", "authenticationFailure": "high",
    "coldStart": "medium", "warmStart": "medium", "linkUp": "info",
}


def normalize_trap(trap_oid: str, varbinds: list[tuple[str, Any]],
                    source_ip: str = "", community_seen: bool = True) -> Event:
    """Build an Event from a decoded SNMPv2c trap PDU."""
    name = _TRAP_NAMES.get(trap_oid, "")
    etype = f"trap.{name or trap_oid}"
    severity = _TRAP_SEVERITY.get(name, "medium")
    vb_txt = "; ".join(f"{oid}={value!r}" for oid, value in varbinds[:8])
    desc = (f"SNMP trap {name or trap_oid}"
             + (f" — {vb_txt}" if vb_txt else ""))
    return Event(
        source="snmp_trap", source_ip=source_ip,
        event_type=etype, severity=severity,
        description=desc[:500],
        raw={"trap_oid": trap_oid,
              "varbinds": [[oid, repr(value)[:200]] for oid, value in varbinds[:32]],
              "community_seen": community_seen},
    )
