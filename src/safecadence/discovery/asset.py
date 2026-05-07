"""Asset records produced by the discovery engine."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class DiscoveredHost:
    """One device that responded to TCP probes during discovery."""
    ip: str
    hostname: str = ""                          # PTR lookup
    mac: str = ""                               # populated only for L2-adjacent hosts
    vendor_guess: str = ""                      # from OUI or banner text
    os_guess: str = ""                          # ios | nxos | asa | aos-cx | eos | linux | windows | unknown
    device_type_guess: str = ""                 # router | switch | firewall | server | printer | iot | unknown
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)   # port -> first 200 bytes of banner
    snmp_sysdescr: str = ""                     # if SNMPv2c probe succeeded
    response_time_ms: int = 0
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryResult:
    """Result of one full subnet sweep."""
    subnet: str
    started_at: str
    finished_at: str
    duration_ms: int
    hosts_scanned: int
    hosts_responding: int
    hosts: list[DiscoveredHost] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet": self.subnet,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "hosts_scanned": self.hosts_scanned,
            "hosts_responding": self.hosts_responding,
            "hosts": [h.to_dict() for h in self.hosts],
        }
