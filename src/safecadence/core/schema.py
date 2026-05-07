"""
Common asset + finding schema. Every vendor adapter normalizes into these
shapes. Keep them backwards-compatible — the schema is part of the public
contract for plugin authors.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity ladder used across findings, risk scoring, and reports."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Weight used by the deterministic risk scoring engine."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH:     12,
            Severity.MEDIUM:    5,
            Severity.LOW:       2,
            Severity.INFO:      0,
        }[self]


@dataclass
class Interface:
    name: str
    description: str = ""
    ip: str = ""
    mac: str = ""
    vlan: int | None = None
    speed: str = ""
    admin_up: bool = True
    oper_up: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Neighbor:
    """LLDP / CDP neighbor record."""
    local_interface: str
    remote_device: str = ""
    remote_interface: str = ""
    remote_ip: str = ""
    protocol: str = "lldp"   # lldp | cdp


@dataclass
class ParsedConfig:
    """
    Output of an adapter's parse step. Vendor-agnostic. Engines run against
    this. Adapters MUST populate vendor / device_type / os / version at
    minimum; everything else is optional but recommended.
    """
    vendor: str
    device_type: str = "switch"   # switch | router | firewall | wlc | server | cloud
    hostname: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""                  # ios | ios-xe | nxos | aos-cx | eos | junos | panos | fortios
    version: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    raw_config: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """One audit finding produced by a config-audit rule."""
    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    fix_snippet: str = ""
    references: list[str] = field(default_factory=list)
    evidence: str = ""
    domain: str = "config"   # config | vuln | eol | health
    matched_at: str = ""
    # Compliance control IDs that this finding maps to (auto-derived)
    nist_800_53: list[str] = field(default_factory=list)
    cis_benchmark: list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    hipaa: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Location:
    """Physical location of an asset, hierarchically."""
    country: str = ""
    region: str = ""
    city: str = ""
    site: str = ""           # office / DC name
    campus: str = ""
    building: str = ""
    floor: str = ""
    room: str = ""           # closet / IDF
    rack: str = ""
    rack_unit: str = ""      # e.g. "U17-U18"
    geo_lat: float | None = None
    geo_lng: float | None = None


@dataclass
class Asset:
    """Top-level asset record. One per scanned device / config."""
    asset_id: str
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""
    version: str = ""
    device_type: str = ""
    ip: str = ""
    mac: str = ""
    site: str = ""
    business_criticality: str = "medium"   # low | medium | high | critical
    # ---- enterprise additions (v2.0) ---- #
    location: Location = field(default_factory=Location)
    owner: str = ""                         # owning team
    owner_email: str = ""
    support_contract: str = ""              # e.g. "Cisco SmartNet 8x5x4 #SC123456"
    support_expires: str = ""               # YYYY-MM-DD
    tags: list[str] = field(default_factory=list)
    uptime_days: int | None = None
    tenant_id: str = ""                     # multi-tenant scoping
    # ------------------------------------- #
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    health_score: int = 0
    risk_score: int = 0
    health_band: str = ""
    risk_band: str = ""
    findings: list[Finding] = field(default_factory=list)
    last_scan: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "findings"},
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    """The full output of one scan invocation."""
    source: str                     # filename / hostname / ip
    vendor: str
    duration_ms: int
    parsed: ParsedConfig
    asset: Asset
    findings: list[Finding] = field(default_factory=list)
    health_score: int = 0
    risk_score: int = 0
    health_band: str = ""
    risk_band: str = ""
    summary: str = ""
    cves: list[dict[str, Any]] = field(default_factory=list)        # enrichment
    eol: dict[str, Any] | None = None                                # enrichment
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "source":        self.source,
            "vendor":        self.vendor,
            "duration_ms":   self.duration_ms,
            "started_at":    self.started_at,
            "health_score":  self.health_score,
            "health_band":   self.health_band,
            "risk_score":    self.risk_score,
            "risk_band":     self.risk_band,
            "summary":       self.summary,
            "asset":         self.asset.to_dict(),
            "findings":      [f.to_dict() for f in self.findings],
            "cves":          list(self.cves),
            "eol":           self.eol,
            "parsed_summary": {
                "hostname": self.parsed.hostname,
                "model":    self.parsed.model,
                "os":       self.parsed.os,
                "version":  self.parsed.version,
                "interfaces": len(self.parsed.interfaces),
                "neighbors":  len(self.parsed.neighbors),
            },
            "parsed_raw": self.parsed.raw_config or "",
        }
