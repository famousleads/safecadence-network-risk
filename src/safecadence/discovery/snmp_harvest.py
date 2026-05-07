"""
v9.4 — SNMP harvest from network gear.

Point at one router/switch with an SNMP community, get back every
neighbor it knows about (LLDP/CDP) and every MAC address it has ever
seen on its forwarding table. This is the single biggest "device count
multiplier per hour of work" — one router routinely yields 50–500
devices that an ARP-based LAN scan would miss entirely.

Implementation: shells out to ``snmpwalk`` (net-snmp) — the same tool
LibreNMS, Forescout, and most enterprise NMS systems actually use under
the hood. A pure-stdlib SNMP-WALK from scratch would be ~600 lines of
fragile BER and is the single biggest "rebuild what's already shipped
on every Linux box" trap. If net-snmp isn't installed, the harvester
returns an actionable error.

For tests, every harvest function takes an optional ``walk_fn`` seam
that returns parsed lines, so we don't need real gear or a subprocess.

OID reference:
  LLDP-MIB:
    1.0.8802.1.1.2.1.4.1.1.5  lldpRemChassisIdSubtype
    1.0.8802.1.1.2.1.4.1.1.5  lldpRemChassisId          (chassis MAC, hex)
    1.0.8802.1.1.2.1.4.1.1.7  lldpRemPortId             (remote port-id)
    1.0.8802.1.1.2.1.4.1.1.8  lldpRemPortDesc           (remote port description)
    1.0.8802.1.1.2.1.4.1.1.9  lldpRemSysName            (remote hostname)
    1.0.8802.1.1.2.1.4.1.1.10 lldpRemSysDesc            (remote sysDescr)
    1.0.8802.1.1.2.1.4.2.1.5  lldpRemManAddrIfSubtype   (remote mgmt IP type)
    1.0.8802.1.1.2.1.4.2.1.4  lldpRemManAddr            (remote mgmt IP)

  CDP-MIB (Cisco):
    1.3.6.1.4.1.9.9.23.1.2.1.1.4   cdpCacheAddress       (neighbor IP)
    1.3.6.1.4.1.9.9.23.1.2.1.1.5   cdpCacheVersion       (IOS version)
    1.3.6.1.4.1.9.9.23.1.2.1.1.6   cdpCacheDeviceId      (neighbor hostname)
    1.3.6.1.4.1.9.9.23.1.2.1.1.7   cdpCachePlatform      (model)
    1.3.6.1.4.1.9.9.23.1.2.1.1.8   cdpCacheCapabilities  (capabilities bitmap)

  BRIDGE-MIB / Q-BRIDGE-MIB:
    1.3.6.1.2.1.17.4.3.1.1         dot1dTpFdbAddress     (MAC address)
    1.3.6.1.2.1.17.4.3.1.2         dot1dTpFdbPort        (bridge port)
    1.3.6.1.2.1.17.7.1.2.2.1.2     dot1qTpFdbPort        (VLAN-aware MAC)
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# ----------------------------------------------------------------- types ----


@dataclass
class HarvestedNeighbor:
    """One neighbor discovered via LLDP or CDP."""
    source_protocol: str           # "lldp" or "cdp"
    via_router: str                # IP we polled
    hostname: str = ""
    ip_address: str = ""
    chassis_id: str = ""           # often the MAC
    port_id: str = ""              # remote port name (e.g. Gi1/0/24)
    port_description: str = ""
    sys_description: str = ""      # vendor sysDescr / IOS version
    platform: str = ""             # model (CDP only)
    capabilities: list[str] = field(default_factory=list)


@dataclass
class HarvestedMac:
    """One MAC address from a bridge forwarding table."""
    mac: str
    port: int
    via_router: str
    vlan: int = 0


@dataclass
class HarvestResult:
    via_router: str
    started_at: str
    finished_at: str
    snmp_version: str = "2c"
    neighbors: list[HarvestedNeighbor] = field(default_factory=list)
    macs: list[HarvestedMac] = field(default_factory=list)
    sys_descr: str = ""
    sys_name: str = ""
    error: str = ""

    @property
    def neighbor_count(self) -> int:
        return len(self.neighbors)

    @property
    def mac_count(self) -> int:
        return len(self.macs)


# ------------------------------------------------------------- snmpwalk ----


def _have_snmpwalk() -> bool:
    return shutil.which("snmpwalk") is not None


def _default_snmpwalk(host: str, community: str, oid: str,
                      *, version: str = "2c", timeout: int = 5) -> list[str]:
    """Default walk: shell out to net-snmp's snmpwalk, return raw lines.

    On Linux/macOS install via:
        macOS: brew install net-snmp
        Debian: apt-get install snmp
        RHEL:   yum install net-snmp-utils
    """
    if not _have_snmpwalk():
        raise RuntimeError(
            "snmpwalk not found. Install net-snmp:\n"
            "  macOS:   brew install net-snmp\n"
            "  Debian:  sudo apt-get install snmp\n"
            "  RHEL:    sudo yum install net-snmp-utils"
        )
    cmd = ["snmpwalk",
           "-v", version,
           "-c", community,
           "-O", "Qn",          # quick, numeric OIDs
           "-t", "2",           # 2s per-OID timeout
           "-r", "1",           # 1 retry
           host, oid]
    out = subprocess.run(cmd, capture_output=True, text=True,
                         timeout=timeout)
    if out.returncode != 0:
        msg = (out.stderr or out.stdout or "").strip()
        raise RuntimeError(f"snmpwalk {host} {oid} failed: {msg[:200]}")
    return [line for line in out.stdout.splitlines() if line.strip()]


WalkFn = Callable[..., list[str]]   # seam type for tests


# -------------------------------------------------------------- parsers ----


_HEX_PAIR = re.compile(r"^[0-9A-Fa-f]{1,2}(?: [0-9A-Fa-f]{1,2})*$")


def _parse_walk_line(line: str) -> tuple[str, str]:
    """`.1.2.3.4 = STRING: foo` → ('.1.2.3.4', 'STRING: foo')."""
    if "=" not in line:
        return ("", line)
    oid, _, val = line.partition("=")
    return (oid.strip(), val.strip())


def _hex_to_mac(s: str) -> str:
    """Turn a hex-string SNMP OctetString into a colon MAC.
    Accepts '00 11 22 33 44 55' or '0:11:22:33:44:55' or 6-byte ASCII."""
    s = s.strip().strip('"')
    if _HEX_PAIR.match(s):
        bytes_ = s.split()
        if len(bytes_) == 6:
            return ":".join(b.zfill(2).lower() for b in bytes_)
    # Sometimes net-snmp returns "Hex-STRING: 00 11 22 33 44 55"
    return s


def _hex_to_ip(s: str) -> str:
    """`Hex-STRING: 0A 00 00 01` → '10.0.0.1'.
    `IpAddress: 10.0.0.1` → '10.0.0.1'."""
    s = s.strip().strip('"')
    if "." in s and s.count(".") == 3 and all(p.isdigit() for p in s.split(".")):
        return s
    if _HEX_PAIR.match(s):
        parts = s.split()
        if len(parts) == 4:
            try:
                return ".".join(str(int(p, 16)) for p in parts)
            except ValueError:
                pass
    return ""


def _strip_type(val: str) -> str:
    """`STRING: "edge-rtr-01"` → `edge-rtr-01`."""
    if ":" in val:
        _, _, payload = val.partition(":")
        return payload.strip().strip('"')
    return val.strip().strip('"')


_LLDP_REM_PREFIX = ".1.0.8802.1.1.2.1.4.1.1."


def parse_lldp_walk(lines: list[str], *, via_router: str) -> list[HarvestedNeighbor]:
    """Group lldpRemEntry sub-OIDs by entry index → list of neighbors."""
    by_index: dict[str, dict[str, str]] = {}
    for raw in lines:
        oid, val = _parse_walk_line(raw)
        if not oid.startswith(_LLDP_REM_PREFIX):
            continue
        # OID shape: .1.0.8802.1.1.2.1.4.1.1.<column>.<timeMark>.<localPort>.<index>
        rest = oid[len(_LLDP_REM_PREFIX):].split(".")
        if len(rest) < 4:
            continue
        column = rest[0]
        idx = ".".join(rest[1:4])
        by_index.setdefault(idx, {})[column] = _strip_type(val)
    out: list[HarvestedNeighbor] = []
    for idx, cols in by_index.items():
        out.append(HarvestedNeighbor(
            source_protocol="lldp",
            via_router=via_router,
            chassis_id=_hex_to_mac(cols.get("5", "")),
            port_id=cols.get("7", ""),
            port_description=cols.get("8", ""),
            hostname=cols.get("9", ""),
            sys_description=cols.get("10", ""),
        ))
    return out


_CDP_PREFIX = ".1.3.6.1.4.1.9.9.23.1.2.1.1."


_CDP_CAP_BITS = [(0x40, "router"), (0x20, "trans-bridge"),
                 (0x10, "src-route-bridge"), (0x08, "switch"),
                 (0x04, "host"), (0x02, "igmp"), (0x01, "repeater")]


def _parse_cdp_caps(s: str) -> list[str]:
    """CDP capability bitmap → list of capability names."""
    s = _strip_type(s)
    try:
        n = int(s.split()[0], 16) if " " in s else int(s, 0)
    except (ValueError, IndexError):
        return []
    return [name for bit, name in _CDP_CAP_BITS if n & bit]


def parse_cdp_walk(lines: list[str], *, via_router: str) -> list[HarvestedNeighbor]:
    by_index: dict[str, dict[str, str]] = {}
    for raw in lines:
        oid, val = _parse_walk_line(raw)
        if not oid.startswith(_CDP_PREFIX):
            continue
        rest = oid[len(_CDP_PREFIX):].split(".")
        if len(rest) < 3:
            continue
        column = rest[0]
        idx = ".".join(rest[1:3])  # ifIndex.entryIndex
        by_index.setdefault(idx, {})[column] = _strip_type(val)
    out: list[HarvestedNeighbor] = []
    for idx, cols in by_index.items():
        out.append(HarvestedNeighbor(
            source_protocol="cdp",
            via_router=via_router,
            ip_address=_hex_to_ip(cols.get("4", "")),
            sys_description=cols.get("5", ""),     # IOS version
            hostname=cols.get("6", ""),
            platform=cols.get("7", ""),
            capabilities=_parse_cdp_caps(cols.get("8", "")),
        ))
    return out


_FDB_PREFIX = ".1.3.6.1.2.1.17.4.3.1."


def parse_mac_table_walk(lines: list[str], *, via_router: str) -> list[HarvestedMac]:
    """BRIDGE-MIB dot1dTpFdb table → MAC + bridge port."""
    by_idx: dict[str, dict[str, str]] = {}
    for raw in lines:
        oid, val = _parse_walk_line(raw)
        if not oid.startswith(_FDB_PREFIX):
            continue
        rest = oid[len(_FDB_PREFIX):].split(".")
        if len(rest) < 7:
            continue
        column = rest[0]                       # 1=address, 2=port, 3=status
        # The next 6 dotted ints are the MAC bytes (the table index).
        mac_bytes = rest[1:7]
        idx = ".".join(mac_bytes)
        by_idx.setdefault(idx, {})[column] = _strip_type(val)
    out: list[HarvestedMac] = []
    for idx, cols in by_idx.items():
        try:
            port = int(cols.get("2", "0").split()[0])
        except (ValueError, IndexError):
            port = 0
        # MAC from the OID index (decimal) — turn into hex.
        bytes_ = [f"{int(b):02x}" for b in idx.split(".") if b.isdigit()]
        if len(bytes_) != 6:
            continue
        out.append(HarvestedMac(
            mac=":".join(bytes_),
            port=port,
            via_router=via_router,
        ))
    return out


# ------------------------------------------------------------ harvester ----


def harvest_from_router(host: str,
                        community: str = "public",
                        *,
                        version: str = "2c",
                        walk_fn: Optional[WalkFn] = None,
                        on_progress: Optional[Callable[[str, int], None]] = None,
                        ) -> HarvestResult:
    """Run all three walks against one router/switch.

    Args:
        host:       management IP of the router
        community:  SNMPv2c community string (or v1)
        version:    snmpwalk -v argument
        walk_fn:    test seam — returns parsed lines for a given oid
        on_progress: optional callback fired as ('lldp', count) etc.
    """
    walk = walk_fn or _default_snmpwalk
    started = datetime.now(timezone.utc).isoformat()

    res = HarvestResult(
        via_router=host,
        started_at=started,
        finished_at="",
        snmp_version=version,
    )

    # 0. sysName + sysDescr — sanity check that SNMP works
    try:
        sd_lines = walk(host, community, ".1.3.6.1.2.1.1.1.0", version=version)
        for line in sd_lines:
            _, val = _parse_walk_line(line)
            res.sys_descr = _strip_type(val)
            break
        sn_lines = walk(host, community, ".1.3.6.1.2.1.1.5.0", version=version)
        for line in sn_lines:
            _, val = _parse_walk_line(line)
            res.sys_name = _strip_type(val)
            break
    except Exception as e:
        res.error = f"sysName/sysDescr probe failed: {e}"
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res

    # 1. LLDP neighbors
    try:
        lldp_lines = walk(host, community, _LLDP_REM_PREFIX.rstrip("."),
                          version=version)
        res.neighbors.extend(parse_lldp_walk(lldp_lines, via_router=host))
        if on_progress:
            on_progress("lldp", len(res.neighbors))
    except Exception as e:
        # LLDP is optional — Cisco gear sometimes only has CDP.
        res.error = (res.error + f"; lldp walk failed: {e}").strip("; ")

    # 2. CDP neighbors (Cisco-only)
    try:
        cdp_lines = walk(host, community, _CDP_PREFIX.rstrip("."),
                         version=version)
        cdp = parse_cdp_walk(cdp_lines, via_router=host)
        res.neighbors.extend(cdp)
        if on_progress:
            on_progress("cdp", len(cdp))
    except Exception as e:
        res.error = (res.error + f"; cdp walk failed: {e}").strip("; ")

    # 3. MAC address table — biggest source of device IPs.
    try:
        mac_lines = walk(host, community, _FDB_PREFIX.rstrip("."),
                         version=version)
        res.macs = parse_mac_table_walk(mac_lines, via_router=host)
        if on_progress:
            on_progress("mac", len(res.macs))
    except Exception as e:
        res.error = (res.error + f"; mac table walk failed: {e}").strip("; ")

    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# --------------------------------------------------- → DiscoveredHost-shape


def neighbors_as_discovered_hosts(result: HarvestResult) -> list[dict]:
    """Convert HarvestedNeighbor records into the dict shape that
    bridge.discovered_to_asset() expects, so they can flow straight into
    /api/platform/adopt-discovered."""
    hosts: list[dict] = []
    for n in result.neighbors:
        ip = n.ip_address or ""
        hostname = n.hostname or n.chassis_id or ip
        # Vendor inference from sysDescr (best-effort)
        vendor = ""
        sd = (n.sys_description or n.platform or "").lower()
        for hint, name in (("cisco", "cisco"), ("arista", "arista"),
                           ("juniper", "juniper"), ("aruba", "aruba"),
                           ("hp ", "hp"), ("brocade", "brocade"),
                           ("dell", "dell"), ("fortinet", "fortinet"),
                           ("palo alto", "palo-alto")):
            if hint in sd:
                vendor = name
                break
        # Capability → device_type heuristic
        dev_type = "network"
        if "router" in n.capabilities or "router" in sd:
            dev_type = "router"
        elif "switch" in n.capabilities or "switch" in sd:
            dev_type = "switch"
        elif "host" in n.capabilities:
            dev_type = "server"

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": n.chassis_id,
            "vendor_guess": vendor,
            "os_guess": "",
            "device_type_guess": dev_type,
            "snmp_sysdescr": n.sys_description,
            "open_ports": [],
            "banners": {
                "_via": f"{n.source_protocol} on {n.via_router}",
                "_remote_port": n.port_id,
                "_platform": n.platform,
            },
        })
    return hosts
