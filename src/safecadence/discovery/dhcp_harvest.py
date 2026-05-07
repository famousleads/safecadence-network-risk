"""
v9.5 — DHCP server lease harvester.

Catches sleeping laptops, phones, and IoT that aren't responding to ARP
right now. The DHCP server saw them when they came online and tracks
the lease — that data is gold.

Two flavors:
  ISC dhcpd (Linux/BSD):  parse /var/lib/dhcp/dhcpd.leases
  Windows DHCP server:    PowerShell `Get-DhcpServerv4Lease` (subprocess)

Both produce DhcpLease records → DiscoveredHost-shaped dicts.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass
class DhcpLease:
    ip: str
    mac: str = ""
    hostname: str = ""
    state: str = "active"            # active | expired | abandoned | free
    starts: str = ""
    ends: str = ""
    vendor_class: str = ""           # option 60
    fingerprint: str = ""            # option 55 fingerprint


@dataclass
class DhcpHarvestResult:
    source: str                       # "isc-dhcpd" | "windows-dhcp"
    started_at: str
    finished_at: str
    leases: list[DhcpLease] = field(default_factory=list)
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.leases)


# ----------------------------------------------------- ISC dhcpd parser

# Each lease block in /var/lib/dhcp/dhcpd.leases looks like:
#   lease 10.0.0.42 {
#     starts 5 2026/05/03 21:00:00;
#     ends 5 2026/05/04 09:00:00;
#     binding state active;
#     hardware ethernet 00:11:22:33:44:55;
#     client-hostname "alice-laptop";
#     set vendor-class-identifier = "MSFT 5.0";
#   }


_LEASE_RE = re.compile(r"lease\s+([\d.]+)\s*\{(.*?)\}", re.DOTALL)


def parse_isc_leases_text(text: str) -> list[DhcpLease]:
    out: list[DhcpLease] = []
    for ip, body in _LEASE_RE.findall(text):
        lease = DhcpLease(ip=ip)
        for raw in body.split(";"):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("hardware ethernet"):
                lease.mac = line.split()[-1].lower()
            elif line.startswith("client-hostname"):
                m = re.search(r'"([^"]*)"', line)
                if m: lease.hostname = m.group(1)
            elif line.startswith("starts"):
                lease.starts = line.split(maxsplit=1)[1] if " " in line else ""
            elif line.startswith("ends"):
                lease.ends = line.split(maxsplit=1)[1] if " " in line else ""
            elif "binding state" in line:
                lease.state = line.split()[-1]
            elif "vendor-class-identifier" in line:
                m = re.search(r'"([^"]*)"', line)
                if m: lease.vendor_class = m.group(1)
        out.append(lease)
    return out


def harvest_isc(lease_file: str = "/var/lib/dhcp/dhcpd.leases",
                *, read_fn: Optional[Callable[[str], str]] = None,
                ) -> DhcpHarvestResult:
    """Parse an ISC dhcpd lease file. Default location for Debian/Ubuntu."""
    started = datetime.now(timezone.utc).isoformat()
    res = DhcpHarvestResult(source="isc-dhcpd", started_at=started,
                            finished_at="")
    reader = read_fn or _default_read
    try:
        text = reader(lease_file)
    except Exception as e:
        res.error = f"failed to read {lease_file}: {e}"
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.leases = parse_isc_leases_text(text)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


def _default_read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# ----------------------------------------------------- Windows DHCP

# Output of `Get-DhcpServerv4Lease -ScopeId X -AllLeases | ConvertTo-Csv`
# is a CSV with at least: IPAddress, ClientId (MAC), HostName, AddressState,
# LeaseExpiryTime. We accept that CSV directly.

import csv
from io import StringIO


def parse_windows_dhcp_csv(csv_text: str) -> list[DhcpLease]:
    out: list[DhcpLease] = []
    rdr = csv.DictReader(StringIO(csv_text))
    for row in rdr:
        ip = (row.get("IPAddress") or "").strip()
        if not ip:
            continue
        out.append(DhcpLease(
            ip=ip,
            mac=(row.get("ClientId") or "").lower().replace("-", ":"),
            hostname=(row.get("HostName") or "").strip(),
            state=(row.get("AddressState") or "active").lower(),
            ends=(row.get("LeaseExpiryTime") or "").strip(),
        ))
    return out


def harvest_windows(*, csv_text: Optional[str] = None,
                    powershell_fn: Optional[Callable[[], str]] = None,
                    ) -> DhcpHarvestResult:
    """Pull leases from a Windows DHCP server.

    If ``csv_text`` is supplied, parse that. Otherwise shell out to
    PowerShell (must be on the DHCP host or have remoting set up).
    """
    started = datetime.now(timezone.utc).isoformat()
    res = DhcpHarvestResult(source="windows-dhcp", started_at=started,
                            finished_at="")
    if csv_text is None:
        runner = powershell_fn or _default_powershell
        try:
            csv_text = runner()
        except Exception as e:
            res.error = str(e)
            res.finished_at = datetime.now(timezone.utc).isoformat()
            return res
    res.leases = parse_windows_dhcp_csv(csv_text)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


def _default_powershell() -> str:
    if not shutil.which("powershell") and not shutil.which("pwsh"):
        raise RuntimeError(
            "powershell/pwsh not found. Run SafeCadence on the DHCP server "
            "or pass leases via the csv_text parameter."
        )
    cmd = ["powershell", "-NoProfile", "-Command",
           "Get-DhcpServerv4Scope | ForEach-Object { "
           "Get-DhcpServerv4Lease -ScopeId $_.ScopeId -AllLeases } "
           "| ConvertTo-Csv -NoTypeInformation"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "powershell failed")
    return out.stdout


# --------------------------------------------------- → DiscoveredHost-shape

def leases_as_discovered_hosts(result: DhcpHarvestResult) -> list[dict]:
    out: list[dict] = []
    for L in result.leases:
        # vendor-class fingerprint heuristic
        vc = L.vendor_class.lower()
        vendor_guess = ""
        os_guess = ""
        dev_type = "unknown"
        if "msft" in vc or "windows" in vc:
            vendor_guess = "microsoft"; os_guess = "windows"; dev_type = "server"
        elif "android" in vc:
            vendor_guess = "google"; os_guess = "android"; dev_type = "mobile"
        elif "appletv" in vc or "apple" in vc:
            vendor_guess = "apple"; dev_type = "media"
        elif "udhcp" in vc:                         # busybox → IoT/embedded
            dev_type = "iot"
        elif "dhcpcd" in vc:
            os_guess = "linux"; dev_type = "server"
        out.append({
            "ip": L.ip,
            "hostname": L.hostname,
            "mac": L.mac,
            "vendor_guess": vendor_guess,
            "os_guess": os_guess,
            "device_type_guess": dev_type,
            "snmp_sysdescr": "",
            "open_ports": [],
            "banners": {
                "_via": f"dhcp ({result.source})",
                "_state": L.state,
                "_starts": L.starts,
                "_ends": L.ends,
                "_vendor_class": L.vendor_class,
            },
        })
    return out
