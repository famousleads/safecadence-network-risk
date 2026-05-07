"""
Optional Nmap wrapper for discovery.

Falls back gracefully when nmap is not installed. Parses Nmap's `-oX` (XML)
output via stdlib ElementTree — no python-nmap dependency.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List

from safecadence.discovery.asset import DiscoveredHost


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(target: str, *, ports: str = "22,23,80,161,443,445,3389,8443",
              timeout: int = 300, top_ports: int | None = None,
              extra_args: list | None = None) -> List[DiscoveredHost]:
    """
    Run nmap against `target` (CIDR / IP / hostname) and return DiscoveredHost
    records. Uses -sS/-sT TCP scan + service banner detection (-sV).

    Requires `nmap` on PATH. Raises FileNotFoundError otherwise.
    """
    if not nmap_available():
        raise FileNotFoundError(
            "nmap not found on PATH. Install with: brew install nmap (macOS) or "
            "apt install nmap (Debian/Ubuntu). Falling back to TCP-only sweep is the "
            "default behaviour of `safecadence discover`."
        )

    args = ["nmap", "-T4", "-Pn", "-sV", "-oX", "-"]
    if top_ports:
        args += ["--top-ports", str(top_ports)]
    else:
        args += ["-p", ports]
    if extra_args:
        args += list(extra_args)
    args.append(target)

    try:
        out = subprocess.run(args, capture_output=True, text=True,
                             timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return []

    if not out.stdout:
        return []

    try:
        root = ET.fromstring(out.stdout)
    except ET.ParseError:
        return []

    hosts: list[DiscoveredHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        hostname = ""
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        open_ports: list[int] = []
        banners: dict[int, str] = {}
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                p = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            open_ports.append(p)
            svc = port_el.find("service")
            if svc is not None:
                product = svc.get("product", "") or ""
                version = svc.get("version", "") or ""
                extra   = svc.get("extrainfo", "") or ""
                banner = " ".join(filter(None, [product, version, extra])).strip()
                if banner:
                    banners[p] = banner

        # Heuristic guesses
        os_guess = ""
        os_match = host_el.find("os/osmatch")
        if os_match is not None:
            os_guess = os_match.get("name", "")

        hosts.append(DiscoveredHost(
            ip=ip, hostname=hostname, mac=mac,
            vendor_guess=vendor, os_guess=os_guess,
            device_type_guess="",
            open_ports=open_ports, banners=banners,
        ))

    return hosts
