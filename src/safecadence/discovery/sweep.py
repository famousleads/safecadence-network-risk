"""
Multi-threaded TCP subnet sweep.

Pure-stdlib, no raw sockets, no root required. Uses TCP-connect liveness
(ports 22, 23, 80, 443, 161, 8080, 8443) as a stand-in for ICMP — most
managed devices will accept a SYN on at least one of those.

Usage:
    from safecadence.discovery import discover_subnet
    result = discover_subnet("10.10.10.0/24", workers=64)
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import time
from datetime import datetime, timezone

from safecadence.discovery.asset import DiscoveredHost, DiscoveryResult
from safecadence.discovery.identify import grab_banners, guess_combined
from safecadence.discovery.oui import vendor_for


# Ports we probe to determine liveness + identify the device.
# Order matters slightly — we short-circuit on first response.
DEFAULT_PORTS: tuple[int, ...] = (22, 443, 80, 23, 8443, 8080, 161, 161)
EXTENDED_PORTS: tuple[int, ...] = (
    22, 23, 53, 80, 161, 443, 445, 631, 830, 873,
    902, 990, 992, 1900, 2049, 3306, 3389, 5060, 5985, 5986,
    8080, 8443, 8728, 8729, 9000, 9100, 9443,
)


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    """True if a TCP SYN+ACK comes back within `timeout` seconds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _reverse_dns(ip: str, *, timeout: float = 0.5) -> str:
    """Best-effort PTR lookup. Empty string on failure."""
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(None)


def _arp_lookup(ip: str) -> str:
    """
    Best-effort MAC lookup from local ARP cache. Returns '' if not in cache.

    This only works for L2-adjacent hosts. Useful when scanning your own
    LAN. We don't try to populate the ARP cache ourselves (that needs
    raw sockets) — but a successful TCP connect will populate it as a
    side effect, so subsequent lookups often succeed.
    """
    import os
    paths = ("/proc/net/arp", "/sbin/arp", "/usr/sbin/arp")
    # Linux fast path: read /proc/net/arp directly
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as fh:
                for line in fh.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and cols[0] == ip and cols[3] != "00:00:00:00:00:00":
                        return cols[3]
        except OSError:
            pass
    # macOS / generic fallback: shell out to `arp -n <ip>`
    try:
        import subprocess
        out = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True, timeout=2
        )
        for line in out.stdout.splitlines():
            # Mac:  ? (10.10.10.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            # Lin:  ? (10.10.10.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
            for tok in line.split():
                if tok.count(":") == 5 and len(tok) == 17:
                    return tok
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return ""


def sweep_host(
    ip: str,
    *,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 0.6,
    grab_banner: bool = True,
    reverse_dns: bool = True,
) -> DiscoveredHost | None:
    """
    Probe one IP. Returns None if the host doesn't respond on any port.
    """
    started = time.perf_counter()
    open_ports: list[int] = []

    # Probe each port; stop early if we've already found 3 open (fingerprint enough)
    for p in ports:
        if _tcp_open(ip, p, timeout):
            open_ports.append(p)
        if len(open_ports) >= 3:
            break

    if not open_ports:
        return None

    duration_ms = int((time.perf_counter() - started) * 1000)
    banners: dict[int, str] = {}
    if grab_banner:
        banners = grab_banners(ip, open_ports, timeout=timeout)

    mac = _arp_lookup(ip)
    oui_vendor = vendor_for(mac) if mac else ""
    vendor_guess, os_guess, dt_guess = guess_combined(banners, oui_vendor)

    hostname = _reverse_dns(ip) if reverse_dns else ""

    return DiscoveredHost(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor_guess=vendor_guess,
        os_guess=os_guess,
        device_type_guess=dt_guess,
        open_ports=open_ports,
        banners=banners,
        response_time_ms=duration_ms,
    )


def discover_subnet(
    cidr: str,
    *,
    workers: int = 64,
    timeout: float = 0.6,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    extended: bool = False,
    grab_banner: bool = True,
    reverse_dns: bool = True,
) -> DiscoveryResult:
    """
    Sweep an entire CIDR block for live hosts.

    `extended=True` probes the full EXTENDED_PORTS list — slower but catches
    devices that only listen on management-VRF ports.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if extended:
        ports = EXTENDED_PORTS

    started = time.perf_counter()
    started_iso = datetime.now(timezone.utc).isoformat()

    hosts: list[DiscoveredHost] = []
    targets = [str(ip) for ip in network.hosts()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                sweep_host, ip,
                ports=ports, timeout=timeout,
                grab_banner=grab_banner, reverse_dns=reverse_dns,
            ): ip
            for ip in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            host = fut.result()
            if host is not None:
                hosts.append(host)

    duration_ms = int((time.perf_counter() - started) * 1000)
    finished_iso = datetime.now(timezone.utc).isoformat()

    # Sort by IP for deterministic output
    hosts.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))

    return DiscoveryResult(
        subnet=str(network),
        started_at=started_iso,
        finished_at=finished_iso,
        duration_ms=duration_ms,
        hosts_scanned=len(targets),
        hosts_responding=len(hosts),
        hosts=hosts,
    )
