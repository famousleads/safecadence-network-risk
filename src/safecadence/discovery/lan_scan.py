"""
LAN deep-scan — finds every device on the local network using multiple sources,
not just TCP probes.

Sources combined:
  1. ARP cache               — every L2-adjacent host the kernel has seen,
                                including ones that don't open any TCP ports
                                (printers in standby, sleeping IoT, mobile
                                phones, etc.)
  2. mDNS / Bonjour           — every device announcing services on .local
                                (Apple devices, IoT, AirPrint, Chromecast, …)
  3. TCP port probes          — DEFAULT_PORTS or EXTENDED_PORTS depending on mode
  4. TLS certificate subject  — for HTTPS targets, pulls CN/Subject from the
                                handshake to identify device model
  5. HTTP title-tag scrape    — Server header + <title> from "/" reveals vendor

All pure-stdlib. No nmap, no scapy, no root required.

Public entry point:
    deep_scan(cidr, *, mode="lan_deep") -> DiscoveryResult
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from safecadence.discovery.asset import DiscoveredHost, DiscoveryResult
from safecadence.discovery.categorize import categorize_device, score_device_risk
from safecadence.discovery.oui import vendor_for
from safecadence.discovery.snmp_probe import parse_sysdescr, snmp_get_sysdescr
from safecadence.discovery.sweep import (
    DEFAULT_PORTS,
    EXTENDED_PORTS,
    sweep_host,
)

# Standard mDNS multicast address + port
_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT = 5353


# ---------------------------------------------------------------- ARP cache reading
def read_arp_cache() -> list[tuple[str, str]]:
    """
    Return [(ip, mac), ...] for every entry in the local ARP cache.
    Cross-platform: tries /proc/net/arp (Linux) then falls back to `arp -an`
    output parsing (macOS, BSD, Windows-WSL).
    """
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Linux fast path
    try:
        with open("/proc/net/arp", "r") as fh:
            lines = fh.readlines()[1:]  # skip header
        for line in lines:
            cols = line.split()
            if len(cols) >= 4:
                ip, hw_type, flags, mac = cols[0], cols[1], cols[2], cols[3]
                if mac != "00:00:00:00:00:00" and ip not in seen:
                    entries.append((ip, mac.lower()))
                    seen.add(ip)
        if entries:
            return entries
    except OSError:
        pass

    # macOS / BSD / fallback: parse `arp -an` output
    # Output looks like:
    #   ? (192.168.4.1) at 28:80:88:xx:xx:xx on en0 ifscope [ethernet]
    try:
        out = subprocess.run(
            ["arp", "-an"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return entries

    pattern = re.compile(
        r"\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]{11,17})"
    )
    for line in out.splitlines():
        m = pattern.search(line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            if mac in ("(incomplete)", "ff:ff:ff:ff:ff:ff") or ip in seen:
                continue
            # Pad short MAC fields like 1:2:3:4:5:6 → 01:02:03:04:05:06
            parts = mac.split(":")
            if len(parts) == 6:
                mac = ":".join(p.zfill(2) for p in parts)
                entries.append((ip, mac))
                seen.add(ip)

    return entries


# ---------------------------------------------------------------- mDNS sweep
def mdns_sweep(timeout: float = 3.0) -> list[dict]:
    """
    Send a one-shot mDNS query for `_services._dns-sd._udp.local` and listen
    for replies. Returns list of {ip, hostname, services} dicts.

    This finds Bonjour devices: Apple gear, AirPrint printers, Chromecast,
    Sonos, smart-home hubs, etc. Many of these don't open any "interesting"
    TCP ports, so ARP + mDNS together find ~100% of an active LAN.
    """
    devices: dict[str, dict] = {}

    # Build mDNS query for PTR _services._dns-sd._udp.local
    # DNS header (12 bytes): id=0, flags=0 (query), qdcount=1
    header = struct.pack(">6H", 0, 0, 1, 0, 0, 0)
    # Encode the question name as length-prefixed labels
    name_parts = [b"_services", b"_dns-sd", b"_udp", b"local"]
    qname = b"".join(bytes([len(p)]) + p for p in name_parts) + b"\x00"
    # qtype=PTR (12), qclass=IN (1)
    question = qname + struct.pack(">HH", 12, 1)
    payload = header + question

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.bind(("", 0))
        sock.sendto(payload, (_MDNS_GROUP, _MDNS_PORT))
        sock.settimeout(0.4)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            ip = addr[0]
            # We don't fully parse the response (would need a full DNS parser).
            # Just record the responder IP and any service-typed labels we
            # can pick out of the body.
            if ip not in devices:
                devices[ip] = {"ip": ip, "hostname": "", "services": set()}
            try:
                s = data.decode("ascii", errors="replace")
                # Look for ".local" hostnames in the response
                hosts = re.findall(r"([a-zA-Z0-9\-]{1,63})\.local", s)
                if hosts and not devices[ip]["hostname"]:
                    devices[ip]["hostname"] = hosts[0] + ".local"
                # Look for service type labels like _http._tcp, _airplay._tcp
                for svc in re.findall(r"_([a-z0-9\-]{1,30})\._tcp", s):
                    devices[ip]["services"].add(svc)
                for svc in re.findall(r"_([a-z0-9\-]{1,30})\._udp", s):
                    devices[ip]["services"].add(svc)
            except Exception:
                pass
    except Exception:
        return list(devices.values())
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    out = []
    for d in devices.values():
        d["services"] = sorted(d["services"])
        out.append(d)
    return out


# ---------------------------------------------------------------- TLS cert inspection
def tls_cert_subject(ip: str, port: int = 443, *, timeout: float = 2.0) -> dict:
    """
    Connect to HTTPS port, do TLS handshake, return subject CN / SANs / issuer.
    Many devices use self-signed certs whose subject is the device model.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return {}
                # Use stdlib to parse — it gives us a dict if we asked nicely
                cert = tls.getpeercert()  # may be empty dict if not verified
                # Even with verify off, getpeercert() can return parsed dict
                # in newer Python; if not, fall back to OID-level parsing via
                # ssl._ssl._test_decode_cert (private API, fragile). Skip that.
                subject_cn = ""
                issuer_cn = ""
                for tup in cert.get("subject", ()):
                    for k, v in tup:
                        if k == "commonName":
                            subject_cn = v
                for tup in cert.get("issuer", ()):
                    for k, v in tup:
                        if k == "commonName":
                            issuer_cn = v
                return {
                    "subject_cn": subject_cn,
                    "issuer_cn": issuer_cn,
                    "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
                }
    except Exception:
        return {}


# ---------------------------------------------------------------- HTTP page scrape
def http_title(ip: str, port: int = 80, *, timeout: float = 2.0, https: bool = False) -> dict:
    """
    GET / and parse <title> + Server header. Returns a dict with what was found.
    Many home gateways and printers show their model as the page title.
    """
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s.settimeout(timeout)
                    s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: safecadence/1.0\r\n\r\n")
                    data = s.recv(8192)
        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: safecadence/1.0\r\n\r\n")
                data = s.recv(8192)
    except Exception:
        return {}
    text = data.decode("utf-8", errors="replace")
    server = ""
    title = ""
    for line in text.splitlines():
        ll = line.lower()
        if ll.startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.IGNORECASE | re.DOTALL)
    if m:
        title = m.group(1).strip()
    return {"server_header": server, "page_title": title}


# ---------------------------------------------------------------- main entry
def deep_scan(
    cidr: str,
    *,
    mode: str = "lan_deep",
    workers: int = 64,
    timeout: float = 1.0,
    use_mdns: bool = True,
    use_arp: bool = True,
    on_host=None,
    on_progress=None,
) -> DiscoveryResult:
    """
    LAN deep scan — combines ARP + mDNS + TCP probes for maximal coverage
    + identification.

    mode:
      "quick"     → DEFAULT_PORTS, no ARP, no mDNS (same as discover_subnet)
      "extended"  → EXTENDED_PORTS, no ARP, no mDNS
      "lan_deep"  → EXTENDED_PORTS + ARP cache + mDNS + TLS cert + HTTP title
                    (the recommended mode for "find everything on my LAN")

    Streaming hooks (both optional, used by /api/discover/stream for SSE):
      on_host(host)               — fires once per fully-enriched DiscoveredHost
      on_progress(scanned, total) — fires after each TCP probe completes
    """
    started = datetime.now(timezone.utc)
    started_iso = started.isoformat()

    # Pick port set
    if mode == "quick":
        ports = DEFAULT_PORTS
        use_arp = False
        use_mdns = False
    elif mode == "extended":
        ports = EXTENDED_PORTS
        use_arp = False
        use_mdns = False
    else:  # lan_deep
        ports = EXTENDED_PORTS

    # Phase 1: build target IP list
    network = ipaddress.ip_network(cidr, strict=False)
    targets: list[str] = [str(ip) for ip in network.hosts()]

    # Add IPs from ARP cache (may include hosts outside the CIDR — those we drop)
    arp_pairs: list[tuple[str, str]] = []
    if use_arp:
        arp_pairs = read_arp_cache()
        # Restrict ARP-discovered IPs to the requested subnet
        arp_pairs = [(ip, mac) for ip, mac in arp_pairs
                     if ipaddress.ip_address(ip) in network]
        # Add ARP IPs to scan list (may already be there)
        for ip, _ in arp_pairs:
            if ip not in targets:
                targets.append(ip)

    # Phase 2: mDNS in parallel with TCP scan
    mdns_results: list[dict] = []
    if use_mdns:
        try:
            mdns_results = mdns_sweep(timeout=2.5)
            for d in mdns_results:
                if d["ip"] not in targets and ipaddress.ip_address(d["ip"]) in network:
                    targets.append(d["ip"])
        except Exception:
            mdns_results = []

    # Phase 3: TCP probe every target
    hosts: list[DiscoveredHost] = []
    arp_map = {ip: mac for ip, mac in arp_pairs}
    mdns_map = {d["ip"]: d for d in mdns_results}

    total = len(targets)
    scanned = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(sweep_host, ip, ports=ports, timeout=timeout): ip
            for ip in targets
        }
        for fut in as_completed(futures):
            ip = futures[fut]
            scanned += 1
            if on_progress:
                try: on_progress(scanned, total)
                except Exception: pass
            try:
                h = fut.result()
            except Exception:
                h = None

            # If TCP sweep returned None but we know the host exists from
            # ARP / mDNS, synthesize a DiscoveredHost so it shows up
            if h is None and (ip in arp_map or ip in mdns_map):
                h = DiscoveredHost(ip=ip)

            if h is None:
                continue

            # Enrich with ARP MAC + OUI vendor
            if ip in arp_map:
                h.mac = arp_map[ip]
                if not h.vendor_guess:
                    v = vendor_for(h.mac)
                    if v:
                        h.vendor_guess = v

            # Enrich with mDNS hostname + services
            if ip in mdns_map:
                m = mdns_map[ip]
                if not h.hostname and m.get("hostname"):
                    h.hostname = m["hostname"]
                if m.get("services"):
                    # Encode services into the device_type_guess if empty
                    svcs = m["services"]
                    if not h.device_type_guess:
                        if "airplay" in svcs or "raop" in svcs:
                            h.device_type_guess = "media"
                        elif "ipp" in svcs or "ipps" in svcs or "printer" in svcs:
                            h.device_type_guess = "printer"
                        elif "homekit" in svcs:
                            h.device_type_guess = "smart-home"
                        elif "ssh" in svcs:
                            h.device_type_guess = "server"

            # Enrich HTTPS hosts with TLS cert subject
            if mode == "lan_deep" and (443 in h.open_ports or 8443 in h.open_ports):
                port = 443 if 443 in h.open_ports else 8443
                cert = tls_cert_subject(ip, port=port, timeout=1.0)
                if cert.get("subject_cn") and not h.vendor_guess:
                    h.vendor_guess = f"TLS:{cert['subject_cn']}"
                if cert and not h.banners.get(port):
                    h.banners[port] = f"TLS subject_cn={cert.get('subject_cn','')} issuer_cn={cert.get('issuer_cn','')}"

            # Enrich HTTP hosts with page title
            if mode == "lan_deep" and (80 in h.open_ports or 8080 in h.open_ports):
                port = 80 if 80 in h.open_ports else 8080
                t = http_title(ip, port=port, timeout=1.0)
                if t.get("page_title") and not h.banners.get(port):
                    h.banners[port] = f"title=\"{t['page_title']}\" server=\"{t.get('server_header','')}\""
                if t.get("page_title") and not h.vendor_guess:
                    h.vendor_guess = f"HTTP:{t['page_title'][:60]}"

            # SNMP v2c sysDescr probe — biggest identification win for network gear
            sysd_result = {}
            sysd_parsed = {}
            if mode == "lan_deep":
                # Try SNMP if 161 is open OR if device looks like network gear
                if 161 in h.open_ports or h.device_type_guess in ("router", "switch", "firewall"):
                    try:
                        sysd_result = snmp_get_sysdescr(ip, timeout=1.0)
                    except Exception:
                        sysd_result = {}
                    if sysd_result.get("ok"):
                        sysd_parsed = parse_sysdescr(sysd_result.get("sys_descr", ""))
                        # Stash the full sysDescr in banners so the UI can show it
                        h.banners[161] = f"sysDescr={sysd_result.get('sys_descr','')[:200]}"
                        if sysd_result.get("sys_name") and not h.hostname:
                            h.hostname = sysd_result["sys_name"]
                        if sysd_parsed.get("vendor") and not h.vendor_guess:
                            h.vendor_guess = sysd_parsed["vendor"]
                        if sysd_parsed.get("os") and not h.os_guess:
                            h.os_guess = sysd_parsed["os"]
                        # snmp_sysdescr field on DiscoveredHost
                        h.snmp_sysdescr = sysd_result.get("sys_descr", "")[:500]

            # Categorization — assign device class
            category = categorize_device(h, sysd_parsed)
            if not h.device_type_guess:
                h.device_type_guess = category

            # Risk scoring — attach to banners as a special "risk" key for UI to read
            risk = score_device_risk(h, sysd_result if sysd_result.get("ok") else None)
            # Stash risk + findings on the host object as attributes (DiscoveredHost is
            # a dataclass so we can't add fields without breaking; use banners dict)
            # The UI reads these via the api response's separate risk_* keys we add below.
            h.banners["__category__"] = category
            h.banners["__risk_score__"] = str(risk["score"])
            h.banners["__risk_band__"] = risk["band"]
            h.banners["__risk_findings__"] = "␟".join(risk["findings"])  # ␟ = unit separator
            h.banners["__risk_actions__"] = "␟".join(risk["recommended_actions"])

            hosts.append(h)
            if on_host:
                try: on_host(h)
                except Exception: pass

    finished = datetime.now(timezone.utc)
    hosts.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))

    return DiscoveryResult(
        subnet=str(network),
        started_at=started_iso,
        finished_at=finished.isoformat(),
        duration_ms=int((finished - started).total_seconds() * 1000),
        hosts_scanned=len(targets),
        hosts_responding=len(hosts),
        hosts=hosts,
    )
