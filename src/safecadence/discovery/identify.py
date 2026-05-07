"""
Banner-grab + heuristic vendor / OS / device-type identification.

Pure-stdlib. Talks TCP only — no SNMP MIB walking, no SSH key-exchange,
no NSE-style probing. The goal is fast, polite identification.
"""

from __future__ import annotations

import re
import socket


_BANNER_PORTS = (
    (22,  "ssh"),     # SSH banner exposes server identity 99% of the time
    (23,  "telnet"),  # Cisco/Aruba/etc print device banner before login
    (80,  "http"),
    (443, "https"),
    (8080,"http"),
    (8443,"https"),
)


def _grab_banner(ip: str, port: int, *, timeout: float = 1.0) -> str:
    """Open a TCP socket, read up to 256 bytes, close. Return decoded banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 443, 8443):
                # Send a minimal HTTP HEAD to elicit Server: header
                payload = b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                try:
                    s.sendall(payload)
                except OSError:
                    return ""
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def grab_banners(ip: str, ports: list[int], *, timeout: float = 1.0) -> dict[int, str]:
    """Grab banners on the subset of `ports` we know how to probe."""
    out: dict[int, str] = {}
    probe_ports = {p for p, _ in _BANNER_PORTS}
    for port in ports:
        if port in probe_ports:
            b = _grab_banner(ip, port, timeout=timeout)
            if b:
                out[port] = b[:200]
    return out


# ------------------------------------------------------------------ #
# Heuristic vendor / OS / device-type guessing                        #
# ------------------------------------------------------------------ #
_VENDOR_RULES: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, vendor, os_guess, device_type_guess)
    (re.compile(r"Cisco IOS XE", re.I),                "Cisco",         "ios-xe", "router"),
    (re.compile(r"Cisco Adaptive Security Appliance", re.I), "Cisco",   "asa",    "firewall"),
    (re.compile(r"Cisco Nexus", re.I),                 "Cisco",         "nxos",   "switch"),
    (re.compile(r"Cisco IOS Software", re.I),          "Cisco",         "ios",    "switch"),
    (re.compile(r"Cisco-IOS", re.I),                   "Cisco",         "ios",    "switch"),
    (re.compile(r"OpenSSH.*Cisco", re.I),              "Cisco",         "ios",    "switch"),
    (re.compile(r"ArubaOS", re.I),                     "Aruba",         "aos-cx", "switch"),
    (re.compile(r"ArubaOS-CX", re.I),                  "Aruba",         "aos-cx", "switch"),
    (re.compile(r"Aruba.*Mobility Controller", re.I),  "Aruba",         "arubaos","wlc"),
    (re.compile(r"HPE.*ProCurve", re.I),               "HP",            "procurve","switch"),
    (re.compile(r"Arista Networks EOS", re.I),         "Arista",        "eos",    "switch"),
    (re.compile(r"Juniper.*JUNOS", re.I),              "Juniper",       "junos",  "router"),
    (re.compile(r"Junos:", re.I),                      "Juniper",       "junos",  "router"),
    (re.compile(r"FortiGate", re.I),                   "Fortinet",      "fortios","firewall"),
    (re.compile(r"FortiOS", re.I),                     "Fortinet",      "fortios","firewall"),
    (re.compile(r"PAN-OS", re.I),                      "Palo Alto Networks","panos","firewall"),
    (re.compile(r"MikroTik", re.I),                    "MikroTik",      "routeros","router"),
    (re.compile(r"RouterOS", re.I),                    "MikroTik",      "routeros","router"),
    (re.compile(r"UBNT", re.I),                        "Ubiquiti",      "edgeos", "router"),
    (re.compile(r"Meraki", re.I),                      "Cisco Meraki",  "meraki", "switch"),
    (re.compile(r"OpenSSH.*Ubuntu", re.I),             "Ubuntu Linux",  "linux",  "server"),
    (re.compile(r"OpenSSH.*Debian", re.I),             "Debian Linux",  "linux",  "server"),
    (re.compile(r"OpenSSH", re.I),                     "Linux",         "linux",  "server"),
    (re.compile(r"Microsoft-IIS", re.I),               "Microsoft",     "windows","server"),
    (re.compile(r"nginx", re.I),                       "Linux",         "linux",  "server"),
    (re.compile(r"Apache", re.I),                      "Linux",         "linux",  "server"),
    (re.compile(r"HP Color LaserJet|HP LaserJet", re.I),"HP",           "printer","printer"),
    (re.compile(r"Brother", re.I),                     "Brother",       "printer","printer"),
    (re.compile(r"Hikvision", re.I),                   "Hikvision",     "iot",    "iot"),
    (re.compile(r"Axis Communications", re.I),         "Axis",          "iot",    "iot"),
]


def guess_from_banners(banners: dict[int, str]) -> tuple[str, str, str]:
    """
    Inspect every banner and return (vendor, os, device_type) — strongest
    match wins. Returns empty strings if nothing matched.
    """
    text = "\n".join(banners.values())
    for pattern, vendor, os_guess, dt_guess in _VENDOR_RULES:
        if pattern.search(text):
            return vendor, os_guess, dt_guess
    return "", "", ""


def guess_combined(banners: dict[int, str], oui_vendor: str) -> tuple[str, str, str]:
    """
    Combine banner heuristics with OUI vendor. OUI alone tells us the
    hardware maker; banner + open ports tell us what's running.
    """
    v, os_guess, dt = guess_from_banners(banners)
    # Banner data is more authoritative than OUI for OS/role determination
    if v:
        return v, os_guess, dt
    if oui_vendor:
        return oui_vendor, "unknown", "network" if any(k in oui_vendor.lower() for k in (
            "cisco", "aruba", "hp", "juniper", "arista", "fortinet",
            "palo alto", "ubiquiti", "mikrotik", "meraki",
        )) else "unknown"
    return "", "", ""
