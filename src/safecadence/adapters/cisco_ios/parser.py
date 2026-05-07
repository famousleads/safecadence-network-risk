"""
Cisco IOS / IOS-XE running-config parser.

Pure-stdlib regex parser. Extracts hostname, version, model, interfaces,
neighbors hints, and exposes the raw config text to engines.
"""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, Neighbor, ParsedConfig


_HOSTNAME_RE   = re.compile(r"^hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_VERSION_RE    = re.compile(r"^version\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_VERSION_BANR  = re.compile(r"Cisco IOS (?:Software|XE Software).*?Version\s+([\w\.\(\)]+)", re.IGNORECASE)
_MODEL_BANNER  = re.compile(r"cisco\s+(\S+)\s+\(.*?\)\s+processor", re.IGNORECASE)
_OS_TYPE_RE    = re.compile(r"\bIOS-XE\b|\bIOS\sSoftware\b|\bNX-OS\b|\bASA\sVersion\b", re.IGNORECASE)
_INT_BLOCK_RE  = re.compile(
    r"^interface\s+(\S+)\s*$(.*?)(?=^interface\s+\S+\s*$|^!\s*$|\Z)",
    re.MULTILINE | re.DOTALL | re.IGNORECASE,
)
_DESC_RE       = re.compile(r"^\s*description\s+(.+)$", re.MULTILINE)
_IP_RE         = re.compile(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", re.MULTILINE)
_VLAN_ACCESS_RE= re.compile(r"^\s*switchport\s+access\s+vlan\s+(\d+)", re.MULTILINE)
_SHUT_RE       = re.compile(r"^\s*shutdown\s*$", re.MULTILINE)


def detect_os(text: str) -> str:
    if not text:
        return "ios"
    s = text.lower()
    # Order matters: more-specific tokens first.
    if "ios xe software" in s or "ios-xe" in s:
        return "ios-xe"
    if "nx-os" in s:
        return "nxos"
    if "asa version" in s:
        return "asa"
    return "ios"


def parse(text: str) -> ParsedConfig:
    """Parse a Cisco IOS / IOS-XE running config."""
    text = text or ""

    hostname = ""
    m = _HOSTNAME_RE.search(text)
    if m:
        hostname = m.group(1)

    version = ""
    m = _VERSION_BANR.search(text)
    if m:
        version = m.group(1)
    elif (m := _VERSION_RE.search(text)) is not None:
        version = m.group(1)

    model = ""
    m = _MODEL_BANNER.search(text)
    if m:
        model = m.group(1)

    os_type = detect_os(text)

    interfaces: list[Interface] = []
    for blk_match in _INT_BLOCK_RE.finditer(text):
        name = blk_match.group(1)
        block = blk_match.group(2) or ""
        desc = ""
        if (m := _DESC_RE.search(block)) is not None:
            desc = m.group(1).strip()
        ip = ""
        if (m := _IP_RE.search(block)) is not None:
            ip = m.group(1)
        vlan_id: int | None = None
        if (m := _VLAN_ACCESS_RE.search(block)) is not None:
            try:
                vlan_id = int(m.group(1))
            except ValueError:
                pass
        admin_up = not bool(_SHUT_RE.search(block))
        interfaces.append(Interface(
            name=name, description=desc, ip=ip, vlan=vlan_id, admin_up=admin_up
        ))

    return ParsedConfig(
        vendor="cisco",
        device_type="switch" if any(i.vlan is not None for i in interfaces) else "router",
        hostname=hostname,
        model=model,
        os=os_type,
        version=version,
        interfaces=interfaces,
        neighbors=[],   # populated only when LLDP/CDP show output is present
        raw_config=text,
    )
