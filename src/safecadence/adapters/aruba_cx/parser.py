"""Aruba CX (AOS-CX) running-config parser."""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, ParsedConfig


_HOSTNAME_RE  = re.compile(r"^hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_VERSION_RE   = re.compile(r"^!Version\s+(?:ArubaOS-CX\s+)?(\S+)", re.MULTILINE | re.IGNORECASE)
_INT_BLOCK_RE = re.compile(
    r"^interface\s+(\S+)\s*$(.*?)(?=^interface\s+\S+\s*$|^!\s*$|\Z)",
    re.MULTILINE | re.DOTALL | re.IGNORECASE,
)
_DESC_RE      = re.compile(r"^\s*description\s+(.+)$", re.MULTILINE)
_IP_RE        = re.compile(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)/\d+", re.MULTILINE)
_VLAN_RE      = re.compile(r"^\s*vlan\s+access\s+(\d+)", re.MULTILINE)
_SHUT_RE      = re.compile(r"^\s*shutdown\s*$", re.MULTILINE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1)

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)

    interfaces: list[Interface] = []
    for blk in _INT_BLOCK_RE.finditer(text):
        name = blk.group(1)
        body = blk.group(2) or ""
        desc = ""
        if (m := _DESC_RE.search(body)):
            desc = m.group(1).strip()
        ip = ""
        if (m := _IP_RE.search(body)):
            ip = m.group(1)
        vlan = None
        if (m := _VLAN_RE.search(body)):
            try:
                vlan = int(m.group(1))
            except ValueError:
                pass
        # AOS-CX defaults to admin DOWN; "no shutdown" indicates up
        admin_up = "no shutdown" in body.lower() or not bool(_SHUT_RE.search(body))
        interfaces.append(Interface(
            name=name, description=desc, ip=ip, vlan=vlan, admin_up=admin_up,
        ))

    return ParsedConfig(
        vendor="aruba-cx",
        device_type="switch",
        hostname=hostname,
        os="aos-cx",
        version=version,
        interfaces=interfaces,
        raw_config=text,
    )
