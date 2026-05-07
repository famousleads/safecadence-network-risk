"""Cisco ASA running-config parser."""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, ParsedConfig


_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_VERSION_RE  = re.compile(r"ASA\s+Version\s+([\w\.\(\)]+)", re.IGNORECASE)
_INT_BLOCK_RE = re.compile(
    r"^interface\s+(\S+)\s*$(.*?)(?=^interface\s+\S+\s*$|^!\s*$|\Z)",
    re.MULTILINE | re.DOTALL | re.IGNORECASE,
)
_NAMEIF_RE = re.compile(r"^\s*nameif\s+(\S+)", re.MULTILINE)
_IP_RE     = re.compile(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)", re.MULTILINE)
_SHUT_RE   = re.compile(r"^\s*shutdown\s*$", re.MULTILINE)
_SECLVL_RE = re.compile(r"^\s*security-level\s+(\d+)", re.MULTILINE)


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
        nameif = ""
        if (m := _NAMEIF_RE.search(body)):
            nameif = m.group(1)
        ip = ""
        if (m := _IP_RE.search(body)):
            ip = m.group(1)
        sec = None
        if (m := _SECLVL_RE.search(body)):
            try:
                sec = int(m.group(1))
            except ValueError:
                pass
        admin_up = not bool(_SHUT_RE.search(body))
        interfaces.append(Interface(
            name=name,
            description=nameif,
            ip=ip,
            admin_up=admin_up,
            extra={"security_level": sec} if sec is not None else {},
        ))

    return ParsedConfig(
        vendor="cisco-asa",
        device_type="firewall",
        hostname=hostname,
        os="asa",
        version=version,
        interfaces=interfaces,
        raw_config=text,
    )
