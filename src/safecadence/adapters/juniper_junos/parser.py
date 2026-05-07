"""Juniper Junos `show configuration` parser (curly-brace style)."""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, ParsedConfig


_HOSTNAME_RE = re.compile(r"host-name\s+(\S+);", re.IGNORECASE)
_VERSION_RE  = re.compile(r"##\s*Last\s+commit:.*?Junos:\s*(\S+)", re.IGNORECASE | re.DOTALL)
_VERSION_FB  = re.compile(r"version\s+(\S+);", re.IGNORECASE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1).rstrip(";")

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)
    elif (m := _VERSION_FB.search(text)):
        version = m.group(1).rstrip(";")

    interfaces: list[Interface] = []
    # Junos `interfaces { <name> { unit 0 { family inet { address X/Y } } } }`
    iface_blocks = re.finditer(
        r"^\s*([a-z]+-?\d+/\d+/\d+|[a-z]+\d+|ge-\d+/\d+/\d+|xe-\d+/\d+/\d+|et-\d+/\d+/\d+|me\d+|fxp\d+)\s*\{(.*?)^\s*\}",
        text, re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    for m in iface_blocks:
        name = m.group(1)
        body = m.group(2) or ""
        desc = ""
        if (dm := re.search(r'description\s+"?([^";\n]+)"?;', body)):
            desc = dm.group(1).strip()
        ip = ""
        if (im := re.search(r"address\s+(\d+\.\d+\.\d+\.\d+)/\d+", body)):
            ip = im.group(1)
        admin_up = "disable;" not in body
        interfaces.append(Interface(name=name, description=desc, ip=ip, admin_up=admin_up))

    return ParsedConfig(
        vendor="juniper-junos",
        device_type="router",
        hostname=hostname,
        os="junos",
        version=version,
        interfaces=interfaces,
        raw_config=text,
    )
