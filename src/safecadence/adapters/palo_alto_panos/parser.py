"""Palo Alto PAN-OS `set` format config parser."""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, ParsedConfig


_HOSTNAME_RE = re.compile(r"set\s+deviceconfig\s+system\s+hostname\s+(\S+)", re.IGNORECASE)
_VERSION_RE  = re.compile(r"set\s+deviceconfig\s+system\s+software-version\s+(\S+)", re.IGNORECASE)
_VERSION_FB  = re.compile(r"PAN-OS\s+(\d+\.\d+\.\d+)", re.IGNORECASE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1).strip().rstrip(";")

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)
    elif (m := _VERSION_FB.search(text)):
        version = m.group(1)

    interfaces: list[Interface] = []
    seen_names: set[str] = set()
    for m in re.finditer(
        r"set\s+network\s+interface\s+ethernet\s+(ethernet\d+/\d+)\s+layer3\s+ip\s+(\d+\.\d+\.\d+\.\d+)/\d+",
        text, re.IGNORECASE,
    ):
        name = m.group(1)
        if name in seen_names:
            continue
        seen_names.add(name)
        interfaces.append(Interface(name=name, ip=m.group(2), admin_up=True))

    return ParsedConfig(
        vendor="palo-alto-panos",
        device_type="firewall",
        hostname=hostname,
        os="panos",
        version=version,
        interfaces=interfaces,
        raw_config=text,
    )
