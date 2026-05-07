"""Fortinet FortiGate `show full-configuration` parser."""

from __future__ import annotations

import re

from safecadence.core.schema import Interface, ParsedConfig


_HOSTNAME_RE = re.compile(r"set\s+hostname\s+\"?([^\"\n]+)\"?", re.IGNORECASE)
_VERSION_RE  = re.compile(r"#config-version=\S*?-(\d+\.\d+\.\d+)", re.IGNORECASE)
_VERSION_FB  = re.compile(r"version\s+(\d[\d\.]+)", re.IGNORECASE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1).strip().rstrip("\"")

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)
    elif (m := _VERSION_FB.search(text)):
        version = m.group(1)

    interfaces: list[Interface] = []
    for m in re.finditer(
        r'edit\s+"([^"]+)"(.*?)next',
        text, re.DOTALL,
    ):
        block = m.group(2)
        if "set ip " not in block and "set vdom" not in block:
            continue
        name = m.group(1)
        ip = ""
        if (im := re.search(r"set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\.\d+\.\d+\.\d+", block)):
            ip = im.group(1)
        admin_up = "set status down" not in block
        interfaces.append(Interface(name=name, ip=ip, admin_up=admin_up))

    return ParsedConfig(
        vendor="fortinet-fortigate",
        device_type="firewall",
        hostname=hostname,
        os="fortios",
        version=version,
        interfaces=interfaces,
        raw_config=text,
    )
