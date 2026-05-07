"""ESXi config parser — `esxcli system version get`, `esxcli system settings advanced list`."""

from __future__ import annotations

import re

from safecadence.core.schema import ParsedConfig


_HOSTNAME_RE = re.compile(r"esxcli system hostname.*?HostName:\s*(\S+)", re.IGNORECASE | re.DOTALL)
_VERSION_RE  = re.compile(r"Version:\s*(\d+\.\d+\.\d+)", re.IGNORECASE)
_BUILD_RE    = re.compile(r"Build:\s*Releasebuild-(\d+)", re.IGNORECASE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1)

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)
        if (b := _BUILD_RE.search(text)):
            version += f" build {b.group(1)}"

    return ParsedConfig(
        vendor="vmware-esxi",
        device_type="hypervisor",
        hostname=hostname,
        os="esxi",
        version=version,
        raw_config=text,
    )
