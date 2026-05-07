"""
Linux server config parser.

Expects a concatenated dump produced by `safecadence-collect.sh` (the helper
script ships with /examples). Sections are headed by `==== <section> ====`.
Sections we look for:
  /etc/os-release
  /etc/hostname
  uname -a
  /etc/ssh/sshd_config
  /etc/sysctl.conf
  systemctl list-unit-files --state=enabled
  iptables-save
"""

from __future__ import annotations

import re

from safecadence.core.schema import ParsedConfig


_HOSTNAME_RE = re.compile(r"==== /etc/hostname ====\s*\n([^\n]+)", re.IGNORECASE)
_HOSTNAME_FB = re.compile(r"^[\w.-]+", re.MULTILINE)
_OSREL_RE    = re.compile(r"==== /etc/os-release ====([\s\S]*?)====")
_PRETTY_RE   = re.compile(r'PRETTY_NAME="([^"]+)"')
_VERSION_RE  = re.compile(r'VERSION_ID="?([\w.\-]+)"?')


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)):
        hostname = m.group(1).strip()

    pretty = ""
    version = ""
    if (m := _OSREL_RE.search(text)):
        block = m.group(1)
        if (pm := _PRETTY_RE.search(block)):
            pretty = pm.group(1)
        if (vm := _VERSION_RE.search(block)):
            version = vm.group(1)

    return ParsedConfig(
        vendor="linux-server",
        device_type="server",
        hostname=hostname,
        os="linux",
        version=version,
        model=pretty,
        raw_config=text,
    )
