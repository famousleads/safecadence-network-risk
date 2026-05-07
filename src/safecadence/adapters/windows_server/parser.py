"""
Windows server config parser.

Parses concatenated PowerShell exports:
  Get-ComputerInfo | Out-String
  Get-Service | Where-Object Status -eq 'Running'
  Get-NetFirewallProfile
  Get-LocalUser
  Get-SmbServerConfiguration
  Get-WindowsFeature -installed     (or Get-WindowsOptionalFeature)
"""

from __future__ import annotations

import re

from safecadence.core.schema import ParsedConfig


_HOSTNAME_RE = re.compile(r"CsName\s*[:=]\s*(\S+)", re.IGNORECASE)
_HOSTNAME_FB = re.compile(r"WindowsHostName\s*[:=]\s*(\S+)", re.IGNORECASE)
_PROD_RE     = re.compile(r"WindowsProductName\s*[:=]\s*([^\n\r]+)", re.IGNORECASE)
_VERSION_RE  = re.compile(r"WindowsVersion\s*[:=]\s*(\S+)", re.IGNORECASE)
_BUILD_RE    = re.compile(r"OsBuildNumber\s*[:=]\s*(\d+)", re.IGNORECASE)


def parse(text: str) -> ParsedConfig:
    text = text or ""
    hostname = ""
    if (m := _HOSTNAME_RE.search(text)) or (m := _HOSTNAME_FB.search(text)):
        hostname = m.group(1).strip()

    product = ""
    if (m := _PROD_RE.search(text)):
        product = m.group(1).strip()

    version = ""
    if (m := _VERSION_RE.search(text)):
        version = m.group(1)
    elif (m := _BUILD_RE.search(text)):
        version = "build " + m.group(1)

    return ParsedConfig(
        vendor="windows-server",
        device_type="server",
        hostname=hostname,
        os="windows",
        version=version,
        model=product,
        raw_config=text,
    )
