"""
Cisco IOS / IOS-XE adapter.

Wraps the regex parser and registers itself with the AdapterRegistry.
Detection is content-driven first, filename-driven second.
"""

from __future__ import annotations

from safecadence.adapters.cisco_ios import parser as ios_parser
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class CiscoIOSAdapter(BaseAdapter):
    slug = "cisco-ios"
    label = "Cisco IOS / IOS-XE"
    os_family = ["ios", "ios-xe", "nxos"]
    filename_hints = (
        "running-config",
        "running_config",
        "startup-config",
        "startup_config",
        "ios",
        "iosxe",
        "ios-xe",
        "show-run",
        "show_run",
    )
    content_hints = (
        "version 12.",
        "version 15.",
        "version 16.",
        "version 17.",
        "Cisco IOS Software",
        "Cisco IOS XE Software",
        "service password-encryption",
        "ip cef",
        "spanning-tree mode",
        "interface GigabitEthernet",
        "interface FastEthernet",
        "interface TenGigabitEthernet",
        "line vty",
        "line con 0",
        "boot system flash",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return ios_parser.parse(text)
