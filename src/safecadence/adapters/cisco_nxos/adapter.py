"""Cisco NX-OS (Nexus) adapter."""

from __future__ import annotations

from safecadence.adapters.cisco_nxos import parser as nx_parser
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class CiscoNXOSAdapter(BaseAdapter):
    slug = "cisco-nxos"
    label = "Cisco NX-OS (Nexus)"
    os_family = ["nxos"]
    filename_hints = ("nxos", "nx-os", "nexus", "running-config-nxos")
    content_hints = (
        "Cisco Nexus Operating System",
        "NX-OS",
        "feature ssh",
        "feature lldp",
        "feature interface-vlan",
        "system default switchport",
        "vrf context management",
        "interface mgmt0",
        "interface Ethernet1/",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return nx_parser.parse(text)
