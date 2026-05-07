from __future__ import annotations

from safecadence.adapters.fortinet_fortigate import parser as fg
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class FortinetFortiGateAdapter(BaseAdapter):
    slug = "fortinet-fortigate"
    label = "Fortinet FortiGate"
    os_family = ["fortios"]
    filename_hints = ("fortigate", "fgt", "fortios", "show-full-config")
    content_hints = (
        "config system global",
        "set hostname",
        "config system interface",
        "config firewall policy",
        "config vpn ipsec",
        "config router static",
        "FortiGate", "FortiOS",
        "#config-version=",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return fg.parse(text)
