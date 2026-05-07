from __future__ import annotations

from safecadence.adapters.juniper_junos import parser as jp
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class JuniperJunosAdapter(BaseAdapter):
    slug = "juniper-junos"
    label = "Juniper Junos"
    os_family = ["junos"]
    filename_hints = ("junos", "juniper", "show-config-juniper", "ex", "qfx", "mx", "srx")
    content_hints = (
        "## Last commit",
        "## Last changed",
        "system {",
        "host-name ",
        "set system",
        "interfaces {",
        "ge-0/0/",
        "xe-0/0/",
        "fxp0",
        "set protocols bgp",
        "set protocols ospf",
        "Junos:",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return jp.parse(text)
