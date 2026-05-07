"""Arista EOS adapter."""

from __future__ import annotations

from safecadence.adapters.arista_eos import parser as eos_parser
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class AristaEOSAdapter(BaseAdapter):
    slug = "arista-eos"
    label = "Arista EOS"
    os_family = ["eos"]
    filename_hints = ("eos", "arista", "show-running-eos")
    content_hints = (
        "Arista Networks EOS",
        "Software image version",
        "transceiver qsfp",
        "switchport mode trunk",
        "interface Ethernet",
        "management api http-commands",
        "service routing protocols model",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return eos_parser.parse(text)
