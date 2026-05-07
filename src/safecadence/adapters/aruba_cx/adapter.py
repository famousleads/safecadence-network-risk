"""Aruba CX adapter."""

from __future__ import annotations

from safecadence.adapters.aruba_cx import parser as cx_parser
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class ArubaCXAdapter(BaseAdapter):
    slug = "aruba-cx"
    label = "Aruba CX (AOS-CX)"
    os_family = ["aos-cx"]
    filename_hints = ("aruba", "cx", "aos-cx", "aoscx", "aruba-cx")
    content_hints = (
        "ArubaOS-CX",
        "!Version ArubaOS-CX",
        "ssh server vrf",
        "vsf member",
        "vrf mgmt",
        "ntp server",
        "interface 1/1/",
        "interface lag",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return cx_parser.parse(text)
