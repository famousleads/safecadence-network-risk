"""Cisco ASA adapter."""

from __future__ import annotations

from safecadence.adapters.cisco_asa import parser as asa_parser
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class CiscoASAAdapter(BaseAdapter):
    slug = "cisco-asa"
    label = "Cisco ASA Firewall"
    os_family = ["asa"]
    filename_hints = ("asa", "firewall", "show-run-asa")
    content_hints = (
        "ASA Version",
        "Cisco Adaptive Security Appliance",
        "interface Management",
        "nameif inside",
        "nameif outside",
        "security-level",
        "access-group",
        "tunnel-group",
        "crypto map",
        "object-group network",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return asa_parser.parse(text)
