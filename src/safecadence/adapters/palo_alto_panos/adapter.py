from __future__ import annotations

from safecadence.adapters.palo_alto_panos import parser as panos
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class PaloAltoPANOSAdapter(BaseAdapter):
    slug = "palo-alto-panos"
    label = "Palo Alto PAN-OS"
    os_family = ["panos"]
    filename_hints = ("panos", "palo-alto", "paloalto", "pan-os")
    content_hints = (
        "set deviceconfig system",
        "set network interface ethernet",
        "set rulebase security rules",
        "set vsys vsys1",
        "PAN-OS",
        "Palo Alto Networks",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return panos.parse(text)
