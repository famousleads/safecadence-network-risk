from __future__ import annotations

from safecadence.adapters.vmware_esxi import parser as ep
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class VMwareESXiAdapter(BaseAdapter):
    slug = "vmware-esxi"
    label = "VMware ESXi"
    os_family = ["esxi"]
    filename_hints = ("esxi", "vmware", "vsphere")
    content_hints = (
        "esxcli system version get",
        "VMware ESXi",
        "Releasebuild-",
        "esxcli software vib",
        "esxcli network firewall ruleset",
        "esxcli system settings advanced list",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return ep.parse(text)
