from __future__ import annotations

from safecadence.adapters.windows_server import parser as wp
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class WindowsServerAdapter(BaseAdapter):
    slug = "windows-server"
    label = "Windows Server"
    os_family = ["windows"]
    filename_hints = ("windows", "winserver", "win-server", "ad", "dc-")
    content_hints = (
        "WindowsProductName",
        "Get-ComputerInfo",
        "OsBuildNumber",
        "WindowsCurrentVersion",
        "Get-LocalUser",
        "Get-NetFirewallProfile",
        "SmbServerConfiguration",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return wp.parse(text)
