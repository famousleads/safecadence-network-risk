from __future__ import annotations

from safecadence.adapters.linux_server import parser as lp
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


@register_adapter
class LinuxServerAdapter(BaseAdapter):
    slug = "linux-server"
    label = "Linux server"
    os_family = ["linux"]
    filename_hints = ("linux", "ubuntu", "rhel", "centos", "debian", "alma", "rocky", "amzn")
    content_hints = (
        "==== /etc/os-release ====",
        "PRETTY_NAME=",
        "==== /etc/ssh/sshd_config ====",
        "==== systemctl list-unit-files",
        "Linux version",
        "uname -a",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return lp.parse(text)
