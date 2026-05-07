"""
Palo Alto PAN-OS adapter — XML API.

PAN-OS exposes an XML API on port 443. Authentication via API key (preferred)
or generated from username+password.

Required credentials: api_key  OR  username + password.

Reference: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api
"""

from __future__ import annotations

from typing import Any
import xml.etree.ElementTree as ET

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Interface, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("palo_alto_panos")
class PaloAltoPANOSAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="palo_alto_panos",
        description="Palo Alto Networks firewalls via PAN-OS XML API",
        vendor="paloalto",
        asset_types=["network"],
        connection_types=[ConnectionType.REST],
        required_credentials=["api_key"],
        documentation_url="https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base = f"https://{target}" if not target.startswith("http") else target
        self.api_key = credentials.get("api_key", "")

    def _op(self, cmd: str) -> ET.Element | None:
        """Run an operational command. Returns parsed XML root or None on error."""
        url = f"{self.base}/api/?type=op&cmd={cmd}&key={self.api_key}"
        r = self.cm.http_get(url)
        if not r.get("ok"):
            return None
        text = r.get("text", "")
        try:
            return ET.fromstring(text)
        except ET.ParseError:
            return None

    def test_connection(self) -> dict:
        root = self._op("<show><system><info></info></system></show>")
        if root is None:
            return {"ok": False, "error": "PAN-OS XML API auth/connection failed"}
        sys = root.find(".//system")
        model = sys.findtext("model", "?") if sys is not None else "?"
        version = sys.findtext("sw-version", "?") if sys is not None else "?"
        return {"ok": True, "detail": f"PAN-OS {version} on {model}"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        commands = {
            "system_info": "<show><system><info></info></system></show>",
            "system_resources": "<show><system><resources></resources></system></show>",
            "interfaces": "<show><interface>all</interface></show>",
            "ha_state": "<show><high-availability><state></state></high-availability></show>",
            "config": "<show><config><running></running></config></show>",
            "license": "<request><license><info></info></license></request>",
        }
        for name, cmd in commands.items():
            root = self._op(cmd)
            out[name] = ET.tostring(root, encoding="unicode") if root is not None else ""
        return out

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        sysinfo_xml = raw.get("system_info", "")
        sys_root = ET.fromstring(sysinfo_xml) if sysinfo_xml else None
        sys = sys_root.find(".//system") if sys_root is not None else None

        def f(elem, key, default=""):
            return elem.findtext(key, default) if elem is not None else default

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Palo Alto",
            product_family="PAN-OS",
            asset_type="network",
            hostname=f(sys, "hostname"),
            model=f(sys, "model"),
            serial_number=f(sys, "serial"),
        )

        hardware = Hardware(
            chassis_pid=f(sys, "model"),
            firmware_version=f(sys, "sw-version"),
        )

        os_obj = OperatingSystem(
            os_type="pan-os",
            os_version=f(sys, "sw-version"),
        )

        # Uptime parsing (e.g. "12 days, 3:45:21")
        uptime_str = f(sys, "uptime")
        if uptime_str:
            try:
                import re
                m = re.match(r"(\d+) days?,\s*(\d+):(\d+):(\d+)", uptime_str)
                if m:
                    d, h, mn, s = map(int, m.groups())
                    os_obj.uptime_seconds = d*86400 + h*3600 + mn*60 + s
            except Exception:
                pass

        # Security checks from config
        config_str = raw.get("config", "")
        security = Security()
        if "<protocol>telnet</protocol>" in config_str:
            security.weak_protocols.append("telnet")
            security.findings.append("Telnet enabled in management profile")
        if "<protocol>http</protocol>" in config_str and "<protocol>https</protocol>" not in config_str:
            security.findings.append("HTTP management enabled without HTTPS")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, os=os_obj,
            security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
