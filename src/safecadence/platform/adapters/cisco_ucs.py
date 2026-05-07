"""
Cisco UCS Manager adapter — XML API.

UCS Manager exposes an XML API on https://<ucsm>/nuova. Auth via
session cookie obtained from aaaLogin.

Required credentials: username, password.

Reference: https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/sw/api/ucs_api_reference.html
"""

from __future__ import annotations

from typing import Any
import xml.etree.ElementTree as ET

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("cisco_ucs")
class CiscoUCSAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="cisco_ucs",
        description="Cisco UCS Manager via XML API",
        vendor="cisco",
        asset_types=["server"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/sw/api/ucs_api_reference.html",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.url = f"https://{target}/nuova" if not target.startswith("http") else f"{target}/nuova"
        self.username = credentials.get("username", "admin")
        self.password = credentials.get("password", "")
        self._cookie = None

    def _login(self) -> str | None:
        if self._cookie:
            return self._cookie
        body = f'<aaaLogin inName="{self.username}" inPassword="{self.password}"/>'
        r = self.cm.http_post(self.url, json=None, headers={"Content-Type": "application/xml"})
        # NOTE: would need to send body as raw XML, http_post sends JSON
        # In production: use httpx directly with content=body
        # For now: returns None; real install should test against UCS Manager
        try:
            with self.cm.http() as c:
                r = c.post(self.url, content=body, headers={"Content-Type": "application/xml"})
                root = ET.fromstring(r.text)
                self._cookie = root.get("outCookie")
                return self._cookie
        except Exception:
            return None

    def _query(self, body: str) -> ET.Element | None:
        cookie = self._login()
        if not cookie:
            return None
        try:
            with self.cm.http() as c:
                r = c.post(self.url, content=body, headers={"Content-Type": "application/xml"})
                return ET.fromstring(r.text)
        except Exception:
            return None

    def test_connection(self) -> dict:
        if self._login():
            return {"ok": True, "detail": "UCS Manager XML API session established"}
        return {"ok": False, "error": "UCS Manager auth failed"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        out = {}
        cookie = self._login()
        if not cookie:
            return {"_error": "auth failed"}

        # Get top-level system info
        body = f'<configResolveDn cookie="{cookie}" inHierarchical="false" dn="sys"/>'
        root = self._query(body)
        out["system"] = ET.tostring(root, encoding="unicode") if root is not None else ""

        # Get all blades/rack servers
        body = f'<configResolveClass cookie="{cookie}" inHierarchical="false" classId="computeBlade"/>'
        root = self._query(body)
        out["blades"] = ET.tostring(root, encoding="unicode") if root is not None else ""

        # Get all chassis
        body = f'<configResolveClass cookie="{cookie}" inHierarchical="false" classId="equipmentChassis"/>'
        root = self._query(body)
        out["chassis"] = ET.tostring(root, encoding="unicode") if root is not None else ""

        return out

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        # Parse system info
        sys_xml = raw.get("system", "")
        sys_root = ET.fromstring(sys_xml) if sys_xml else None
        sys_top = sys_root.find(".//topSystem") if sys_root is not None else None

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Cisco",
            product_family="UCS Manager",
            asset_type="server",
            hostname=sys_top.get("name", "") if sys_top is not None else "",
            model=sys_top.get("mode", "") if sys_top is not None else "",
        )

        hardware = Hardware(
            chassis_pid="UCS Manager",
            firmware_version=sys_top.get("currentVersion", "") if sys_top is not None else "",
        )

        os_obj = OperatingSystem(os_type="ucs-manager")
        security = Security()

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, os=os_obj,
            security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
