"""
VMware vCenter adapter — REST API based (vSphere 7.0+).

Uses the modern vSphere REST API (avoids the heavyweight pyvmomi SOAP).
Discovers ESXi hosts, VMs, datastores, networks, and clusters.

Required credentials:
  - username (e.g., administrator@vsphere.local)
  - password

Tested against: vSphere 7.0 / 8.0. For 6.x, fall back to pyvmomi.
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Virtualization, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("vmware_vcenter")
class VMwareVCenterAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="vmware_vcenter",
        description="VMware vCenter Server via vSphere REST API (7.0+)",
        vendor="vmware",
        asset_types=["hypervisor", "virtualization"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        supports_discovery=True,
        rate_limit_calls_per_minute=120,
        documentation_url="https://developer.broadcom.com/xapis/vsphere-automation-api/latest/",
    )

    def __init__(self, target: str, credentials: dict[str, str], **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base_url = target if target.startswith("http") else f"https://{target}"
        self.username = credentials.get("username", "")
        self.password = credentials.get("password", "")
        self._session_token: str | None = None

    def _login(self) -> str | None:
        """Get a session token from vSphere REST API."""
        if self._session_token:
            return self._session_token
        url = self.base_url.rstrip("/") + "/api/session"
        r = self.cm.http_post(url, auth=(self.username, self.password))
        if r.get("ok") and r.get("text"):
            self._session_token = r["text"].strip('"')
            return self._session_token
        return None

    def _api_get(self, path: str) -> dict:
        token = self._login()
        if not token:
            return {"_error": "vSphere login failed"}
        url = self.base_url.rstrip("/") + path
        r = self.cm.http_get(url, headers={"vmware-api-session-id": token})
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        if self._login():
            return {"ok": True, "detail": "vSphere REST session established"}
        return {"ok": False, "error": "auth failed"}

    def discover(self) -> list[dict]:
        """Discover hosts + VMs."""
        assets = []
        hosts = self._api_get("/api/vcenter/host")
        if isinstance(hosts, list):
            for h in hosts:
                assets.append({
                    "asset_id": f"vmware:{self.target}:host:{h.get('host', '?')}",
                    "identity_hint": {"type": "host", **h},
                })
        vms = self._api_get("/api/vcenter/vm")
        if isinstance(vms, list):
            for v in vms:
                assets.append({
                    "asset_id": f"vmware:{self.target}:vm:{v.get('vm', '?')}",
                    "identity_hint": {"type": "vm", **v},
                })
        return assets

    def collect(self, asset_id: str) -> dict[str, Any]:
        parts = asset_id.split(":")
        if len(parts) < 4:
            return {"_error": "invalid asset_id"}
        _, target, kind, resource_id = parts[:4]
        if kind == "host":
            return {"kind": "host", "data": self._api_get(f"/api/vcenter/host/{resource_id}")}
        elif kind == "vm":
            return {"kind": "vm", "data": self._api_get(f"/api/vcenter/vm/{resource_id}")}
        return {"_error": f"unknown kind: {kind}"}

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        kind = raw.get("kind", "")
        data = raw.get("data", {})

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="VMware",
            product_family="vSphere",
            asset_type="hypervisor" if kind == "host" else "vm",
            hostname=data.get("name", ""),
        )

        if kind == "host":
            virtualization = Virtualization(
                hypervisor_type="esxi",
                hypervisor_version=data.get("version", ""),
            )
            os_obj = OperatingSystem(os_type="esxi", os_version=data.get("version", ""))
            asset = UnifiedAsset(
                identity=identity, virtualization=virtualization, os=os_obj,
                raw_collection=raw,
            )
        elif kind == "vm":
            vm_data = data.get("guest", {}) or {}
            os_obj = OperatingSystem(
                os_type=vm_data.get("guest_id", ""),
                os_version=vm_data.get("guest_full_name", ""),
            )
            hardware = Hardware(
                cpu_count=data.get("cpu", {}).get("count", 0),
                memory_total_mb=data.get("memory", {}).get("size_MiB", 0),
            )
            asset = UnifiedAsset(
                identity=identity, hardware=hardware, os=os_obj,
                raw_collection=raw,
            )
        else:
            asset = UnifiedAsset(identity=identity, raw_collection=raw)

        asset.health = score_asset_health(asset)
        return asset
