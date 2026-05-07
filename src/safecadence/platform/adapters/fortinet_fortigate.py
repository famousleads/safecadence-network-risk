"""
Fortinet FortiGate adapter — REST API.

FortiOS exposes a comprehensive REST API on port 443 (or admin-https-port).
Auth via API token (preferred) or username+password.

Required credentials: api_token  OR  username + password.

Reference: https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/940969/rest-api-administrator
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Interface, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("fortinet_fortigate")
class FortinetFortiGateAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="fortinet_fortigate",
        description="Fortinet FortiGate firewalls via FortiOS REST API",
        vendor="fortinet",
        asset_types=["network"],
        connection_types=[ConnectionType.REST],
        required_credentials=["api_token"],
        documentation_url="https://docs.fortinet.com/product/fortigate/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base = f"https://{target}" if not target.startswith("http") else target
        self.token = credentials.get("api_token", "")

    def _get(self, path: str) -> dict:
        url = f"{self.base}/api/v2{path}"
        r = self.cm.http_get(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        })
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        r = self._get("/monitor/system/status")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        d = r.get("results", {}) or {}
        return {"ok": True, "detail": f"FortiGate {d.get('hostname','?')} FortiOS {d.get('version','?')}"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "system_status": self._get("/monitor/system/status"),
            "system_resource": self._get("/monitor/system/resource/usage"),
            "interface": self._get("/cmdb/system/interface"),
            "global": self._get("/cmdb/system/global"),
            "admin": self._get("/cmdb/system/admin"),
            "policy_summary": self._get("/cmdb/firewall/policy"),
            "ha_status": self._get("/monitor/system/ha-statistics"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        status = raw.get("system_status", {}).get("results", {}) or {}
        glob = raw.get("global", {}).get("results", {}) or {}

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Fortinet",
            product_family="FortiGate",
            asset_type="network",
            hostname=status.get("hostname", ""),
            model=status.get("model_name", ""),
            serial_number=status.get("serial", ""),
        )

        hardware = Hardware(
            chassis_pid=status.get("model_name", ""),
            firmware_version=status.get("version", ""),
        )

        # Resource usage
        res = raw.get("system_resource", {}).get("results", {}) or {}
        if res.get("memory"):
            mem_data = res["memory"][0] if res["memory"] else {}
            hardware.memory_total_mb = int(mem_data.get("total", 0)) // 1024 if mem_data.get("total") else 0

        os_obj = OperatingSystem(
            os_type="fortios",
            os_version=status.get("version", ""),
        )

        # Interfaces
        interfaces = []
        for iface in (raw.get("interface", {}).get("results", []) or [])[:50]:
            interfaces.append(Interface(
                name=iface.get("name", ""),
                ip_address=iface.get("ip", "0.0.0.0/0").split("/")[0] if iface.get("ip") else "",
                status=iface.get("status", ""),
                description=iface.get("description", ""),
            ))

        # Security checks
        security = Security()
        # Check for default admin
        for admin in raw.get("admin", {}).get("results", []) or []:
            if admin.get("name") == "admin" and not admin.get("two-factor"):
                security.findings.append("Default 'admin' account exists without 2FA")
                security.recommended_actions.append("Enable two-factor auth on admin account or rename it")
        # Check global hardening
        if glob.get("admin-https-redirect") == "disable":
            security.findings.append("Admin HTTP not redirected to HTTPS")
        if glob.get("admin-telnet") == "enable":
            security.weak_protocols.append("telnet")
            security.findings.append("Telnet admin enabled — disable immediately")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, os=os_obj,
            interfaces=interfaces, security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
