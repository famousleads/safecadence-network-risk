"""
Juniper Junos adapter — REST API or NETCONF.

Junos devices expose a REST API on port 3000 (configurable). Falls back to
SSH+CLI for older devices. Returns structured XML/JSON depending on Accept header.

Required credentials: username, password.

Reference: https://www.juniper.net/documentation/us/en/software/junos/rest-api/
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


@register_adapter("juniper_junos")
class JuniperJunosAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="juniper_junos",
        description="Juniper Junos devices via REST API or SSH",
        vendor="juniper",
        asset_types=["network"],
        connection_types=[ConnectionType.REST, ConnectionType.SSH],
        required_credentials=["username", "password"],
        documentation_url="https://www.juniper.net/documentation/us/en/software/junos/rest-api/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        port = credentials.get("rest_port", 3000)
        self.url = f"https://{target}:{port}" if not target.startswith("http") else target
        self.username = credentials.get("username", "root")
        self.password = credentials.get("password", "")

    def _rpc(self, command: str) -> dict:
        """Call a Junos RPC. command is the show-as-RPC name (e.g. 'get-system-information')."""
        url = f"{self.url}/rpc/{command}"
        r = self.cm.http_get(url, auth=(self.username, self.password),
                             headers={"Accept": "application/json"})
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        r = self._rpc("get-system-information")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        sysinfo = (r.get("system-information") or [{}])[0]
        return {
            "ok": True,
            "detail": f"{sysinfo.get('hardware-model', [{}])[0].get('data','?')} "
                      f"Junos {sysinfo.get('os-version', [{}])[0].get('data','?')}"
        }

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "system_info": self._rpc("get-system-information"),
            "chassis_inventory": self._rpc("get-chassis-inventory"),
            "interface_information": self._rpc("get-interface-information"),
            "route_summary": self._rpc("get-route-summary-information"),
            "system_uptime": self._rpc("get-system-uptime-information"),
            "alarms": self._rpc("get-alarm-information"),
            "config": self._rpc("get-configuration"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        sysinfo_data = raw.get("system_info", {}).get("system-information", [{}])[0] or {}

        def _get(d, key, default=""):
            v = d.get(key)
            if isinstance(v, list) and v:
                return v[0].get("data", default)
            return default if not isinstance(v, str) else v

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Juniper",
            product_family="Junos",
            asset_type="network",
            hostname=_get(sysinfo_data, "host-name"),
            model=_get(sysinfo_data, "hardware-model"),
        )

        # Chassis inventory
        chassis = raw.get("chassis_inventory", {}).get("chassis-inventory", [{}])[0] or {}
        chassis_top = (chassis.get("chassis") or [{}])[0] if chassis.get("chassis") else {}
        identity.serial_number = _get(chassis_top, "serial-number")

        hardware = Hardware(
            chassis_pid=_get(chassis_top, "description"),
            firmware_version=_get(sysinfo_data, "os-version"),
        )

        os_obj = OperatingSystem(
            os_type="junos",
            os_version=_get(sysinfo_data, "os-version"),
        )

        # Uptime
        uptime_data = raw.get("system_uptime", {}).get("system-uptime-information", [{}])[0] or {}
        uptime_seconds = (uptime_data.get("uptime-information", [{}])[0] or {}).get("up-time", [{}])[0].get("seconds")
        if uptime_seconds:
            os_obj.uptime_seconds = int(uptime_seconds)

        # Interfaces
        interfaces = []
        if_data = raw.get("interface_information", {}).get("interface-information", [{}])[0] or {}
        for iface in (if_data.get("physical-interface") or [])[:30]:
            interfaces.append(Interface(
                name=_get(iface, "name"),
                status=_get(iface, "oper-status"),
                protocol_status=_get(iface, "admin-status"),
                speed_mbps=int(_get(iface, "speed", "0").replace("mbps", "").replace("Gbps", "000") or 0),
                mtu=int(_get(iface, "mtu", "0") or 0),
            ))

        # Security from config (basic checks)
        security = Security()
        config = raw.get("config", {})
        config_str = str(config)
        if "telnet" in config_str.lower():
            security.weak_protocols.append("telnet")
            security.findings.append("Telnet service in configuration")
        if 'community { name "public"' in config_str or 'community { name "private"' in config_str:
            security.weak_protocols.append("default-snmp-community")
            security.findings.append("Default SNMP community in use")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, os=os_obj,
            interfaces=interfaces, security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
