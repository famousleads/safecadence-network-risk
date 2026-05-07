"""
Arista EOS adapter — eAPI (JSON-RPC over HTTPS).

Arista exposes a clean JSON-RPC eAPI on every EOS switch. Unlike Cisco's
SSH/show-command approach, eAPI returns structured JSON — much cleaner.

Required credentials: username, password.
eAPI must be enabled on the switch:
  management api http-commands
   no shutdown

Reference: https://www.arista.com/en/um-eos/eos-section-7-3-eos-command-api
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


@register_adapter("arista_eos")
class AristaEOSAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="arista_eos",
        description="Arista EOS switches via eAPI JSON-RPC",
        vendor="arista",
        asset_types=["network"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://www.arista.com/en/um-eos/eos-section-7-3-eos-command-api",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.url = f"https://{target}/command-api" if not target.startswith("http") else f"{target}/command-api"
        self.username = credentials.get("username", "admin")
        self.password = credentials.get("password", "")

    def _eapi(self, commands: list[str]) -> dict:
        """Run multiple show commands in one eAPI call. Returns {cmd: result_dict}."""
        payload = {
            "jsonrpc": "2.0",
            "method": "runCmds",
            "params": {"version": 1, "cmds": commands, "format": "json"},
            "id": 1,
        }
        r = self.cm.http_post(self.url, json=payload, auth=(self.username, self.password))
        if not r.get("ok"):
            return {"_error": r.get("error", "?")}
        body = r.get("json") or {}
        if "error" in body:
            return {"_error": body["error"].get("message", "?")}
        results = body.get("result", [])
        return {commands[i]: results[i] for i in range(min(len(commands), len(results)))}

    def test_connection(self) -> dict:
        r = self._eapi(["show version"])
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        v = r.get("show version", {})
        return {"ok": True, "detail": f"Arista {v.get('modelName','?')} EOS {v.get('version','?')}"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return self._eapi([
            "show version",
            "show inventory",
            "show interfaces",
            "show interfaces status",
            "show ip route summary",
            "show running-config",
            "show environment power",
            "show environment cooling",
            "show environment temperature",
            "show vlan",
        ])

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        ver = raw.get("show version", {}) or {}
        inv = raw.get("show inventory", {}) or {}
        env_pwr = raw.get("show environment power", {}) or {}
        env_cool = raw.get("show environment cooling", {}) or {}
        env_tmp = raw.get("show environment temperature", {}) or {}

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Arista",
            product_family="EOS",
            asset_type="network",
            hostname=ver.get("hostname", ""),
            model=ver.get("modelName", ""),
            serial_number=ver.get("serialNumber", ""),
            chassis_serial_number=ver.get("serialNumber", ""),
        )

        hardware = Hardware(
            chassis_pid=ver.get("modelName", ""),
            memory_total_mb=int(ver.get("memTotal", 0)) // 1024 if ver.get("memTotal") else 0,
            memory_used_mb=(int(ver.get("memTotal", 0)) - int(ver.get("memFree", 0))) // 1024 if ver.get("memTotal") else 0,
            firmware_version=ver.get("version", ""),
            power_supplies=[
                {"slot": k, "status": (v.get("state") or "").lower()}
                for k, v in (env_pwr.get("powerSupplies", {}) or {}).items()
            ],
            fans=[
                {"slot": fan_name, "status": fan_data.get("status", "ok")}
                for fan_name, fan_data in (env_cool.get("fans", {}) or {}).items()
            ],
            temperatures=[
                {"sensor": t.get("name", "?"), "celsius": t.get("currentTemperature", 0),
                 "status": t.get("status", "ok")}
                for t in (env_tmp.get("tempSensors", []) or [])
            ],
        )

        os_obj = OperatingSystem(
            os_type="eos",
            os_version=ver.get("version", ""),
            uptime_seconds=int(ver.get("uptime", 0)),
        )

        # Interfaces
        interfaces = []
        if_data = raw.get("show interfaces", {}).get("interfaces", {}) or {}
        for name, info in if_data.items():
            interfaces.append(Interface(
                name=name,
                status=info.get("interfaceStatus", ""),
                protocol_status=info.get("lineProtocolStatus", ""),
                ip_address=(info.get("interfaceAddress", [{}])[0] or {}).get("primaryIp", {}).get("address", "") if info.get("interfaceAddress") else "",
                mac_address=info.get("physicalAddress", ""),
                speed_mbps=int(info.get("bandwidth", 0)) // 1_000_000,
                mtu=info.get("mtu", 0),
                description=info.get("description", ""),
            ))

        # Security checks against running-config
        security = Security()
        running = raw.get("show running-config", {}).get("output", "") if isinstance(raw.get("show running-config"), dict) else ""
        if isinstance(running, str):
            if "no transport input ssh" in running or "transport input telnet" in running:
                security.weak_protocols.append("telnet")
                security.findings.append("Telnet enabled on management lines")
            if "snmp-server community public" in running or "snmp-server community private" in running:
                security.weak_protocols.append("default-snmp-community")
                security.findings.append("Default SNMP community string in use")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, os=os_obj,
            interfaces=interfaces, security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
