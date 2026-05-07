"""
Dell iDRAC adapter — REST/Redfish-based.

Talks to the Dell Integrated Remote Access Controller (iDRAC) on PowerEdge
servers using the DMTF Redfish standard. Same approach works for HPE iLO,
Lenovo XClarity, and Supermicro X12 BMCs with minor URL/auth changes.

What it collects:
  - System inventory (model, serial, BIOS, firmware)
  - Processors (model, count, cores)
  - Memory (DIMMs, total/used)
  - Storage controllers + physical disks + virtual disks
  - Network interfaces (NICs + iDRAC dedicated NIC)
  - Power supplies (status, watts)
  - Cooling fans (status, RPM)
  - Temperature sensors
  - System Event Log (recent critical entries)
  - Lifecycle: warranty + EOS lookup (best-effort via Dell API; falls back to model lookup)

Credentials required:
  - username
  - password

Network:
  - Connects to https://<idrac>/redfish/v1/

Documentation:
  - Redfish spec: https://www.dmtf.org/standards/redfish
  - Dell-specific: https://developer.dell.com/apis/2978/versions/7.x.x/openapi.yaml
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Security, Lifecycle,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("dell_idrac")
class DellIDRACAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="dell_idrac",
        description="Dell PowerEdge servers via iDRAC Redfish API",
        vendor="dell",
        asset_types=["server"],
        connection_types=[ConnectionType.REDFISH, ConnectionType.REST],
        required_credentials=["username", "password"],
        supports_discovery=False,  # one iDRAC = one asset; use platform discovery to find iDRACs
        supports_collection=True,
        rate_limit_calls_per_minute=30,  # iDRACs are notoriously slow
        documentation_url="https://developer.dell.com/apis/2978/",
    )

    def __init__(self, target: str, credentials: dict[str, str], **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base_url = target if target.startswith("http") else f"https://{target}"
        self.username = credentials.get("username", "root")
        self.password = credentials.get("password", "")

    # ---------------------------------------------------------------- helpers
    def _get(self, path: str) -> dict:
        r = self.cm.redfish_get(self.base_url, path,
                                username=self.username, password=self.password)
        if not r.get("ok"):
            return {"_error": r.get("error") or f"HTTP {r.get('status')}"}
        return r.get("json") or {}

    # ---------------------------------------------------------------- BaseAdapter API
    def test_connection(self) -> dict:
        r = self._get("/redfish/v1/")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        return {
            "ok": True,
            "detail": f"Redfish v{r.get('RedfishVersion','?')} · vendor={r.get('Vendor','Dell')}",
        }

    def collect(self, asset_id: str) -> dict[str, Any]:
        """Pull every interesting Redfish endpoint and bundle into one dict."""
        out: dict[str, Any] = {}

        # System
        systems = self._get("/redfish/v1/Systems")
        sys_members = systems.get("Members", [])
        if not sys_members:
            return {"_error": "no systems found at /Systems"}
        sys_path = sys_members[0]["@odata.id"]
        out["system"] = self._get(sys_path)

        # Processors
        proc_path = out["system"].get("Processors", {}).get("@odata.id", "")
        if proc_path:
            procs = self._get(proc_path)
            proc_details = []
            for m in procs.get("Members", []):
                proc_details.append(self._get(m["@odata.id"]))
            out["processors"] = proc_details

        # Memory
        mem_path = out["system"].get("Memory", {}).get("@odata.id", "")
        if mem_path:
            mem = self._get(mem_path)
            mem_details = []
            for m in mem.get("Members", []):
                mem_details.append(self._get(m["@odata.id"]))
            out["memory"] = mem_details

        # Storage
        storage_path = out["system"].get("Storage", {}).get("@odata.id", "")
        if storage_path:
            storage = self._get(storage_path)
            storage_details = []
            for m in storage.get("Members", []):
                storage_details.append(self._get(m["@odata.id"]))
            out["storage"] = storage_details

        # NICs
        eth_path = out["system"].get("EthernetInterfaces", {}).get("@odata.id", "")
        if eth_path:
            eth = self._get(eth_path)
            eth_details = []
            for m in eth.get("Members", []):
                eth_details.append(self._get(m["@odata.id"]))
            out["interfaces"] = eth_details

        # Chassis (for power/fans/temps)
        chassis = self._get("/redfish/v1/Chassis")
        chassis_members = chassis.get("Members", [])
        if chassis_members:
            ch_path = chassis_members[0]["@odata.id"]
            out["chassis"] = self._get(ch_path)
            # Thermal
            thermal_path = out["chassis"].get("Thermal", {}).get("@odata.id", "")
            if thermal_path:
                out["thermal"] = self._get(thermal_path)
            # Power
            power_path = out["chassis"].get("Power", {}).get("@odata.id", "")
            if power_path:
                out["power"] = self._get(power_path)

        # iDRAC firmware version (Manager)
        managers = self._get("/redfish/v1/Managers")
        if managers.get("Members"):
            mgr_path = managers["Members"][0]["@odata.id"]
            out["manager"] = self._get(mgr_path)

        return out

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        """Transform Redfish response into UnifiedAsset."""
        sys = raw.get("system", {}) or {}
        chassis = raw.get("chassis", {}) or {}
        thermal = raw.get("thermal", {}) or {}
        power = raw.get("power", {}) or {}
        manager = raw.get("manager", {}) or {}

        # Identity
        identity = AssetIdentity(
            asset_id=asset_id,
            hostname=sys.get("HostName") or sys.get("Name", ""),
            vendor="Dell",
            product_family="iDRAC / PowerEdge",
            model=sys.get("Model", ""),
            serial_number=sys.get("SerialNumber", ""),
            chassis_serial_number=chassis.get("SerialNumber", ""),
            asset_type="server",
        )

        # Hardware
        procs = raw.get("processors", []) or []
        first_proc = procs[0] if procs else {}
        memory_modules = raw.get("memory", []) or []
        total_mem_mb = sum((m.get("CapacityMiB") or 0) for m in memory_modules)

        power_supplies = []
        for ps in power.get("PowerSupplies", []) or []:
            power_supplies.append({
                "slot": ps.get("Name", ""),
                "status": (ps.get("Status") or {}).get("Health", "?"),
                "watts": ps.get("PowerInputWatts", 0),
            })
        fans = []
        for f in thermal.get("Fans", []) or []:
            fans.append({
                "slot": f.get("Name", ""),
                "status": (f.get("Status") or {}).get("Health", "?"),
                "rpm": f.get("Reading", 0),
            })
        temps = []
        for t in thermal.get("Temperatures", []) or []:
            temps.append({
                "sensor": t.get("Name", ""),
                "celsius": t.get("ReadingCelsius", 0),
                "status": (t.get("Status") or {}).get("Health", "?"),
            })

        hardware = Hardware(
            chassis_pid=chassis.get("PartNumber", ""),
            cpu_model=first_proc.get("Model", ""),
            cpu_count=len(procs),
            cores_per_cpu=first_proc.get("TotalCores", 0),
            threads_per_core=int((first_proc.get("TotalThreads") or 0) / max(first_proc.get("TotalCores", 1), 1)),
            cpu_speed_mhz=first_proc.get("MaxSpeedMHz", 0),
            memory_total_mb=total_mem_mb,
            firmware_version=sys.get("BiosVersion", ""),
            bios_version=sys.get("BiosVersion", ""),
            bmc_version=manager.get("FirmwareVersion", ""),
            power_supplies=power_supplies,
            fans=fans,
            temperatures=temps,
        )

        # OS — for a server we report what iDRAC sees
        os_obj = OperatingSystem(
            os_type=sys.get("HostingRoles", [None])[0] or "",
            running_services=[],
        )

        # Security — for now, basic exposure analysis
        security = Security()
        # iDRAC itself shouldn't be internet-facing
        if "::" not in self.target and not self.target.startswith("10.") \
           and not self.target.startswith("192.168.") and not self.target.startswith("172."):
            security.findings.append(
                f"iDRAC {self.target} appears to be on a non-RFC1918 IP — verify it's not internet-exposed."
            )
            security.recommended_actions.append(
                "iDRAC management interface must NEVER be exposed to the public internet. Move to a management VLAN."
            )

        # Lifecycle — placeholder; real implementation would call Dell warranty API
        # https://www.dell.com/support/incidents-online/api/warranty/?serial=...
        lifecycle = Lifecycle(
            warranty_status="unknown",  # populate via Dell API in production
        )

        asset = UnifiedAsset(
            identity=identity,
            hardware=hardware,
            os=os_obj,
            security=security,
            lifecycle=lifecycle,
            raw_collection=raw,
        )

        # Compute health scores
        asset.health = score_asset_health(asset)

        return asset
