"""
Nutanix Prism adapter — REST API.

Nutanix Prism Element exposes a REST API on port 9440. Auth via basic-auth
(admin / cluster-password).

Required credentials: username, password.

Reference: https://www.nutanix.dev/api-reference/
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, Virtualization, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("nutanix_prism")
class NutanixPrismAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="nutanix_prism",
        description="Nutanix Prism Element via REST API",
        vendor="nutanix",
        asset_types=["hypervisor", "virtualization"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://www.nutanix.dev/api-reference/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        port = credentials.get("port", 9440)
        self.base = f"https://{target}:{port}" if not target.startswith("http") else target
        self.username = credentials.get("username", "admin")
        self.password = credentials.get("password", "")

    def _get(self, path: str) -> dict:
        url = f"{self.base}/PrismGateway/services/rest{path}"
        r = self.cm.http_get(url, auth=(self.username, self.password))
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        r = self._get("/v2.0/cluster/")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        return {"ok": True, "detail": f"Nutanix cluster '{r.get('name','?')}' AOS {r.get('version','?')}"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "cluster": self._get("/v2.0/cluster/"),
            "hosts": self._get("/v2.0/hosts/"),
            "vms": self._get("/v2.0/vms/?include_vm_disk_config=true"),
            "containers": self._get("/v2.0/containers/"),
            "alerts": self._get("/v2.0/alerts/?count=20&resolved=false"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        cluster = raw.get("cluster", {}) or {}
        hosts = (raw.get("hosts", {}) or {}).get("entities", []) or []
        vms = (raw.get("vms", {}) or {}).get("entities", []) or []

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Nutanix",
            product_family="Prism (AHV)",
            asset_type="hypervisor",
            hostname=cluster.get("name", ""),
        )

        hardware = Hardware(
            firmware_version=cluster.get("version", ""),
        )

        virtualization = Virtualization(
            hypervisor_type="ahv",
            hypervisor_version=cluster.get("version", ""),
            cluster_name=cluster.get("name", ""),
            host_count=len(hosts),
            vm_count=len(vms),
            vm_powered_on=sum(1 for v in vms if v.get("power_state") == "on"),
            vm_powered_off=sum(1 for v in vms if v.get("power_state") == "off"),
        )

        security = Security()
        alerts = (raw.get("alerts", {}) or {}).get("entities", []) or []
        for a in alerts[:10]:
            sev = (a.get("severity") or "").lower()
            if sev in ("critical", "warning"):
                security.findings.append(f"[{sev}] {a.get('message', '?')[:120]}")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, virtualization=virtualization,
            security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset


@register_adapter("hyperv_host")
class HyperVHostAdapter(BaseAdapter):
    """Microsoft Hyper-V via WinRM/PowerShell.

    Skeleton — requires pywinrm (pip install pywinrm) and Hyper-V hosts
    with WinRM enabled. Each Hyper-V host = one adapter target.
    """
    capabilities = AdapterCapabilities(
        name="hyperv_host",
        description="Microsoft Hyper-V hosts via WinRM/PowerShell",
        vendor="microsoft",
        asset_types=["hypervisor", "virtualization"],
        connection_types=[ConnectionType.AGENT],
        required_credentials=["username", "password"],
        documentation_url="https://learn.microsoft.com/en-us/powershell/module/hyper-v/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)

    def test_connection(self) -> dict:
        try:
            import winrm
            session = winrm.Session(
                f"http://{self.target}:5985/wsman",
                auth=(self.credentials.get("username", ""), self.credentials.get("password", "")),
            )
            r = session.run_ps("Get-VMHost | Select-Object Name,Version | ConvertTo-Json")
            if r.status_code == 0:
                return {"ok": True, "detail": "WinRM connection established"}
            return {"ok": False, "error": r.std_err.decode("utf-8", errors="replace")}
        except ImportError:
            return {"ok": False, "error": "pywinrm not installed: pip install pywinrm"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def collect(self, asset_id: str) -> dict[str, Any]:
        try:
            import winrm
            session = winrm.Session(
                f"http://{self.target}:5985/wsman",
                auth=(self.credentials.get("username", ""), self.credentials.get("password", "")),
            )
            commands = {
                "host": "Get-VMHost | ConvertTo-Json",
                "vms": "Get-VM | Select Name,State,CPUUsage,MemoryAssigned,Uptime | ConvertTo-Json",
                "switches": "Get-VMSwitch | Select Name,SwitchType | ConvertTo-Json",
                "storage": "Get-VMHost | Select VirtualMachinePath,VirtualHardDiskPath | ConvertTo-Json",
            }
            import json
            out = {}
            for name, cmd in commands.items():
                r = session.run_ps(cmd)
                if r.status_code == 0 and r.std_out:
                    try:
                        out[name] = json.loads(r.std_out.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        out[name] = r.std_out.decode("utf-8", errors="replace")
            return out
        except Exception as e:
            return {"_error": str(e)}

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        host = raw.get("host", {}) or {}
        vms = raw.get("vms", []) or []
        if not isinstance(vms, list):
            vms = [vms]

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Microsoft",
            product_family="Hyper-V",
            asset_type="hypervisor",
            hostname=host.get("Name", "") if isinstance(host, dict) else "",
        )

        virtualization = Virtualization(
            hypervisor_type="hyper-v",
            hypervisor_version=str(host.get("Version", "")) if isinstance(host, dict) else "",
            host_count=1,
            vm_count=len(vms),
            vm_powered_on=sum(1 for v in vms if v.get("State") == "Running"),
            vm_powered_off=sum(1 for v in vms if v.get("State") == "Off"),
        )

        asset = UnifiedAsset(
            identity=identity, virtualization=virtualization, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
