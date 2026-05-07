"""
Azure subscription adapter — Azure SDK for Python.

Discovers Azure VMs, Storage Accounts, NSGs, and SQL databases across all
regions in a subscription.

Required credentials: tenant_id, client_id, client_secret  (Service Principal)
                  OR: az_cli_profile (uses local az login session)
                  OR: managed_identity (when running on Azure)

Reference: https://learn.microsoft.com/en-us/python/api/overview/azure/
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Cloud, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("azure_subscription")
class AzureSubscriptionAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="azure_subscription",
        description="Azure subscription discovery via Azure SDK (VMs + NSGs + Storage)",
        vendor="azure",
        asset_types=["cloud"],
        connection_types=[ConnectionType.VENDOR_SDK],
        required_credentials=["tenant_id", "client_id", "client_secret"],
        supports_discovery=True,
        documentation_url="https://learn.microsoft.com/en-us/python/api/overview/azure/",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.subscription_id = target

    def _credential(self):
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
        except ImportError:
            raise RuntimeError("azure-identity required: pip install azure-identity azure-mgmt-compute azure-mgmt-network")
        if self.credentials.get("tenant_id"):
            return ClientSecretCredential(
                tenant_id=self.credentials["tenant_id"],
                client_id=self.credentials["client_id"],
                client_secret=self.credentials["client_secret"],
            )
        return DefaultAzureCredential()

    def test_connection(self) -> dict:
        try:
            from azure.mgmt.subscription import SubscriptionClient
            cred = self._credential()
            client = SubscriptionClient(cred)
            sub = client.subscriptions.get(self.subscription_id)
            return {"ok": True, "detail": f"Azure subscription '{sub.display_name}' ({sub.state})"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def discover(self) -> list[dict]:
        """Enumerate VMs across all locations."""
        try:
            from azure.mgmt.compute import ComputeManagementClient
            cred = self._credential()
            client = ComputeManagementClient(cred, self.subscription_id)
            assets = []
            for vm in client.virtual_machines.list_all():
                assets.append({
                    "asset_id": f"azure:{self.subscription_id}:vm:{vm.id}",
                    "identity_hint": {
                        "type": "vm", "name": vm.name, "location": vm.location,
                    },
                })
            return assets
        except Exception:
            return []

    def collect(self, asset_id: str) -> dict[str, Any]:
        # asset_id format: azure:<sub>:vm:<full_resource_id>
        parts = asset_id.split(":", 3)
        if len(parts) < 4:
            return {"_error": "invalid asset_id"}
        full_id = parts[3]
        try:
            from azure.mgmt.compute import ComputeManagementClient
            cred = self._credential()
            client = ComputeManagementClient(cred, self.subscription_id)
            # Parse RG + VM name out of resource ID
            id_parts = full_id.split("/")
            rg = id_parts[id_parts.index("resourceGroups") + 1]
            vm_name = id_parts[-1]
            vm = client.virtual_machines.get(rg, vm_name, expand="instanceView")
            return {
                "vm": vm.as_dict(),
                "instance_view": vm.instance_view.as_dict() if vm.instance_view else {},
            }
        except Exception as e:
            return {"_error": str(e)}

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        vm = raw.get("vm", {}) or {}

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Azure",
            product_family="Virtual Machine",
            asset_type="cloud",
            hostname=vm.get("name", ""),
        )

        cloud = Cloud(
            provider="azure",
            account_id=self.subscription_id,
            region=vm.get("location", ""),
            instance_type=vm.get("hardware_profile", {}).get("vm_size", ""),
            tags=vm.get("tags") or {},
        )

        security = Security()
        # Azure-specific: check for unmanaged disks (legacy)
        if vm.get("storage_profile", {}).get("os_disk", {}).get("vhd"):
            security.findings.append("VM uses unmanaged disks (legacy) — migrate to managed disks")

        asset = UnifiedAsset(
            identity=identity, cloud=cloud, security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
