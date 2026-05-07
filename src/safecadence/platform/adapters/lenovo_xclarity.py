"""
Lenovo XClarity adapter — Redfish.

Lenovo XClarity Controller (XCC) and XClarity Administrator (LXCA) both
expose a standard Redfish API. Same architecture as Dell iDRAC and HPE iLO,
which is why we just inherit DellIDRACAdapter and override identity strings.

Required credentials: username, password.

Reference: https://pubs.lenovo.com/lxca/lxca_apirest_redfishservice.html
"""

from __future__ import annotations

from safecadence.platform.adapter_base import (
    AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.adapters.dell_idrac import DellIDRACAdapter
from safecadence.platform.schema import UnifiedAsset


@register_adapter("lenovo_xclarity")
class LenovoXClarityAdapter(DellIDRACAdapter):
    capabilities = AdapterCapabilities(
        name="lenovo_xclarity",
        description="Lenovo ThinkSystem servers via XClarity Controller (Redfish)",
        vendor="lenovo",
        asset_types=["server"],
        connection_types=[ConnectionType.REDFISH, ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://pubs.lenovo.com/lxca/lxca_apirest_redfishservice.html",
    )

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        asset = super().normalize(asset_id, raw)
        asset.identity.vendor = "Lenovo"
        asset.identity.product_family = "ThinkSystem / XClarity"
        return asset


@register_adapter("supermicro_ipmi")
class SupermicroIPMIAdapter(DellIDRACAdapter):
    """Supermicro X12+ systems via Redfish on the BMC."""
    capabilities = AdapterCapabilities(
        name="supermicro_ipmi",
        description="Supermicro servers via Redfish-capable BMC (X12+)",
        vendor="supermicro",
        asset_types=["server"],
        connection_types=[ConnectionType.REDFISH, ConnectionType.IPMI],
        required_credentials=["username", "password"],
        documentation_url="https://www.supermicro.com/manuals/other/RedfishRefGuide.pdf",
    )

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        asset = super().normalize(asset_id, raw)
        asset.identity.vendor = "Supermicro"
        asset.identity.product_family = "Supermicro IPMI"
        return asset
