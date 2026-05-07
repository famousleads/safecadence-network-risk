"""
HPE iLO adapter — Redfish-based.

HPE Integrated Lights-Out is HPE's BMC, equivalent to Dell iDRAC. Redfish
implementations are 95% identical between vendors, so this adapter inherits
heavily from the Dell iDRAC adapter and only overrides vendor-specific bits.

Tested against: iLO 5 (Gen10/Gen10 Plus), iLO 6 (Gen11). iLO 4 (Gen9) supports
Redfish but with quirks — should work; not officially tested.
"""

from __future__ import annotations

from safecadence.platform.adapter_base import (
    AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.adapters.dell_idrac import DellIDRACAdapter
from safecadence.platform.schema import UnifiedAsset


@register_adapter("hpe_ilo")
class HPEILOAdapter(DellIDRACAdapter):
    capabilities = AdapterCapabilities(
        name="hpe_ilo",
        description="HPE ProLiant servers via iLO Redfish API",
        vendor="hpe",
        asset_types=["server"],
        connection_types=[ConnectionType.REDFISH, ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://hewlettpackard.github.io/ilo-rest-api-docs/",
    )

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        asset = super().normalize(asset_id, raw)
        # Override vendor-specific identity fields
        asset.identity.vendor = "HPE"
        asset.identity.product_family = "iLO / ProLiant"
        # HPE puts BIOS in a different field on some models
        sys = raw.get("system", {}) or {}
        if not asset.hardware.bios_version:
            asset.hardware.bios_version = sys.get("BiosVersion", "")
        return asset
