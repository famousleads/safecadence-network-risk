from __future__ import annotations

import re

from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


_SUB_RE = re.compile(r'subscription[Ii]d["\s:]+([0-9a-f-]{36})|"id":\s*"/subscriptions/([0-9a-f-]{36})"')


@register_adapter
class AzureCloudAdapter(BaseAdapter):
    slug = "azure-cloud"
    label = "Azure subscription"
    os_family = ["azure"]
    filename_hints = ("azure", "arm", "bicep", "azuredeploy", "az-")
    content_hints = (
        '"Microsoft.Network/networkSecurityGroups"',
        '"Microsoft.Storage/storageAccounts"',
        '"Microsoft.Compute/virtualMachines"',
        '"Microsoft.Web/sites"',
        "azurerm_", "azapi_",
        "tenantId", "subscriptionId",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        sub = ""
        if (m := _SUB_RE.search(text or "")):
            sub = m.group(1) or m.group(2) or ""
        return ParsedConfig(
            vendor="azure-cloud",
            device_type="cloud",
            hostname=sub or "azure-subscription",
            os="azure",
            version="",
            model="Azure",
            raw_config=text or "",
        )
