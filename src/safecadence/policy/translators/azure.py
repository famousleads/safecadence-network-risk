"""Azure translator. Outputs az CLI / Bicep / Azure Policy snippets."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("azure")
class AzureTranslator(BaseTranslator):
    asset_match = ["cloud"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "block_public_exposure":
            return TranslatedFix(
                fix=[
                    "# Block public network access on storage accounts:",
                    "az storage account update --name $STORAGE_ACCT --resource-group $RG --public-network-access Disabled",
                    "# Restrict NSG inbound — remove 0.0.0.0/0 source:",
                    "az network nsg rule delete -g $RG --nsg-name $NSG -n AllowAnyInbound || true",
                ],
                rollback=["az storage account update --name $STORAGE_ACCT --resource-group $RG --public-network-access Enabled"],
                verify=["az storage account show --name $STORAGE_ACCT --resource-group $RG --query publicNetworkAccess"],
            )
        if cid == "enforce_logging":
            return TranslatedFix(
                fix=[
                    "# Enable Activity Log diagnostic setting:",
                    "az monitor diagnostic-settings subscription create --name SC-Activity --location global "
                    "--logs '[{\"category\":\"Administrative\",\"enabled\":true},{\"category\":\"Security\",\"enabled\":true}]' "
                    "--workspace $LAW_RESOURCE_ID",
                ],
                rollback=["az monitor diagnostic-settings subscription delete --name SC-Activity"],
                verify=["az monitor diagnostic-settings subscription list"],
            )
        if cid == "enforce_encryption_at_rest":
            return TranslatedFix(
                fix=[
                    "# Storage account: ensure encryption is on (default true since 2017, verify):",
                    "az storage account update --name $STORAGE_ACCT --resource-group $RG --encryption-services blob file",
                    "# Managed disk encryption:",
                    "az disk encryption create --resource-group $RG --disk-name $DISK --enabled true",
                ],
                rollback=["# Disabling at-rest encryption is not supported on Azure Storage."],
                verify=["az storage account show --name $STORAGE_ACCT --resource-group $RG --query encryption"],
            )
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=[
                    "# Enable Azure AD Conditional Access requiring MFA for admins:",
                    "# Configured in Entra ID portal:",
                    "# Security > Conditional Access > New policy > Grant > Require multi-factor authentication",
                    "# CLI snippet (preview):",
                    "az rest --method POST --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' --body @ca-mfa.json",
                ],
                rollback=["# Disable the Conditional Access policy in Entra ID portal."],
                verify=["az rest --method GET --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'"],
            )
        if cid == "enforce_cloud_iam":
            return TranslatedFix(
                fix=[
                    "# Audit role assignments and remove Owner where Contributor suffices:",
                    "az role assignment list --all --output table",
                    "# Use Azure AD Privileged Identity Management (PIM) for just-in-time elevation.",
                ],
                rollback=[],
                verify=["az role assignment list --all --query '[?roleDefinitionName==`Owner`]'"],
            )
        return TranslatedFix(applicable=False, notes=f"azure: no translation for {cid}")
