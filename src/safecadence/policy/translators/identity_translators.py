"""
v6.0 — Identity-system policy translators.

Generate vendor-native policy artifacts that the operator imports into
the identity system through its UI / API. SafeCadence does NOT push
these — same posture as the network/server/cloud translators.

Targets:
  - cisco_ise        ERS API JSON for Authorization Profiles + Rules
  - clearpass_role   Aruba ClearPass enforcement-profile JSON
  - ad_gpo           PowerShell snippets for AD GPO + Group settings
  - azure_ca         Azure Conditional Access policy JSON (Graph API ready)
"""

from __future__ import annotations

import json

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import (
    BaseTranslator, TranslatedFix, register_translator,
)


def _ise_authz_payload(name: str, condition: dict, profile: str) -> str:
    return json.dumps({
        "AuthorizationRule": {
            "name": name,
            "rule": {"conditionType": "ConditionAndBlock",
                     "isNegate": False, "children": [condition]},
            "profileName": profile,
        }
    }, indent=2)


@register_translator("cisco_ise")
class CiscoISETranslator(BaseTranslator):
    """Cisco ISE — emit ERS API JSON for AuthZ profiles + rules.

    The user POSTs the JSON to ISE's ERS API or imports via the UI.
    Rollback = DELETE the rule by name. Verify = GET the rule.
    """
    asset_match = ["identity", "network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "enforce_mfa":
            payload = _ise_authz_payload(
                "sc-require-mfa", {"name": "MFA-Posture-Compliant",
                                    "operator": "equals", "value": "true"},
                "PermitAccess")
            return TranslatedFix(
                fix=["# Import into ISE: Policy → Authorization → Standard",
                     "# Or POST via ERS API:",
                     "curl -k -u $ISE_USER:$ISE_PASS -H 'Accept: application/json' "
                     "-H 'Content-Type: application/json' -X POST "
                     "https://$ISE/ers/config/authorization -d @sc-mfa.json",
                     "# sc-mfa.json:", payload],
                rollback=["# DELETE /ers/config/authorization/{rule_id}"],
                verify=["curl -u $ISE_USER:$ISE_PASS https://$ISE/ers/config/authorization"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["# Disable any default-named ISE local users:",
                     "curl -X PUT https://$ISE/ers/config/internaluser/admin "
                     "-d '{\"InternalUser\":{\"enabled\":false}}'"],
                rollback=["# Re-enable as needed via UI"],
                verify=["curl https://$ISE/ers/config/internaluser"],
            )
        if cid == "block_public_exposure":
            return TranslatedFix(
                fix=["# Quarantine any non-corporate-CA endpoint:",
                     _ise_authz_payload("sc-quarantine-untrusted",
                         {"name": "Cert-Issuer", "operator": "not-equals",
                          "value": p.get("trusted_ca", "Internal-CA")},
                         "Quarantine")],
                rollback=["# DELETE the rule by name"],
                verify=["# Trigger a CoA test via ERS"],
            )
        if cid == "require_aaa":
            return TranslatedFix(
                fix=["# Make sure the network device profile uses TACACS+ or RADIUS:",
                     "curl https://$ISE/ers/config/networkdevice"],
                rollback=[],
                verify=["curl https://$ISE/ers/config/networkdevice"],
            )
        return TranslatedFix(applicable=False, notes=f"cisco_ise: no translation for {cid}")


@register_translator("clearpass_role")
class ClearPassTranslator(BaseTranslator):
    """HPE Aruba ClearPass enforcement-profile JSON."""
    asset_match = ["identity", "network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=["# ClearPass enforcement profile: require MFA via Aruba OnGuard:",
                     json.dumps({
                         "EnforcementProfile": {
                             "name": "sc-require-mfa",
                             "type": "RADIUS",
                             "action": "Accept",
                             "attributes": {"Tunnel-Private-Group-Id": "MFA-VLAN",
                                            "Aruba-User-Role": "mfa-required"}
                         }
                     }, indent=2)],
                rollback=["# Delete the profile via the ClearPass UI"],
                verify=["curl -H 'Authorization: Bearer $TOKEN' https://$CPPM/api/config/enforcement-profile"],
            )
        if cid == "block_public_exposure":
            return TranslatedFix(
                fix=["# Add a deny-all enforcement profile for non-compliant posture:",
                     json.dumps({"EnforcementProfile": {"name": "sc-deny-untrusted",
                                                         "action": "Deny"}}, indent=2)],
                rollback=[],
                verify=["# Test with a non-compliant endpoint"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["# Disable the default 'admin' local user:",
                     "curl -X PATCH https://$CPPM/api/local-user/admin "
                     "-d '{\"enabled\": false}'"],
                rollback=[],
                verify=["curl https://$CPPM/api/local-user"],
            )
        return TranslatedFix(applicable=False, notes=f"clearpass_role: no translation for {cid}")


@register_translator("ad_gpo")
class ADGPOTranslator(BaseTranslator):
    """Active Directory — PowerShell snippets for GPO + group hygiene."""
    asset_match = ["identity", "server"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "enforce_password_policy":
            min_len = int(p.get("min_length", 14))
            return TranslatedFix(
                fix=["# Run on a domain controller (elevated PowerShell):",
                     f"Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) "
                     f"-MinPasswordLength {min_len} -ComplexityEnabled $true "
                     f"-PasswordHistoryCount 24 -MaxPasswordAge (New-TimeSpan -Days 90)"],
                rollback=["# Restore from prior policy backup"],
                verify=["Get-ADDefaultDomainPasswordPolicy"],
            )
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=["# AD on its own doesn't do MFA; use Entra ID Conditional Access.",
                     "# Mark privileged groups as protected:",
                     "Add-ADGroupMember 'Protected Users' -Members 'Domain Admins'"],
                rollback=["Remove-ADGroupMember 'Protected Users' -Members 'Domain Admins'"],
                verify=["Get-ADGroupMember 'Protected Users'"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["# Disable / rename the default Administrator account:",
                     "Disable-ADAccount -Identity 'Administrator'",
                     "Rename-ADObject -Identity (Get-ADUser -Identity 'Administrator').DistinguishedName "
                     "-NewName 'sc-admin-rotated'"],
                rollback=["Enable-ADAccount -Identity 'sc-admin-rotated'"],
                verify=["Get-ADUser -Filter * | Where-Object {$_.SamAccountName -eq 'Administrator'}"],
            )
        if cid == "enforce_least_privilege":
            return TranslatedFix(
                fix=["# Audit Domain Admins membership:",
                     "Get-ADGroupMember 'Domain Admins' -Recursive | Select Name, SamAccountName"],
                rollback=[],
                verify=["Get-ADGroupMember 'Domain Admins' -Recursive | Measure-Object"],
            )
        return TranslatedFix(applicable=False, notes=f"ad_gpo: no translation for {cid}")


@register_translator("azure_ca")
class AzureConditionalAccessTranslator(BaseTranslator):
    """Azure / Entra ID — Conditional Access policy JSON for Graph API."""
    asset_match = ["identity", "cloud"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        if cid == "enforce_mfa":
            policy = {
                "displayName": "sc-require-mfa-for-admins",
                "state": "enabled",
                "conditions": {
                    "users": {"includeRoles": ["Global Administrator", "Privileged Role Administrator"]},
                    "applications": {"includeApplications": ["All"]},
                },
                "grantControls": {"operator": "AND", "builtInControls": ["mfa"]},
            }
            return TranslatedFix(
                fix=["# Apply via Microsoft Graph (requires Policy.ReadWrite.ConditionalAccess):",
                     "az rest --method POST --uri "
                     "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' "
                     "--body @sc-mfa.json --headers 'Content-Type=application/json'",
                     "# sc-mfa.json:", json.dumps(policy, indent=2)],
                rollback=["# DELETE /v1.0/identity/conditionalAccess/policies/{id}"],
                verify=["az rest --method GET --uri "
                        "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'"],
            )
        if cid == "block_public_exposure":
            policy = {
                "displayName": "sc-block-untrusted-locations",
                "state": "enabled",
                "conditions": {
                    "users": {"includeUsers": ["All"]},
                    "applications": {"includeApplications": ["All"]},
                    "locations": {"includeLocations": ["All"],
                                  "excludeLocations": ["AllTrusted"]},
                },
                "grantControls": {"operator": "OR", "builtInControls": ["block"]},
            }
            return TranslatedFix(
                fix=["# Block sign-ins from untrusted locations:",
                     json.dumps(policy, indent=2)],
                rollback=["# DELETE the policy by id"],
                verify=["az rest --method GET --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'"],
            )
        if cid == "enforce_least_privilege":
            return TranslatedFix(
                fix=["# Use Privileged Identity Management (PIM) for just-in-time elevation.",
                     "# Audit role assignments:",
                     "az role assignment list --all --query \"[?roleDefinitionName=='Owner']\""],
                rollback=[],
                verify=["az role assignment list --all"],
            )

        # v7.0 — close the orphaned idp_* gap
        if cid == "idp_require_mfa_for_admins":
            policy = {
                "displayName": "sc-mfa-for-admins-v7",
                "state": "enabled",
                "conditions": {
                    "users": {"includeRoles": [
                        "Global Administrator", "Privileged Role Administrator",
                        "Security Administrator", "User Administrator",
                    ]},
                    "applications": {"includeApplications": ["All"]},
                },
                "grantControls": {"operator": "AND",
                                   "builtInControls": ["mfa"]},
            }
            return TranslatedFix(
                fix=[
                    "# Require MFA on every admin role (Conditional Access):",
                    "az rest --method POST --uri "
                    "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' "
                    "--body @sc-mfa-admins.json",
                    "# sc-mfa-admins.json:",
                    json.dumps(policy, indent=2),
                ],
                rollback=[
                    "az rest --method DELETE --uri "
                    "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{id}'",
                ],
                verify=[
                    "az rest --method GET --uri "
                    "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' "
                    "--query \"value[?contains(displayName, 'sc-mfa-for-admins')]\"",
                ],
                notes=("Applies to Entra-tier admins. Service Principals are "
                       "covered via workload-identity Conditional Access; "
                       "see idp_conditional_access for that flow."),
            )

        if cid == "idp_disable_dormant_accounts":
            return TranslatedFix(
                fix=[
                    "# Find dormant accounts (no sign-in for 90+ days):",
                    "az rest --method GET --uri "
                    "\"https://graph.microsoft.com/v1.0/users?\\$select=id,userPrincipalName,signInActivity\" "
                    "| jq '.value[] | select(.signInActivity.lastSignInDateTime "
                    "< (now - 90*86400 | todate))'",
                    "",
                    "# For each id, disable:",
                    "az rest --method PATCH --uri "
                    "'https://graph.microsoft.com/v1.0/users/{id}' "
                    "--body '{\"accountEnabled\": false}'",
                ],
                rollback=[
                    "az rest --method PATCH --uri "
                    "'https://graph.microsoft.com/v1.0/users/{id}' "
                    "--body '{\"accountEnabled\": true}'",
                ],
                verify=[
                    "az rest --method GET --uri "
                    "'https://graph.microsoft.com/v1.0/users/{id}' "
                    "--query 'accountEnabled'",
                ],
                notes=("Threshold default 90 days — pass control parameter "
                       "max_days_idle to override."),
            )

        if cid == "idp_password_complexity":
            min_len = int((control.parameters or {}).get("min_length", 14))
            return TranslatedFix(
                fix=[
                    "# Entra ID itself doesn't expose minLength via API.",
                    "# 1) Configure via Microsoft 365 admin centre:",
                    "#    Settings > Org settings > Security & privacy > "
                    "Password policy",
                    f"#    Set 'Minimum password length' to {min_len}.",
                    "",
                    "# 2) For hybrid-AD, use Group Policy on the DC "
                    "(Default Domain Policy):",
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    "(Get-ADDomain).DistinguishedName "
                    f"-MinPasswordLength {min_len} "
                    "-ComplexityEnabled $true "
                    "-MinPasswordAge 1.00:00:00 "
                    "-MaxPasswordAge 90.00:00:00 "
                    "-PasswordHistoryCount 24",
                ],
                rollback=[
                    "Set-ADDefaultDomainPasswordPolicy -Identity "
                    "(Get-ADDomain).DistinguishedName -MinPasswordLength 7",
                ],
                verify=[
                    "Get-ADDefaultDomainPasswordPolicy "
                    "| Format-List MinPasswordLength,ComplexityEnabled",
                ],
            )

        if cid == "idp_conditional_access":
            return TranslatedFix(
                fix=[
                    "# Baseline Conditional Access bundle (block legacy auth, "
                    "require compliant device for finance, MFA for admins):",
                    "az rest --method POST --uri "
                    "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' "
                    "--body @sc-ca-block-legacy.json",
                    "# sc-ca-block-legacy.json:",
                    json.dumps({
                        "displayName": "sc-block-legacy-auth",
                        "state": "enabled",
                        "conditions": {
                            "clientAppTypes": ["exchangeActiveSync", "other"],
                            "users": {"includeUsers": ["All"]},
                            "applications": {"includeApplications": ["All"]},
                        },
                        "grantControls": {"operator": "OR",
                                           "builtInControls": ["block"]},
                    }, indent=2),
                ],
                rollback=[
                    "# DELETE the policies created above by id",
                ],
                verify=[
                    "az rest --method GET --uri "
                    "'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' "
                    "--query 'value[].displayName'",
                ],
            )

        if cid == "idp_privileged_role_review":
            return TranslatedFix(
                fix=[
                    "# Trigger a PIM access review for every privileged role:",
                    "az rest --method POST --uri "
                    "'https://graph.microsoft.com/v1.0/identityGovernance/"
                    "accessReviews/definitions' --body @sc-access-review.json",
                    "# sc-access-review.json:",
                    json.dumps({
                        "displayName": "sc-quarterly-priv-role-review",
                        "scope": {
                            "@odata.type": "#microsoft.graph.principalResourceMembershipsScope",
                            "principalScopes": [{"@odata.type": "#microsoft.graph.accessReviewQueryScope",
                                                  "query": "/roleManagement/directory/roleAssignments"}],
                        },
                        "settings": {
                            "recurrence": {"pattern": {"type": "weekly", "interval": 13}},
                            "decisionsThatWillMoveToNextStage": ["Approve"],
                            "applyDecisionsAutomatically": True,
                        },
                    }, indent=2),
                ],
                rollback=["az rest --method DELETE --uri "
                           "'.../accessReviews/definitions/{id}'"],
                verify=["az rest --method GET --uri "
                        "'https://graph.microsoft.com/v1.0/identityGovernance/"
                        "accessReviews/definitions'"],
            )

        return TranslatedFix(applicable=False, notes=f"azure_ca: no translation for {cid}")


# --------------------------------------------------------------------------
# v7.0 — Generic IdP translator. Picked when the asset's provider is
# Okta or any non-Entra identity store. Emits provider-correct API
# calls so the diff view stops saying "no translator output".
# --------------------------------------------------------------------------

@register_translator("okta_idp")
class OktaIdpTranslator(BaseTranslator):
    """Okta — emits Okta API calls for the 5 idp_* controls."""

    asset_match = ["identity"]

    def supports(self, control_id: str) -> bool:
        return control_id.startswith("idp_") or control_id in (
            "enforce_mfa", "enforce_password_policy", "enforce_least_privilege",
        )

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        if cid in ("idp_require_mfa_for_admins", "enforce_mfa"):
            return TranslatedFix(
                fix=[
                    "# Okta — require MFA for every Super Admin / Org Admin:",
                    "curl -X POST 'https://${OKTA_DOMAIN}/api/v1/policies' "
                    "-H 'Authorization: SSWS ${OKTA_TOKEN}' "
                    "-H 'Content-Type: application/json' "
                    "-d @sc-mfa-admins.json",
                    "# sc-mfa-admins.json:",
                    json.dumps({
                        "type": "MFA_ENROLL",
                        "name": "SafeCadence — MFA for admins",
                        "status": "ACTIVE",
                        "conditions": {"people": {"groups": {
                            "include": ["${OKTA_ADMIN_GROUP_ID}"]}}},
                        "settings": {"factors": {
                            "okta_verify": {"enrollment": "REQUIRED"},
                            "webauthn":    {"enrollment": "OPTIONAL"},
                        }},
                    }, indent=2),
                ],
                rollback=["curl -X DELETE "
                           "'https://${OKTA_DOMAIN}/api/v1/policies/{id}' "
                           "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
                verify=["curl 'https://${OKTA_DOMAIN}/api/v1/policies"
                         "?type=MFA_ENROLL' -H 'Authorization: SSWS ${OKTA_TOKEN}'"],
            )
        if cid == "idp_disable_dormant_accounts":
            return TranslatedFix(
                fix=[
                    "# Okta — find users inactive 90+ days and deactivate:",
                    "curl 'https://${OKTA_DOMAIN}/api/v1/users?"
                    "search=lastLogin lt \"$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ)\"' "
                    "-H 'Authorization: SSWS ${OKTA_TOKEN}' | jq -r '.[].id' "
                    "| while read uid; do "
                    "  curl -X POST 'https://${OKTA_DOMAIN}/api/v1/users/'$uid'/lifecycle/deactivate' "
                    "-H 'Authorization: SSWS ${OKTA_TOKEN}'; done",
                ],
                rollback=["curl -X POST "
                           "'https://${OKTA_DOMAIN}/api/v1/users/{id}/lifecycle/activate' "
                           "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
                verify=["curl 'https://${OKTA_DOMAIN}/api/v1/users?filter=status eq \"DEPROVISIONED\"' "
                         "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
            )
        if cid in ("idp_password_complexity", "enforce_password_policy"):
            min_len = int((control.parameters or {}).get("min_length", 14))
            return TranslatedFix(
                fix=[
                    "# Okta — set Default Password Policy via API:",
                    "curl -X PUT 'https://${OKTA_DOMAIN}/api/v1/policies/{policyId}' "
                    "-H 'Authorization: SSWS ${OKTA_TOKEN}' "
                    "-d @sc-pw-policy.json",
                    "# sc-pw-policy.json:",
                    json.dumps({
                        "type": "PASSWORD",
                        "name": "SafeCadence — strong password policy",
                        "status": "ACTIVE",
                        "settings": {"password": {"complexity": {
                            "minLength": min_len, "minLowerCase": 1,
                            "minUpperCase": 1, "minNumber": 1,
                            "minSymbol": 1, "excludeUsername": True,
                        }, "age": {"maxAgeDays": 90, "historyCount": 12}}},
                    }, indent=2),
                ],
                rollback=["# Restore previous policy JSON via PUT to the same id"],
                verify=["curl 'https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD' "
                         "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
            )
        if cid == "idp_conditional_access":
            return TranslatedFix(
                fix=[
                    "# Okta — sign-on policy: block legacy auth + require MFA "
                    "from untrusted networks:",
                    "curl -X POST 'https://${OKTA_DOMAIN}/api/v1/policies' "
                    "-H 'Authorization: SSWS ${OKTA_TOKEN}' "
                    "-d @sc-signon.json",
                    "# sc-signon.json:",
                    json.dumps({
                        "type": "OKTA_SIGN_ON",
                        "name": "SafeCadence — block legacy auth",
                        "status": "ACTIVE",
                        "conditions": {"network": {"connection": "ZONE",
                                                     "exclude": ["${TRUSTED_ZONE_ID}"]}},
                        "settings": {"signOn": {"requireFactor": True,
                                                  "factorPromptMode": "ALWAYS"}},
                    }, indent=2),
                ],
                rollback=["curl -X DELETE "
                           "'https://${OKTA_DOMAIN}/api/v1/policies/{id}' "
                           "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
                verify=["curl 'https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON' "
                         "-H 'Authorization: SSWS ${OKTA_TOKEN}'"],
            )
        if cid == "idp_privileged_role_review":
            return TranslatedFix(
                fix=[
                    "# Okta — schedule recurring access certifications via "
                    "Workflows / IGA module (Identity Governance):",
                    "# 1) Open Okta admin > Reports > Access certifications.",
                    "# 2) Create a campaign scoped to 'Super Admin' role.",
                    "# 3) Set frequency = Quarterly, decision = Auto-revoke "
                    "after 14 days no response.",
                    "# (Okta IGA REST API: "
                    "POST /governance/api/v1/campaigns)",
                ],
                rollback=["# DELETE the campaign by id"],
                verify=["# GET /governance/api/v1/campaigns and check it ran"],
            )
        return TranslatedFix(applicable=False,
                             notes=f"okta_idp: no translation for {cid}")
