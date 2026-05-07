"""GCP translator. Outputs gcloud CLI + Org Policy snippets."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("gcp")
class GCPTranslator(BaseTranslator):
    asset_match = ["cloud"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "block_public_exposure":
            return TranslatedFix(
                fix=[
                    "# Org Policy: deny public Cloud Storage buckets:",
                    "gcloud resource-manager org-policies enable-enforce iam.allowedPolicyMemberDomains --organization=$ORG_ID",
                    "# Remove 0.0.0.0/0 firewall rules:",
                    "gcloud compute firewall-rules list --filter=\"sourceRanges:0.0.0.0/0\"",
                    "gcloud compute firewall-rules delete $RULE_NAME --quiet",
                ],
                rollback=[
                    "gcloud resource-manager org-policies disable-enforce iam.allowedPolicyMemberDomains --organization=$ORG_ID",
                ],
                verify=["gcloud compute firewall-rules list --filter=\"sourceRanges:0.0.0.0/0\""],
            )
        if cid == "enforce_logging":
            return TranslatedFix(
                fix=[
                    "# Enable audit logging at org level:",
                    "gcloud logging sinks create sc-audit-sink storage.googleapis.com/$LOG_BUCKET "
                    "--log-filter='logName:cloudaudit.googleapis.com' --organization=$ORG_ID",
                ],
                rollback=["gcloud logging sinks delete sc-audit-sink --organization=$ORG_ID"],
                verify=["gcloud logging sinks list --organization=$ORG_ID"],
            )
        if cid == "enforce_encryption_at_rest":
            return TranslatedFix(
                fix=[
                    "# All GCP storage is encrypted by default; switch to CMEK for stronger control:",
                    "gcloud kms keyrings create sc-keyring --location=global",
                    "gcloud kms keys create sc-key --keyring=sc-keyring --location=global --purpose=encryption",
                    "# Use CMEK on a new bucket:",
                    "gsutil mb -l us -b on -p $PROJECT_ID gs://$BUCKET",
                    "gsutil kms encryption -k projects/$PROJECT_ID/locations/global/keyRings/sc-keyring/cryptoKeys/sc-key gs://$BUCKET",
                ],
                rollback=["gsutil kms encryption -d gs://$BUCKET"],
                verify=["gsutil kms encryption gs://$BUCKET"],
            )
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=[
                    "# Require 2-Step Verification at the Workspace org level:",
                    "# Admin console > Security > 2-Step Verification > Enforce",
                    "# Or via gcloud Identity Platform:",
                    "gcloud identity-platform tenants update $TENANT --enable-mfa",
                ],
                rollback=["gcloud identity-platform tenants update $TENANT --no-enable-mfa"],
                verify=["gcloud identity-platform tenants describe $TENANT"],
            )
        if cid == "enforce_cloud_iam":
            return TranslatedFix(
                fix=[
                    "# Audit IAM bindings for primitive roles:",
                    "gcloud projects get-iam-policy $PROJECT_ID --format=json | jq '.bindings[] | select(.role | test(\"roles/(owner|editor)\"))'",
                    "# Remove primitive roles in favor of predefined / custom:",
                    "gcloud projects remove-iam-policy-binding $PROJECT_ID --member=user:$EMAIL --role=roles/owner",
                ],
                rollback=["# Re-add only when necessary"],
                verify=["gcloud projects get-iam-policy $PROJECT_ID"],
            )
        return TranslatedFix(applicable=False, notes=f"gcp: no translation for {cid}")
