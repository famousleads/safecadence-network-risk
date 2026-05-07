"""Backup-platform translators.

Closes the v6.2 gap where the backup template (`enforce_backup_retention`,
`enforce_backup_immutability`, `enforce_backup_air_gap`) shipped without any
translator able to materialise the controls. Three vendor targets are
covered here, matching the platforms most enterprise + mid-market shops use:

  - veeam       — Veeam Backup & Replication (Hardened Repository, immutable
                  backups, periodic SureBackup verification)
  - aws_s3_lock — AWS S3 with Object Lock + Backup Vault Lock for immutable,
                  WORM, ransomware-resistant retention
  - azure_blob  — Azure Blob immutability policies + Backup Vault soft delete

Each translator produces three command/script blocks per supported control:
fix, rollback, verify. Snippets are conservative and idempotent where the
underlying API allows it. Operators run them through their existing change
control — SafeCadence never executes them.
"""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import (
    BaseTranslator, TranslatedFix, register_translator,
)


# --------------------------------------------------------------------------
# Veeam Backup & Replication
# --------------------------------------------------------------------------

@register_translator("veeam")
class VeeamTranslator(BaseTranslator):
    """Veeam B&R 12+ — uses Veeam PowerShell module (`Veeam.Backup.PowerShell`).

    Snippets assume the operator has launched a session with `Connect-VBRServer`
    against the backup server. Each command is documented in the official
    Veeam B&R 12 PowerShell reference.
    """

    asset_match = ["backup"]

    def supports(self, control_id: str) -> bool:
        return control_id in {
            "enforce_backup_retention",
            "enforce_backup_immutability",
            "enforce_backup_air_gap",
            "enforce_backup_verification",
        }

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}

        if cid == "enforce_backup_retention":
            days = int(p.get("retention_days", 30))
            return TranslatedFix(
                fix=[
                    f"# Set GFS retention on every job: {days} daily restore points",
                    "Get-VBRJob | ForEach-Object {",
                    "  $opts = $_.GetOptions()",
                    f"  $opts.BackupStorageOptions.RetainCycles = {days}",
                    "  $_.SetOptions($opts)",
                    "}",
                ],
                rollback=[
                    "# Revert retention to the previous value (operator-supplied):",
                    "# Get-VBRJob | ForEach-Object { ... SetOptions ... }",
                ],
                verify=[
                    "Get-VBRJob | Select-Object Name, "
                    "@{n='RetainCycles';e={$_.GetOptions().BackupStorageOptions.RetainCycles}}",
                ],
                notes=(f"Veeam GFS retention will be set to {days} daily restore "
                       "points. Adjust weekly/monthly/yearly as required."),
            )

        if cid == "enforce_backup_immutability":
            days = int(p.get("immutability_days", 14))
            return TranslatedFix(
                fix=[
                    "# Convert the repo into a Hardened Repository (immutable, "
                    "Linux-only, single-use Veeam credential):",
                    "$repo = Get-VBRBackupRepository -Name '<HARDENED_REPO_NAME>'",
                    f"Set-VBRRepositoryAccessPermission -Repository $repo "
                    f"-MakeImmutableForDays {days}",
                    "# Or for newly-created repos, use the GUI installer with "
                    "the 'Make recent backups immutable' flag.",
                ],
                rollback=[
                    "$repo = Get-VBRBackupRepository -Name '<HARDENED_REPO_NAME>'",
                    "Set-VBRRepositoryAccessPermission -Repository $repo "
                    "-MakeImmutableForDays 0",
                ],
                verify=[
                    "Get-VBRBackupRepository | Select-Object Name, "
                    "@{n='ImmutabilityDays';e={$_.GetImmutabilitySettings().Days}}",
                ],
                notes=("Hardened Repository on a dedicated Linux host is the "
                       "Veeam-supported pattern. The Windows backup server "
                       "user must NOT have SSH/sudo on the hardened host."),
            )

        if cid == "enforce_backup_air_gap":
            return TranslatedFix(
                fix=[
                    "# Add a tape / disconnected secondary repo and enable "
                    "Scale-Out Backup Repository tier-out:",
                    "$tape = Add-VBRTapeMediaPool -Name 'Offsite-Vault' "
                    "-Library '<LIBRARY_NAME>' -MediaSet '<MEDIA_SET>'",
                    "Get-VBRJob | ForEach-Object {",
                    "  Add-VBRBackupCopyJob -Name ($_.Name + '-Copy') "
                    "-Repository (Get-VBRBackupRepository -Name '<OFFSITE>') "
                    "-Job $_",
                    "}",
                    "# Schedule eject so media physically leaves the loader.",
                ],
                rollback=[
                    "Get-VBRBackupCopyJob | Where Name -like '*-Copy' "
                    "| Remove-VBRBackupCopyJob -Confirm:$false",
                ],
                verify=[
                    "Get-VBRBackupCopyJob | Select Name, NextRun, LastResult",
                    "Get-VBRTapeJob | Select Name, NextRun, LastState",
                ],
                notes=("True air gap requires the tape/secondary repo to be "
                       "physically removed or to live on a separate domain "
                       "with no shared credentials."),
            )

        if cid == "enforce_backup_verification":
            return TranslatedFix(
                fix=[
                    "# Enable SureBackup application-aware verification weekly:",
                    "$job = Get-VBRJob -Name '<JOB_NAME>'",
                    "$opts = $job.GetOptions()",
                    "$opts.ViSourceOptions.UseChangeTracking = $true",
                    "$job.SetOptions($opts)",
                    "Add-VBRSureBackupJob -Name ($job.Name + '-SureBackup') "
                    "-VirtualLab (Get-VBRSureBackupVirtualLab -Name '<LAB>') "
                    "-LinkedJob $job -ScheduleOptions (New-VBRSureBackupJobScheduleOptions -Type Weekly)",
                ],
                rollback=[
                    "Get-VBRSureBackupJob | Where Name -like '*-SureBackup' "
                    "| Remove-VBRSureBackupJob -Confirm:$false",
                ],
                verify=[
                    "Get-VBRSureBackupJob | Select Name, NextRun, LastResult",
                ],
            )

        return TranslatedFix(applicable=False,
                             notes=f"Veeam translator does not implement {cid}.")


# --------------------------------------------------------------------------
# AWS S3 Object Lock + Backup Vault Lock
# --------------------------------------------------------------------------

@register_translator("aws_s3_lock")
class AWSS3LockTranslator(BaseTranslator):
    """AWS S3 Object Lock + AWS Backup Vault Lock for immutable backups.

    Operates at the bucket / vault level. Object Lock requires the bucket be
    created with versioning + Object Lock enabled — for existing buckets,
    AWS support has to enable it after a request, and we surface that
    caveat in the notes.
    """

    asset_match = ["backup", "cloud"]

    def supports(self, control_id: str) -> bool:
        return control_id in {
            "enforce_backup_retention",
            "enforce_backup_immutability",
            "enforce_backup_air_gap",
            "enforce_encryption_at_rest",
        }

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}

        if cid == "enforce_backup_immutability":
            days = int(p.get("immutability_days", 30))
            return TranslatedFix(
                fix=[
                    "# 1. Enable Object Lock on the backup bucket (must be done at create time):",
                    "aws s3api create-bucket --bucket $BACKUP_BUCKET --object-lock-enabled-for-bucket",
                    "aws s3api put-bucket-versioning --bucket $BACKUP_BUCKET "
                    "--versioning-configuration Status=Enabled",
                    "",
                    "# 2. Set a default Compliance-mode retention on the bucket:",
                    "aws s3api put-object-lock-configuration --bucket $BACKUP_BUCKET "
                    f"--object-lock-configuration 'ObjectLockEnabled=Enabled,"
                    f"Rule={{DefaultRetention={{Mode=COMPLIANCE,Days={days}}}}}'",
                    "",
                    "# 3. For AWS Backup vaults: apply Vault Lock in compliance mode.",
                    "aws backup put-backup-vault-lock-configuration --backup-vault-name $VAULT "
                    f"--min-retention-days {days} --max-retention-days 36500 "
                    "--changeable-for-days 3",
                ],
                rollback=[
                    "# COMPLIANCE-mode locks cannot be lifted before expiry. "
                    "Use GOVERNANCE mode if you need a rollback path:",
                    "aws s3api put-object-lock-configuration --bucket $BACKUP_BUCKET "
                    "--object-lock-configuration 'ObjectLockEnabled=Enabled'",
                ],
                verify=[
                    "aws s3api get-object-lock-configuration --bucket $BACKUP_BUCKET",
                    "aws backup describe-backup-vault --backup-vault-name $VAULT "
                    "--query 'Locked'",
                ],
                notes=("COMPLIANCE mode is irreversible — even root cannot "
                       "delete protected versions until the retention expires. "
                       "Pilot in GOVERNANCE first if uncertain."),
            )

        if cid == "enforce_backup_retention":
            days = int(p.get("retention_days", 35))
            return TranslatedFix(
                fix=[
                    "# Backup plan with cold storage transition + delete after retention:",
                    "cat > backup-plan.json <<'EOF'",
                    "{",
                    '  "BackupPlan": {',
                    '    "BackupPlanName": "SafeCadence-Standard",',
                    '    "Rules": [{',
                    '      "RuleName": "DailyBackups",',
                    '      "TargetBackupVaultName": "$VAULT",',
                    '      "ScheduleExpression": "cron(0 5 ? * * *)",',
                    f'      "Lifecycle": {{ "DeleteAfterDays": {days} }}',
                    '    }]',
                    '  }',
                    "}",
                    "EOF",
                    "aws backup create-backup-plan --backup-plan file://backup-plan.json",
                ],
                rollback=[
                    "aws backup delete-backup-plan --backup-plan-id $PLAN_ID",
                ],
                verify=[
                    "aws backup get-backup-plan --backup-plan-id $PLAN_ID "
                    "--query 'BackupPlan.Rules[*].Lifecycle'",
                ],
            )

        if cid == "enforce_backup_air_gap":
            return TranslatedFix(
                fix=[
                    "# Cross-account, cross-region copy to an isolated 'vault' account:",
                    "aws backup put-backup-vault-access-policy --backup-vault-name $VAULT "
                    "--policy file://vault-deny-delete.json",
                    "# Copy each restore point to the isolated account/region:",
                    "aws backup start-copy-job --recovery-point-arn $RP_ARN "
                    "--source-backup-vault-name $VAULT "
                    "--destination-backup-vault-arn $ISO_VAULT_ARN "
                    "--iam-role-arn $COPY_ROLE",
                ],
                rollback=[
                    "# Remove the deny-delete policy on the isolation vault.",
                    "aws backup delete-backup-vault-access-policy --backup-vault-name $ISO_VAULT",
                ],
                verify=[
                    "aws backup list-copy-jobs --by-destination-vault-arn $ISO_VAULT_ARN",
                ],
                notes=("True air gap on AWS = a separate AWS Organization, "
                       "different root credentials, MFA-delete on the bucket, "
                       "and Vault Lock in COMPLIANCE mode on the destination."),
            )

        if cid == "enforce_encryption_at_rest":
            return TranslatedFix(
                fix=[
                    "aws s3api put-bucket-encryption --bucket $BACKUP_BUCKET "
                    "--server-side-encryption-configuration "
                    "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                    "{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$KMS_KEY_ARN\"}}]}'",
                    "aws backup update-recovery-point-lifecycle "
                    "--backup-vault-name $VAULT --recovery-point-arn $RP_ARN "
                    "--lifecycle DeleteAfterDays=$DAYS",
                ],
                rollback=[
                    "aws s3api delete-bucket-encryption --bucket $BACKUP_BUCKET",
                ],
                verify=[
                    "aws s3api get-bucket-encryption --bucket $BACKUP_BUCKET",
                ],
            )

        return TranslatedFix(applicable=False,
                             notes=f"AWS S3 Lock translator does not implement {cid}.")


# --------------------------------------------------------------------------
# Azure Blob Immutability + Azure Backup Vault soft delete
# --------------------------------------------------------------------------

@register_translator("azure_blob_immutable")
class AzureBlobImmutableTranslator(BaseTranslator):
    """Azure Blob storage immutability + Recovery Services Vault soft delete.

    Mirrors the AWS S3 Lock translator. Uses the `az` CLI; equivalent ARM/
    Bicep templates are linked in the notes for declarative shops.
    """

    asset_match = ["backup", "cloud"]

    def supports(self, control_id: str) -> bool:
        return control_id in {
            "enforce_backup_retention",
            "enforce_backup_immutability",
            "enforce_backup_air_gap",
            "enforce_encryption_at_rest",
        }

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}

        if cid == "enforce_backup_immutability":
            days = int(p.get("immutability_days", 30))
            return TranslatedFix(
                fix=[
                    "# 1. Enable versioning + soft-delete on the storage account:",
                    "az storage account blob-service-properties update "
                    "--account-name $SA --resource-group $RG "
                    "--enable-versioning true --enable-delete-retention true "
                    f"--delete-retention-days {days}",
                    "",
                    "# 2. Apply a time-based, locked immutability policy at "
                    "container scope (cannot be reduced once locked):",
                    "az storage container immutability-policy create "
                    "--account-name $SA --container-name $CONTAINER "
                    f"--period {days} --allow-protected-append-writes true",
                    "az storage container immutability-policy lock "
                    "--account-name $SA --container-name $CONTAINER "
                    "--if-match '*'",
                    "",
                    "# 3. For Recovery Services Vault — turn on soft delete + "
                    "MUA (multi-user authorization) on the vault.",
                    "az backup vault backup-properties set --name $VAULT "
                    "--resource-group $RG --soft-delete-feature-state Enable",
                ],
                rollback=[
                    "# A LOCKED immutability policy cannot be reduced. "
                    "You can extend it; you cannot shorten it.",
                    "az storage container immutability-policy extend "
                    "--account-name $SA --container-name $CONTAINER "
                    "--period $NEW_DAYS --if-match $ETAG",
                ],
                verify=[
                    "az storage container immutability-policy show "
                    "--account-name $SA --container-name $CONTAINER",
                    "az backup vault backup-properties show --name $VAULT "
                    "--resource-group $RG",
                ],
                notes=("Locked time-based policies satisfy SEC 17a-4(f), "
                       "FINRA, CFTC, and EU GDPR retention requirements."),
            )

        if cid == "enforce_backup_retention":
            days = int(p.get("retention_days", 30))
            return TranslatedFix(
                fix=[
                    "# Define a daily backup policy with extended retention:",
                    "az backup policy create --vault-name $VAULT "
                    "--resource-group $RG --name SafeCadence-Daily "
                    "--policy '@policy.json'",
                    "",
                    "# policy.json (excerpt):",
                    "# {",
                    "#   \"properties\": {",
                    "#     \"backupManagementType\": \"AzureIaasVM\",",
                    "#     \"schedulePolicy\": {\"scheduleRunFrequency\": \"Daily\"},",
                    f"#     \"retentionPolicy\": {{ \"dailySchedule\": "
                    f"{{ \"retentionDuration\": {{ \"count\": {days}, \"durationType\": \"Days\" }} }} }}",
                    "#   }",
                    "# }",
                ],
                rollback=[
                    "az backup policy delete --vault-name $VAULT "
                    "--resource-group $RG --name SafeCadence-Daily",
                ],
                verify=[
                    "az backup policy show --vault-name $VAULT "
                    "--resource-group $RG --name SafeCadence-Daily "
                    "--query 'properties.retentionPolicy'",
                ],
            )

        if cid == "enforce_backup_air_gap":
            return TranslatedFix(
                fix=[
                    "# Cross-region restore (CRR) keeps a copy in a paired region:",
                    "az backup vault backup-properties set --name $VAULT "
                    "--resource-group $RG --cross-region-restore-flag Enabled",
                    "",
                    "# Multi-User Authorization (MUA) requires a second tenant "
                    "approval before destructive operations:",
                    "az backup vault resource-guard set --name $VAULT "
                    "--resource-group $RG --resource-guard-id $GUARD_ID",
                ],
                rollback=[
                    "az backup vault resource-guard remove --name $VAULT "
                    "--resource-group $RG",
                ],
                verify=[
                    "az backup vault show --name $VAULT --resource-group $RG "
                    "--query 'properties.publicNetworkAccess, properties.encryption'",
                ],
                notes=("Resource Guard + MUA + immutable Vault is the Azure-"
                       "native equivalent to AWS Vault Lock COMPLIANCE mode."),
            )

        if cid == "enforce_encryption_at_rest":
            return TranslatedFix(
                fix=[
                    "az storage account update --name $SA --resource-group $RG "
                    "--encryption-key-source Microsoft.Keyvault "
                    "--encryption-key-vault $KV_URI "
                    "--encryption-key-name $KEY_NAME",
                ],
                rollback=[
                    "az storage account update --name $SA --resource-group $RG "
                    "--encryption-key-source Microsoft.Storage",
                ],
                verify=[
                    "az storage account show --name $SA --resource-group $RG "
                    "--query 'encryption'",
                ],
            )

        return TranslatedFix(applicable=False,
                             notes=f"Azure Blob translator does not implement {cid}.")
