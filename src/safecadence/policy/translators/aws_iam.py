"""AWS translator. Outputs IAM JSON policies, security-group rules,
S3 bucket policies, CloudTrail config, KMS encryption snippets."""

from __future__ import annotations

import json

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("aws_iam")
class AWSTranslator(BaseTranslator):
    asset_match = ["cloud"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "block_public_exposure":
            return TranslatedFix(
                fix=[
                    "# Block all public S3 access at account level:",
                    "aws s3control put-public-access-block --account-id $ACCOUNT_ID --public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    "",
                    "# For EC2 — remove 0.0.0.0/0 ingress from security groups:",
                    "aws ec2 revoke-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0",
                ],
                rollback=[
                    "aws s3control delete-public-access-block --account-id $ACCOUNT_ID",
                ],
                verify=[
                    "aws s3control get-public-access-block --account-id $ACCOUNT_ID",
                    "aws ec2 describe-security-groups --query 'SecurityGroups[*].IpPermissions'",
                ],
            )
        if cid == "enforce_cloud_iam":
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyWildcardActions",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
                }]
            }
            return TranslatedFix(
                fix=[
                    "# Attach a deny-wildcard SCP to the OU or account.",
                    "# scp.json:",
                    json.dumps(policy, indent=2),
                    "aws organizations create-policy --type SERVICE_CONTROL_POLICY --name DenyWildcards "
                    "--description 'Deny wildcard actions' --content file://scp.json",
                ],
                rollback=["aws organizations delete-policy --policy-id $POLICY_ID"],
                verify=["aws organizations list-policies --filter SERVICE_CONTROL_POLICY"],
            )
        if cid == "enforce_logging":
            return TranslatedFix(
                fix=[
                    "# Enable CloudTrail org-wide trail:",
                    "aws cloudtrail create-trail --name SafeCadence-OrgTrail --s3-bucket-name $LOG_BUCKET --is-multi-region-trail --is-organization-trail",
                    "aws cloudtrail start-logging --name SafeCadence-OrgTrail",
                    "# Enable Config:",
                    "aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=$CONFIG_ROLE_ARN,recordingGroup={allSupported=true,includeGlobalResourceTypes=true}",
                    "aws configservice start-configuration-recorder --configuration-recorder-name default",
                ],
                rollback=["aws cloudtrail stop-logging --name SafeCadence-OrgTrail"],
                verify=["aws cloudtrail get-trail-status --name SafeCadence-OrgTrail"],
            )
        if cid == "enforce_encryption_at_rest":
            return TranslatedFix(
                fix=[
                    "# Enable EBS default encryption:",
                    "aws ec2 enable-ebs-encryption-by-default",
                    "# Enable S3 default encryption:",
                    "aws s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration "
                    "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
                ],
                rollback=["aws ec2 disable-ebs-encryption-by-default"],
                verify=["aws ec2 get-ebs-encryption-by-default",
                        "aws s3api get-bucket-encryption --bucket $BUCKET"],
            )
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=[
                    "# IAM policy fragment — deny if no MFA:",
                    json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
                        }]
                    }, indent=2),
                ],
                rollback=["# detach the MFA-deny policy from impacted IAM principals"],
                verify=["aws iam list-virtual-mfa-devices"],
            )
        if cid == "enforce_least_privilege":
            return TranslatedFix(
                fix=["# Use IAM Access Analyzer to find unused access:",
                     "aws accessanalyzer create-analyzer --analyzer-name SC-Unused --type ACCOUNT_UNUSED_ACCESS",
                     "# Generate least-priv policy from CloudTrail:",
                     "aws iam generate-service-last-accessed-details --arn $ROLE_ARN"],
                rollback=["aws accessanalyzer delete-analyzer --analyzer-name SC-Unused"],
                verify=["aws accessanalyzer list-analyzers"],
            )
        return TranslatedFix(applicable=False, notes=f"aws_iam: no translation for {cid}")
