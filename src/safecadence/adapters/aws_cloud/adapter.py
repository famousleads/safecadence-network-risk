"""
AWS adapter — text-based.

Designed to ingest exports from:
  aws iam list-users, list-roles, list-account-aliases
  aws ec2 describe-security-groups
  aws s3api list-buckets / get-bucket-policy / get-bucket-encryption
  aws cloudtrail describe-trails
  aws kms list-keys / list-aliases
  aws config describe-configuration-recorders
  CloudFormation / Terraform plan output
"""

from __future__ import annotations

import re

from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


_ACCOUNT_RE = re.compile(r'"Account":\s*"(\d{12})"|account[-_ ]?id["\s:]+(\d{12})', re.IGNORECASE)
_REGION_RE  = re.compile(r'"Region":\s*"([a-z]+-[a-z]+-\d+)"|region["\s:]+([a-z]+-[a-z]+-\d+)', re.IGNORECASE)


@register_adapter
class AWSCloudAdapter(BaseAdapter):
    slug = "aws-cloud"
    label = "AWS account"
    os_family = ["aws"]
    filename_hints = ("aws", "ec2", "s3", "iam", "cloudformation", "terraform-aws")
    content_hints = (
        '"AwsAccountId"', '"AccountAliases"', '"OwnerId"',
        "aws_iam_user", "aws_security_group", "aws_s3_bucket",
        "AWS::EC2::SecurityGroup", "AWS::S3::Bucket", "AWS::IAM::",
        "arn:aws:",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        text = text or ""
        account = ""
        region  = ""
        if (m := _ACCOUNT_RE.search(text)):
            account = (m.group(1) or m.group(2) or "")
        if (m := _REGION_RE.search(text)):
            region = (m.group(1) or m.group(2) or "")
        return ParsedConfig(
            vendor="aws-cloud",
            device_type="cloud",
            hostname=account or "aws-account",
            os="aws",
            version=region,
            model="AWS",
            raw_config=text,
        )
