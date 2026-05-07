"""
AWS account adapter — boto3-based.

Discovers EC2 instances, RDS databases, S3 buckets, security groups,
IAM users, and Lambda functions across all enabled regions.

Each AWS account = one adapter target. Each EC2/RDS/etc resource =
one UnifiedAsset.

Required credentials:
  - access_key_id
  - secret_access_key
  - region (default region; the adapter scans all enabled)
  - session_token (optional, for STS-assumed roles)

Or set AWS_PROFILE env var and pass {profile: 'name'} as credentials.
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


@register_adapter("aws_account")
class AWSAccountAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="aws_account",
        description="AWS account discovery via boto3 SDK (EC2 + RDS + S3 + SG + IAM + Lambda)",
        vendor="aws",
        asset_types=["cloud"],
        connection_types=[ConnectionType.VENDOR_SDK],
        required_credentials=["access_key_id", "secret_access_key"],
        supports_discovery=True,
        rate_limit_calls_per_minute=120,
        requires_python_extras=["aws"],
        documentation_url="https://boto3.amazonaws.com/v1/documentation/api/latest/index.html",
    )

    def __init__(self, target: str, credentials: dict[str, str], **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.account_id = target  # aws account ID
        self._session = None

    def _boto3_session(self):
        if self._session:
            return self._session
        try:
            import boto3
        except ImportError:
            raise RuntimeError("boto3 required. Install: pip install boto3")
        if self.credentials.get("profile"):
            self._session = boto3.Session(profile_name=self.credentials["profile"])
        else:
            self._session = boto3.Session(
                aws_access_key_id=self.credentials.get("access_key_id"),
                aws_secret_access_key=self.credentials.get("secret_access_key"),
                aws_session_token=self.credentials.get("session_token"),
                region_name=self.credentials.get("region", "us-east-1"),
            )
        return self._session

    def test_connection(self) -> dict:
        try:
            sts = self._boto3_session().client("sts")
            ident = sts.get_caller_identity()
            return {"ok": True, "detail": f"Account {ident.get('Account')} as {ident.get('Arn')}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def discover(self) -> list[dict]:
        """Enumerate all EC2 instances + RDS + S3 buckets across enabled regions."""
        assets = []
        try:
            sess = self._boto3_session()
            ec2 = sess.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        except Exception:
            regions = [self.credentials.get("region", "us-east-1")]

        for region in regions:
            # EC2 instances
            try:
                ec2_r = self._boto3_session().client("ec2", region_name=region)
                for r in ec2_r.describe_instances().get("Reservations", []):
                    for i in r.get("Instances", []):
                        if i.get("State", {}).get("Name") == "terminated":
                            continue
                        assets.append({
                            "asset_id": f"aws:{self.account_id}:ec2:{region}:{i['InstanceId']}",
                            "identity_hint": {
                                "type": "ec2",
                                "region": region,
                                "instance_id": i["InstanceId"],
                            },
                        })
            except Exception:
                pass

            # RDS — TODO
            # S3 — TODO (S3 is global, only enumerate once)

        return assets

    def collect(self, asset_id: str) -> dict[str, Any]:
        # asset_id format: aws:<account>:<service>:<region>:<resource_id>
        parts = asset_id.split(":")
        if len(parts) < 5:
            return {"_error": "invalid asset_id"}
        _, account, service, region, resource_id = parts[:5]

        if service == "ec2":
            try:
                ec2 = self._boto3_session().client("ec2", region_name=region)
                resp = ec2.describe_instances(InstanceIds=[resource_id])
                instances = resp.get("Reservations", [{}])[0].get("Instances", [])
                if instances:
                    inst = instances[0]
                    # Also get security group rules
                    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    sg_rules = []
                    if sg_ids:
                        sg_resp = ec2.describe_security_groups(GroupIds=sg_ids)
                        sg_rules = sg_resp.get("SecurityGroups", [])
                    return {"instance": inst, "security_groups": sg_rules, "service": "ec2"}
            except Exception as e:
                return {"_error": str(e)}

        return {"_error": f"unsupported service: {service}"}

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        parts = asset_id.split(":")
        _, account_id, service, region, resource_id = parts[:5]

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="AWS",
            product_family=service.upper(),
            asset_type="cloud",
        )

        cloud = Cloud(
            provider="aws",
            account_id=account_id,
            region=region,
            instance_id=resource_id,
        )

        security = Security()

        if service == "ec2" and "instance" in raw:
            inst = raw["instance"]
            identity.hostname = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), ""
            )
            cloud.instance_type = inst.get("InstanceType", "")
            cloud.image_id = inst.get("ImageId", "")
            cloud.vpc_id = inst.get("VpcId", "")
            cloud.subnet_id = inst.get("SubnetId", "")
            cloud.iam_role = (inst.get("IamInstanceProfile") or {}).get("Arn", "")
            cloud.public_ip = inst.get("PublicIpAddress", "")
            cloud.public_exposure = bool(inst.get("PublicIpAddress"))
            cloud.tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            cloud.security_groups = [
                {"id": sg["GroupId"], "name": sg["GroupName"]}
                for sg in inst.get("SecurityGroups", [])
            ]

            # Security findings — check for 0.0.0.0/0 ingress on any SG
            for sg in raw.get("security_groups", []):
                for rule in sg.get("IpPermissions", []):
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "any")
                            security.findings.append(
                                f"Security group {sg['GroupId']} allows port {port} from 0.0.0.0/0"
                            )
                            security.recommended_actions.append(
                                f"Restrict {sg['GroupId']} ingress to known IP ranges only"
                            )
                            if port in (22, 3389):
                                security.critical_cves = max(1, security.critical_cves)

        asset = UnifiedAsset(
            identity=identity,
            cloud=cloud,
            security=security,
            raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
