"""
v9.6 — Cloud connectors: AWS EC2, Azure VMs, GCP Compute.

Cloud assets are invisible to LAN scans by definition. This module pulls
them via each provider's CLI (aws / az / gcloud) and produces unified
DiscoveredHost-shaped records.

Why CLI not SDK?
  - No new heavy deps (boto3 alone is ~70MB).
  - Operators already have these CLIs configured with credentials and
    profiles — we leverage their existing auth chain (sso, profiles,
    env vars, IMDS) instead of asking them to wire credentials into us.
  - The CLI output format is stable and well-documented.

All three harvesters take an optional run_fn seam for tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# ----------------------------------------------------------- shared types

@dataclass
class CloudInstance:
    cloud: str                         # "aws" | "azure" | "gcp"
    instance_id: str
    name: str = ""
    region: str = ""
    state: str = ""                    # running | stopped | terminated …
    instance_type: str = ""
    public_ip: str = ""
    private_ip: str = ""
    os: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    launched_at: str = ""


@dataclass
class CloudHarvestResult:
    cloud: str
    started_at: str
    finished_at: str
    instances: list[CloudInstance] = field(default_factory=list)
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.instances)


RunFn = Callable[[list[str]], str]


def _run(cmd: list[str], *, timeout: int = 60) -> str:
    """Default: shell out, return stdout. Raises RuntimeError on non-zero."""
    if not shutil.which(cmd[0]):
        raise RuntimeError(
            f"{cmd[0]} CLI not found. Install it and configure credentials, "
            f"or paste raw JSON output into the slide-over."
        )
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "command failed")
    return out.stdout


# ============================================================ status probes


def _probe(cmd: list[str], *, timeout: int = 6) -> tuple[bool, str]:
    """(installed, version_or_error)."""
    bin_ = cmd[0]
    if not shutil.which(bin_):
        return False, "not installed"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return True, (r.stderr or r.stdout).strip().splitlines()[0][:200]
        return True, (r.stdout or "").strip().splitlines()[0][:200]
    except Exception as e:
        return True, f"probe failed: {e}"


def cli_status() -> dict:
    """Probe each cloud CLI for install + auth status.

    Returns:
      {
        aws:   {installed, version, authed, identity, install_hint, auth_hint},
        azure: {...},
        gcp:   {...},
      }
    """
    out: dict = {}

    # ---- AWS ----
    inst, ver = _probe(["aws", "--version"])
    aws: dict = {"installed": inst, "version": ver if inst else "",
                 "install_hint": (
                     "macOS:    brew install awscli\n"
                     "Linux:    curl \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o awscliv2.zip\n"
                     "          unzip awscliv2.zip && sudo ./aws/install\n"
                     "Linux ARM: same URL but awscli-exe-linux-aarch64.zip\n"
                     "Windows:  https://awscli.amazonaws.com/AWSCLIV2.msi\n"
                     "Docs:     https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html\n"
                     "(install AWS CLI v2 — v1 from pip is deprecated)"
                 ),
                 "auth_hint": (
                     "IAM user:    aws configure          # prompts for access key + secret + region\n"
                     "AWS SSO:     aws configure sso      # browser flow, recommended for orgs on Identity Center\n"
                     "EC2 host:    nothing — instance role is auto-detected\n"
                     "Env vars:    AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION\n"
                     "Verify:      aws sts get-caller-identity"
                 ),
                 "min_iam": "ec2:DescribeInstances (read-only)",
                 "authed": False, "identity": "",
                 "authed_error": ""}
    if inst:
        ok, who = _probe(["aws", "sts", "get-caller-identity",
                          "--output", "text", "--query", "Arn"], timeout=8)
        # _probe returns (True, output_or_err) when binary exists; we
        # need to check if it actually returned an ARN.
        if ok and "arn:" in who:
            aws["authed"] = True
            aws["identity"] = who
        else:
            aws["authed"] = False
            aws["authed_error"] = who or "no credentials"
    out["aws"] = aws

    # ---- Azure ----
    inst, ver = _probe(["az", "version", "--output", "tsv"])
    az: dict = {"installed": inst, "version": ver if inst else "",
                "install_hint": (
                    "macOS:    brew install azure-cli\n"
                    "Debian:   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash\n"
                    "RHEL:     sudo dnf install azure-cli\n"
                    "Windows:  winget install -e --id Microsoft.AzureCLI\n"
                    "          (or download MSI from https://aka.ms/installazurecliwindows)\n"
                    "Docs:     https://learn.microsoft.com/cli/azure/install-azure-cli"
                ),
                "auth_hint": (
                    "Interactive:  az login                  # opens browser, picks default subscription\n"
                    "Pick sub:     az account set --subscription <name-or-id>\n"
                    "Service Pri:  az login --service-principal -u <appId> -p <secret> --tenant <tenant>\n"
                    "Managed Id:   az login --identity        # on Azure VMs / App Service\n"
                    "Verify:       az account show"
                ),
                "min_iam": "Reader role on subscription(s)",
                "authed": False, "identity": "",
                "authed_error": ""}
    if inst:
        ok, who = _probe(["az", "account", "show", "--query", "user.name",
                          "-o", "tsv"], timeout=8)
        if ok and who and "ERROR" not in who.upper() and "Please run" not in who:
            az["authed"] = True
            az["identity"] = who.strip()
        else:
            az["authed_error"] = who or "not logged in"
    out["azure"] = az

    # ---- GCP ----
    inst, ver = _probe(["gcloud", "--version"])
    gcp: dict = {"installed": inst, "version": ver if inst else "",
                 "install_hint": (
                     "macOS:    brew install --cask gcloud-cli\n"
                     "          (older brew taps used 'google-cloud-sdk' — both work)\n"
                     "Linux:    curl https://sdk.cloud.google.com | bash\n"
                     "          exec -l $SHELL\n"
                     "Debian:   sudo apt-get install google-cloud-cli\n"
                     "          (after adding the Google Cloud apt repo — see docs)\n"
                     "Windows:  download GoogleCloudSDKInstaller.exe from\n"
                     "          https://cloud.google.com/sdk/docs/install\n"
                     "Docs:     https://cloud.google.com/sdk/docs/install"
                 ),
                 "auth_hint": (
                     "Interactive:  gcloud auth login                # browser flow\n"
                     "Set project:  gcloud config set project YOUR_PROJECT_ID\n"
                     "Service acct: gcloud auth activate-service-account --key-file=key.json\n"
                     "Workload Id:  on GKE/GCE, ADC is auto-detected — no setup\n"
                     "Verify:       gcloud auth list   &&   gcloud config get-value project"
                 ),
                 "min_iam": "compute.instances.list (Compute Viewer role)",
                 "authed": False, "identity": "",
                 "authed_error": ""}
    if inst:
        ok, who = _probe(["gcloud", "auth", "list",
                          "--filter=status:ACTIVE",
                          "--format=value(account)"], timeout=8)
        if ok and who and "@" in who:
            gcp["authed"] = True
            gcp["identity"] = who.strip()
        else:
            gcp["authed_error"] = who or "no active account"
    out["gcp"] = gcp

    return out


# ============================================================== AWS

def _aws_cmd(profile: str, region: str) -> list[str]:
    cmd = ["aws", "ec2", "describe-instances",
           "--no-paginate", "--output", "json"]
    if profile: cmd += ["--profile", profile]
    if region:  cmd += ["--region", region]
    return cmd


def parse_aws_describe_instances(json_text: str) -> list[CloudInstance]:
    out: list[CloudInstance] = []
    try:
        data = json.loads(json_text or "{}")
    except json.JSONDecodeError:
        return out
    for res in data.get("Reservations", []):
        for inst in res.get("Instances", []):
            tags = {t.get("Key", ""): t.get("Value", "")
                    for t in inst.get("Tags") or []}
            name = tags.get("Name", "") or inst.get("InstanceId", "")
            out.append(CloudInstance(
                cloud="aws",
                instance_id=inst.get("InstanceId", ""),
                name=name,
                region=(inst.get("Placement") or {}).get("AvailabilityZone", "")[:-1],
                state=(inst.get("State") or {}).get("Name", ""),
                instance_type=inst.get("InstanceType", ""),
                public_ip=inst.get("PublicIpAddress", "") or "",
                private_ip=inst.get("PrivateIpAddress", "") or "",
                os=(inst.get("PlatformDetails") or
                    inst.get("Platform") or "linux"),
                tags=tags,
                launched_at=str(inst.get("LaunchTime") or ""),
            ))
    return out


def harvest_aws(*, profile: str = "", region: str = "",
                run_fn: Optional[RunFn] = None,
                json_text: Optional[str] = None,
                ) -> CloudHarvestResult:
    started = datetime.now(timezone.utc).isoformat()
    res = CloudHarvestResult(cloud="aws", started_at=started, finished_at="")
    if json_text is not None:
        res.instances = parse_aws_describe_instances(json_text)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    runner = run_fn or _run
    try:
        text = runner(_aws_cmd(profile, region))
    except Exception as e:
        res.error = str(e)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.instances = parse_aws_describe_instances(text)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# ============================================================== Azure

def _az_cmd(subscription: str) -> list[str]:
    cmd = ["az", "vm", "list", "-d", "-o", "json"]
    if subscription: cmd += ["--subscription", subscription]
    return cmd


def parse_az_vm_list(json_text: str) -> list[CloudInstance]:
    out: list[CloudInstance] = []
    try:
        rows = json.loads(json_text or "[]")
    except json.JSONDecodeError:
        return out
    for r in rows:
        out.append(CloudInstance(
            cloud="azure",
            instance_id=r.get("vmId", "") or r.get("id", ""),
            name=r.get("name", ""),
            region=r.get("location", ""),
            state=(r.get("powerState", "") or "").replace("VM ", ""),
            instance_type=(r.get("hardwareProfile") or {}).get("vmSize", ""),
            public_ip=r.get("publicIps", "") or "",
            private_ip=r.get("privateIps", "") or "",
            os=(r.get("storageProfile", {}).get("osDisk", {}).get("osType", "")
                or "").lower(),
            tags=r.get("tags") or {},
            launched_at=r.get("timeCreated", "") or "",
        ))
    return out


def harvest_azure(*, subscription: str = "",
                  run_fn: Optional[RunFn] = None,
                  json_text: Optional[str] = None,
                  ) -> CloudHarvestResult:
    started = datetime.now(timezone.utc).isoformat()
    res = CloudHarvestResult(cloud="azure", started_at=started, finished_at="")
    if json_text is not None:
        res.instances = parse_az_vm_list(json_text)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    runner = run_fn or _run
    try:
        text = runner(_az_cmd(subscription))
    except Exception as e:
        res.error = str(e)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.instances = parse_az_vm_list(text)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# ============================================================== GCP

def _gcloud_cmd(project: str) -> list[str]:
    cmd = ["gcloud", "compute", "instances", "list", "--format=json"]
    if project: cmd += ["--project", project]
    return cmd


def parse_gcloud_list(json_text: str) -> list[CloudInstance]:
    out: list[CloudInstance] = []
    try:
        rows = json.loads(json_text or "[]")
    except json.JSONDecodeError:
        return out
    for r in rows:
        # GCP nests IPs inside networkInterfaces[].accessConfigs[].natIP
        priv = ""; pub = ""
        for ni in r.get("networkInterfaces") or []:
            priv = priv or ni.get("networkIP", "")
            for ac in ni.get("accessConfigs") or []:
                pub = pub or ac.get("natIP", "")
        zone = r.get("zone", "").rsplit("/", 1)[-1]
        labels = r.get("labels") or {}
        out.append(CloudInstance(
            cloud="gcp",
            instance_id=str(r.get("id", "")),
            name=r.get("name", ""),
            region=zone[:-2] if zone and zone[-2:].lstrip("-").isalpha() else zone,
            state=r.get("status", "").lower(),
            instance_type=r.get("machineType", "").rsplit("/", 1)[-1],
            public_ip=pub, private_ip=priv,
            os=labels.get("os", "") or "linux",
            tags=labels,
            launched_at=r.get("creationTimestamp", "") or "",
        ))
    return out


def harvest_gcp(*, project: str = "",
                run_fn: Optional[RunFn] = None,
                json_text: Optional[str] = None,
                ) -> CloudHarvestResult:
    started = datetime.now(timezone.utc).isoformat()
    res = CloudHarvestResult(cloud="gcp", started_at=started, finished_at="")
    if json_text is not None:
        res.instances = parse_gcloud_list(json_text)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    runner = run_fn or _run
    try:
        text = runner(_gcloud_cmd(project))
    except Exception as e:
        res.error = str(e)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.instances = parse_gcloud_list(text)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# --------------------------------------------------- → DiscoveredHost-shape

def instances_as_discovered_hosts(result: CloudHarvestResult) -> list[dict]:
    out: list[dict] = []
    for i in result.instances:
        os_lower = (i.os or "").lower()
        if "windows" in os_lower:
            os_guess = "windows"; vendor = "microsoft"
        elif "linux" in os_lower:
            os_guess = "linux"; vendor = ""
        else:
            os_guess = os_lower or ""; vendor = ""
        out.append({
            "ip": i.public_ip or i.private_ip,
            "hostname": i.name,
            "mac": "",
            "vendor_guess": vendor or i.cloud,
            "os_guess": os_guess,
            "device_type_guess": "server",
            "snmp_sysdescr": f"{i.cloud}/{i.instance_type}",
            "open_ports": [],
            "banners": {
                "_via": f"{i.cloud} {i.region}",
                "_instance_id": i.instance_id,
                "_state": i.state,
                "_private_ip": i.private_ip,
                "_public_ip": i.public_ip,
                "_launched": i.launched_at,
                "_tags": ",".join(f"{k}={v}" for k, v in
                                   list(i.tags.items())[:5]),
            },
        })
    return out
