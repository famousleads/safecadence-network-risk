"""Cloud controls: IAM, public exposure, logging, encryption."""

from __future__ import annotations

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _check_block_public_exposure(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cloud = asset.get("cloud") or {}
    if cloud.get("public_exposure"):
        return EvaluationResult.FAIL, f"public exposure: ip={cloud.get('public_ip','')}"
    return EvaluationResult.PASS, "no public exposure"


register_control(ControlSpec(
    id="block_public_exposure",
    description="Cloud assets must not be publicly accessible unless explicitly allowed",
    applies_to=["cloud"],
    severity=Severity.CRITICAL,
    frameworks=["nist:AC-3", "cis:cloud-4.1", "pci:1.3"],
    check_fn=_check_block_public_exposure,
))


def _check_enforce_cloud_iam(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cloud = asset.get("cloud") or {}
    sec = asset.get("security") or {}
    findings = " ".join(sec.get("findings") or []).lower()
    if cloud.get("iam_role") == "" or cloud.get("iam_role") is None:
        return EvaluationResult.FAIL, "no IAM role attached"
    if "wildcard" in findings or "iam:*" in findings:
        return EvaluationResult.FAIL, "wildcard IAM permissions detected"
    return EvaluationResult.PASS, "iam role attached, no wildcard findings"


register_control(ControlSpec(
    id="enforce_cloud_iam",
    description="Cloud assets must have a least-privilege IAM role attached",
    applies_to=["cloud"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-6", "cis:cloud-1.16", "pci:7.1"],
    check_fn=_check_enforce_cloud_iam,
))


def _check_enforce_logging(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    raw = asset.get("raw_collection") or {}
    if isinstance(raw, dict):
        ident = (asset.get("identity") or {})
        provider = (asset.get("cloud") or {}).get("provider", "")
        # AWS CloudTrail / GCP Cloud Audit / Azure Activity Log markers
        markers = {"aws": "cloudtrail", "azure": "activity log", "gcp": "cloud audit"}
        m = markers.get(provider, "log")
        if m in str(raw).lower():
            return EvaluationResult.PASS, f"logging marker '{m}' present"
        return EvaluationResult.FAIL, f"no '{m}' marker found in collected data"
    return EvaluationResult.UNKNOWN, "no raw collection to evaluate"


register_control(ControlSpec(
    id="enforce_logging",
    description="Cloud audit logging (CloudTrail/Activity Log/Cloud Audit) must be enabled",
    applies_to=["cloud"],
    severity=Severity.HIGH,
    frameworks=["nist:AU-2", "cis:cloud-3.1", "pci:10.1"],
    check_fn=_check_enforce_logging,
))
