"""Server-side controls: patch level, password policy, MFA, encryption, default creds."""

from __future__ import annotations

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _check_enforce_patch_level(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    sec = asset.get("security") or {}
    if (sec.get("missing_patches") or []):
        return EvaluationResult.FAIL, f"{len(sec['missing_patches'])} missing patches"
    if sec.get("critical_cves", 0) > 0:
        return EvaluationResult.FAIL, f"{sec['critical_cves']} critical CVEs require patching"
    return EvaluationResult.PASS, "no missing patches or critical CVEs detected"


register_control(ControlSpec(
    id="enforce_patch_level",
    description="No critical CVEs and no documented missing patches",
    applies_to=["server", "network", "storage", "hypervisor"],
    severity=Severity.HIGH,
    frameworks=["nist:SI-2", "cis:1.8", "pci:6.2"],
    check_fn=_check_enforce_patch_level,
))


def _check_enforce_encryption_at_rest(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    # v6.4.3 — look in three places: the storage block, the cloud
    # block (S3/Blob/EBS), and the security findings text. Real
    # adapters report this in different shapes.
    storage = asset.get("storage") or {}
    cloud = asset.get("cloud") or {}
    sec = asset.get("security") or {}
    flag = storage.get("encryption_at_rest")
    if flag is None:
        flag = cloud.get("encryption_at_rest")
    if flag is None:
        # Cloud-specific signals
        if cloud.get("kms_key_id") or cloud.get("encryption_key_arn"):
            return EvaluationResult.PASS, "KMS-encrypted (cloud)"
        if cloud.get("default_encryption") is False:
            return EvaluationResult.FAIL, "default encryption disabled"
    if flag is True:
        return EvaluationResult.PASS, "encryption-at-rest enabled"
    if flag is False:
        return EvaluationResult.FAIL, "encryption-at-rest disabled"
    # Heuristic from findings text — last resort.
    findings = " ".join(sec.get("findings") or []).lower()
    if "no default encryption" in findings or "encryption disabled" in findings:
        return EvaluationResult.FAIL, "finding flagged: no encryption at rest"
    return EvaluationResult.UNKNOWN, "encryption-at-rest state not collected"


register_control(ControlSpec(
    id="enforce_encryption_at_rest",
    description="Storage must have encryption-at-rest enabled",
    applies_to=["storage", "server", "cloud"],
    severity=Severity.HIGH,
    frameworks=["nist:SC-28", "cis:3.4", "pci:3.4"],
    check_fn=_check_enforce_encryption_at_rest,
))


def _check_enforce_encryption_in_transit(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    sec = asset.get("security") or {}
    weak = sec.get("weak_protocols") or []
    if any(p in ("telnet", "ftp", "http", "smb1", "sslv3", "tls1.0") for p in weak):
        return EvaluationResult.FAIL, f"weak transport protocols in use: {weak}"
    return EvaluationResult.PASS, "no weak transport protocols detected"


register_control(ControlSpec(
    id="enforce_encryption_in_transit",
    description="No cleartext protocols (Telnet/FTP/HTTP/SMB1) in use",
    applies_to=["server", "network", "storage"],
    severity=Severity.HIGH,
    frameworks=["nist:SC-8", "cis:5.2", "pci:4.1"],
    check_fn=_check_enforce_encryption_in_transit,
))


def _check_restrict_default_creds(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    sec = asset.get("security") or {}
    findings = " ".join(sec.get("findings") or []).lower()
    if "default credential" in findings or "default password" in findings:
        return EvaluationResult.FAIL, "default credentials flagged in findings"
    return EvaluationResult.PASS, "no default-credential findings"


register_control(ControlSpec(
    id="restrict_default_creds",
    description="No default vendor credentials in use",
    applies_to=["server", "network", "storage", "hypervisor", "cloud"],
    severity=Severity.CRITICAL,
    frameworks=["nist:IA-5", "cis:5.4", "pci:2.1"],
    check_fn=_check_restrict_default_creds,
))


def _check_enforce_password_policy(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    # Length requirement comes from params; default 12.
    min_len = int(params.get("min_length", 12))
    raw = str(asset.get("raw_collection") or "").lower()
    if not raw:
        return EvaluationResult.UNKNOWN, "no config collected"
    # Naive parse — translators do the heavy lifting; check is best-effort.
    if "minlen" in raw or "min-length" in raw or "minimum-length" in raw:
        return EvaluationResult.PASS, "password length policy detected"
    return EvaluationResult.UNKNOWN, f"could not verify min_length={min_len} from collected data"


register_control(ControlSpec(
    id="enforce_password_policy",
    description="Local password policy enforces minimum length and complexity",
    applies_to=["server", "network"],
    severity=Severity.MEDIUM,
    frameworks=["nist:IA-5", "cis:5.4", "pci:8.2.3"],
    check_fn=_check_enforce_password_policy,
))


def _check_enforce_mfa(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    sec = asset.get("security") or {}
    if sec.get("mfa_enabled") is True:
        return EvaluationResult.PASS, "MFA enabled"
    if sec.get("mfa_enabled") is False:
        return EvaluationResult.FAIL, "MFA disabled"
    return EvaluationResult.UNKNOWN, "MFA state not collected"


register_control(ControlSpec(
    id="enforce_mfa",
    description="Multi-factor authentication required for administrative access",
    applies_to=["server", "cloud", "network"],
    severity=Severity.HIGH,
    frameworks=["nist:IA-2", "cis:5.6", "pci:8.4.2"],
    check_fn=_check_enforce_mfa,
))


def _check_enforce_least_privilege(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    sec = asset.get("security") or {}
    if sec.get("over_privileged_accounts", 0) > 0:
        return EvaluationResult.FAIL, f"{sec['over_privileged_accounts']} over-privileged accounts"
    return EvaluationResult.PASS, "no over-privileged accounts flagged"


register_control(ControlSpec(
    id="enforce_least_privilege",
    description="No accounts have privileges beyond their role",
    applies_to=["server", "cloud", "network"],
    severity=Severity.MEDIUM,
    frameworks=["nist:AC-6", "cis:5.5", "pci:7.1"],
    check_fn=_check_enforce_least_privilege,
))
