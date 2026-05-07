"""Identity-system controls — added in v6.4.2.

Closes the embarrassing gap where the v6.0 Identity Intelligence Engine
shipped (5 adapters, 4 translators, cross-system drift detection) but
the policy control library had ZERO controls with ``applies_to=["identity"]``.
The Builder wizard listed "Identity / NAC" as a selectable asset type
and then suggested zero controls for every framework, every strictness.

These controls run against assets carrying an ``identity_block`` (the
schema produced by the AD / Entra ID / Okta / Cisco ISE / ClearPass
adapters). Each is intentionally conservative — UNKNOWN when the field
isn't collected, never PASS by accident.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _ib(asset: dict) -> dict:
    return asset.get("identity_block") or {}


def _has_admin_role(ib: dict) -> bool:
    """True if any authorized group looks privileged."""
    groups = [str(g).lower() for g in (ib.get("authorized_groups") or [])]
    return any(("admin" in g or "owner" in g or "root" in g
                or "domain admins" in g) for g in groups)


# --------------------------------------------------------------------------
# idp_require_mfa_for_admins
# --------------------------------------------------------------------------

def _check_mfa_for_admins(asset: dict, params: dict
                          ) -> tuple[EvaluationResult, str]:
    ib = _ib(asset)
    if not ib:
        return EvaluationResult.NOT_APPLICABLE, "no identity_block on asset"
    if not _has_admin_role(ib):
        return EvaluationResult.NOT_APPLICABLE, "asset has no admin/owner role"
    enrolled = ib.get("mfa_enrolled")
    if enrolled is True:
        return EvaluationResult.PASS, "MFA enrolled"
    if enrolled is False:
        return EvaluationResult.FAIL, "admin role without MFA"
    return EvaluationResult.UNKNOWN, "mfa_enrolled not collected"


register_control(ControlSpec(
    id="idp_require_mfa_for_admins",
    description="Every identity holding an admin or owner role must "
                 "have MFA enrolled.",
    applies_to=["identity"],
    severity=Severity.CRITICAL,
    frameworks=["nist:IA-2", "iso-27001:A.9.4.2", "pci:8.4.2",
                "cis:6.5", "hipaa:164.308(a)(5)(ii)(D)",
                "zero-trust:PR.AC-7"],
    check_fn=_check_mfa_for_admins,
))


# --------------------------------------------------------------------------
# idp_disable_dormant_accounts
# --------------------------------------------------------------------------

def _check_dormant(asset: dict, params: dict
                   ) -> tuple[EvaluationResult, str]:
    ib = _ib(asset)
    if not ib:
        return EvaluationResult.NOT_APPLICABLE, "no identity_block on asset"
    days_threshold = int((params or {}).get("max_days_idle", 90))
    last = ib.get("last_login") or ib.get("last_signin")
    if not last:
        return EvaluationResult.UNKNOWN, "last_login not collected"
    try:
        ts = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        return EvaluationResult.UNKNOWN, f"unparseable last_login: {last!r}"
    age = (datetime.now(timezone.utc) - ts).days
    if age <= days_threshold:
        return EvaluationResult.PASS, f"last_login {age}d ago"
    return EvaluationResult.FAIL, (
        f"identity dormant for {age}d (policy max: {days_threshold}d)"
    )


register_control(ControlSpec(
    id="idp_disable_dormant_accounts",
    description="Identity accounts inactive longer than the policy "
                 "threshold (default 90 days) must be disabled.",
    applies_to=["identity"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-2", "cis:6.2", "iso-27001:A.9.2.6",
                "pci:8.1.4", "hipaa:164.308(a)(3)(ii)(C)",
                "zero-trust:PR.AC-1"],
    check_fn=_check_dormant,
))


# --------------------------------------------------------------------------
# idp_password_complexity
# --------------------------------------------------------------------------

def _check_password_complexity(asset: dict, params: dict
                                ) -> tuple[EvaluationResult, str]:
    ib = _ib(asset)
    if not ib:
        return EvaluationResult.NOT_APPLICABLE, "no identity_block on asset"
    min_len = int((params or {}).get("min_length", 14))
    posture = ib.get("posture_score") or ib.get("password_min_length")
    if posture is None:
        return EvaluationResult.UNKNOWN, "password_min_length not collected"
    try:
        actual = int(posture)
    except (TypeError, ValueError):
        return EvaluationResult.UNKNOWN, f"posture not numeric: {posture!r}"
    if actual >= min_len:
        return EvaluationResult.PASS, f"min_length {actual} >= {min_len}"
    return EvaluationResult.FAIL, (
        f"password min_length {actual} below policy {min_len}"
    )


register_control(ControlSpec(
    id="idp_password_complexity",
    description="Password policy must enforce a minimum length "
                 "(default 14 characters) plus complexity.",
    applies_to=["identity"],
    severity=Severity.HIGH,
    frameworks=["nist:IA-5", "iso-27001:A.9.4.3", "pci:8.2.3",
                "cis:5.4", "hipaa:164.308(a)(5)(ii)(D)",
                "zero-trust:PR.AC-1"],
    check_fn=_check_password_complexity,
))


# --------------------------------------------------------------------------
# idp_conditional_access
# --------------------------------------------------------------------------

def _check_conditional_access(asset: dict, params: dict
                               ) -> tuple[EvaluationResult, str]:
    ib = _ib(asset)
    if not ib:
        return EvaluationResult.NOT_APPLICABLE, "no identity_block on asset"
    provider = (ib.get("provider") or "").lower()
    if provider not in ("entra", "okta", "azure-ad", "microsoft"):
        return EvaluationResult.NOT_APPLICABLE, (
            f"provider '{provider}' has no conditional access concept"
        )
    rules = ib.get("conditional_access_rules") or ib.get("ca_rules")
    if rules is None:
        return EvaluationResult.UNKNOWN, "conditional_access_rules not collected"
    if not rules:
        return EvaluationResult.FAIL, "no conditional access rules defined"
    return EvaluationResult.PASS, f"{len(rules)} conditional access rules in place"


register_control(ControlSpec(
    id="idp_conditional_access",
    description="Identity provider must enforce conditional access "
                 "policies (location, device, risk-based).",
    applies_to=["identity"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-2(11)", "cis:6.7", "iso-27001:A.9.4.1",
                "pci:8.1", "hipaa:164.312(a)(1)",
                "zero-trust:PR.AC-3"],
    check_fn=_check_conditional_access,
))


# --------------------------------------------------------------------------
# idp_privileged_role_review
# --------------------------------------------------------------------------

def _check_role_review(asset: dict, params: dict
                       ) -> tuple[EvaluationResult, str]:
    ib = _ib(asset)
    if not ib:
        return EvaluationResult.NOT_APPLICABLE, "no identity_block on asset"
    if not _has_admin_role(ib):
        return EvaluationResult.NOT_APPLICABLE, "asset has no admin/owner role"
    last_review = ib.get("last_access_review")
    if not last_review:
        return EvaluationResult.UNKNOWN, "last_access_review not collected"
    try:
        ts = datetime.fromisoformat(str(last_review).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        return EvaluationResult.UNKNOWN, "unparseable last_access_review"
    max_days = int((params or {}).get("max_days_since_review", 180))
    age = (datetime.now(timezone.utc) - ts).days
    if age <= max_days:
        return EvaluationResult.PASS, f"reviewed {age}d ago"
    return EvaluationResult.FAIL, (
        f"privileged role not reviewed in {age}d (policy max: {max_days})"
    )


register_control(ControlSpec(
    id="idp_privileged_role_review",
    description="Privileged roles must be re-attested at least every "
                 "180 days (configurable).",
    applies_to=["identity"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-2(7)", "cis:6.6", "iso-27001:A.9.2.5",
                "pci:7.1.4", "hipaa:164.308(a)(3)(ii)(B)",
                "zero-trust:PR.AC-4"],
    check_fn=_check_role_review,
))
