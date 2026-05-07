"""
v7.7 — Identity findings + remediation.

Two related capabilities:

  scan_findings(assets, ...) → list of Finding
       Static analysis pass over the asset graph that surfaces stale
       NHIs, accounts without MFA, over-privileged principals, and
       service accounts whose human owner has departed.

  remediate_path({chain_summary | edges}) → UnifiedPolicyIR
       Given an identity attack path, generate the policy IR that
       severs the path. Operators preview/apply via the existing flow.

No I/O — pure functions over the asset graph. Designed to be called
from the daemon (continuous monitoring) and from the UI/REST API.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from safecadence.identity.ir import UnifiedPolicyIR, validate_ir


@dataclass
class Finding:
    finding_id: str
    kind: str                           # stale_nhi | no_mfa | over_privileged
                                         # | orphan_service_account
                                         # | never_rotated | unused_admin
    severity: str                       # low | medium | high | critical
    title: str
    principal: str = ""
    evidence: dict = field(default_factory=dict)
    suggested_ir: dict = field(default_factory=dict)


# ---------------------------------------------------------------- public

def scan_findings(assets: Iterable[dict], *,
                   stale_days: int = 90,
                   over_priv_threshold: int = 5,
                   now: float | None = None) -> list[Finding]:
    """Run the full v7.7 finding catalog against the given assets."""
    findings: list[Finding] = []
    findings.extend(_find_stale_nhis(assets, stale_days=stale_days, now=now))
    findings.extend(_find_no_mfa(assets))
    findings.extend(_find_over_privileged(assets, over_priv_threshold))
    findings.extend(_find_never_rotated_nhis(assets, stale_days=stale_days))
    findings.extend(_find_orphan_service_accounts(assets))
    return findings


def remediate_path(body: dict) -> UnifiedPolicyIR:
    """Given an attack path (or its chain_summary string), produce an
    IR that severs the weakest link. v7.7 strategy: deny the action
    on the terminal asset for the human at the start of the chain.
    """
    chain_summary = body.get("chain_summary", "")
    edges = body.get("edges") or []

    if not chain_summary and not edges:
        raise ValueError("remediate_path needs chain_summary or edges")

    if edges:
        nodes = ([edges[0].get("src", "")] +
                 [e.get("dst", "") for e in edges if e.get("dst")])
    else:
        nodes = [n.strip() for n in chain_summary.split("→") if n.strip()]

    if len(nodes) < 2:
        raise ValueError("path too short to remediate")

    human = nodes[0]
    terminal = nodes[-1]
    intermediate = nodes[1:-1]

    intent = (f"Sever attack path: {human} cannot reach {terminal} "
              f"via {' → '.join(intermediate) or 'direct path'}")

    ir_dict = {
        "intent": intent,
        "subjects": {"principals": [human]},
        "resources": {"asset_ids": [terminal]},
        "actions": ["*"],
        "conditions": [],
        "effect": "deny",
        "severity": "enforce",
        "targets": ["all"],
        "author": "remediation-engine",
    }
    return validate_ir(ir_dict)


# ---------------------------------------------------------------- internals

def _find_stale_nhis(assets: Iterable[dict], *, stale_days: int,
                      now: float | None) -> list[Finding]:
    out: list[Finding] = []
    cutoff_ts = (now or time.time()) - stale_days * 86400
    for a in assets:
        nhi = a.get("nhi") or {}
        if not nhi.get("nhi_id"):
            continue
        last_used = _to_ts(nhi.get("last_used_at"))
        if last_used is None or last_used > cutoff_ts:
            continue
        days = int(((now or time.time()) - last_used) / 86400)
        out.append(Finding(
            finding_id=f"stale-nhi-{nhi['nhi_id']}",
            kind="stale_nhi",
            severity="high" if days > 180 else "medium",
            title=f"NHI {nhi['nhi_id']} unused for {days} days",
            principal=nhi["nhi_id"],
            evidence={"last_used_at": nhi.get("last_used_at"),
                       "subtype": nhi.get("subtype"),
                       "provider": nhi.get("provider")},
            suggested_ir={
                "intent": f"deactivate stale NHI {nhi['nhi_id']}",
                "subjects": {"principals": [nhi["nhi_id"]]},
                "resources": {"asset_types": ["identity"]},
                "actions": ["*"], "effect": "deny",
                "severity": "enforce",
                "targets": [nhi.get("provider") or "okta"],
            },
        ))
    return out


def _find_no_mfa(assets: Iterable[dict]) -> list[Finding]:
    out: list[Finding] = []
    for a in assets:
        ib = a.get("identity_block") or {}
        if not ib.get("provider"):
            continue
        if ib.get("mfa_enrolled") is False and ib.get("user_count", 0) > 0:
            out.append(Finding(
                finding_id=f"no-mfa-{ib.get('provider')}-{ib.get('tenant_id', '')}",
                kind="no_mfa",
                severity="high",
                title=f"{ib.get('provider')} tenant has users without MFA",
                evidence={"provider": ib.get("provider"),
                           "tenant_id": ib.get("tenant_id"),
                           "user_count": ib.get("user_count")},
                suggested_ir={
                    "intent": (f"require MFA in {ib.get('provider')} "
                                f"for tenant {ib.get('tenant_id')}"),
                    "subjects": {"groups": ["All"]},
                    "actions": ["login"],
                    "conditions": [{"kind": "mfa_required", "value": True}],
                    "effect": "require_step_up",
                    "severity": "enforce",
                    "targets": [ib.get("provider") or "all"],
                },
            ))
    return out


def _find_over_privileged(assets: Iterable[dict],
                            threshold: int) -> list[Finding]:
    out: list[Finding] = []
    for a in assets:
        ib = a.get("identity_block") or {}
        for principal, groups in (ib.get("group_memberships") or {}).items():
            count = len(groups or [])
            if count >= threshold:
                out.append(Finding(
                    finding_id=f"over-priv-{principal}",
                    kind="over_privileged",
                    severity="medium" if count < threshold * 2 else "high",
                    title=(f"{principal} is in {count} groups "
                           f"(threshold {threshold})"),
                    principal=principal,
                    evidence={"groups": list(groups or [])},
                    suggested_ir={
                        "intent": (f"review {principal}'s group memberships "
                                    f"({count} groups)"),
                        "subjects": {"principals": [principal]},
                        "actions": ["admin"], "effect": "require_step_up",
                        "severity": "warn",
                        "targets": ["all"],
                    },
                ))
    return out


def _find_never_rotated_nhis(assets: Iterable[dict],
                                *, stale_days: int) -> list[Finding]:
    out: list[Finding] = []
    cutoff = time.time() - stale_days * 86400
    for a in assets:
        nhi = a.get("nhi") or {}
        if not nhi.get("nhi_id"):
            continue
        last_rot = _to_ts(nhi.get("last_rotated_at"))
        if last_rot is not None and last_rot > cutoff:
            continue
        out.append(Finding(
            finding_id=f"never-rotated-{nhi['nhi_id']}",
            kind="never_rotated",
            severity="high" if (nhi.get("subtype") in
                                  ("api_key", "client_secret", "machine_cert"))
                       else "medium",
            title=f"NHI {nhi['nhi_id']} has not been rotated",
            principal=nhi["nhi_id"],
            evidence={"last_rotated_at": nhi.get("last_rotated_at") or "never",
                       "credential_type": nhi.get("credential_type"),
                       "subtype": nhi.get("subtype")},
            suggested_ir={
                "intent": f"rotate credential for {nhi['nhi_id']}",
                "subjects": {"principals": [nhi["nhi_id"]]},
                "actions": ["rotate"], "effect": "allow",
                "severity": "enforce",
                "targets": [nhi.get("provider") or "okta"],
            },
        ))
    return out


def _find_orphan_service_accounts(assets: Iterable[dict]) -> list[Finding]:
    out: list[Finding] = []
    # Build a set of "active" human principals
    active_humans: set[str] = set()
    for a in assets:
        ib = a.get("identity_block") or {}
        for human in (ib.get("group_memberships") or {}).keys():
            active_humans.add(human)
        for u in (ib.get("authorized_users") or []):
            active_humans.add(u)

    for a in assets:
        nhi = a.get("nhi") or {}
        if nhi.get("subtype") != "service_account":
            continue
        owner = nhi.get("owner_principal", "")
        if owner and owner not in active_humans:
            out.append(Finding(
                finding_id=f"orphan-sa-{nhi['nhi_id']}",
                kind="orphan_service_account",
                severity="critical",
                title=(f"Service account {nhi['nhi_id']} owned by "
                       f"departed/unknown principal {owner}"),
                principal=nhi["nhi_id"],
                evidence={"owner_principal": owner,
                           "provider": nhi.get("provider")},
                suggested_ir={
                    "intent": (f"reassign or disable orphan service "
                                f"account {nhi['nhi_id']}"),
                    "subjects": {"principals": [nhi["nhi_id"]]},
                    "actions": ["*"], "effect": "deny",
                    "severity": "enforce",
                    "targets": [nhi.get("provider") or "okta"],
                },
            ))
    return out


def _to_ts(s) -> float | None:
    if not s:
        return None
    if isinstance(s, (int, float)):
        return float(s)
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None
