"""
v12.0 — SOC 2 evidence pack scaffold (Schellman / A-LIGN style).

The v11.x ``compliance.evidence_chain`` module already records the
per-finding evidence trail SafeCadence uses internally. This module is
the *external-facing* packaging layer: when an auditor asks "give me
everything you have on access reviews for Q3", we want to hand them a
single bundle that maps to **their** workpaper format, not our internal
finding model.

Best-judgement format choice
----------------------------

We use the layout common to Schellman, A-LIGN, Prescient, and other
mid-market SOC 2 auditors:

* One folder per Common Criteria area (CC1 – CC9).
* Inside each: an index `README.txt`, a per-control subfolder, and
  inside the subfolder: a `control.md` describing intent + period,
  `population.csv` listing the relevant items, and a `samples/`
  folder holding the evidence artefacts.
* All artefact filenames are hashed (`sha256-…`) so an auditor can
  re-verify integrity offline.

This module ships the **manifest layer** today — the part that decides
*what goes in the pack*. The actual artefact rendering (zipping, hash
manifest, signed cover letter) reuses the existing report renderers
from ``safecadence.reports``.

Common Criteria covered
-----------------------

The SOC 2 trust services criteria 2017 include CC1 – CC9. We map every
SafeCadence framework into the relevant CCs:

* CC1 Control Environment       — governance, code of conduct
* CC2 Communication             — security communications, training
* CC3 Risk Assessment           — risk register, threat model
* CC4 Monitoring Activities     — continuous monitoring, scans
* CC5 Control Activities        — access reviews, change management
* CC6 Logical & Physical Access — IAM, MFA, NHI, vault, audit logs
* CC7 System Operations         — incident response, vulnerability mgmt
* CC8 Change Management         — config drift, rollback, approvals
* CC9 Risk Mitigation           — vendor risk, BCP / DR

Public API
----------

* ``list_cc_areas()``                   — the nine areas with descriptions.
* ``map_finding_to_cc(finding)``        — best-effort CC area for a finding.
* ``build_manifest(findings, period)``  — pack manifest dict ready to render.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# --------------------------------------------------------------------------
# CC area definitions
# --------------------------------------------------------------------------


CC_AREAS: list[dict] = [
    {
        "id": "CC1",
        "title": "Control Environment",
        "summary": "Governance, ethics, board oversight, organization structure.",
    },
    {
        "id": "CC2",
        "title": "Communication & Information",
        "summary": "Internal and external communication of security policies.",
    },
    {
        "id": "CC3",
        "title": "Risk Assessment",
        "summary": "Risk identification, register, and treatment.",
    },
    {
        "id": "CC4",
        "title": "Monitoring Activities",
        "summary": "Ongoing evaluations and continuous monitoring.",
    },
    {
        "id": "CC5",
        "title": "Control Activities",
        "summary": "Access reviews, change-management approvals.",
    },
    {
        "id": "CC6",
        "title": "Logical & Physical Access Controls",
        "summary": "IAM, MFA, NHI rotation, vault, network segmentation.",
    },
    {
        "id": "CC7",
        "title": "System Operations",
        "summary": "Vulnerability management, incident response, monitoring.",
    },
    {
        "id": "CC8",
        "title": "Change Management",
        "summary": "Configuration drift detection, change approvals, rollback.",
    },
    {
        "id": "CC9",
        "title": "Risk Mitigation",
        "summary": "Vendor risk, business continuity, disaster recovery.",
    },
]


# Map SafeCadence control families → SOC 2 Common Criteria.
# Best-judgement defaults; operators can override per-engagement.
_FAMILY_TO_CC: dict[str, str] = {
    # Identity
    "iam":             "CC6",
    "mfa":             "CC6",
    "nhi":             "CC6",
    "vault":           "CC6",
    "access_review":   "CC5",
    # Vuln & ops
    "patching":        "CC7",
    "vulnerability":   "CC7",
    "incident":        "CC7",
    # Network
    "segmentation":    "CC6",
    "firewall":        "CC6",
    # Change & drift
    "change_mgmt":     "CC8",
    "drift":           "CC8",
    "rollback":        "CC8",
    # Monitoring
    "monitoring":      "CC4",
    "logging":         "CC4",
    "audit_log":       "CC4",
    # Vendor / BCP
    "vendor":          "CC9",
    "bcp":             "CC9",
    "backup":          "CC9",
    # Risk & comm
    "risk":            "CC3",
    "policy":          "CC2",
    "training":        "CC2",
    # Governance
    "governance":      "CC1",
}


def list_cc_areas() -> list[dict]:
    """Return a copy of CC_AREAS suitable for serialization."""
    return [dict(a) for a in CC_AREAS]


def map_finding_to_cc(finding: dict) -> str:
    """Best-effort mapping. Falls back to CC7 (System Operations).

    Looks at the finding's ``family`` field first, then any ``controls``
    entries with a matching family, then keyword-matches the title.
    """
    fam = (finding.get("family") or "").lower()
    if fam in _FAMILY_TO_CC:
        return _FAMILY_TO_CC[fam]

    for ctrl in finding.get("controls") or []:
        cf = (ctrl.get("family") or "").lower()
        if cf in _FAMILY_TO_CC:
            return _FAMILY_TO_CC[cf]

    title = (finding.get("title") or "").lower()
    for keyword, cc in _FAMILY_TO_CC.items():
        if keyword in title:
            return cc

    return "CC7"


# --------------------------------------------------------------------------
# Manifest builder
# --------------------------------------------------------------------------


def build_manifest(
    findings: list[dict],
    *,
    period_start: str | None = None,
    period_end: str | None = None,
    org_display_name: str = "SafeCadence Customer",
) -> dict:
    """Build a SOC 2 evidence-pack manifest.

    Args:
        findings: list of finding dicts.
        period_start / period_end: ISO date strings for the audit period.
        org_display_name: name on the cover letter.

    Returns a dict shaped for downstream rendering:

    ::

        {
          "generated_at": "...",
          "org_display_name": "...",
          "period": {"start": "...", "end": "..."},
          "areas": [
            {"id": "CC6", "title": "...", "summary": "...",
             "finding_count": 12,
             "controls": [
                {"control_id": "...", "title": "...", "evidence_count": ...},
                ...
             ]},
            ...
          ],
          "total_finding_count": ...,
        }
    """
    now = datetime.now(timezone.utc).isoformat()

    # Bucket findings by CC area.
    by_cc: dict[str, list[dict]] = {a["id"]: [] for a in CC_AREAS}
    for f in findings or []:
        cc = map_finding_to_cc(f)
        if cc not in by_cc:
            cc = "CC7"
        by_cc[cc].append(f)

    areas_out: list[dict] = []
    for area in CC_AREAS:
        fs = by_cc[area["id"]]
        # Within an area, group findings by control_id for the workpaper.
        controls_idx: dict[str, dict] = {}
        for f in fs:
            for ctrl in f.get("controls") or []:
                cid = ctrl.get("control_id") or "unmapped"
                row = controls_idx.setdefault(
                    cid,
                    {
                        "control_id": cid,
                        "title": ctrl.get("title") or "",
                        "framework": ctrl.get("framework") or "",
                        "evidence_count": 0,
                    },
                )
                row["evidence_count"] += 1
        areas_out.append(
            {
                "id": area["id"],
                "title": area["title"],
                "summary": area["summary"],
                "finding_count": len(fs),
                "controls": sorted(
                    controls_idx.values(), key=lambda r: r["control_id"]
                ),
            }
        )

    return {
        "generated_at": now,
        "org_display_name": org_display_name,
        "period": {"start": period_start, "end": period_end},
        "areas": areas_out,
        "total_finding_count": sum(len(v) for v in by_cc.values()),
        "format": "schellman-a-lign-2017",
    }


__all__ = [
    "CC_AREAS",
    "list_cc_areas",
    "map_finding_to_cc",
    "build_manifest",
]
