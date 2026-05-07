"""
v7.7 — Identity evidence pack.

Produces a single artifact in three formats — JSON (programmatic),
CSV (spreadsheet), PDF (auditor) — capturing the state of identity
across all connected systems for a point-in-time review.

Maps cleanly to:
  * SOC 2 CC6 (Logical & Physical Access Controls)
  * ISO 27001 A.9 (Access Control)
  * NIST SP 800-53 AC-2, AC-5, AC-6, IA-2, IA-5

Re-uses the existing v7.2 _build_pdf helper from safecadence.evidence_pack
so we don't reinvent PDF emission.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable


def build_pack(assets: Iterable[dict], *,
                requested_by: str = "api") -> dict:
    """Compute the pack and emit all three formats.

    Returns:
        {
          'json':       <dict — programmatic view>,
          'csv_text':   <str  — flat csv for spreadsheets>,
          'pdf_bytes':  <bytes — auditor-friendly PDF>,
          'meta':       {generated_at, requested_by, asset_count, ...}
        }
    """
    from safecadence.identity.findings import scan_findings
    from safecadence.identity.attack_paths import compute_identity_paths
    from safecadence.identity.jit import list_grants

    asset_list = list(assets)
    findings = scan_findings(asset_list)
    paths = compute_identity_paths(asset_list)
    jit_grants = list_grants()

    summary = _summarize(asset_list, findings, paths, jit_grants)

    json_view = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "requested_by": requested_by,
            "asset_count": len(asset_list),
        },
        "summary": summary,
        "findings": [
            {"id": f.finding_id, "kind": f.kind, "severity": f.severity,
              "title": f.title, "principal": f.principal,
              "evidence": f.evidence}
            for f in findings
        ],
        "attack_paths": [
            {"chain_summary": p.chain_summary(),
              "terminal_asset": p.terminal_asset,
              "risk_score": p.risk_score, "reasons": p.reasons}
            for p in paths[:20]
        ],
        "jit_grants": [
            {"grant_id": g.grant_id, "principal": g.principal,
              "action": g.action, "resource": g.resource,
              "target": g.target, "status": g.status,
              "expires_at": g.expires_at, "created_at": g.created_at}
            for g in jit_grants[-50:]
        ],
        "frameworks": {
            "soc2_cc6": _soc2_mapping(summary, findings),
            "iso27001_a9": _iso_mapping(summary, findings),
            "nist_800_53": _nist_mapping(summary, findings),
        },
    }

    csv_text = _to_csv(findings, paths)
    pdf_bytes = _to_pdf(json_view)

    return {
        "json": json_view,
        "csv_text": csv_text,
        "pdf_bytes": pdf_bytes,
        "meta": json_view["meta"],
    }


# ---------------------------------------------------------------- summary

def _summarize(assets: list[dict], findings: list,
                paths: list, jit_grants: list) -> dict:
    providers = set()
    nhi_count = 0
    mfa_yes = 0
    mfa_no = 0
    crown_jewels = 0

    for a in assets:
        ib = a.get("identity_block") or {}
        ident = a.get("identity") or {}
        if ib.get("provider"):
            providers.add(ib["provider"])
        if ib.get("mfa_enrolled") is True:
            mfa_yes += 1
        elif ib.get("mfa_enrolled") is False:
            mfa_no += 1
        if (a.get("nhi") or {}).get("nhi_id"):
            nhi_count += 1
        if ident.get("criticality") == "crown-jewel":
            crown_jewels += 1

    sev_count: dict[str, int] = {}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    return {
        "providers_connected": sorted(providers),
        "asset_count": len(assets),
        "nhi_count": nhi_count,
        "mfa_compliant_tenants": mfa_yes,
        "mfa_noncompliant_tenants": mfa_no,
        "crown_jewel_count": crown_jewels,
        "finding_count": len(findings),
        "findings_by_severity": sev_count,
        "attack_path_count": len(paths),
        "jit_grants_total": len(jit_grants),
        "jit_grants_active": sum(1 for g in jit_grants if g.status == "active"),
    }


# ---------------------------------------------------------------- mappings

def _soc2_mapping(summary: dict, findings: list) -> dict:
    return {
        "CC6.1 — Logical access provisioned per role": {
            "evidence": (f"{summary['asset_count']} assets reviewed; "
                          f"{summary['mfa_noncompliant_tenants']} tenants "
                          "without MFA"),
            "status": ("compliant"
                       if summary["mfa_noncompliant_tenants"] == 0
                       else "exceptions_present"),
        },
        "CC6.2 — Identification & authentication of users": {
            "evidence": f"providers connected: {summary['providers_connected']}",
            "status": "compliant" if summary["providers_connected"] else "no_data",
        },
        "CC6.3 — Removal of access on role change": {
            "evidence": (f"{sum(1 for f in findings if f.kind == 'orphan_service_account')} "
                          "orphan service accounts; "
                          f"{sum(1 for f in findings if f.kind == 'stale_nhi')} "
                          "stale NHIs"),
            "status": "exceptions_present" if findings else "compliant",
        },
    }


def _iso_mapping(summary: dict, findings: list) -> dict:
    return {
        "A.9.2 User access management": {
            "evidence": f"{summary['finding_count']} access findings",
            "status": "compliant" if not findings else "review_required",
        },
        "A.9.4 System and application access control": {
            "evidence": f"{summary['attack_path_count']} identity attack paths detected",
            "status": ("compliant"
                       if summary["attack_path_count"] == 0
                       else "review_required"),
        },
    }


def _nist_mapping(summary: dict, findings: list) -> dict:
    return {
        "AC-2 Account Management": {
            "stale_nhis": sum(1 for f in findings if f.kind == "stale_nhi"),
            "never_rotated": sum(1 for f in findings if f.kind == "never_rotated"),
        },
        "AC-5 Separation of Duties": {
            "over_privileged": sum(1 for f in findings
                                   if f.kind == "over_privileged"),
        },
        "IA-2 Identification & Authentication": {
            "no_mfa_findings": sum(1 for f in findings if f.kind == "no_mfa"),
        },
    }


# ---------------------------------------------------------------- csv

def _to_csv(findings: list, paths: list) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["section", "id", "severity", "kind", "title",
                "principal", "evidence_json"])
    for f in findings:
        w.writerow(["finding", f.finding_id, f.severity, f.kind, f.title,
                     f.principal, json.dumps(f.evidence, sort_keys=True)])
    for p in paths[:20]:
        w.writerow(["attack_path", "", "high", "identity_path",
                     p.chain_summary(), p.terminal_asset,
                     json.dumps({"risk": p.risk_score,
                                  "reasons": p.reasons}, sort_keys=True)])
    return out.getvalue()


# ---------------------------------------------------------------- pdf

def _to_pdf(view: dict) -> bytes:
    """Render the pack as a simple text-only PDF using the v7.2 emitter."""
    try:
        from safecadence.evidence_pack import _build_pdf
    except ImportError:
        return b"%PDF-1.4\n% identity evidence pack - pdf engine missing\n"

    pages: list[list[str]] = []
    summary = view["summary"]
    pages.append([
        "SafeCadence Identity Evidence Pack",
        f"Generated:       {view['meta']['generated_at']}",
        f"Requested by:    {view['meta']['requested_by']}",
        f"Assets reviewed: {summary['asset_count']}",
        f"Providers:       {', '.join(summary['providers_connected']) or '(none)'}",
        f"NHIs:            {summary['nhi_count']}",
        f"Findings:        {summary['finding_count']}  by severity: "
        f"{summary['findings_by_severity']}",
        f"Attack paths:    {summary['attack_path_count']}",
        f"Active JIT:      {summary['jit_grants_active']}/"
        f"{summary['jit_grants_total']} total",
    ])
    pages.append(["Findings (top 30)"] + [
        f"  [{f['severity']:>8}] {f['kind']:>20} — {f['title']}"
        for f in view["findings"][:30]
    ])
    pages.append(["Attack paths (top 10)"] + [
        f"  ({p['risk_score']:>5.1f})  {p['chain_summary']}"
        for p in view["attack_paths"][:10]
    ])
    pages.append(["SOC 2 CC6 mapping"] + [
        f"  {k}: {v['status']}" for k, v in view["frameworks"]["soc2_cc6"].items()
    ])
    return _build_pdf(pages)
