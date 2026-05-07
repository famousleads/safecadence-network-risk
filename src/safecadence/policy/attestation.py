"""
Compliance attestation reports — auditor-ready summaries.

Generates a structured report listing:
  * scope (assets covered, time window)
  * per-control evaluation results
  * exceptions accepted with risk
  * audit-trail evidence pointer

Output formats:
  * dict (default)        — for the API
  * markdown              — for human review
  * pdf (optional)        — uses reportlab if installed

Designed to support SOC 2, ISO 27001, PCI-DSS, HIPAA evidence
collection. The auditor reads the report; SafeCadence stays read-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from safecadence.policy.audit import read_recent
from safecadence.policy.evaluator import evaluate
from safecadence.policy.schema import SecurityPolicy, Severity
from safecadence.policy.frameworks import load_mappings


def build_attestation(policy: SecurityPolicy, assets: list[dict],
                      *, framework: str = "") -> dict[str, Any]:
    ev = evaluate(policy, assets)
    mappings = load_mappings()
    matrix: dict[str, dict[str, list]] = {}

    for c in policy.controls:
        refs = mappings.get(c.control_id, {})
        for fw, items in refs.items():
            if framework and fw != framework:
                continue
            for ref in items:
                matrix.setdefault(fw, {}).setdefault(ref, []).append(c.control_id)

    pass_pct = (ev.pass_count / max(1, ev.pass_count + ev.fail_count)) * 100

    return {
        "attestation_id": ev.evaluation_id,
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_filter": framework or "all",
        "asset_scope": {
            "asset_count": len(assets),
            "applicable_count": len(ev.asset_results),
        },
        "compliance_summary": {
            "pass_count": ev.pass_count,
            "fail_count": ev.fail_count,
            "na_count": ev.na_count,
            "coverage_pct": ev.coverage_pct,
            "compliance_pct": round(pass_pct, 1),
        },
        "controls_to_framework": matrix,
        "violations": [v.serialize() for v in ev.violations],
        "exceptions_accepted": [{
            "exception_id": ex.exception_id,
            "asset_id": ex.asset_id,
            "control_id": ex.control_id,
            "approved_by": ex.approved_by,
            "approved_at": ex.approved_at,
            "expires_at": ex.expires_at,
            "justification": ex.justification,
        } for ex in (policy.exceptions or [])],
        "audit_trail_pointer": {
            "recent_events_sample": read_recent(limit=10),
            "log_location": "~/.safecadence/policy_audit-*.jsonl",
        },
    }


def attestation_markdown(att: dict) -> str:
    out = []
    out.append(f"# Compliance Attestation Report")
    out.append("")
    out.append(f"**Policy:** {att['policy_name']}  ")
    out.append(f"**Attestation ID:** `{att['attestation_id']}`  ")
    out.append(f"**Generated:** {att['generated_at']}  ")
    out.append(f"**Framework filter:** {att['framework_filter']}  ")
    out.append("")
    cs = att["compliance_summary"]
    out.append(f"## Summary")
    out.append("")
    out.append(f"- Assets in scope: **{att['asset_scope']['asset_count']}**")
    out.append(f"- Applicable assets: **{att['asset_scope']['applicable_count']}**")
    out.append(f"- Pass: **{cs['pass_count']}**, Fail: **{cs['fail_count']}**, "
               f"N/A: **{cs['na_count']}**")
    out.append(f"- Compliance: **{cs['compliance_pct']}%**, Coverage: **{cs['coverage_pct']}%**")
    out.append("")
    if att.get("controls_to_framework"):
        out.append(f"## Framework coverage")
        out.append("")
        for fw, refs in att["controls_to_framework"].items():
            out.append(f"### {fw}")
            for ref, ctrls in refs.items():
                out.append(f"- **{ref}** ← {', '.join(ctrls)}")
            out.append("")
    if att.get("violations"):
        out.append(f"## Open violations ({len(att['violations'])})")
        out.append("")
        for v in att["violations"][:50]:
            out.append(f"- `{v['asset_id']}` / `{v['control_id']}` "
                       f"({v['severity']}) — {v['evidence']}")
    if att.get("exceptions_accepted"):
        out.append(f"\n## Exceptions accepted with risk")
        out.append("")
        for ex in att["exceptions_accepted"]:
            out.append(f"- `{ex['asset_id']}` / `{ex['control_id']}` — "
                       f"approved by {ex['approved_by']} on {ex['approved_at']}, "
                       f"expires {ex['expires_at'] or 'never'}")
            out.append(f"  > {ex['justification']}")
    return "\n".join(out)
