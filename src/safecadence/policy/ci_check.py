"""
v6.1 — CI/CD policy gate.

`safecadence policy ci-check` evaluates every policy against the current
fleet and exits with code != 0 when any policy regresses or fails (configurable
thresholds). Designed for GitHub Actions / GitLab CI / Jenkins / any CI that
can run a binary and check exit codes.

Output formats:
  - text       human-readable summary (default)
  - json       structured for downstream tools
  - sarif      SARIF 2.1.0 for GitHub Code Scanning integration
  - junit      JUnit XML for legacy CI display

Failure modes (configurable via flags):
  --fail-on-fail       any control failure → exit 1   (default: enabled)
  --fail-on-regression any newly-failing control vs. last evaluation → exit 1
  --fail-on-critical   any critical-severity violation → exit 2
  --fail-on-kev        any asset with a KEV CVE → exit 2
  --max-fail N         exit 0 only if total failures ≤ N
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def _load_assets() -> list[dict]:
    from pathlib import Path
    base = Path.home() / ".safecadence" / "platform_assets"
    if not base.exists():
        return []
    out = []
    for f in base.glob("*.json"):
        try: out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception: continue
    return out


def evaluate_all() -> dict[str, Any]:
    """Run every saved policy; return aggregated CI summary + violations."""
    from safecadence.policy.drift import detect_drift
    from safecadence.policy.evaluator import evaluate
    from safecadence.policy.store import get, list_policies
    assets = _load_assets()
    metas = list_policies()
    out_policies = []
    total_pass = total_fail = total_na = 0
    total_regressions = 0
    all_violations = []
    has_kev = False

    for meta in metas:
        p = get(meta["policy_id"])
        if not p: continue
        ev = evaluate(p, assets)
        total_pass += ev.pass_count
        total_fail += ev.fail_count
        total_na += ev.na_count
        for v in ev.violations:
            all_violations.append({
                "policy_id": p.policy_id, "policy_name": p.policy_name,
                "asset_id": v.asset_id, "control_id": v.control_id,
                "severity": v.severity.value if hasattr(v.severity, "value") else v.severity,
                "evidence": v.evidence,
            })
        drift = detect_drift(p.policy_id)
        total_regressions += len(drift.get("regressions", []))
        out_policies.append({
            "policy_id": p.policy_id, "policy_name": p.policy_name,
            "pass": ev.pass_count, "fail": ev.fail_count,
            "regressions": len(drift.get("regressions", [])),
        })

    for a in assets:
        if (a.get("security") or {}).get("kev_cves", 0) > 0:
            has_kev = True; break

    return {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "policy_count": len(out_policies),
        "asset_count": len(assets),
        "total_pass": total_pass, "total_fail": total_fail,
        "total_na": total_na, "total_regressions": total_regressions,
        "fleet_has_kev_cves": has_kev,
        "policies": out_policies,
        "violations": all_violations,
    }


def decide_exit_code(summary: dict, *,
                     fail_on_fail: bool = True,
                     fail_on_regression: bool = True,
                     fail_on_critical: bool = False,
                     fail_on_kev: bool = False,
                     max_fail: int | None = None) -> tuple[int, list[str]]:
    """Apply the configured gate criteria; return (exit_code, reasons)."""
    reasons: list[str] = []
    code = 0
    if fail_on_fail and summary["total_fail"] > 0:
        code = max(code, 1)
        reasons.append(f"{summary['total_fail']} policy failures (--fail-on-fail)")
    if fail_on_regression and summary["total_regressions"] > 0:
        code = max(code, 1)
        reasons.append(f"{summary['total_regressions']} regressions vs prior evaluation "
                       f"(--fail-on-regression)")
    if fail_on_critical and any(v["severity"] == "critical" for v in summary["violations"]):
        code = 2
        reasons.append("critical-severity violations present (--fail-on-critical)")
    if fail_on_kev and summary["fleet_has_kev_cves"]:
        code = 2
        reasons.append("fleet contains KEV-listed CVEs (--fail-on-kev)")
    if max_fail is not None and summary["total_fail"] > max_fail:
        code = max(code, 1)
        reasons.append(f"total failures {summary['total_fail']} > --max-fail {max_fail}")
    return code, reasons


# --------------------------------------------------------------------------
# Output formats
# --------------------------------------------------------------------------

def render_text(summary: dict, exit_code: int, reasons: list[str]) -> str:
    out = []
    status = "PASS" if exit_code == 0 else "FAIL"
    out.append(f"safecadence policy ci-check  →  {status}  (exit {exit_code})")
    out.append(f"  evaluated_at:    {summary['evaluated_at']}")
    out.append(f"  policies:        {summary['policy_count']}")
    out.append(f"  assets scanned:  {summary['asset_count']}")
    out.append(f"  pass / fail / NA: {summary['total_pass']} / {summary['total_fail']} / {summary['total_na']}")
    out.append(f"  regressions:     {summary['total_regressions']}")
    out.append(f"  fleet has KEV:   {summary['fleet_has_kev_cves']}")
    if reasons:
        out.append("")
        out.append("Failures:")
        for r in reasons:
            out.append(f"  - {r}")
    if summary["violations"]:
        out.append("")
        out.append("Top violations (first 10):")
        for v in summary["violations"][:10]:
            out.append(f"  [{v['severity']:<8}] {v['asset_id']} / {v['control_id']}  "
                       f"({v['policy_name']})")
    return "\n".join(out)


def render_sarif(summary: dict) -> str:
    """Minimal SARIF 2.1.0 for GitHub Code Scanning."""
    sev_map = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note", "info": "note"}
    results = [{
        "ruleId": v["control_id"],
        "level": sev_map.get(v["severity"], "warning"),
        "message": {"text": f"{v['evidence']} (asset {v['asset_id']}, "
                              f"policy {v['policy_name']})"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"asset://{v['asset_id']}"},
            }
        }],
    } for v in summary["violations"]]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "safecadence-netrisk",
                "informationUri": "https://safecadence.com/",
                "rules": [],
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def render_junit(summary: dict) -> str:
    """JUnit XML — every violation becomes a failed test case."""
    cases = []
    for v in summary["violations"]:
        sev = v["severity"]
        cases.append(
            f'  <testcase classname="{v["policy_name"]}" '
            f'name="{v["asset_id"]} / {v["control_id"]}">'
            f'<failure message="{sev}">{v["evidence"]}</failure>'
            f'</testcase>'
        )
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="safecadence" tests="{len(cases)}" '
            f'failures="{summary["total_fail"]}">\n'
            + "\n".join(cases)
            + "\n</testsuite>\n")
