"""Per-device diff view — the killer remediation primitive.

Given a saved policy and a specific asset, this module returns:
  - A control-by-control breakdown showing which controls FAIL on the
    asset and exactly which commands the right multi-vendor translator
    would emit to make them PASS.
  - For each fix command, a heuristic "already present?" flag derived
    from the asset's collected raw config text — so the operator can
    see at a glance whether they need to apply the line, remove a
    conflicting line, or skip it.
  - A unified diff between the current config text and the proposed
    target text, in the device's native syntax, so the change can be
    pasted into a CLI session or piped into ansible/netconf without
    a translation step.

This is the difference between a compliance dashboard ("99 violations
across your fleet") and an actual remediation tool ("on edge-rtr-01,
these 4 lines need to change to satisfy your PCI policy").

Pure-Python. No I/O. The renderer never SSHes anywhere — operators
take the diff and apply it through their existing change-management
process. (Actual config push is intentionally out of scope; we
integrate with Ansible/Terraform/NSO for that.)
"""

from __future__ import annotations

import difflib
from typing import Any

from safecadence.policy.controls import get_control
from safecadence.policy.evaluator import evaluate
from safecadence.policy.schema import (
    EvaluationResult, PolicyControl, PolicyEvaluation, SecurityPolicy,
    Severity,
)
from safecadence.policy.translators import (
    TranslatedFix, get_translator, pick_translator_for_asset,
)


def _config_text(asset: dict) -> str:
    """Pull the running-config / system text from collected raw data.

    Mirrors the helper the network controls use so the diff view sees
    exactly the same view of the asset that the evaluator did.
    """
    raw = asset.get("raw_collection") or {}
    if isinstance(raw, dict):
        for k in ("show_running-config", "running-config", "running",
                  "config", "show running-config", "show_system"):
            v = raw.get(k)
            if isinstance(v, str) and v:
                return v
        return "\n".join(v for v in raw.values() if isinstance(v, str))
    return str(raw or "")


def _normalize(line: str) -> str:
    """Strip leading whitespace and trailing comments for presence
    comparison. We want '  transport input ssh' to match
    'transport input ssh' regardless of indentation."""
    return line.strip().lower().rstrip("!").rstrip()


def _lines_present(target_lines: list[str], cfg: str) -> set[int]:
    """Return indices of lines from ``target_lines`` that already appear
    (verbatim, modulo whitespace) in the asset's current config."""
    if not cfg:
        return set()
    cfg_norm = {_normalize(l) for l in cfg.splitlines() if l.strip()
                and not l.strip().startswith("#")}
    out: set[int] = set()
    for i, line in enumerate(target_lines):
        norm = _normalize(line)
        if not norm or norm.startswith("#"):
            continue
        if norm in cfg_norm:
            out.add(i)
    return out


def _per_control_diff(control_id: str, severity: str, evidence: str,
                      fix: TranslatedFix, current_cfg: str) -> dict:
    """Build the rendered output for one failing control."""
    fix_lines = list(fix.fix or [])
    present = _lines_present(fix_lines, current_cfg)
    annotated_fix = []
    for i, line in enumerate(fix_lines):
        annotated_fix.append({
            "line": line,
            "already_present": i in present,
        })
    return {
        "control_id": control_id,
        "severity": severity,
        "evidence": evidence,
        "applicable": fix.applicable,
        "translator_notes": fix.notes,
        "fix": annotated_fix,
        "rollback": list(fix.rollback or []),
        "verify": list(fix.verify or []),
        "lines_to_add": sum(1 for x in annotated_fix
                             if not x["already_present"]
                             and x["line"].strip()
                             and not x["line"].strip().startswith("#")),
        "lines_already_satisfied": sum(1 for x in annotated_fix
                                        if x["already_present"]),
    }


def compute_diff(policy: SecurityPolicy, asset: dict) -> dict[str, Any]:
    """Return the full per-device diff payload for one asset+policy pair.

    Shape (stable — the UI + CLI both render this dict directly):
        {
          "asset_id": str,
          "asset_vendor": str | None,
          "asset_type": str | None,
          "policy_id": str,
          "policy_name": str,
          "translator": str | None,
          "evaluation": {pass_count, fail_count, na_count, coverage_pct},
          "controls": [
            {
              "control_id": str,
              "status": "pass" | "fail" | "na" | "unknown",
              "severity": str,
              "evidence": str,
              "fix": [{"line": str, "already_present": bool}, ...],
              "rollback": [str, ...],
              "verify": [str, ...],
              "lines_to_add": int,
              "lines_already_satisfied": int,
            }, ...
          ],
          "unified_diff": str,    # vendor-syntax patch ready to apply
          "summary": str,
        }
    """
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id", "")
    vendor = ident.get("vendor")
    atype = ident.get("asset_type")

    # Single-asset evaluation — keeps the evaluator honest about
    # group_member_cache and target_asset_types.
    eval_result: PolicyEvaluation = evaluate(policy, [asset])

    # Map control_id → status from this evaluation
    status_by_control: dict[str, str] = {}
    evidence_by_control: dict[str, str] = {}
    for row in (eval_result.asset_results or []):
        if row.get("asset_id") != aid:
            continue
        for cid, status in (row.get("controls") or {}).items():
            status_by_control[cid] = status
    for v in (eval_result.violations or []):
        if v.asset_id == aid:
            sev = v.severity.value if hasattr(v.severity, "value") else v.severity
            evidence_by_control[v.control_id] = (
                f"[{sev}] {v.evidence}" if v.evidence else f"[{sev}]"
            )

    translator = pick_translator_for_asset(asset)
    translator_name = getattr(translator, "vendor_target", None)

    current_cfg = _config_text(asset)
    target_lines: list[str] = list(current_cfg.splitlines())

    rendered_controls: list[dict] = []
    for control in (policy.controls or []):
        cid = control.control_id
        status = status_by_control.get(cid, "unknown")
        spec = get_control(cid)
        sev = (control.severity.value if hasattr(control.severity, "value")
               else control.severity) if control.severity else (
                spec.severity.value if spec and hasattr(spec.severity, "value")
                else "medium")

        # Only run the translator for FAIL controls — PASS or NA needs
        # no remediation; UNKNOWN we surface so the operator can decide.
        if status not in ("fail", "unknown"):
            rendered_controls.append({
                "control_id": cid,
                "status": status,
                "severity": sev,
                "evidence": "",
                "fix": [],
                "rollback": [],
                "verify": [],
                "lines_to_add": 0,
                "lines_already_satisfied": 0,
            })
            continue

        fix = TranslatedFix(applicable=False,
                             notes="no translator selected for this asset")
        if translator and translator.supports(cid):
            try:
                fix = translator.translate(control, asset)
            except Exception as e:                        # pragma: no cover
                fix = TranslatedFix(
                    applicable=False,
                    notes=f"translator error: {type(e).__name__}: {e}",
                )

        rendered = _per_control_diff(
            control_id=cid,
            severity=sev,
            evidence=evidence_by_control.get(cid, ""),
            fix=fix,
            current_cfg=current_cfg,
        )
        rendered["status"] = status
        rendered_controls.append(rendered)

        # Append fix lines that aren't already satisfied to the target
        # config so the unified diff at the bottom shows the cumulative
        # change. We deliberately keep ordering stable.
        for ann in rendered["fix"]:
            if not ann["already_present"]:
                line = ann["line"]
                if line.strip() and not line.strip().startswith("#"):
                    target_lines.append(line)

    # Build a unified diff so an operator can `git apply` if they want.
    unified = "".join(difflib.unified_diff(
        [l + "\n" for l in current_cfg.splitlines()],
        [l + "\n" for l in target_lines],
        fromfile=f"{aid} (current)",
        tofile=f"{aid} (target — policy: {policy.policy_name})",
        n=2,
    ))

    fail_count = sum(1 for c in rendered_controls if c["status"] == "fail")
    pass_count = sum(1 for c in rendered_controls if c["status"] == "pass")
    na_count = sum(1 for c in rendered_controls if c["status"] in ("na", "not_applicable"))
    total_changes = sum(c["lines_to_add"] for c in rendered_controls)

    return {
        "asset_id": aid,
        "asset_vendor": vendor,
        "asset_type": atype,
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "translator": translator_name,
        "evaluation": {
            "pass_count": pass_count,
            "fail_count": fail_count,
            "na_count": na_count,
            "control_count": len(rendered_controls),
        },
        "controls": rendered_controls,
        "unified_diff": unified,
        "summary": (
            f"{aid} ({vendor or 'unknown vendor'}) — "
            f"policy '{policy.policy_name}': "
            f"{fail_count} fail / {pass_count} pass / {na_count} N/A. "
            f"{total_changes} config line(s) need to change."
            if fail_count else
            f"{aid} satisfies policy '{policy.policy_name}' — no changes needed."
        ),
    }


def render_text(diff_payload: dict) -> str:
    """Render the diff payload as a CLI-friendly text block."""
    lines: list[str] = []
    p = diff_payload
    lines.append("=" * 72)
    lines.append(f"  {p['asset_id']}  ({p.get('asset_vendor') or 'unknown'})")
    lines.append(f"  Policy: {p.get('policy_name')}  ({p.get('policy_id')})")
    lines.append(f"  Translator: {p.get('translator') or 'none — manual review'}")
    lines.append("=" * 72)
    lines.append(p.get("summary", ""))
    lines.append("")

    for c in p.get("controls") or []:
        if c["status"] not in ("fail", "unknown"):
            continue
        sev = (c.get("severity") or "medium").upper()
        lines.append(f"--- {c['control_id']}  [{sev}]  status={c['status']}")
        if c.get("evidence"):
            lines.append(f"    evidence: {c['evidence']}")
        if c.get("translator_notes"):
            lines.append(f"    note:     {c['translator_notes']}")
        if not c.get("applicable", True):
            lines.append("    (no fix available — manual remediation required)")
            lines.append("")
            continue
        lines.append(f"    {c['lines_already_satisfied']} satisfied · "
                     f"{c['lines_to_add']} to add")
        for ann in c.get("fix") or []:
            mark = "✓" if ann["already_present"] else "+"
            lines.append(f"      {mark} {ann['line']}")
        if c.get("verify"):
            lines.append(f"    Verify:")
            for v in c["verify"][:3]:
                lines.append(f"      ? {v}")
        lines.append("")

    if p.get("unified_diff"):
        lines.append("Unified diff (apply with `git apply` or paste into device):")
        lines.append("")
        lines.append(p["unified_diff"])
    return "\n".join(lines)
