"""
v6.1 — "Make it stop" one-click top-N risk fix.

Given the current fleet + every saved policy, identify the top-N highest-
priority violations and generate ONE consolidated remediation plan that
addresses all of them. Then export it in any of the 7 export formats.

Beats every CSPM that says "here are 5,000 findings, good luck" by
explicitly answering "what 1 playbook do I run TODAY to fix the most?"

The ranking weights:
  - severity (critical=400, high=200, medium=50, low=10)
  - asset criticality (crown-jewel=+200, high=+100)
  - asset KEV CVE count (each KEV = +50)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from safecadence.policy.evaluator import evaluate
from safecadence.policy.remediation import generate_plan
from safecadence.policy.schema import (
    PolicyEvaluation, PolicyViolation, RemediationPlan, SecurityPolicy,
    Severity,
)
from safecadence.policy.store import get as store_get, list_policies


_SEV_WEIGHT = {"critical": 400, "high": 200, "medium": 50, "low": 10, "info": 0}


def _build_reach_index(assets: list[dict]) -> dict[str, dict]:
    """Compute, per asset, two reach numbers used for risk weighting:

      - ``internet_hops`` — minimum hops from the public internet to this
        asset. ``0`` if directly internet-facing, ``999`` if unreachable.
        Closer to the edge = higher exploit blast.
      - ``downstream_crown_jewels`` — number of crown-jewel assets reachable
        FROM this asset. A high value means a single compromise here cascades
        to multiple high-value targets (a true hub of the kill-chain).

    The function is best-effort: it falls back to neutral numbers if the
    attack-paths module isn't importable so top_n_violations always returns.
    """
    out: dict[str, dict] = {}
    try:
        from safecadence.platform.attack_paths import blast_radius
    except Exception:
        return out
    # 1) Reach FROM the internet — single BFS run, gives us internet_hops
    try:
        br_in = blast_radius("internet", assets, max_hops=8)
        for r in br_in.get("paths") or []:
            out.setdefault(r["asset_id"], {})["internet_hops"] = r["hops"]
    except Exception:
        pass
    # 2) Downstream crown-jewel reach per asset — bounded by max_hops to
    #    keep this O(n * max_hops) instead of O(n²). Skip on big fleets.
    if len(assets) <= 200:
        crown_ids = {(a.get("identity") or {}).get("asset_id")
                     for a in assets
                     if ((a.get("identity") or {}).get("criticality") or "").lower()
                        == "crown-jewel"}
        if crown_ids:
            for a in assets:
                aid = (a.get("identity") or {}).get("asset_id")
                if not aid:
                    continue
                try:
                    br = blast_radius(aid, assets, max_hops=4)
                except Exception:
                    continue
                cnt = sum(1 for r in (br.get("paths") or [])
                          if r["asset_id"] in crown_ids)
                out.setdefault(aid, {})["downstream_crown_jewels"] = cnt
    return out


def _violation_score(v: PolicyViolation, asset: dict,
                     reach: dict | None = None) -> int:
    """Higher = fix this one first.

    Beyond severity + crown-jewel + KEV, we now also weight:
      - **internet proximity** — the closer to the edge, the more urgent
      - **downstream crown-jewel reach** — hubs that compromise many CJs
    """
    sev = v.severity.value if isinstance(v.severity, Severity) else v.severity
    score = _SEV_WEIGHT.get((sev or "").lower(), 0)
    ident = asset.get("identity") or {}
    crit = (ident.get("criticality") or "").lower()
    if crit == "crown-jewel": score += 200
    elif crit == "high":      score += 100
    sec = asset.get("security") or {}
    score += sec.get("kev_cves", 0) * 50
    # Reach weighting — only kicks in if the index was built for this asset.
    r = (reach or {}).get((ident.get("asset_id") or "")) or {}
    hops = r.get("internet_hops")
    if hops is not None:
        # 0 hops = +150, 1 hop = +100, 2 hops = +60, 3 hops = +30, else 0.
        score += [150, 100, 60, 30][hops] if hops < 4 else 0
    downstream = r.get("downstream_crown_jewels", 0)
    if downstream:
        score += min(downstream, 10) * 30  # cap at +300
    return score


def _dedupe_violations(scored):
    """De-duplicate (asset_id, control_id) — same violation surfaced from
    two different policies should count once, not twice. Keep the highest-
    scoring instance and remember the merged source policies.
    """
    by_key: dict[tuple, list] = {}
    for s, asset, v, pol in scored:
        key = (v.asset_id, v.control_id)
        by_key.setdefault(key, []).append((s, asset, v, pol))
    deduped = []
    for key, items in by_key.items():
        items.sort(key=lambda t: -t[0])
        winner = items[0]
        # Annotate the winning violation with the other source policies.
        if len(items) > 1:
            other_pols = [p.policy_id for _, _, _, p in items[1:]]
            try:
                winner[2]._merged_from = other_pols  # type: ignore[attr-defined]
            except Exception:
                pass
        deduped.append(winner)
    return deduped


def top_n_violations(assets: list[dict], top_n: int = 5) -> dict[str, Any]:
    """Find the top-N violations across every saved policy.

    Returns {top_n, violations, source_policies, summary}.
    """
    by_id = {(a.get("identity") or {}).get("asset_id"): a for a in assets}
    all_metas = list_policies()
    scored: list[tuple[int, dict, PolicyViolation, SecurityPolicy]] = []
    reach_index = _build_reach_index(assets)

    for meta in all_metas:
        p = store_get(meta["policy_id"])
        if not p: continue
        ev = evaluate(p, assets)
        for v in ev.violations:
            asset = by_id.get(v.asset_id) or {}
            scored.append((_violation_score(v, asset, reach_index),
                           asset, v, p))

    scored = _dedupe_violations(scored)
    scored.sort(key=lambda t: -t[0])
    top = scored[:top_n]
    return {
        "top_n": top_n,
        "found": len(scored),
        "selected": len(top),
        "summary": (f"Selected the top {len(top)} of {len(scored)} fleet-wide "
                    f"violations (ranked by severity + asset criticality + "
                    f"KEV count + internet-reach + downstream crown-jewel impact)."),
        "violations": [{
            "score": s, "asset_id": v.asset_id, "control_id": v.control_id,
            "severity": v.severity.value if isinstance(v.severity, Severity) else v.severity,
            "policy_id": pol.policy_id, "policy_name": pol.policy_name,
            "evidence": v.evidence,
            "internet_hops": (reach_index.get(v.asset_id) or {}).get("internet_hops"),
            "downstream_crown_jewels": (reach_index.get(v.asset_id) or {}).get(
                "downstream_crown_jewels", 0),
            "merged_from_policies": getattr(v, "_merged_from", []),
        } for s, _, v, pol in top],
    }


def fix_top_risks_plan(assets: list[dict], top_n: int = 5) -> RemediationPlan:
    """Build a single RemediationPlan covering the top-N violations.

    Each top-N violation is converted into a RemediationStep using the same
    multi-vendor translator the per-policy export uses, so the resulting
    plan can be passed to any of the 7 exporters (Ansible, Terraform, etc.).
    """
    by_id = {(a.get("identity") or {}).get("asset_id"): a for a in assets}
    top_data = top_n_violations(assets, top_n=top_n)

    # Group selected violations back by their source policy so we can
    # generate proper RemediationSteps via the existing engine.
    grouped: dict[str, list[PolicyViolation]] = defaultdict(list)
    pol_cache: dict[str, SecurityPolicy] = {}
    for v in top_data["violations"]:
        # Re-build a PolicyViolation-shaped object from the dict we returned
        from safecadence.policy.schema import PolicyViolation as _PV
        pv = _PV(violation_id=f"top_{v['asset_id']}_{v['control_id']}",
                 policy_id=v["policy_id"], control_id=v["control_id"],
                 asset_id=v["asset_id"],
                 severity=Severity((v["severity"] or "medium").lower()),
                 evidence=v["evidence"])
        grouped[v["policy_id"]].append(pv)
        if v["policy_id"] not in pol_cache:
            p = store_get(v["policy_id"])
            if p: pol_cache[v["policy_id"]] = p

    # Build a synthetic combined plan: for each policy, generate a plan
    # with just its top-N violations, then merge steps.
    from safecadence.policy.schema import RemediationPlan as _RP
    combined = _RP(plan_id="top_risks_combined", policy_id="(multi-policy)")
    for pid, viols in grouped.items():
        pol = pol_cache.get(pid)
        if not pol: continue
        ev = PolicyEvaluation(policy_id=pid, violations=viols,
                              fail_count=len(viols))
        plan = generate_plan(pol, ev, by_id)
        combined.steps.extend(plan.steps)

    combined.summary = {
        "total": len(combined.steps),
        "translated": sum(1 for s in combined.steps if s.fix_commands),
        "untranslated": sum(1 for s in combined.steps if not s.fix_commands),
        "source_policies": len(grouped),
    }
    return combined
