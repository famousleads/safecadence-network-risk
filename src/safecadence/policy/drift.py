"""
Drift detection — compares current PolicyEvaluation to prior evaluations.

Surfaces:
  * regressions   — control passed before, now failing
  * improvements  — control failed before, now passing (good drift)
  * stale         — controls no longer applicable due to asset removal
  * trend         — overall pass-rate delta over the window

History is read from ~/.safecadence/policy_evaluations/<policy_id>/*.json
(written by the evaluator's persist helper). Cross-platform via pathlib.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from safecadence.policy.schema import PolicyEvaluation


def _eval_dir(policy_id: str) -> Path:
    base = Path.home() / ".safecadence" / "policy_evaluations" / policy_id
    base.mkdir(parents=True, exist_ok=True)
    return base


def persist_evaluation(ev: PolicyEvaluation) -> Path:
    """Save an evaluation snapshot for later drift comparison."""
    d = _eval_dir(ev.policy_id)
    f = d / f"{ev.evaluation_id}.json"
    payload = {
        "evaluation_id": ev.evaluation_id, "policy_id": ev.policy_id,
        "evaluated_at": ev.evaluated_at, "asset_results": ev.asset_results,
        "pass_count": ev.pass_count, "fail_count": ev.fail_count,
        "na_count": ev.na_count, "coverage_pct": ev.coverage_pct,
        "violations": [v.serialize() for v in ev.violations],
    }
    f.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return f


def list_evaluations(policy_id: str) -> list[dict]:
    out = []
    for f in sorted(_eval_dir(policy_id).glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def detect_drift(policy_id: str) -> dict[str, Any]:
    """Compare the latest evaluation vs. the one before it."""
    history = list_evaluations(policy_id)
    if len(history) < 2:
        return {"policy_id": policy_id, "history_size": len(history),
                "regressions": [], "improvements": [], "trend": None}

    history.sort(key=lambda h: h.get("evaluated_at", ""))
    prev, curr = history[-2], history[-1]

    prev_map = {a["asset_id"]: a["controls"] for a in prev.get("asset_results", [])}
    curr_map = {a["asset_id"]: a["controls"] for a in curr.get("asset_results", [])}

    regressions = []
    improvements = []
    for aid, cur_controls in curr_map.items():
        prev_controls = prev_map.get(aid, {})
        for cid, cur_state in cur_controls.items():
            old_state = prev_controls.get(cid, "")
            if old_state == "pass" and cur_state == "fail":
                regressions.append({"asset_id": aid, "control_id": cid,
                                    "from": old_state, "to": cur_state})
            elif old_state == "fail" and cur_state == "pass":
                improvements.append({"asset_id": aid, "control_id": cid,
                                     "from": old_state, "to": cur_state})

    prev_total = (prev.get("pass_count", 0) + prev.get("fail_count", 0)) or 1
    curr_total = (curr.get("pass_count", 0) + curr.get("fail_count", 0)) or 1
    prev_pct = prev.get("pass_count", 0) / prev_total * 100
    curr_pct = curr.get("pass_count", 0) / curr_total * 100

    return {
        "policy_id": policy_id,
        "history_size": len(history),
        "previous_evaluated_at": prev.get("evaluated_at"),
        "current_evaluated_at": curr.get("evaluated_at"),
        "regressions": regressions,
        "improvements": improvements,
        "trend": {
            "previous_pass_pct": round(prev_pct, 1),
            "current_pass_pct": round(curr_pct, 1),
            "delta": round(curr_pct - prev_pct, 1),
        },
    }
