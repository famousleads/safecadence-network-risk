"""
AI Executive Briefing — leadership-ready 1-page summary of the fleet's
current security posture.

Combines: platform inventory + every active policy's last evaluation +
attack-path blast-radius + ATT&CK coverage + drift trend → narrative
the CEO/CTO/CISO can read in 3 minutes.

Two paths (mirroring the policy interpreter):
  - AI path:     calls BYO-AI provider (OpenAI / Anthropic / Ollama)
                 to produce real prose + recommendations
  - Offline path: deterministic markdown summary built from the data —
                  always works, no API key required

Returns a dict the CLI/API can render as JSON or Markdown.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def _summarize_assets(assets: list[dict]) -> dict:
    by_type: Counter = Counter()
    by_grade: Counter = Counter()
    crit = high = kev = 0
    crown = 0
    for a in assets:
        ident = a.get("identity") or {}
        by_type[ident.get("asset_type") or "unknown"] += 1
        h = a.get("health") or {}
        by_grade[h.get("grade") or "?"] += 1
        sec = a.get("security") or {}
        crit += sec.get("critical_cves", 0)
        high += sec.get("high_cves", 0)
        kev += sec.get("kev_cves", 0)
        if (ident.get("criticality") or "").lower() == "crown-jewel":
            crown += 1
    return {
        "asset_count": len(assets), "by_type": dict(by_type),
        "by_grade": dict(by_grade), "critical_cves_total": crit,
        "high_cves_total": high, "kev_cves_total": kev, "crown_jewels": crown,
    }


def _summarize_policies(policy_metas: list[dict],
                        policy_evals: dict[str, dict]) -> dict:
    total_pass = total_fail = 0
    worst_policies = []
    for meta in policy_metas:
        pid = meta.get("policy_id")
        ev = policy_evals.get(pid) or {}
        total_pass += ev.get("pass", 0)
        total_fail += ev.get("fail", 0)
        if ev.get("fail", 0) > 0:
            worst_policies.append({
                "policy_name": meta.get("policy_name"),
                "fail": ev.get("fail", 0),
                "coverage_pct": ev.get("coverage_pct", 0),
            })
    worst_policies.sort(key=lambda p: -p["fail"])
    overall = (total_pass / max(1, total_pass + total_fail)) * 100
    return {
        "policy_count": len(policy_metas),
        "overall_compliance_pct": round(overall, 1),
        "total_failures": total_fail,
        "top_5_failing_policies": worst_policies[:5],
    }


def build_briefing_offline(assets: list[dict], policy_metas: list[dict],
                           policy_evals: dict[str, dict]) -> dict[str, Any]:
    """Deterministic Markdown briefing — always available, no AI needed."""
    asset_summary = _summarize_assets(assets)
    policy_summary = _summarize_policies(policy_metas, policy_evals)
    now = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Top 3 risks (heuristic ranking)
    risks: list[dict] = []
    if asset_summary["kev_cves_total"] > 0:
        risks.append({
            "title": f"{asset_summary['kev_cves_total']} KEV-listed CVEs in active fleet",
            "severity": "critical",
            "why": "These are CVEs CISA has documented as actively exploited in the wild "
                   "right now. Every hour these go unpatched is hour adversaries are using them.",
            "action": "Run `safecadence policy interpret \"enforce patch level\"` and apply the generated playbook.",
        })
    if policy_summary["total_failures"] > 0:
        risks.append({
            "title": f"{policy_summary['total_failures']} policy failures across {policy_summary['policy_count']} active policies",
            "severity": "high",
            "why": f"Overall fleet compliance is at {policy_summary['overall_compliance_pct']}%. "
                   f"Top failing policy: {(policy_summary['top_5_failing_policies'] or [{'policy_name':'n/a'}])[0]['policy_name']}.",
            "action": "Use `safecadence policy export <policy_id> --format ansible` to get fix-it playbooks.",
        })
    if asset_summary["by_grade"].get("F", 0) + asset_summary["by_grade"].get("D", 0) > 0:
        risks.append({
            "title": f"{asset_summary['by_grade'].get('F', 0) + asset_summary['by_grade'].get('D', 0)} assets graded D or F on health",
            "severity": "high",
            "why": "Composite health score combines hardware, security, lifecycle, and operational signals.",
            "action": "Drill into `/api/platform/health` to see which assets and why.",
        })
    if asset_summary["crown_jewels"] > 0:
        # Add a positive note when crown-jewels exist
        risks.append({
            "title": f"{asset_summary['crown_jewels']} crown-jewel assets identified",
            "severity": "info",
            "why": "Identifying crown-jewels is half the battle. Make sure they all carry critical-severity policies.",
            "action": "Run `safecadence policy shadow` to find any crown-jewels with no governing policy.",
        })

    md = []
    md.append(f"# Executive Security Briefing")
    md.append(f"_Generated {now} from SafeCadence Device Intelligence Platform_")
    md.append("")
    md.append(f"## Fleet snapshot")
    md.append(f"- **Assets:** {asset_summary['asset_count']} across "
              f"{len(asset_summary['by_type'])} infrastructure domains "
              f"({', '.join(f'{n} {t}' for t, n in asset_summary['by_type'].items())})")
    md.append(f"- **Crown-jewels:** {asset_summary['crown_jewels']}")
    md.append(f"- **Health distribution:** {asset_summary['by_grade']}")
    md.append(f"- **Open CVEs:** {asset_summary['critical_cves_total']} critical, "
              f"{asset_summary['high_cves_total']} high, "
              f"**{asset_summary['kev_cves_total']} actively exploited (CISA KEV)**")
    md.append("")
    md.append(f"## Policy posture")
    md.append(f"- **Policies in force:** {policy_summary['policy_count']}")
    md.append(f"- **Overall compliance:** {policy_summary['overall_compliance_pct']}%")
    md.append(f"- **Open failures:** {policy_summary['total_failures']}")
    if policy_summary["top_5_failing_policies"]:
        md.append("- **Top failing policies:**")
        for p in policy_summary["top_5_failing_policies"]:
            md.append(f"  - {p['policy_name']}: {p['fail']} failures ({p['coverage_pct']}% coverage)")
    md.append("")
    md.append(f"## Top risks this week")
    for i, r in enumerate(risks[:5], 1):
        md.append(f"### {i}. {r['title']}  _(severity: {r['severity']})_")
        md.append(f"- **Why it matters:** {r['why']}")
        md.append(f"- **Recommended action:** {r['action']}")
    if not risks:
        md.append("_No top-priority risks detected. Continue periodic drift evaluation._")
    md.append("")
    md.append(f"## Recommended spend")
    md.append("- **This quarter:** $0. Every recommendation above is "
              "addressable with already-owned tools + the SafeCadence-generated "
              "Ansible/Terraform playbooks.")
    md.append("- **Next quarter:** Review crown-jewel coverage, consider "
              "pen-test of the top blast-radius surfaces.")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "offline",
        "asset_summary": asset_summary,
        "policy_summary": policy_summary,
        "top_risks": risks[:5],
        "markdown": "\n".join(md),
    }


def build_briefing(assets: list[dict], policy_metas: list[dict],
                   policy_evals: dict[str, dict],
                   *, ai: bool = False, provider: str | None = None,
                   api_key: str | None = None, model: str | None = None) -> dict[str, Any]:
    """Public entry. AI path enriches the offline briefing with prose.

    Returns the offline briefing dict in all cases; when AI succeeds, an
    additional ``ai_narrative`` field carries the LLM-generated executive
    prose and ``source`` is updated to ``ai:<provider>``. When AI is requested
    but unavailable, ``ai_error`` is populated with the reason so the caller
    can surface it (no more silent fallback).
    """
    base = build_briefing_offline(assets, policy_metas, policy_evals)
    if not ai:
        return base
    try:
        from safecadence.ai.client import (
            AIProvider, detect_provider,
            _call_openai, _call_anthropic, _call_ollama,
        )
    except Exception as e:
        base["ai_error"] = f"AI client unavailable ({e}); install with `pip install safecadence-netrisk[ai]`."
        return base
    import os
    if provider:
        try:
            prov = AIProvider(provider.lower())
        except ValueError:
            base["ai_error"] = f"unknown provider {provider!r}; choose openai/anthropic/ollama"
            return base
    else:
        prov = detect_provider()
    if prov == AIProvider.NONE:
        base["ai_error"] = (
            "no AI provider configured; set OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            "or OLLAMA_HOST (or pass --provider explicitly)"
        )
        return base
    prompt = (
        "You are a CISO writing a one-page executive briefing for the CEO. "
        "Below is structured data on the security state of an infrastructure fleet. "
        "Produce a tight, plain-English narrative (300-500 words) that:\n"
        "  1. opens with the single most important sentence\n"
        "  2. names the 3 biggest risks and what each could cost the business\n"
        "  3. lists 3 actions that should happen this week, with effort estimate\n"
        "  4. ends with a forward-looking sentence about trajectory\n"
        "Do not invent data. Cite numbers from the data block.\n\n"
        f"DATA:\n{base['markdown']}\n\n"
        "Return Markdown. No code fences. Start with a # heading."
    )
    try:
        if prov == AIProvider.OPENAI:
            key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
            if not key:
                base["ai_error"] = "OPENAI_API_KEY not set (or pass api_key=)"
                return base
            text = _call_openai(prompt, api_key=key,
                                model=model or "gpt-4o-mini", timeout=45)
        elif prov == AIProvider.ANTHROPIC:
            key = (api_key or os.environ.get("ANTHROPIC_API_KEY", "")).strip()
            if not key:
                base["ai_error"] = "ANTHROPIC_API_KEY not set (or pass api_key=)"
                return base
            text = _call_anthropic(prompt, api_key=key,
                                   model=model or "claude-haiku-4-5-20251001", timeout=45)
        elif prov == AIProvider.OLLAMA:
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            text = _call_ollama(prompt, host=host,
                                model=model or "llama3.1", timeout=120)
        else:
            base["ai_error"] = f"provider {prov.value!r} not implemented"
            return base
    except Exception as e:
        # Surface the actual error instead of swallowing it. The offline
        # briefing still ships, so the UI degrades gracefully.
        base["ai_error"] = f"{prov.value} call failed: {type(e).__name__}: {e}"
        return base
    base["source"] = f"ai:{prov.value}"
    base["ai_narrative"] = text.strip()
    base["ai_model"] = model or {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-haiku-4-5-20251001",
        "ollama": "llama3.1",
    }.get(prov.value, "default")
    base["markdown"] = (
        text.strip()
        + f"\n\n---\n\n_AI narrative generated via {prov.value} ({base['ai_model']}). "
          "Underlying data and offline summary follow._\n\n"
        + base["markdown"]
    )
    return base


# --------------------------------------------------------------------------
# Compliance gap delta — diff two evaluations to attribute regressions.
# --------------------------------------------------------------------------

def compliance_gap_delta(prev: dict, curr: dict) -> dict[str, Any]:
    """Compare two PolicyEvaluation dicts and return per-control deltas
    with asset attribution.
    """
    prev_results = {a["asset_id"]: a.get("controls", {})
                    for a in (prev.get("asset_results") or [])}
    curr_results = {a["asset_id"]: a.get("controls", {})
                    for a in (curr.get("asset_results") or [])}

    regressions: list[dict] = []
    improvements: list[dict] = []
    for aid, cur_controls in curr_results.items():
        prev_controls = prev_results.get(aid, {})
        for cid, cur_state in cur_controls.items():
            old = prev_controls.get(cid, "")
            if old == "pass" and cur_state == "fail":
                regressions.append({
                    "asset_id": aid, "control_id": cid,
                    "from": old, "to": cur_state,
                })
            elif old == "fail" and cur_state == "pass":
                improvements.append({
                    "asset_id": aid, "control_id": cid,
                    "from": old, "to": cur_state,
                })

    by_control_reg: Counter = Counter(r["control_id"] for r in regressions)
    by_control_imp: Counter = Counter(i["control_id"] for i in improvements)
    by_asset_reg: Counter = Counter(r["asset_id"] for r in regressions)

    prev_pct = prev.get("pass_count", 0) / max(1, (prev.get("pass_count", 0) + prev.get("fail_count", 0))) * 100
    curr_pct = curr.get("pass_count", 0) / max(1, (curr.get("pass_count", 0) + curr.get("fail_count", 0))) * 100

    return {
        "previous_evaluated_at": prev.get("evaluated_at"),
        "current_evaluated_at": curr.get("evaluated_at"),
        "compliance_pct_delta": round(curr_pct - prev_pct, 1),
        "previous_compliance_pct": round(prev_pct, 1),
        "current_compliance_pct": round(curr_pct, 1),
        "regression_count": len(regressions),
        "improvement_count": len(improvements),
        "regressions": regressions,
        "improvements": improvements,
        "regressions_by_control": dict(by_control_reg.most_common()),
        "improvements_by_control": dict(by_control_imp.most_common()),
        "regressions_by_asset": dict(by_asset_reg.most_common()),
    }
