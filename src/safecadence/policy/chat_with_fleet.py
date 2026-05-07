"""
v6.1 — AI chat with fleet (v4 platform + v5 policy aware).

Conversational AI over the unified asset inventory + policy state.
Operator types a question → SafeCadence packs the relevant fleet context
into a prompt → BYO-AI provider answers in plain English.

Honest about scope:
  * Read-only. The AI never executes anything.
  * No history persisted to the AI provider — only the current question
    + a summarized snapshot of the fleet are sent each call.
  * Falls back to a deterministic search-based answer when no AI is
    configured, so the feature still works offline.
"""

from __future__ import annotations

import json
import os
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


def _summarize_fleet(assets: list[dict]) -> dict[str, Any]:
    """Compact snapshot the AI can reason over without blowing the context window."""
    by_type: dict[str, int] = {}
    by_vendor: dict[str, int] = {}
    crit_assets, high_kev, crown = [], [], []
    for a in assets:
        ident = a.get("identity") or {}
        t = ident.get("asset_type") or "unknown"
        v = (ident.get("vendor") or "").lower()
        by_type[t] = by_type.get(t, 0) + 1
        by_vendor[v] = by_vendor.get(v, 0) + 1
        sec = a.get("security") or {}
        if sec.get("critical_cves", 0) >= 3:
            crit_assets.append(ident.get("asset_id"))
        if sec.get("kev_cves", 0) > 0:
            high_kev.append({"id": ident.get("asset_id"),
                              "vendor": v, "kev": sec.get("kev_cves")})
        if (ident.get("criticality") or "").lower() == "crown-jewel":
            crown.append(ident.get("asset_id"))
    return {
        "asset_count": len(assets),
        "by_type": by_type, "by_vendor": by_vendor,
        "assets_with_3plus_critical_cves": crit_assets[:30],
        "assets_with_kev_cves": high_kev[:30],
        "crown_jewels": crown[:30],
    }


def _summarize_policies() -> list[dict]:
    """Compact policy state for the AI prompt."""
    from safecadence.policy.evaluator import evaluate
    from safecadence.policy.store import get, list_policies
    out = []
    assets = _load_assets()
    for meta in list_policies():
        p = get(meta["policy_id"])
        if not p: continue
        ev = evaluate(p, assets)
        out.append({
            "policy_id": p.policy_id, "policy_name": p.policy_name,
            "controls": [c.control_id for c in p.controls],
            "pass": ev.pass_count, "fail": ev.fail_count,
            "coverage_pct": ev.coverage_pct,
            "top_failing_controls": list({v.control_id for v in ev.violations[:10]}),
        })
    return out


def _offline_answer(question: str, fleet: dict, policies: list[dict]) -> str:
    """Best-effort keyword answer when no AI is configured."""
    q = question.lower()
    parts = []
    if any(k in q for k in ("how many", "count", "total")):
        parts.append(f"Fleet has {fleet['asset_count']} assets across "
                     f"{len(fleet['by_type'])} asset types: {fleet['by_type']}.")
    if "kev" in q or "exploit" in q:
        n = len(fleet["assets_with_kev_cves"])
        parts.append(f"{n} assets carry KEV-listed CVEs (actively exploited): "
                     f"{[a['id'] for a in fleet['assets_with_kev_cves'][:10]]}")
    if "crown" in q or "critical asset" in q:
        parts.append(f"Crown-jewel assets ({len(fleet['crown_jewels'])}): "
                     f"{fleet['crown_jewels'][:10]}")
    if "polic" in q or "compliance" in q:
        if policies:
            tot_fail = sum(p["fail"] for p in policies)
            parts.append(f"{len(policies)} policies in force; {tot_fail} total failures. "
                         f"Worst: {sorted(policies, key=lambda p: -p['fail'])[0]['policy_name']}")
        else:
            parts.append("No policies are currently saved.")
    if not parts:
        parts.append("(Offline answer — set OPENAI_API_KEY / ANTHROPIC_API_KEY / "
                     "OLLAMA_HOST and pass --ai for richer answers.)")
        parts.append(f"Fleet snapshot: {json.dumps(fleet, indent=2, default=str)[:1000]}")
    return "\n\n".join(parts)


def ask(question: str, *, ai: bool = False, provider: str | None = None,
        api_key: str | None = None, model: str | None = None) -> dict[str, Any]:
    """Public entry. Returns {answer, source, fleet_size, policy_count}."""
    assets = _load_assets()
    fleet = _summarize_fleet(assets)
    policies = _summarize_policies()

    if not ai:
        return {"source": "offline",
                "answer": _offline_answer(question, fleet, policies),
                "fleet_size": fleet["asset_count"],
                "policy_count": len(policies)}

    try:
        from safecadence.ai.client import (
            AIProvider, detect_provider,
            _call_openai, _call_anthropic, _call_ollama,
        )
    except Exception:
        return {"source": "offline-fallback-import",
                "answer": _offline_answer(question, fleet, policies),
                "fleet_size": fleet["asset_count"],
                "policy_count": len(policies)}

    if provider:
        try: prov = AIProvider(provider.lower())
        except ValueError:
            return {"source": "offline-bad-provider",
                    "answer": _offline_answer(question, fleet, policies),
                    "fleet_size": fleet["asset_count"], "policy_count": len(policies)}
    else:
        prov = detect_provider()
    if prov == AIProvider.NONE:
        return {"source": "offline-no-key",
                "answer": _offline_answer(question, fleet, policies),
                "fleet_size": fleet["asset_count"], "policy_count": len(policies)}

    prompt = (
        "You are a SafeCadence security analyst. Answer the user's question "
        "about their infrastructure fleet using ONLY the data block provided. "
        "Be concrete: cite asset_ids, vendors, and counts. Do not invent.\n\n"
        f"FLEET SNAPSHOT (JSON):\n{json.dumps(fleet, indent=2, default=str)}\n\n"
        f"POLICY STATE (JSON):\n{json.dumps(policies, indent=2, default=str)}\n\n"
        f"USER QUESTION:\n{question}\n\n"
        "Respond in clear plain English with bullet points where appropriate. "
        "If the question can't be answered from the data, say so."
    )

    try:
        if prov == AIProvider.OPENAI:
            key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
            if not key: raise RuntimeError("no key")
            text = _call_openai(prompt, api_key=key,
                                model=model or "gpt-4o-mini", timeout=30)
        elif prov == AIProvider.ANTHROPIC:
            key = (api_key or os.environ.get("ANTHROPIC_API_KEY", "")).strip()
            if not key: raise RuntimeError("no key")
            text = _call_anthropic(prompt, api_key=key,
                                   model=model or "claude-haiku-4-5-20251001", timeout=30)
        elif prov == AIProvider.OLLAMA:
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            text = _call_ollama(prompt, host=host,
                                model=model or "llama3.1", timeout=120)
        else:
            raise RuntimeError("provider not supported")
    except Exception as e:
        return {"source": f"offline-ai-error:{e}",
                "answer": _offline_answer(question, fleet, policies),
                "fleet_size": fleet["asset_count"], "policy_count": len(policies)}

    return {"source": f"ai:{prov.value}", "answer": text,
            "fleet_size": fleet["asset_count"], "policy_count": len(policies)}
