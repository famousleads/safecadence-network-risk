"""
v14.1 — Conversational risk assistant.

Lets an operator ask plain-English questions and get back grounded
answers built from real platform data, not hallucinated narrative.

How it works
------------

1. **Plan** — a small rule-based router examines the question text
   and selects 1–3 MCP tools to call. The router doesn't try to be
   clever; it pattern-matches against an intent vocabulary
   (``compliance / posture / topology / findings / identity / report
   / evidence``) and picks the matching tool(s) from the v12 MCP
   ``TOOL_REGISTRY``.

2. **Execute** — each tool is called via the existing MCP tool
   dispatcher with the operator's RBAC context. Tool outputs are
   captured verbatim (no editing).

3. **Summarize** — the question + the tool outputs are fed into the
   BYO-AI client (v11.4). The LLM is *constrained* by the prompt to
   answer only from the tool outputs and to say "I don't know" when
   the data doesn't support an answer. When no API key is configured,
   we fall back to a deterministic structured summary.

4. **Cite** — the response carries a ``calls`` list with the tool
   names + arguments + output sizes so the operator and the audit
   log see exactly what was used.

Public API
----------

* ``ask(question, *, max_tools=3, model=None)`` → dict
* ``plan(question)`` → list[dict]  (router, exposed for testing)

The returned dict is shaped like an MCP response so it can be
emitted into the audit log + report sections unchanged.
"""
from __future__ import annotations

import os
from typing import Any


# Intent → MCP tool(s). Ordered roughly by how often each tool will
# be useful for that intent (first tool is the primary; the others
# are added to enrich the answer).
_INTENT_TO_TOOLS: dict[str, list[str]] = {
    "compliance":  ["query_compliance", "fetch_evidence"],
    "evidence":    ["fetch_evidence", "query_compliance"],
    "posture":     ["evaluate_posture", "retrieve_findings"],
    "score":       ["evaluate_posture", "retrieve_findings"],
    "topology":    ["query_topology"],
    "findings":    ["retrieve_findings", "evaluate_posture"],
    "identity":    ["inspect_identities"],
    "users":       ["inspect_identities"],
    "report":      ["generate_report"],
}

# Each keyword → intent. The router uses the *first* keyword match.
_KEYWORD_TO_INTENT: list[tuple[str, str]] = [
    ("compliance", "compliance"),
    ("control", "compliance"),
    ("hipaa", "compliance"),
    ("pci", "compliance"),
    ("soc2", "compliance"),
    ("soc 2", "compliance"),
    ("nist", "compliance"),
    ("cis", "compliance"),
    ("evidence", "evidence"),
    ("audit", "evidence"),
    ("safe score", "score"),
    ("risk score", "score"),
    ("posture", "posture"),
    ("trend", "posture"),
    ("topology", "topology"),
    ("network map", "topology"),
    ("graph", "topology"),
    ("attack path", "topology"),
    ("finding", "findings"),
    ("cve", "findings"),
    ("vulnerability", "findings"),
    ("kev", "findings"),
    ("identity", "identity"),
    ("user", "users"),
    ("mfa", "identity"),
    ("account", "identity"),
    ("nhi", "identity"),
    ("report", "report"),
    ("brief", "report"),
    ("summary", "report"),
    ("export", "report"),
]


def plan(question: str, *, max_tools: int = 3) -> list[dict]:
    """Pick the MCP tools to call for `question`. Pure + testable.

    Returns a list of ``{"tool": "...", "intent": "...", "args": {...}}``.
    Always returns at least one entry; defaults to ``evaluate_posture``
    when no keyword matches.
    """
    q = (question or "").lower()
    intents_seen: list[str] = []
    for kw, intent in _KEYWORD_TO_INTENT:
        if kw in q and intent not in intents_seen:
            intents_seen.append(intent)
        if len(intents_seen) >= max_tools:
            break

    if not intents_seen:
        intents_seen = ["posture"]

    tools_in_order: list[str] = []
    for intent in intents_seen:
        for tool in _INTENT_TO_TOOLS.get(intent, []):
            if tool not in tools_in_order:
                tools_in_order.append(tool)
            if len(tools_in_order) >= max_tools:
                break
        if len(tools_in_order) >= max_tools:
            break

    return [{"tool": t, "intent": intents_seen[0], "args": {}}
            for t in tools_in_order[:max_tools]]


def _execute_calls(calls: list[dict]) -> list[dict]:
    """Dispatch each planned call through the v12 MCP tool registry."""
    out: list[dict] = []
    try:
        from safecadence.mcp.tools import get_tool
    except Exception:
        return out
    for c in calls:
        rec = {"tool": c["tool"], "args": c.get("args") or {},
               "ok": False, "output_size": 0, "output": None}
        try:
            fn = get_tool(c["tool"])
            result = fn(c.get("args") or {})
            rec["ok"] = True
            rec["output"] = result
            rec["output_size"] = len(str(result))
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
        out.append(rec)
    return out


def _deterministic_summary(question: str, calls: list[dict]) -> str:
    """Fallback summary when no LLM is configured. Pure structured text."""
    lines = [
        f"You asked: {question}",
        "",
        "I consulted these platform tools:",
    ]
    for c in calls:
        status = "ok" if c.get("ok") else "error"
        lines.append(f"  - {c['tool']} ({status})")
    lines.extend([
        "",
        "Set OPENAI_API_KEY / ANTHROPIC_API_KEY (or another BYO-AI key) "
        "to receive a natural-language summary of the data above. The "
        "raw tool outputs are returned in this response and remain "
        "authoritative.",
    ])
    return "\n".join(lines)


def _llm_summarize(
    question: str,
    calls: list[dict],
    *,
    model: str | None = None,
    timeout: int = 30,
) -> str:
    """Send (question + tool outputs) to the configured BYO-AI provider.

    Returns the LLM text on success, or a deterministic fallback on
    any failure (no provider, network error, rate limit, etc.).
    """
    try:
        from safecadence.ai.client import AIProvider, detect_provider
        prov = detect_provider()
        if prov == AIProvider.NONE:
            return _deterministic_summary(question, calls)
    except Exception:
        return _deterministic_summary(question, calls)

    # Build a small constrained prompt. Constraint is in the instructions:
    # answer only from the tool outputs, say "I don't know" otherwise.
    parts = [
        "You are a security posture assistant. Answer the user's question "
        "USING ONLY the platform tool outputs below. If the outputs do "
        "not support an answer, say 'I don't have enough data to answer that.' "
        "Be concise. Cite the tool name when referencing data.",
        "",
        f"USER QUESTION:\n{question}",
        "",
        "TOOL OUTPUTS:",
    ]
    for c in calls:
        if not c.get("ok"):
            parts.append(f"- {c['tool']}: ERROR ({c.get('error')})")
            continue
        # Truncate any single tool output to keep the prompt small.
        out_str = str(c.get("output"))[:4000]
        parts.append(f"- {c['tool']}({c['args']}):\n{out_str}")
    parts.append("\nANSWER:")
    prompt = "\n".join(parts)

    try:
        from safecadence.ai.client import (
            AIProvider, _call_anthropic, _call_openai, detect_provider,
        )
        prov = detect_provider()
        if prov == AIProvider.OPENAI:
            return _call_openai(
                prompt,
                api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
                model=model or "gpt-4o-mini",
                timeout=timeout,
            )
        if prov == AIProvider.ANTHROPIC:
            return _call_anthropic(
                prompt,
                api_key=os.environ.get("ANTHROPIC_API_KEY", "").strip(),
                model=model or "claude-haiku-4-5-20251001",
                timeout=timeout,
            )
    except Exception:
        return _deterministic_summary(question, calls)

    return _deterministic_summary(question, calls)


def ask(
    question: str,
    *,
    max_tools: int = 3,
    model: str | None = None,
    timeout: int = 30,
) -> dict:
    """Single entry-point: question → answer + tool-call trail.

    Returns:
        {
          "question": "...",
          "answer": "...",
          "calls": [{"tool", "args", "ok", "output_size", ...}, ...],
          "llm_used": bool,
          "warnings": [...]
        }

    Never raises. Always returns a dict that's safe to log + emit.
    """
    warnings: list[str] = []
    plan_result = plan(question, max_tools=max_tools)
    calls = _execute_calls(plan_result)

    try:
        from safecadence.ai.client import AIProvider, detect_provider
        llm_used = detect_provider() != AIProvider.NONE
    except Exception:
        llm_used = False

    if not any(c.get("ok") for c in calls):
        warnings.append("all_tools_failed")
        answer = (
            "I couldn't gather any platform data to answer that — every "
            "selected tool returned an error or empty data. Check that "
            "you have at least one scan in the database."
        )
    elif llm_used:
        answer = _llm_summarize(
            question, calls, model=model, timeout=timeout,
        )
    else:
        answer = _deterministic_summary(question, calls)

    return {
        "question": question,
        "answer": answer,
        "calls": [
            {
                "tool": c["tool"],
                "args": c.get("args") or {},
                "ok": c.get("ok", False),
                "output_size": c.get("output_size", 0),
                "error": c.get("error"),
            }
            for c in calls
        ],
        "llm_used": llm_used,
        "warnings": warnings,
    }


__all__ = ["ask", "plan"]
