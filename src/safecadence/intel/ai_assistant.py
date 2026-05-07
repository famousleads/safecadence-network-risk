"""
v7.9 — AI assistant.

Natural-language Q&A over the entire SafeCadence knowledge graph.

User asks:
   "how many crown-jewel assets have failing policies right now?"
   "which contractors are over-privileged?"
   "what NHIs haven't been rotated in 90 days?"
   "summarize identity risk in plain English"

The assistant has read access to the platform store + findings +
attack paths and uses BYO-AI (existing safecadence.ai.client) to
answer in natural language with citations.

Constraints:
  * read-only — never proposes a write
  * cites the source data (asset IDs, finding IDs)
  * if no AI key, falls back to a rules-based "best effort" answerer
    that handles common questions deterministically
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class AssistantAnswer:
    text: str
    cited: list[dict] = field(default_factory=list)
    used_ai: bool = False
    fallback_reason: str = ""


_SYSTEM_PROMPT = """You are SafeCadence's read-only platform assistant.
You receive a JSON snapshot of the user's fleet (assets, findings, attack
paths, identity systems, JIT grants) and a natural-language question.

Constraints:
  * Answer ONLY using the data provided. If the data does not support
    an answer, say so honestly.
  * Be concise — 2 to 6 sentences for typical questions.
  * Cite asset IDs / finding IDs where relevant: e.g. "(srv-prod-01)".
  * Never propose write actions — this is a read-only assistant.
  * Never fabricate counts, identifiers, or relationships.
"""


# v9.56 — limits.
#
# MAX_QUESTION_CHARS caps user input so a runaway script can't burn
# the API budget on multi-MB questions. ~2 KB is room for a couple of
# paragraphs; anything longer is almost certainly a bug or abuse.
#
# MAX_SNAPSHOT_CHARS bounds the JSON we ship to the LLM. The pre-v9.56
# code took str-slice [:6000] of a JSON dump, which silently truncated
# mid-record and gave the LLM a partial fleet without telling it.
# v9.56 builds the snapshot under the budget by entity caps (see
# _build_snapshot's max_findings / max_paths args) and surfaces the
# truncation in `truncated_*` keys the model can read.
MAX_QUESTION_CHARS = 2_000
MAX_SNAPSHOT_CHARS = 6_000


def ask_assistant(question: str, *,
                   assets: Iterable[dict] | None = None,
                   findings: Iterable[object] | None = None,
                   attack_paths: Iterable[object] | None = None,
                   ai_call=None) -> AssistantAnswer:
    """Answer a natural-language question about the fleet.

    Parameters
    ----------
    question     The user's question.
    assets / findings / attack_paths
                 Override sources for testing. If omitted, pulled from the
                 live platform store.
    ai_call      Test seam — callable(system_prompt, user_prompt, model) -> str.
                 If given, the real AI client is bypassed entirely; the
                 callable's return value is treated as a successful AI
                 response. Pass `None` (default) to use the real client.
    """
    if not question or not question.strip():
        return AssistantAnswer(text="(no question)", used_ai=False,
                                 fallback_reason="empty question")
    # v9.56 — hard cap question length. Truncating silently would let
    # an attacker push the prompt envelope; raising loud is the right
    # call here so misuse shows up in the audit log instead of in the
    # LLM bill.
    if len(question) > MAX_QUESTION_CHARS:
        return AssistantAnswer(
            text=(f"(question too long — {len(question)} chars; "
                    f"cap is {MAX_QUESTION_CHARS}. Trim and re-ask.)"),
            used_ai=False,
            fallback_reason=f"question exceeds {MAX_QUESTION_CHARS}-char cap",
        )

    assets = list(assets) if assets is not None else _load_assets()
    findings = list(findings) if findings is not None else _load_findings(assets)
    attack_paths = (list(attack_paths) if attack_paths is not None
                     else _load_paths(assets))

    snapshot = _build_snapshot(assets, findings, attack_paths)

    # v9.56 — air-gap honor. SC_AI_DISABLED=1 (or any truthy value)
    # short-circuits BEFORE reading API keys from env, so an air-gap
    # deployment with a leftover OPENAI_API_KEY in the shell never
    # hits the wire. The deterministic fallback is good enough for
    # common questions.
    #
    # The check is unconditional — even an ai_call test seam is
    # blocked here. Tests that want to exercise the AI path must
    # not set SC_AI_DISABLED. Anything weaker would let a future
    # PR accidentally bypass air-gap by passing a fake call site.
    if _ai_globally_disabled():
        ans = _ask_deterministic(question, snapshot)
        ans.fallback_reason = "SC_AI_DISABLED is set (air-gap mode)"
        return ans

    # Try AI first
    try:
        ans, used, why = _ask_via_ai(question, snapshot, ai_call=ai_call)
        if used:
            # v9.56.1 — belt-and-suspenders output screen. The system
            # prompt forbids the model from proposing write actions,
            # but a clever prompt-injection ("ignore previous
            # instructions...") could still talk a smart-enough model
            # into emitting destructive CLI. We scan the answer for
            # write-shaped tokens and prepend a warning if any land.
            # We don't strip them — that would hide the model's
            # suggestion from the user; we want the operator to SEE
            # the model went off the rails. The warning makes it
            # impossible to miss.
            warning = _screen_for_write_intent(ans)
            screened_text = (warning + ans) if warning else ans
            return AssistantAnswer(
                text=screened_text,
                cited=_extract_citations(ans, snapshot=snapshot),
                used_ai=True,
                fallback_reason=("write-intent screen tripped — see "
                                   "warning at top of answer")
                                   if warning else "",
            )
        # AI not configured (no key, no provider) — fall through with
        # the reason we figured out so the user sees why.
        det = _ask_deterministic(question, snapshot)
        det.fallback_reason = why or "no AI provider configured"
        return det
    except Exception as exc:                                # pragma: no cover
        # Fall through to deterministic fallback. The exception class
        # name + message gives the operator something to grep for.
        fallback = _ask_deterministic(question, snapshot)
        fallback.fallback_reason = (
            f"AI unavailable: {type(exc).__name__}: {exc}"
        )
        return fallback


# v9.56.1 — write-intent token list. NOT exhaustive; not meant to be.
# This is a tripwire for "the model started suggesting destructive
# commands despite a read-only system prompt", not a CLI safety
# parser. If a real write-intent reaches the user, the system prompt
# itself was bypassed — the right place to fix that is the prompt,
# not this screen. The screen exists to make the bypass visible.
_WRITE_INTENT_PATTERNS = [
    # Cisco / Arista / generic shutdown
    (r"\bno\s+(?:shutdown|switchport|access-list|ip\s+route)\b",
     "config-mode 'no' command"),
    (r"\bshutdown\b\s*(?:$|\n)", "interface shutdown"),
    # Cisco reload
    (r"\breload\b(?!\s+(?:in|at|cancel|pending))", "device reload"),
    (r"\bwrite\s+erase\b", "factory reset (write erase)"),
    (r"\berase\s+(?:startup-config|nvram)", "config erase"),
    # Junos / Arista commit
    (r"\bcommit\s+(?:and-quit|confirmed|check)?\s*(?:$|\n)", "junos commit"),
    # Network blast
    (r"\bip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\b", "default route override"),
    # Linux destructive
    (r"\brm\s+-rf\b", "rm -rf"),
    (r"\bmkfs\b", "mkfs"),
    (r"\b(?:reboot|shutdown\s+-[hr])\b", "host reboot"),
    # Identity destructive
    (r"\b(?:DROP|DELETE)\s+(?:USER|TABLE|DATABASE)\b", "SQL drop/delete"),
    # Generic "execute this" social engineering
    (r"\b(?:please\s+)?(?:run|execute|paste)\s+(?:the\s+following|this)\b",
     "imperative-execute language"),
]


def _screen_for_write_intent(text: str) -> str:
    """Returns a warning prefix if `text` contains any write-shaped
    tokens, else empty string.

    Output shape — chosen for visibility, not magic:

      ⚠️  WRITE-INTENT DETECTED — this assistant is read-only.
      The model's response below contains language that looks
      like destructive operations (matched: ...). Do NOT execute
      anything from this answer without independently verifying
      against vendor documentation and your change-management
      process.

      ────────────

    The model's actual answer follows unchanged so the operator
    sees what was suggested.
    """
    import re
    if not text:
        return ""
    matches: list[str] = []
    for pat, label in _WRITE_INTENT_PATTERNS:
        try:
            if re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE):
                matches.append(label)
        except re.error:                                    # pragma: no cover
            continue
    if not matches:
        return ""
    # Dedupe while preserving order so the warning is stable.
    seen: set[str] = set()
    unique = []
    for m in matches:
        if m in seen:
            continue
        seen.add(m)
        unique.append(m)
    return (
        "⚠️  WRITE-INTENT DETECTED — this assistant is read-only.\n"
        f"The model's response below contains language matching: "
        f"{', '.join(unique)}.\n"
        "Do NOT execute anything from this answer without "
        "independently verifying against vendor documentation and "
        "your change-management process.\n"
        "──────────────────────────\n\n"
    )


def _ai_globally_disabled() -> bool:
    """Master kill switch — same shape as ai/explain_finding._is_disabled.
    Air-gap deployments set ``SC_AI_DISABLED=1`` and we honor it
    everywhere AI could call out, including this module."""
    import os
    v = (os.environ.get("SC_AI_DISABLED") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- snapshot

def _build_snapshot(assets, findings, attack_paths,
                      *, max_findings: int = 50,
                      max_paths: int = 20,
                      max_crown_jewels: int = 25) -> dict:
    """Compact summary the AI can fit in a prompt window.

    v9.56 changes:
      * Per-entity caps are explicit args, with `truncated_*` flags
        in the output so the LLM knows when it's seeing a slice.
        Pre-v9.56 the function silently returned the first 50
        findings with no signal.
      * `asset_id_index` and `finding_id_index` are sets returned
        for citation cross-checks (callers strip them before sending
        to the LLM).
    """
    by_type: dict[str, int] = {}
    by_env: dict[str, int] = {}
    by_crit: dict[str, int] = {}
    nhi_count = 0
    nhi_subtypes: dict[str, int] = {}
    no_mfa = 0
    crown_jewels: list[str] = []
    asset_ids: set[str] = set()

    for a in assets:
        ident = a.get("identity") or {}
        aid = ident.get("asset_id", "") or ""
        if aid:
            asset_ids.add(aid)
        by_type[ident.get("asset_type", "")] = by_type.get(ident.get("asset_type", ""), 0) + 1
        by_env[ident.get("environment", "")] = by_env.get(ident.get("environment", ""), 0) + 1
        by_crit[ident.get("criticality", "")] = by_crit.get(ident.get("criticality", ""), 0) + 1
        if ident.get("criticality") == "crown-jewel":
            crown_jewels.append(aid)
        ib = a.get("identity_block") or {}
        if ib.get("mfa_enrolled") is False:
            no_mfa += 1
        nhi = a.get("nhi") or {}
        if nhi.get("nhi_id"):
            nhi_count += 1
            nhi_subtypes[nhi.get("subtype", "")] = (
                nhi_subtypes.get(nhi.get("subtype", ""), 0) + 1)

    findings_summary = []
    finding_ids: set[str] = set()
    for f in findings[:max_findings]:
        fid = getattr(f, "finding_id", "") or ""
        if fid:
            finding_ids.add(fid)
        findings_summary.append({
            "id": fid,
            "kind": getattr(f, "kind", ""),
            "severity": getattr(f, "severity", ""),
            "title": getattr(f, "title", ""),
            "principal": getattr(f, "principal", ""),
        })

    paths_summary = []
    for p in attack_paths[:max_paths]:
        paths_summary.append({
            "chain": p.chain_summary() if hasattr(p, "chain_summary") else "",
            "terminal": getattr(p, "terminal_asset", ""),
            "risk": getattr(p, "risk_score", 0),
        })

    out = {
        "asset_count": len(assets),
        "by_type": by_type,
        "by_env": by_env,
        "by_criticality": by_crit,
        "crown_jewels": crown_jewels[:max_crown_jewels],
        "truncated_crown_jewels": len(crown_jewels) > max_crown_jewels,
        "nhi_count": nhi_count,
        "nhi_subtypes": nhi_subtypes,
        "tenants_no_mfa": no_mfa,
        "findings": findings_summary,
        "truncated_findings": len(findings) > max_findings,
        "total_findings": len(findings),
        "attack_paths": paths_summary,
        "truncated_attack_paths": len(attack_paths) > max_paths,
        "total_attack_paths": len(attack_paths),
        # Internal indexes for citation cross-check; stripped before
        # the JSON dump so the LLM doesn't see them.
        "_internal_asset_ids": sorted(asset_ids),
        "_internal_finding_ids": sorted(finding_ids),
    }
    return out


# ---------------------------------------------------------------- ai path

def _ask_via_ai(question: str, snapshot: dict,
                 ai_call=None) -> tuple[str, bool, str]:
    """Returns ``(answer, used_ai, why)``.

    ``used_ai`` is True only when an actual model call returned text
    (real client or test-seam). ``why`` carries a short reason for
    why we did/didn't use AI — surfaced to the operator as
    ``fallback_reason`` when the deterministic path runs.

    v9.56 changes:
      * ai_call test seam is honored cleanly without faking a
        provider — was previously masked behind a confusing
        AIProvider.OPENAI assignment.
      * Snapshot is truncated by length AFTER the entity caps in
        _build_snapshot, with a warning prepended so the LLM knows
        the data isn't complete.
      * HTTP error path includes the response body excerpt so the
        operator can tell rate-limit (429) from bad-key (401) from
        overload (503) from a real bug.
    """
    # Test seam: ai_call wins over any real provider so unit tests
    # never accidentally hit OpenAI or Ollama.
    if ai_call is not None:
        user_prompt = _build_user_prompt(question, snapshot)
        return (ai_call(_SYSTEM_PROMPT, user_prompt, "test-model"),
                 True, "test ai_call seam")

    from safecadence.ai.client import AIError, AIProvider, detect_provider

    chosen = detect_provider()
    if chosen == AIProvider.NONE:
        return ("", False, "no AI provider configured "
                            "(set OPENAI_API_KEY / ANTHROPIC_API_KEY / "
                            "OLLAMA_HOST)")

    user_prompt = _build_user_prompt(question, snapshot)
    try:
        import os
        import httpx
    except ImportError as exc:                              # pragma: no cover
        raise AIError(f"httpx missing: {exc}")

    if chosen == AIProvider.OPENAI:
        key = os.environ.get("OPENAI_API_KEY", "")
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json={"model": "gpt-4o-mini", "temperature": 0.2,
                   "messages": [
                       {"role": "system", "content": _SYSTEM_PROMPT},
                       {"role": "user", "content": user_prompt},
                   ]},
            timeout=30,
        )
        if r.status_code >= 400:
            raise AIError(_http_error_reason("openai", r))
        return (r.json()["choices"][0]["message"]["content"], True,
                 "openai")

    if chosen == AIProvider.ANTHROPIC:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "Content-Type": "application/json"},
            json={"model": "claude-3-5-sonnet-latest", "max_tokens": 800,
                   "system": _SYSTEM_PROMPT,
                   "messages": [{"role": "user", "content": user_prompt}]},
            timeout=30,
        )
        if r.status_code >= 400:
            raise AIError(_http_error_reason("anthropic", r))
        return (r.json()["content"][0]["text"], True, "anthropic")

    if chosen == AIProvider.OLLAMA:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        r = httpx.post(
            f"{host}/api/chat",
            json={"model": "llama3.1", "stream": False,
                   "messages": [
                       {"role": "system", "content": _SYSTEM_PROMPT},
                       {"role": "user", "content": user_prompt},
                   ]},
            timeout=120,
        )
        if r.status_code >= 400:
            raise AIError(_http_error_reason("ollama", r))
        return (r.json()["message"]["content"], True, "ollama")

    return ("", False, f"unknown provider: {chosen!r}")


def _http_error_reason(provider: str, r) -> str:
    """v9.56 — surface the HTTP body excerpt so the operator can tell
    rate-limit (429) from bad-key (401) from overload (503).
    Pre-v9.56 we just said 'openai 429' which was useless."""
    code = getattr(r, "status_code", "??")
    body = ""
    try:
        body = r.text or ""
    except Exception:                                       # pragma: no cover
        body = ""
    body = body.strip().splitlines()[0] if body else ""
    if len(body) > 200:
        body = body[:200] + "…"
    label = "rate limit" if str(code) == "429" else (
        "auth (check API key)" if str(code) == "401" else (
        "forbidden" if str(code) == "403" else (
        "model overloaded" if str(code) in ("502", "503") else (
        "server error" if str(code).startswith("5") else "client error"))))
    return f"{provider} {code} — {label}{(': ' + body) if body else ''}"


def _build_user_prompt(question: str, snapshot: dict) -> str:
    """v9.56 — explicit truncation contract with the LLM.

    If the JSON-encoded snapshot exceeds MAX_SNAPSHOT_CHARS we cut
    by length AFTER the entity caps in _build_snapshot have already
    bounded the per-section sizes. The model is told inline that the
    data is partial and asked to caveat its answer accordingly.

    Internal indexes (`_internal_*`) used only by citation
    cross-check are stripped before the dump so the LLM doesn't see
    raw ID lists outside the structured records.
    """
    public = {k: v for k, v in snapshot.items()
                if not k.startswith("_internal_")}
    payload = json.dumps(public, indent=2, sort_keys=True)
    truncated = len(payload) > MAX_SNAPSHOT_CHARS
    if truncated:
        payload = payload[:MAX_SNAPSHOT_CHARS]
        warning = (
            "\n\nNOTE: snapshot truncated to "
            f"{MAX_SNAPSHOT_CHARS} chars after per-entity caps. "
            "Caveat answers that depend on full enumeration with "
            "'based on partial data'."
        )
    else:
        warning = ""
    return (f"Fleet snapshot:\n{payload}{warning}\n\n"
             f"Question: {question}")


# ---------------------------------------------------------------- fallback

_KEYWORD_INTENTS = [
    ("crown", "crown-jewel"),
    ("crown-jewel", "crown-jewel"),
    ("over-privileged", "over_privileged"),
    ("overprivileged", "over_privileged"),
    ("stale", "stale_nhi"),
    ("never rotated", "never_rotated"),
    ("rotation", "never_rotated"),
    ("orphan", "orphan_service_account"),
    ("no mfa", "no_mfa"),
    ("without mfa", "no_mfa"),
    ("attack path", "paths"),
    ("nhi", "nhis"),
    ("non-human", "nhis"),
    ("how many", "count"),
    ("count", "count"),
]


def _ask_deterministic(question: str, snapshot: dict) -> AssistantAnswer:
    """Best-effort answers without an AI, by keyword matching against
    the snapshot. Common questions still get answered; uncommon ones
    surface a graceful "no AI configured" message."""
    q = question.lower()
    intents: list[str] = []
    for kw, intent in _KEYWORD_INTENTS:
        if kw in q:
            intents.append(intent)

    if "crown-jewel" in intents:
        cj = snapshot.get("crown_jewels", [])
        return AssistantAnswer(
            text=(f"There are {len(cj)} crown-jewel assets in your fleet"
                  + (": " + ", ".join(cj[:8]) + ("…" if len(cj) > 8 else "")
                      if cj else ".")),
            used_ai=False, fallback_reason="no AI key set",
            cited=[{"asset_id": a} for a in cj[:8]],
        )
    if "paths" in intents:
        ps = snapshot.get("attack_paths", [])
        if not ps:
            text = "No identity attack paths detected in the current snapshot."
        else:
            text = (f"{len(ps)} identity attack path(s). "
                    f"Highest-risk: {ps[0]['chain']} (risk {ps[0]['risk']:.1f}).")
        return AssistantAnswer(text=text, used_ai=False,
                                 fallback_reason="no AI key set")
    for kind in ("over_privileged", "stale_nhi", "never_rotated",
                 "orphan_service_account", "no_mfa"):
        if kind in intents:
            matching = [f for f in snapshot.get("findings", [])
                         if f.get("kind") == kind]
            text = (f"{len(matching)} '{kind}' finding(s)."
                    + (" Top: " + matching[0].get("title", "")
                        if matching else ""))
            return AssistantAnswer(
                text=text, used_ai=False, fallback_reason="no AI key set",
                cited=[{"finding_id": f.get("id")}
                        for f in matching[:5] if f.get("id")],
            )
    if "nhis" in intents or "count" in intents:
        return AssistantAnswer(
            text=(f"Fleet has {snapshot.get('asset_count', 0)} assets, "
                  f"{snapshot.get('nhi_count', 0)} NHIs "
                  f"({snapshot.get('nhi_subtypes', {})}), "
                  f"{snapshot.get('tenants_no_mfa', 0)} tenant(s) without MFA. "
                  f"For nuanced questions, set OPENAI_API_KEY or "
                  "ANTHROPIC_API_KEY and re-ask."),
            used_ai=False, fallback_reason="no AI key set",
        )
    return AssistantAnswer(
        text=(f"Without an AI key configured I can answer counts and "
              f"common kinds. Your fleet has {snapshot.get('asset_count', 0)} "
              f"assets, {len(snapshot.get('findings', []))} findings, "
              f"{len(snapshot.get('attack_paths', []))} attack paths. "
              "Set OPENAI_API_KEY or ANTHROPIC_API_KEY and try a more "
              "specific question."),
        used_ai=False, fallback_reason="no AI key set",
    )


def _extract_citations(text: str, *,
                          snapshot: dict | None = None) -> list[dict]:
    """v9.56 — cross-check candidate citations against the snapshot's
    actual IDs before claiming them.

    Pre-v9.56 this was pure regex theatre: anything in parens with
    4+ chars came back as a citation. "(see RFC 1234)" got cited as
    id "see RFC 1234". "(approximately 5)" came back too. The LLM
    can hallucinate any ID and we'd dutifully echo it as evidence.

    Now the function pulls the same paren-bracketed candidates AND
    bare-token candidates that look ID-shaped, then keeps only the
    ones that are present in the snapshot's `_internal_asset_ids` or
    `_internal_finding_ids` sets. Anything else is discarded — the
    UI's "cited" panel only carries IDs the model could have
    legitimately seen.
    """
    import re
    if not text:
        return []
    asset_ids = set((snapshot or {}).get("_internal_asset_ids") or [])
    finding_ids = set((snapshot or {}).get("_internal_finding_ids") or [])
    if not (asset_ids or finding_ids):
        # No snapshot IDs to cross-check against → empty cite list
        # is honestly better than fabricated ones.
        return []
    # Candidate pool: everything in parens, plus standalone tokens
    # that match common SafeCadence ID prefixes (asset/finding/etc).
    candidates: list[str] = []
    for m in re.finditer(r"\(([a-zA-Z0-9_\-:./]{3,})\)", text):
        candidates.append(m.group(1))
    for m in re.finditer(
        r"\b((?:f_|w_|j_|r_|c_|nhi[-_])?[a-z][a-z0-9_\-]{2,}[0-9])\b",
        text,
    ):
        candidates.append(m.group(1))
    seen: set[str] = set()
    out: list[dict] = []
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        if c in asset_ids:
            out.append({"id": c, "kind": "asset"})
        elif c in finding_ids:
            out.append({"id": c, "kind": "finding"})
        if len(out) >= 20:
            break
    return out


def _load_assets() -> list[dict]:
    try:
        from safecadence.server.platform_api import list_assets
        return list_assets()
    except Exception:
        return []


def _load_findings(assets):
    try:
        from safecadence.identity.findings import scan_findings
        return scan_findings(assets)
    except Exception:
        return []


def _load_paths(assets):
    try:
        from safecadence.identity.attack_paths import compute_identity_paths
        return compute_identity_paths(assets)
    except Exception:
        return []
