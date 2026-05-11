"""
AI helpers for the report module.

The strategy is:

  1. If ``OPENAI_API_KEY`` is set, call OpenAI Chat Completions
     (stdlib-only HTTPS POST — no SDK dependency).
  2. Else if ``ANTHROPIC_API_KEY`` is set, call Anthropic Messages API.
  3. Otherwise, fall back to deterministic templated prose that uses the
     actual data values, so an offline build still produces realistic
     consultant-grade copy (not a placeholder).

All helpers are pure functions and never raise — failure modes degrade
to a minimal but useful string.

v10.6 changes (May 2026):
  * Real LLM calls now live here directly (urllib + json), with a
    30-second timeout and a single retry on 5xx — no third-party SDK.
  * ``explain_cve`` and ``detect_quick_wins`` are LLM-aware on top of
    the existing deterministic fallbacks.
"""

from __future__ import annotations

import json as _json
import os
import time as _time
from typing import Any, Iterable
from urllib import error as _urlerr
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# provider plumbing
# --------------------------------------------------------------------------


# Module-level model names — overridable by env for tests / future tuning.
OPENAI_MODEL = os.environ.get("SAFECADENCE_OPENAI_MODEL", "gpt-4o-mini")
ANTHROPIC_MODEL = os.environ.get(
    "SAFECADENCE_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"
)
LLM_TIMEOUT_SEC = 30


def _active_provider() -> str | None:
    """Return ``'openai'`` or ``'anthropic'`` (whichever env key is set first)
    or ``None`` for stub mode.
    """
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


def _has_api_key() -> bool:
    return _active_provider() is not None or bool(
        os.environ.get("OLLAMA_HOST")
        or os.environ.get("SAFECADENCE_LOCAL_LLM")
    )


def _http_post_json(url: str, payload: dict, headers: dict,
                    timeout: float = LLM_TIMEOUT_SEC,
                    retry_on_5xx: bool = True) -> dict | None:
    """Stdlib JSON POST. Returns the parsed body on 2xx, ``None`` on failure.

    Retries once on transient 5xx so a single flake doesn't tank the
    report build. Never raises.
    """
    body = _json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **headers}
    attempts = 2 if retry_on_5xx else 1
    last_err: Exception | None = None
    for i in range(attempts):
        req = _urlreq.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with _urlreq.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return _json.loads(raw)
                except Exception:
                    return None
        except _urlerr.HTTPError as e:
            last_err = e
            if 500 <= e.code < 600 and i + 1 < attempts:
                _time.sleep(0.5)
                continue
            return None
        except Exception as e:                         # pragma: no cover
            last_err = e
            return None
    if last_err:
        return None
    return None


def _call_openai(prompt: str, *, system: str | None = None,
                 max_tokens: int = 400) -> str | None:
    """Single Chat-Completions call. Returns assistant text or ``None``."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    msgs: list[dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    payload = {
        "model": OPENAI_MODEL,
        "messages": msgs,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    resp = _http_post_json(
        "https://api.openai.com/v1/chat/completions",
        payload,
        {"Authorization": f"Bearer {key}"},
    )
    if not isinstance(resp, dict):
        return None
    try:
        text = resp["choices"][0]["message"]["content"]
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return None
    return None


def _call_anthropic(prompt: str, *, system: str | None = None,
                    max_tokens: int = 400) -> str | None:
    """Single Messages-API call. Returns assistant text or ``None``."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    payload: dict[str, Any] = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system
    resp = _http_post_json(
        "https://api.anthropic.com/v1/messages",
        payload,
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
    )
    if not isinstance(resp, dict):
        return None
    try:
        blocks = resp.get("content") or []
        # Standard shape: [{"type":"text","text":"..."}]
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text":
                t = b.get("text")
                if isinstance(t, str) and t.strip():
                    return t.strip()
    except Exception:
        return None
    return None


def _try_ai(prompt: str, *, system: str | None = None,
            max_tokens: int = 400) -> str | None:
    """Attempt a real LLM call (OpenAI first, Anthropic second).
    Returns ``None`` when no key is configured, on network failure, or
    on an empty response.

    Falls back to the legacy ``safecadence.ai.explain_findings`` shim
    when neither real provider key is set but a local-LLM env var is
    (Ollama, SAFECADENCE_LOCAL_LLM) — keeps prior behavior alive.
    """
    provider = _active_provider()
    if provider == "openai":
        out = _call_openai(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out
        # If OpenAI is configured but failed, fall through to legacy/local LLM
        # rather than silently returning None — keeps the demo "best-effort".
    elif provider == "anthropic":
        out = _call_anthropic(prompt, system=system, max_tokens=max_tokens)
        if out:
            return out

    # Legacy / local LLM path — preserves earlier behavior.
    if not _has_api_key():
        return None
    try:
        from safecadence.ai import explain_findings  # type: ignore
        out = explain_findings({"summary": prompt, "findings": [], "cves": []})
        if isinstance(out, str) and out.strip():
            return out.strip()
    except Exception:
        pass
    return None


def llm_status() -> dict:
    """Return ``{provider, model}`` for the active LLM, or ``{provider: None}``."""
    p = _active_provider()
    if p == "openai":
        return {"provider": "openai", "model": OPENAI_MODEL}
    if p == "anthropic":
        return {"provider": "anthropic", "model": ANTHROPIC_MODEL}
    return {"provider": None, "model": None}


# --------------------------------------------------------------------------
# 1. executive summary
# --------------------------------------------------------------------------


_TONE_OPENERS = {
    "professional": "This SafeCadence NetRisk report",
    "executive":    "Executive summary",
    "technical":    "Technical readout",
    "audit":        "Audit-ready summary",
    "forward-looking": "Quarter-over-quarter posture",
}


def _band_for_score(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "elevated"
    if score >= 40: return "moderate"
    if score >= 20: return "low"
    return "minimal"


def _ciso_part1(kev, crit, high, eol):
    if kev:
        return (f"{kev} CISA KEV-listed CVE{'s' if kev != 1 else ''} on assets in scope "
                "represent the highest residual risk — these are exploited in the wild now, "
                "not theoretically.")
    if crit >= 5:
        return (f"{crit} critical findings concentrate the bulk of residual risk; "
                "remediation is the most material lever available this quarter.")
    if eol >= 3:
        return (f"{eol} devices past vendor end-of-support cannot be patched and "
                "constitute durable, unmitigatable risk.")
    if high >= 10:
        return (f"{high} high-severity findings collectively raise the breach-likelihood "
                "envelope above acceptable thresholds.")
    return "Residual risk is within acceptable bounds — emphasis shifts to detection maturity."


def _engineer_part1(kev, crit, high):
    if kev:
        return (f"KEV catalog: {kev} CVE{'s' if kev != 1 else ''} match active exploitation entries — "
                "treat as P0 patch class, ship this week.")
    if crit:
        return (f"{crit} critical CVEs are ready for patch — cluster by vendor and "
                "deploy in a single change window.")
    if high:
        return (f"{high} high-severity items are next in the queue; group by host class.")
    return "No P0/P1 patch items. Focus shifts to baseline drift detection."


def _auditor_part1(kev, crit, eol):
    bits = []
    if kev:
        bits.append(f"{kev} KEV-listed CVE{'s' if kev != 1 else ''} trigger SI-2, RA-5, "
                    "and PCI 6.3.3 control failures")
    if crit:
        bits.append(f"{crit} critical findings inform CC7.1 and CIS 7.x evidence")
    if eol:
        bits.append(f"{eol} EOL device{'s' if eol != 1 else ''} fail SI-2(2) supportability")
    if bits:
        return "Control implications: " + "; ".join(bits) + "."
    return "No findings of audit consequence in the current scan window."


def generate_executive_summary(report_data: dict, *, tone: str = "professional") -> str:
    """Produce a three-part executive summary from a KPI dict.

    The structure is consistent across tones:
      1. Lead with the most actionable threat.
      2. Quantify the gap.
      3. One concrete this-week recommendation.
    The wording (and ordering of facts) changes per tone so each audience
    feels addressed in their own language.
    """
    kpi = report_data.get("kpi") or report_data
    hosts  = int(kpi.get("hosts") or 0)
    crit   = int(kpi.get("critical") or 0)
    high   = int(kpi.get("high") or 0)
    cves   = int(kpi.get("cves") or 0)
    kev    = int(kpi.get("kev") or 0)
    eol    = int(kpi.get("eol") or 0)
    eos    = int(kpi.get("eos_software") or 0)

    # heuristic risk score from KPIs (0..100)
    score = min(100, crit * 8 + high * 3 + kev * 6 + eol * 4 + eos * 2)
    band = _band_for_score(score)

    if hosts == 0:
        return ("No assets in scope. Add scans or widen the scope filter to surface "
                "fleet posture, CVE exposure, and compliance signals.")

    # ---- Part 1: lead with the most actionable threat (per tone) ----
    if tone == "ciso":
        p1 = _ciso_part1(kev, crit, high, eol)
    elif tone in ("engineer", "technical"):
        p1 = _engineer_part1(kev, crit, high)
    elif tone in ("auditor", "audit"):
        p1 = _auditor_part1(kev, crit, eol)
    elif tone == "forward-looking":
        if kev:
            p1 = (f"Quarter opens with {kev} KEV-listed CVE{'s' if kev != 1 else ''} carried over — "
                  "these set the immediate operating ceiling on risk.")
        else:
            p1 = (f"Quarter opens with no KEV-listed exposure on assets in scope — "
                  "a meaningful improvement over the prior quarter for organizations "
                  "tracking that metric.")
    else:  # executive / professional / default
        if kev:
            p1 = (f"{kev} CISA KEV-listed CVE{'s' if kev != 1 else ''} sit on critical "
                  "assets — these are exploited in the wild this week, not later.")
        elif crit >= 5:
            p1 = (f"{crit} critical CVEs are open across the fleet — they concentrate "
                  "the bulk of breach risk and are the single highest leverage move.")
        elif eol >= 3:
            p1 = (f"{eol} devices are past vendor end-of-support — they cannot be "
                  "patched and should be replaced before next quarter.")
        elif crit:
            p1 = (f"{crit} critical CVE{'s' if crit != 1 else ''} need attention this sprint.")
        else:
            p1 = ("No critical or KEV-listed vulnerabilities — the environment's "
                  "current security posture is solid.")

    # ---- Part 2: quantify the gap (per tone) ----
    if tone == "ciso":
        p2 = (f"Across {hosts} in-scope systems, the environment carries an overall "
              f"risk index of {score}/100 ({band}), composed of {crit} critical and "
              f"{high} high findings.")
    elif tone in ("engineer", "technical"):
        p2 = (f"Scope: {hosts} hosts, {cves} distinct CVE classes. Severity split: "
              f"critical={crit}, high={high}. Lifecycle drift: {eol} HW EOL, "
              f"{eos} SW EOS.")
    elif tone in ("auditor", "audit"):
        p2 = (f"Sample size: {hosts} in-scope assets. Open findings: {crit} critical, "
              f"{high} high. Lifecycle exceptions: {eol} HW past EOS, {eos} SW past EOS. "
              "Evidence per-host and per-control is appended.")
    elif tone == "forward-looking":
        p2 = (f"Across {hosts} assets the active risk index is {score}/100 ({band}); "
              f"{crit} critical and {high} high findings drive the number, with "
              f"{eol} EOL hardware items on a replacement clock.")
    else:  # executive / professional
        p2 = (f"Across {hosts} in-scope systems your environment carries an overall "
              f"risk index of {score}/100 ({band}), driven by {crit} critical and "
              f"{high} high findings.")

    # ---- Part 3: one concrete this-week recommendation (per tone) ----
    rec_bits = []
    if kev:
        rec_bits.append("patch the KEV-listed items")
    elif crit:
        rec_bits.append("close the critical CVE queue")
    if high and not kev:
        rec_bits.append("schedule high-severity patches")
    if eol >= 1:
        rec_bits.append(f"replace {eol} end-of-support device{'s' if eol != 1 else ''} before next quarter")
    if eos >= 1:
        rec_bits.append(f"upgrade {eos} EOS software stack{'s' if eos != 1 else ''}")
    if not rec_bits:
        rec_bits.append("maintain scan cadence and tighten identity hygiene")
    # Common shared move
    if kev or crit:
        rec_bits.append("rotate any admin accounts still on shared credentials")

    rec = ", ".join(rec_bits[:3])

    if tone == "ciso":
        p3 = (f"This week, prioritize: {rec}. The action plan in the report scopes each "
              "to a target date based on its priority class.")
    elif tone in ("engineer", "technical"):
        p3 = (f"Sprint backlog: {rec}. P0/P1 remediation snippets are inline against "
              "each finding in the action plan.")
    elif tone in ("auditor", "audit"):
        p3 = (f"Recommended remediation: {rec}. Each item maps back to one or more "
              "controls; tracking is in the risk register.")
    elif tone == "forward-looking":
        p3 = (f"Recommended this quarter: {rec}, with a posture re-snapshot in 30 days "
              "to confirm trend.")
    else:
        p3 = f"Recommended this week: {rec}."

    deterministic = " ".join((p1, p2, p3))
    # v10.6: pass the structured KPI data + tone hint so the LLM can shape
    # the narrative without inventing numbers. The fallback (deterministic)
    # is sent as a "preserve every number" anchor.
    kpi_blob = _json.dumps({
        "hosts": hosts, "critical": crit, "high": high, "cves": cves,
        "kev": kev, "eol": eol, "eos_software": eos, "risk_index": score,
    })
    ai = _try_ai(
        "Write a 2-3 sentence executive summary for a security report. "
        f"Tone: {tone}. "
        "Use exactly the numbers in this KPI JSON — do not invent new figures: "
        f"{kpi_blob}.\n\n"
        "For reference, here is the deterministic version (you may rephrase "
        "but keep every number identical):\n"
        f"{deterministic}",
        system="You are a senior security consultant. Concise, executive-grade prose.",
        max_tokens=300,
    )
    return ai or deterministic


# --------------------------------------------------------------------------
# 2. CVE plain-language explainer
# --------------------------------------------------------------------------


_SEVERITY_PHRASES = {
    "critical": "an unauthenticated remote attacker can fully compromise this system",
    "high":     "an attacker who reaches this host can escalate privileges or read data they shouldn't",
    "medium":   "an attacker with some foothold can chain this with other issues to widen impact",
    "low":      "this is a hygiene item — fix it during the next maintenance window",
}


def explain_cve_plain_language(cve_id: str, severity: str, host: str | None = None) -> str:
    """Three-sentence plain-English explainer for a CVE (legacy signature)."""
    out = explain_cve(cve_id, severity, host=host)
    return out["explanation"]


def explain_cve(cve_id: str, severity: str, *, kev: bool = False,
                host: str | None = None) -> dict:
    """Return ``{explanation: str, source: 'llm'|'stub'}`` for a CVE.

    With an LLM key set, asks the model for a 2-3 sentence non-technical
    explanation. Without, returns a deterministic templated message that
    plugs the severity into a stock phrase.
    """
    sev = (severity or "").lower()
    phrase = _SEVERITY_PHRASES.get(sev, "this issue requires investigation and a fix")
    where = f" on {host}" if host else ""
    kev_note = (
        " It is on the CISA Known Exploited Vulnerabilities list — exploitation has been "
        "observed in the wild, not theorized."
        if kev else ""
    )
    deterministic = (
        f"{cve_id}{where}: {phrase}.{kev_note} "
        f"Treat this as {sev or 'unrated'} priority. "
        "Apply the vendor patch or the configuration mitigation listed in the action plan; "
        "if patching is blocked, isolate the host on a management VLAN and add detection rules."
    )
    prompt_parts = [
        f"Vulnerability: {cve_id}",
        f"Severity: {sev or 'unknown'}",
    ]
    if kev:
        prompt_parts.append("KEV-listed: yes (actively exploited)")
    if host:
        prompt_parts.append(f"Affected host: {host}")
    prompt = (
        "\n".join(prompt_parts)
        + "\n\nDescribe in 2 sentences for a non-technical reader: what this CVE "
          "means in plain English and what one action a security team should take. "
          "Do not invent CVSS scores or vendor names. Keep it concise."
    )
    ai = _try_ai(prompt, system="You are a senior security analyst writing for executives.", max_tokens=200)
    if ai:
        return {"explanation": ai, "source": "llm"}
    return {"explanation": deterministic, "source": "stub"}


# --------------------------------------------------------------------------
# 3. quick wins
# --------------------------------------------------------------------------


def find_quick_wins(findings: list, max_results: int = 5) -> list[dict]:
    """Pick high-leverage findings = (risk_reduction / effort_minutes) high.

    Returns dicts with: title, host, risk_reduction, effort_minutes, why.
    Falls back to severity-ordered picks if those fields aren't present.
    """
    if not findings:
        return []

    def score(f: dict) -> float:
        rr = float(f.get("risk_reduction") or 0)
        eff = float(f.get("effort_minutes") or 0)
        if eff > 0 and rr > 0:
            return rr / eff
        # heuristic: severity weight / effort guess
        sev_w = {"critical": 40, "high": 20, "medium": 8, "low": 2}.get(
            (f.get("severity") or "").lower(), 1)
        e_guess = 30 if f.get("fix_snippet") else 90
        return sev_w / max(1, e_guess)

    ranked = sorted(findings, key=score, reverse=True)
    out: list[dict] = []
    for f in ranked[:max_results]:  # noqa: PERF401  (loop body is non-trivial)
        title = f.get("title") or f.get("rule_id") or f.get("id") or "Unnamed finding"
        host = f.get("host") or f.get("hostname") or ""
        rr = f.get("risk_reduction") or {"critical": 18, "high": 10, "medium": 4, "low": 1}.get(
            (f.get("severity") or "").lower(), 5)
        eff = f.get("effort_minutes") or (15 if f.get("fix_snippet") else 60)
        why = f.get("rationale") or (
            f"Cuts ~{rr} risk points for ~{eff} minutes of work — "
            f"high leverage."
        )
        out.append({
            "title": title,
            "host": host,
            "risk_reduction": rr,
            "effort_minutes": eff,
            "why": why,
            "severity": f.get("severity") or "high",
        })
    return out


def detect_quick_wins(actions: list[dict], *, top_n: int = 3) -> list[dict]:
    """Pick the top ``top_n`` actions by (risk_reduction / effort_minutes).

    With an LLM key set, sends the action list and asks the model to
    rank by leverage. Falls back to the deterministic heuristic on any
    error / missing key.

    Each input ``action`` should look like::

        {"id": "...", "title": "...", "risk_reduction": <num>,
         "effort_minutes": <num>, "severity": "..."}

    Returns ``[{id, score, source, ...}]`` sorted high → low. ``source``
    is ``'llm'`` or ``'heuristic'`` so the caller can label the badge.
    """
    if not actions:
        return []

    def _heuristic_score(a: dict) -> float:
        rr = float(a.get("risk_reduction") or 0)
        eff = float(a.get("effort_minutes") or 0)
        if rr > 0 and eff > 0:
            return rr / eff
        sev_w = {"critical": 40, "high": 20, "medium": 8, "low": 2}.get(
            (a.get("severity") or "").lower(), 1)
        e_guess = float(a.get("effort_minutes") or 60) or 60
        return sev_w / e_guess

    # --- LLM path -----------------------------------------------------
    if _has_api_key():
        # Build a small, structured payload so the model can rank without
        # hallucinating new actions. We pin to the ids supplied.
        try:
            compact = [
                {
                    "id": str(a.get("id") or a.get("title") or i),
                    "title": str(a.get("title") or ""),
                    "risk_reduction": a.get("risk_reduction"),
                    "effort_minutes": a.get("effort_minutes"),
                    "severity": a.get("severity"),
                }
                for i, a in enumerate(actions)
            ]
            prompt = (
                "Rank the following remediation actions by leverage "
                "(risk reduction per minute of effort). Return ONLY a JSON "
                f"array of the top {top_n} action ids, highest leverage first, "
                "no prose, no markdown. Allowed ids: "
                + ", ".join(a["id"] for a in compact)
                + "\n\nActions:\n" + _json.dumps(compact)
            )
            raw = _try_ai(
                prompt,
                system="You output JSON only. No prose. No code fences.",
                max_tokens=200,
            )
            if raw:
                # Strip fences if the model added them despite instructions.
                s = raw.strip()
                if s.startswith("```"):
                    s = s.strip("`")
                    if s.lower().startswith("json"):
                        s = s[4:]
                    s = s.strip()
                ids = _json.loads(s)
                if isinstance(ids, list) and ids:
                    by_id = {str(a.get("id") or a.get("title") or i): a
                             for i, a in enumerate(actions)}
                    ordered: list[dict] = []
                    seen: set[str] = set()
                    for raw_id in ids:
                        key = str(raw_id)
                        if key in by_id and key not in seen:
                            a = dict(by_id[key])
                            a["score"] = round(_heuristic_score(a), 3)
                            a["source"] = "llm"
                            ordered.append(a)
                            seen.add(key)
                        if len(ordered) >= top_n:
                            break
                    if ordered:
                        return ordered
        except Exception:
            pass  # fall through to heuristic

    # --- heuristic fallback ------------------------------------------
    ranked = sorted(actions, key=_heuristic_score, reverse=True)
    out: list[dict] = []
    for a in ranked[:top_n]:
        b = dict(a)
        b["score"] = round(_heuristic_score(a), 3)
        b["source"] = "heuristic"
        out.append(b)
    return out


# --------------------------------------------------------------------------
# 4. patch sequencing
# --------------------------------------------------------------------------


_TIER_ORDER = [
    ("identity", 0, "Identity providers — patch first; downstream auth depends on these."),
    ("firewall", 1, "Edge / firewall — patch before opening internal change windows."),
    ("network",  2, "Network gear — patch in maintenance windows after edge."),
    ("server",   3, "OS-level patches on servers — schedule rolling restarts."),
    ("cloud",    4, "Cloud control plane — apply after on-prem stabilizes."),
    ("backup",   5, "Backup infrastructure — patch last to keep recovery available."),
    ("app",      6, "Application patches — go last; verify against staging."),
]


def _tier_for(asset_type: str) -> tuple[int, str]:
    a = (asset_type or "").lower()
    for name, tier, note in _TIER_ORDER:
        if name in a:
            return tier, note
    return 9, "Patch alongside its peer tier."


def sequence_patches(findings: list) -> list[dict]:
    """Group findings into ordered patch waves based on asset role."""
    if not findings:
        return []
    waves: dict[int, dict] = {}
    for f in findings:
        atype = f.get("asset_type") or f.get("type") or ""
        tier, note = _tier_for(atype)
        wave = waves.setdefault(tier, {
            "wave": tier + 1, "tier_note": note, "items": [],
        })
        wave["items"].append({
            "title": f.get("title") or f.get("id") or f.get("rule_id") or "Patch",
            "host":  f.get("host") or f.get("hostname") or "",
            "severity": f.get("severity") or "high",
            "asset_type": atype,
        })
    return [waves[k] for k in sorted(waves.keys())]


# --------------------------------------------------------------------------
# 5. stakeholder narrative
# --------------------------------------------------------------------------


_AUDIENCE_TONE = {
    "ceo":          "executive",
    "ciso":         "executive",
    "engineer":     "technical",
    "auditor":      "audit",
    "soc-analyst":  "technical",
    "soc":          "technical",
}


def stakeholder_narrative(report_data: dict, *, audience: str) -> str:
    """Same data, different framing per audience."""
    tone = _AUDIENCE_TONE.get((audience or "").lower(), "professional")
    base = generate_executive_summary(report_data, tone=tone)
    a = (audience or "").lower()
    if a == "ceo":
        return ("For the board: " + base + " Business risk is concentrated in a "
                "small number of fixes; the action plan section lists the dollar-cheap, "
                "fast-to-execute ones first.")
    if a == "ciso":
        return ("Security leadership view: " + base + " Recommend pairing the KEV "
                "remediation list below with this quarter's patch SLO.")
    if a == "engineer":
        return ("Engineering readout: " + base + " Use the action plan's P0/P1 list as "
                "your sprint backlog; remediation snippets are inline per finding.")
    if a == "auditor":
        return ("Audit framing: " + base + " Evidence and control mappings are "
                "appended; sampling notes are in the host inventory section.")
    if a in ("soc-analyst", "soc"):
        return ("SOC analyst brief: " + base + " Detection rules for KEV CVEs are listed "
                "in the action plan; tune correlation accordingly.")
    return base


__all__ = [
    "generate_executive_summary",
    "explain_cve_plain_language",
    "explain_cve",
    "find_quick_wins",
    "detect_quick_wins",
    "sequence_patches",
    "stakeholder_narrative",
    "llm_status",
]
