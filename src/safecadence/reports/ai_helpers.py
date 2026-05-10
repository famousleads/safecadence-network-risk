"""
AI helpers for the report module.

The strategy is:

  1. Try the existing ``safecadence.ai`` provider when an API key is
     present. If it returns a non-empty string, use it.
  2. Otherwise, fall back to deterministic templated prose that uses the
     actual data values, so an offline build still produces realistic
     consultant-grade copy (not a placeholder).

All helpers are pure functions returning ``str`` (or ``list[dict]``)
and never raise — failure modes degrade to a minimal but useful string.
"""

from __future__ import annotations

import os
from typing import Any, Iterable


# --------------------------------------------------------------------------
# provider plumbing
# --------------------------------------------------------------------------


def _has_api_key() -> bool:
    return bool(
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OLLAMA_HOST")
        or os.environ.get("SAFECADENCE_LOCAL_LLM")
    )


def _try_ai(prompt: str) -> str | None:
    """Attempt to run the prompt through ``safecadence.ai``. Returns ``None``
    on any failure (no key, network, import error, empty response).
    """
    if not _has_api_key():
        return None
    try:
        # Best-effort: re-use the per-scan ``explain_findings`` helper by
        # passing a synthetic scan-shaped dict. The wrapper expects a dict
        # with at least a 'findings' or 'cves' field — we cooperate by
        # passing the prompt as 'summary' and signalling intent.
        from safecadence.ai import explain_findings  # type: ignore
        out = explain_findings({"summary": prompt, "findings": [], "cves": []})
        if isinstance(out, str) and out.strip():
            return out.strip()
    except Exception:
        pass
    return None


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


def generate_executive_summary(report_data: dict, *, tone: str = "professional") -> str:
    """Produce a multi-sentence executive summary from a kpi dict."""
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

    top_host = (report_data.get("top_host") or {}).get("hostname") or ""
    top_score = (report_data.get("top_host") or {}).get("score")
    fw_weak = (report_data.get("weakest_framework") or "")

    opener = _TONE_OPENERS.get(tone, _TONE_OPENERS["professional"])

    if hosts == 0:
        return ("No assets in scope. Add scans or widen the scope filter to surface "
                "fleet posture, CVE exposure, and compliance signals.")

    parts: list[str] = []
    if tone == "executive":
        parts.append(
            f"{opener}: across {hosts} assets your environment carries an "
            f"overall risk posture of {band} ({score}/100)."
        )
        parts.append(
            f"The most material exposures are {crit} critical and {high} high "
            f"findings, with {kev} KEV-listed vulnerabilities — KEV items represent "
            "exploits known to be used in active attacks."
        )
        if eol or eos:
            parts.append(
                f"You have {eol} end-of-support hardware unit{'s' if eol != 1 else ''} "
                f"and {eos} software stack{'s' if eos != 1 else ''} past vendor "
                "end-of-life; these systems do not receive security patches."
            )
        parts.append(
            "Recommended focus this week: patch KEV CVEs first, then rotate any "
            "admin accounts without MFA, then schedule replacements for end-of-support "
            "gear before next quarter."
        )
    elif tone == "technical":
        parts.append(
            f"{opener}: {hosts} hosts in scope; {cves} distinct CVEs of which {kev} "
            "appear in the CISA KEV catalog (treat as P0 patch class)."
        )
        parts.append(
            f"Severity distribution: critical={crit}, high={high}. Lifecycle: "
            f"{eol} HW past EOS, {eos} SW past EOS."
        )
        if top_host and top_score:
            parts.append(
                f"Highest single-host risk is {top_host} (risk {top_score}). Investigate "
                "remediation snippets in the action plan section."
            )
        if fw_weak:
            parts.append(
                f"Weakest control framework is {fw_weak} — failing controls are itemized "
                "in the compliance posture section with remediation notes."
            )
    elif tone == "audit":
        parts.append(
            f"{opener}. {hosts} in-scope assets evaluated against NIST 800-53, "
            "CIS v8, PCI DSS, HIPAA, and SOC 2 control families."
        )
        parts.append(
            f"Findings: {crit} critical, {high} high. KEV exposure: {kev}. "
            f"End-of-support hardware: {eol}. End-of-software systems: {eos}."
        )
        parts.append(
            "Evidence is captured per-host in the host inventory section and per-control "
            "in the compliance posture section. No automated remediation has been "
            "performed during this report cycle."
        )
    elif tone == "forward-looking":
        parts.append(
            f"{opener}: posture trend over the last quarter shows {hosts} assets "
            f"under management. Active risk index is {score}/100 ({band})."
        )
        parts.append(
            f"Active issues: {crit} critical / {high} high CVE classes with {kev} "
            "KEV-listed exposures. Patch-cycle KPIs and end-of-life replacements "
            "are tracked in the recommended actions section."
        )
        parts.append(
            "Forward look: prioritize KEV remediation in the next sprint, and "
            "schedule the EOL replacements before the close of the next quarter."
        )
    else:  # professional
        parts.append(
            f"{opener} reviewed {hosts} assets and surfaced {crit} critical and "
            f"{high} high findings, totaling {cves} CVE classes with {kev} on the "
            f"CISA KEV catalog."
        )
        if top_host:
            parts.append(
                f"The single largest exposure is on {top_host} (risk score {top_score or 'high'}); "
                "patching its KEV-listed vulnerabilities will materially reduce overall risk."
            )
        if eol or eos:
            parts.append(
                f"Lifecycle drift adds {eol} end-of-support hardware unit"
                f"{'s' if eol != 1 else ''} and {eos} end-of-software stack"
                f"{'s' if eos != 1 else ''} to the picture; these no longer receive "
                "vendor patches and represent durable risk until replaced."
            )
        parts.append(
            "Top action this week: remediate KEV-listed CVEs, then close MFA gaps on "
            "privileged accounts, then plan EOL replacements for next cycle."
        )

    deterministic = " ".join(parts)
    ai = _try_ai(
        "Rewrite the following executive summary in a polished consultant tone, "
        "preserving every number exactly:\n\n" + deterministic
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
    """Three-sentence plain-English explainer for a CVE."""
    sev = (severity or "").lower()
    phrase = _SEVERITY_PHRASES.get(sev, "this issue requires investigation and a fix")
    where = f" on {host}" if host else ""
    deterministic = (
        f"{cve_id}{where}: {phrase}. "
        f"Treat this as {sev or 'unrated'} priority. "
        "Apply the vendor patch or the configuration mitigation listed in the action plan; "
        "if patching is blocked, isolate the host on a management VLAN and add detection rules."
    )
    ai = _try_ai(
        f"Explain {cve_id} (severity {sev or 'unknown'}) in plain language for a "
        "non-technical executive, in 2-3 sentences. Keep it concrete."
    )
    return ai or deterministic


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
    for f in ranked[:max_results]:
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
    "find_quick_wins",
    "sequence_patches",
    "stakeholder_narrative",
]
