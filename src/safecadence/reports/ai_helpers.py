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
