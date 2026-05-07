"""Prompt templates for the BYOK AI summarizer."""

from __future__ import annotations

from safecadence.core.schema import ScanResult


SYSTEM_PROMPT = (
    "You are a senior network security architect writing for a busy IT director. "
    "Be specific, prioritize ruthlessly, and do not invent vulnerabilities that "
    "are not in the provided findings. Use plain language and short paragraphs. "
    "Always end with a numbered 30/60/90 day remediation roadmap."
)


def build_user_prompt(result: ScanResult, *, max_findings: int = 25) -> str:
    p = result.parsed
    findings_lines: list[str] = []
    for i, f in enumerate(result.findings[:max_findings], start=1):
        findings_lines.append(
            f"{i}. [{f.severity.value.upper()}] {f.title} "
            f"(rule {f.rule_id}, domain {f.domain})"
        )
        if f.description:
            findings_lines.append(f"   Why it matters: {f.description.strip()[:400]}")
        if f.remediation:
            findings_lines.append(f"   Suggested fix: {f.remediation.strip()[:400]}")
    findings_block = "\n".join(findings_lines) if findings_lines else "No findings."

    return (
        "Device under review:\n"
        f"  hostname: {p.hostname or 'unknown'}\n"
        f"  vendor:   {result.vendor}\n"
        f"  os:       {p.os or 'unknown'} {p.version or ''}\n"
        f"  model:    {p.model or 'unknown'}\n"
        f"  health:   {result.health_score}/100 ({result.health_band})\n"
        f"  risk:     {result.risk_score}/100 ({result.risk_band})\n"
        f"  summary:  {result.summary}\n\n"
        f"Findings (top {min(max_findings, len(result.findings))}):\n"
        f"{findings_block}\n\n"
        "Write an executive briefing with these sections:\n"
        "1. **What's at stake** (2-3 sentences in business terms)\n"
        "2. **Top 3 risks to fix this week**\n"
        "3. **30-day plan**\n"
        "4. **60-day plan**\n"
        "5. **90-day plan**\n"
        "Where appropriate, name compensating controls a network team can apply "
        "without device downtime."
    )
