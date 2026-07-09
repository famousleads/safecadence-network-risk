"""
Bring-Your-Own-Key AI integration.

By design, no API keys are ever sent to safecadence.com or any third party
besides the user's chosen provider. The user controls their own usage,
budget, and privacy.

Supported providers:
  - openai     (env: OPENAI_API_KEY)
  - anthropic  (env: ANTHROPIC_API_KEY; model via SAFECADENCE_CLAUDE_MODEL,
                fallback via SAFECADENCE_CLAUDE_FALLBACK)
  - ollama     (env: OLLAMA_HOST / SAFECADENCE_LOCAL_LLM — air-gapped friendly)
  - none       (deterministic fallback — no AI)

If the model declines to answer (AIRefusal), we retry once on the fallback
model and then drop to the deterministic engine. You always get a briefing.

Usage:
    from safecadence.ai import explain_findings
    txt = explain_findings(scan_result, provider="openai")
    txt = explain_findings(scan_result, provider="anthropic", effort="high")
"""

from safecadence.ai.client import (
    EFFORT_LEVELS,
    AIError,
    AIProvider,
    AIRefusal,
    detect_provider,
    explain_findings,
)

__all__ = [
    "AIError",
    "AIProvider",
    "AIRefusal",
    "EFFORT_LEVELS",
    "detect_provider",
    "explain_findings",
]
