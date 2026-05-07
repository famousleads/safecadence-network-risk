"""
Bring-Your-Own-Key AI integration.

By design, no API keys are ever sent to safecadence.com or any third party
besides the user's chosen provider. The user controls their own usage,
budget, and privacy.

Supported providers:
  - openai     (env: OPENAI_API_KEY)
  - anthropic  (env: ANTHROPIC_API_KEY)
  - none       (deterministic fallback — no AI)

Usage:
    from safecadence.ai import explain_findings
    txt = explain_findings(scan_result, provider="openai")
"""

from safecadence.ai.client import (
    AIError,
    AIProvider,
    detect_provider,
    explain_findings,
)

__all__ = ["AIError", "AIProvider", "detect_provider", "explain_findings"]
