"""
v14 — AI & Machine Identity Governance.

First-class registry, inventory, and trust scoring for AI agents,
API keys, and other machine identities. Connects to v11.x identity
adapters (Okta/Entra/ISE/AD/ClearPass), the v12 MCP server (which
records every tool call with org+user+agent attribution), and the
v13 Security Knowledge Graph (machine identities become first-class
graph nodes via the ``nhi`` node type).

Submodules
----------

* ``agents``        — register / list / deprecate AI agents; record
                      invocations for cross-tool attribution.
* ``api_keys``      — API key inventory with age + rotation + last-seen
                      tracking. Never stores secret material — only the
                      last-four handle.
* ``trust_score``   — 0–100 trust score per key + per agent, with the
                      per-factor breakdown so an operator sees *why*.

Public re-exports
-----------------

::

    from safecadence.ai_governance import (
        register_agent, list_agents, register_api_key, list_api_keys,
        score_api_key, score_agent,
    )

ML-driven anomaly detection (a real anomaly detector trained on
customer-aggregated operational data) is intentionally v14 *next*
work, not v14 *first* work — the agent + key + scoring registry
above ship first because they're useful immediately and create the
data substrate the ML work will train on.
"""
from __future__ import annotations

from safecadence.ai_governance.agents import (
    VALID_STATUS,
    ensure_agent_schema,
    get_agent,
    list_agents,
    record_invocation,
    register_agent,
    set_agent_status,
)
from safecadence.ai_governance.api_keys import (
    age_days,
    deprecate,
    ensure_api_key_schema,
    list_api_keys,
    record_seen,
    register_api_key,
    rotate,
)
from safecadence.ai_governance.trust_score import (
    DEFAULTS,
    score_agent,
    score_all_keys,
    score_api_key,
)

__version__ = "0.1.0-alpha"

__all__ = [
    # agents
    "VALID_STATUS", "ensure_agent_schema", "register_agent",
    "list_agents", "get_agent", "set_agent_status", "record_invocation",
    # api_keys
    "ensure_api_key_schema", "register_api_key", "list_api_keys",
    "record_seen", "rotate", "deprecate", "age_days",
    # trust_score
    "DEFAULTS", "score_api_key", "score_agent", "score_all_keys",
]
