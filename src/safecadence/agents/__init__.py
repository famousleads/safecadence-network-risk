"""
v16.0 — Behavioral agents layer.

Five submodules that compose into "AI agents that work for you while
you sleep, that you actually trust":

* ``memory``             — persistent stateful memory + dedup signatures.
* ``nudges``             — operator-facing inbox of proactive suggestions;
                            live updates via the v13 SSE bus.
* ``adversarial``        — red + blue agent pair on the v13 Knowledge
                            Graph; only surfaces disagreements.
* ``drift_explainer``    — closes the v13 drift_daemon loop by
                            attributing + soliciting + filing.
* ``regulatory_watcher`` — proactive RSS/JSON polling of NVD/KEV/NIST.

Each module is independently usable. They share the same SQLite
schema (memory + nudges) so signatures dedup across agents — if the
drift_explainer already nudged about an asset, the regulatory_watcher
won't double-up.

What the agents layer ADDS on top of v14/v15
--------------------------------------------

* v14 ai_governance answered "WHO is acting?" (identity + trust).
* v15.2 cluster config answered "HOW do operators wire it up?"
* v16 agents answers "WHAT do the AI agents actually DO?"

Public re-exports
-----------------

Importing ``safecadence.agents`` is enough for common use::

    from safecadence.agents import (
        # memory
        ensure_memory_schema, record, has_recent, recall,
        # nudges
        ensure_nudge_schema, create_nudge, list_nudges,
        accept_nudge, dismiss_nudge, snooze_nudge,
        # adversarial
        run_round,
        # drift explainer
        explain_drift, handle_response,
        # regulatory
        run_watch_pass,
    )
"""
from __future__ import annotations

from safecadence.agents.adversarial import (
    run_blue,
    run_red,
    run_round,
)
from safecadence.agents.drift_explainer import (
    explain_drift,
    handle_response,
    identify_responsible_engineer,
)
from safecadence.agents.memory import (
    VALID_KINDS as MEMORY_KINDS,
    ensure_memory_schema,
    forget,
    has_recent,
    prune_expired,
    recall,
    record,
)
from safecadence.agents.nudges import (
    VALID_SEVERITIES,
    VALID_STATUSES,
    accept_nudge,
    create_nudge,
    dismiss_nudge,
    ensure_nudge_schema,
    list_nudges,
    nudge_summary,
    promote_due_snoozes,
    snooze_nudge,
)
from safecadence.agents.regulatory_watcher import (
    DEFAULT_FEEDS,
    classify_relevance,
    fetch_feed,
    is_enabled as regulatory_is_enabled,
    run_watch_pass,
)

__version__ = "1.0.0"

__all__ = [
    # memory
    "MEMORY_KINDS", "ensure_memory_schema", "record", "has_recent",
    "recall", "forget", "prune_expired",
    # nudges
    "VALID_STATUSES", "VALID_SEVERITIES",
    "ensure_nudge_schema", "create_nudge", "list_nudges",
    "accept_nudge", "dismiss_nudge", "snooze_nudge",
    "promote_due_snoozes", "nudge_summary",
    # adversarial
    "run_red", "run_blue", "run_round",
    # drift explainer
    "identify_responsible_engineer", "explain_drift", "handle_response",
    # regulatory
    "DEFAULT_FEEDS", "regulatory_is_enabled",
    "fetch_feed", "classify_relevance", "run_watch_pass",
]
