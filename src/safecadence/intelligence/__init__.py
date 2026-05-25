"""
v14.1 — Intelligence layer.

Honest "AI" features that work on the customer's own data + published
industry baselines, with full source attribution. Local-first stays
intact: no customer data leaves the customer's network.

Modules
-------

* ``corpus``         — ReferenceCorpus: blends customer's local history
                       with published per-vertical industry baselines
                       (NVD, KEV, DBIR, IBM, Mandiant, Microsoft,
                       CyberArk, Qualys; citations in baselines/*.json).
* ``forecasting``    — OLS-based predictive risk forecasting with
                       honest confidence intervals + a
                       ``data_source_breakdown`` field showing exactly
                       how much local vs. baseline data fed the answer.
* ``anomaly``        — EWMA + z-score against the entity's own
                       history; corpus-seeded cold-start.
* ``assistant``      — Natural-language assistant that routes to the
                       v12 MCP tools, executes them, and summarizes
                       via the BYO-AI client (with deterministic
                       fallback when no LLM key is configured).
* ``remediation_pr`` — Generates vendor-specific config diffs +
                       pre-attached rollback. Refuses to hallucinate
                       when no recipe exists and no LLM is configured.

What this layer is NOT
----------------------

* It is **not** a trained ML model. We don't have a global training
  corpus and we never will — local-first means customer data stays
  with the customer.
* It does **not** claim any "model accuracy %" or "trained on N
  billion findings" numbers. The forecasts are OLS slopes on the
  customer's own history; the baselines are public per-vertical
  industry distributions.
* It does **not** ship a trained anomaly model. Anomaly detection is
  per-entity EWMA — the host learns from itself, never from any
  other customer's data.

Honest "AI"
-----------

What we ship today is a real, useful intelligence layer that produces
modest, defensible results today and gets better as the customer's
local history accumulates. Every output carries the data-source
breakdown so the customer and any auditor can see exactly what fed
the answer — never a single hidden model.
"""
from __future__ import annotations

from safecadence.intelligence.anomaly import (
    DEFAULT_ALPHA,
    DEFAULT_MIN_N,
    DEFAULT_Z_THRESHOLD,
    EWMAState,
    batch_detect_per_entity,
    detect,
)
from safecadence.intelligence.assistant import ask, plan
from safecadence.intelligence.corpus import (
    KNOWN_METRICS,
    KNOWN_VERTICALS,
    LOCAL_PRIMARY_DAYS,
    MIN_LOCAL_DAYS,
    ReferenceCorpus,
)
from safecadence.intelligence.forecasting import forecast_many, forecast_metric
from safecadence.intelligence.remediation_pr import draft_remediation_pr
# v14.0 — full release additions
from safecadence.intelligence.multi_turn import Conversation, Turn
from safecadence.intelligence.dismissal_learning import (
    VALID_DECISIONS as DISMISSAL_DECISIONS,
    annotate_findings,
    ensure_dismissal_schema,
    find_matching_dismissals,
    list_dismissals,
    record_dismissal,
)
from safecadence.intelligence.remediation_executor import (
    preview_remediation,
    queue_remediation,
)

__version__ = "1.0.0"

__all__ = [
    # corpus
    "MIN_LOCAL_DAYS", "LOCAL_PRIMARY_DAYS",
    "KNOWN_VERTICALS", "KNOWN_METRICS", "ReferenceCorpus",
    # forecasting
    "forecast_metric", "forecast_many",
    # anomaly
    "DEFAULT_ALPHA", "DEFAULT_Z_THRESHOLD", "DEFAULT_MIN_N",
    "EWMAState", "detect", "batch_detect_per_entity",
    # assistant
    "ask", "plan",
    # remediation
    "draft_remediation_pr",
    # v14.0 multi-turn
    "Conversation", "Turn",
    # v14.0 dismissal learning
    "DISMISSAL_DECISIONS", "ensure_dismissal_schema", "record_dismissal",
    "find_matching_dismissals", "annotate_findings", "list_dismissals",
    # v14.0 remediation executor
    "preview_remediation", "queue_remediation",
]
