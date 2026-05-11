"""
SafeCadence ML + intelligence depth (v11.0).

Stdlib-only ML primitives that give the platform useful "smart" behavior
without sklearn/numpy/scipy as runtime dependencies. Models that need
trained artifacts (e.g. supervised risk classifiers) ship in v11.0.x
point releases — this baseline returns sensible heuristic answers on
real data even when no training has happened.

Modules
-------
* :mod:`anomaly`        — sliding z-score + seasonal (weekday) anomaly
* :mod:`predict_risk`   — EWMA + trend-based 30-day risk forecast
* :mod:`cluster_findings` — k-medoids clustering with from-scratch
  silhouette score (no sklearn)
* :mod:`drift_forecast` — config-drift forecaster per asset
* :mod:`nlq`            — natural-language query parser with optional
  LLM fallback when ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY`` is set
* :mod:`playbooks`      — threat-hunting playbooks (KEV response,
  lateral movement, credential compromise)
* :mod:`api`            — FastAPI router exposing the above

All modules degrade gracefully — they never raise on empty data, never
require an LLM key, and never write to disk outside ``~/.safecadence``.
"""

from __future__ import annotations

__all__ = [
    "anomaly",
    "predict_risk",
    "cluster_findings",
    "drift_forecast",
    "nlq",
    "playbooks",
]
