"""
v14.1 — ReferenceCorpus: data-source abstraction for the intelligence layer.

Every intelligence module reads from this single interface, never
directly from raw stores. That makes one swap-point if/when richer
data sources appear later.

Two sources today
-----------------

1. **Local** — the customer's own scan / finding / drift history out
   of ``sqlite_store``. Always preferred when ≥ ``MIN_LOCAL_DAYS``
   days of history exist for the requested metric.

2. **Baseline** — published industry distributions per vertical
   (healthcare / finance / msp-smb / retail / defense / generic).
   Sourced from public reports (NVD, CISA KEV, Verizon DBIR, IBM
   Cost of a Data Breach, Mandiant M-Trends, Microsoft Digital
   Defense, CyberArk, Qualys TruRisk). Citations live alongside the
   data in ``baselines/<vertical>.json``.

Blending rule
-------------

When local data is partial (between ``MIN_LOCAL_DAYS`` and
``LOCAL_PRIMARY_DAYS``), the corpus returns a blended series weighted
toward local data linearly with age:

    weight_local = clamp((days_local - MIN_LOCAL_DAYS)
                         / (LOCAL_PRIMARY_DAYS - MIN_LOCAL_DAYS), 0, 1)

Every result includes ``data_source_breakdown`` so downstream callers
(and the customer / auditor) can see exactly what fed the answer.

Public API
----------

* ``ReferenceCorpus(vertical="generic", local_store=None)``
* ``corpus.get_series(metric)``         → {"values", "data_source_breakdown", ...}
* ``corpus.get_distribution(metric)``   → {"p25","p50","p75","p90","p99","source_breakdown"}
* ``corpus.list_verticals()``           → ["healthcare", "finance", ...]
* ``corpus.list_metrics()``             → known metric ids
* ``corpus.cite(metric)``               → citation string for `metric` in the vertical

Constants
---------

* ``MIN_LOCAL_DAYS``       = 7   (below this, 100% baseline)
* ``LOCAL_PRIMARY_DAYS``   = 90  (at/above this, 100% local)
* ``KNOWN_VERTICALS``      = ("healthcare", "finance", "msp-smb",
                              "retail", "defense", "generic")
* ``KNOWN_METRICS``        = a fixed set; new metrics require a baseline
                              entry across every vertical to ship.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


# Tunables — env-overridable so operators can change the local/baseline
# crossover for their own circumstances.
MIN_LOCAL_DAYS:     int = int(os.getenv("SC_CORPUS_MIN_LOCAL_DAYS",     "7"))
LOCAL_PRIMARY_DAYS: int = int(os.getenv("SC_CORPUS_LOCAL_PRIMARY_DAYS", "90"))

KNOWN_VERTICALS: tuple[str, ...] = (
    "healthcare", "finance", "msp-smb", "retail", "defense", "generic",
)

KNOWN_METRICS: tuple[str, ...] = (
    "safe_score",
    "open_critical",
    "open_high",
    "drift_events_per_week",
    "mean_time_to_remediate_days",
    "mfa_coverage_pct",
    "stale_account_pct",
    "patch_lag_days",
    "nhi_growth_rate_pct",
)


def _baselines_dir() -> Path:
    return Path(__file__).resolve().parent / "baselines"


def _load_baseline(vertical: str) -> dict:
    p = _baselines_dir() / f"{vertical}.json"
    if not p.exists():
        # Fall back to generic; never raise — corpus is library code,
        # callers shouldn't crash because a baseline file is missing.
        p = _baselines_dir() / "generic.json"
        if not p.exists():
            return {"vertical": "generic", "metrics": {}, "citations": {}}
    try:
        return json.loads(p.read_text("utf-8"))
    except Exception:
        return {"vertical": vertical, "metrics": {}, "citations": {}}


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _local_weight(days_local: int) -> float:
    """Linear ramp from MIN_LOCAL_DAYS → LOCAL_PRIMARY_DAYS."""
    if days_local <= MIN_LOCAL_DAYS:
        return 0.0
    if days_local >= LOCAL_PRIMARY_DAYS:
        return 1.0
    return _clamp(
        (days_local - MIN_LOCAL_DAYS) /
        max(1, LOCAL_PRIMARY_DAYS - MIN_LOCAL_DAYS),
        0.0, 1.0,
    )


class ReferenceCorpus:
    """Per-vertical data abstraction. One instance per (customer, vertical)."""

    def __init__(
        self,
        vertical: str = "generic",
        *,
        local_store: Any = None,
    ) -> None:
        v = (vertical or "generic").lower()
        if v not in KNOWN_VERTICALS:
            v = "generic"
        self.vertical = v
        self.local_store = local_store
        self._baseline = _load_baseline(v)

    # ---------- introspection -------------------------------------- #

    def list_verticals(self) -> list[str]:
        return list(KNOWN_VERTICALS)

    def list_metrics(self) -> list[str]:
        return list(KNOWN_METRICS)

    def cite(self, metric: str) -> str:
        citations = self._baseline.get("citations") or {}
        return citations.get(metric, "Public industry distribution; see baselines/*.json")

    # ---------- distributions -------------------------------------- #

    def get_distribution(self, metric: str) -> dict:
        """Return the baseline distribution for the metric.

        Shape:
            {
              "metric": "...",
              "p25": .., "p50": .., "p75": .., "p90": .., "p99": ..,
              "unit": "...",
              "source_breakdown": {"baseline_pct": 100, "local_pct": 0},
              "citation": "..."
            }

        Distribution is always baseline-only — distributions are
        cross-population shapes, while local data is a single
        time-series. Use ``get_series`` for the latter.
        """
        m = (self._baseline.get("metrics") or {}).get(metric) or {}
        return {
            "metric": metric,
            "p25": m.get("p25"),
            "p50": m.get("p50"),
            "p75": m.get("p75"),
            "p90": m.get("p90"),
            "p99": m.get("p99"),
            "unit": m.get("unit", ""),
            "source_breakdown": {"baseline_pct": 100, "local_pct": 0},
            "citation": self.cite(metric),
        }

    # ---------- time series ---------------------------------------- #

    def get_series(self, metric: str) -> dict:
        """Return a numeric time series for the metric, blending local
        and baseline data per the rules at the top of this module.

        Shape:
            {
              "metric": "...",
              "values": [{"day": -29, "v": ...}, ..., {"day": 0, "v": ...}],
              "data_source_breakdown": {
                 "local_pct": 0–100,
                 "baseline_pct": 0–100,
                 "days_local": int,
                 "vertical": "..."
              },
              "citation": "..."
            }
        """
        local_series = self._pull_local_series(metric)
        days_local = len(local_series)
        w_local = _local_weight(days_local)
        w_base = 1.0 - w_local

        baseline_series = self._synthesize_baseline_series(metric, n_days=30)

        # Always normalize both to the same window (30 days back to today).
        merged: list[dict] = []
        for i in range(30):
            day_idx = i - 29
            local_v = local_series[i] if i < days_local else None
            base_v = baseline_series[i]
            if local_v is None:
                v = base_v
            elif w_local == 0.0:
                v = base_v
            elif w_local == 1.0:
                v = local_v
            else:
                v = w_local * local_v + w_base * base_v
            merged.append({"day": day_idx, "v": round(float(v), 3)})

        return {
            "metric": metric,
            "values": merged,
            "data_source_breakdown": {
                "local_pct": round(w_local * 100, 1),
                "baseline_pct": round(w_base * 100, 1),
                "days_local": days_local,
                "vertical": self.vertical,
            },
            "citation": self.cite(metric),
        }

    # ---------- internal helpers ----------------------------------- #

    def _pull_local_series(self, metric: str) -> list[float]:
        """Try to read the customer's own last-30-day series for the
        metric. Returns [] when nothing is available — corpus then
        falls back fully to baseline.

        Defensive: never raises. A missing/empty store degrades to "".
        """
        store = self.local_store
        if store is None:
            return []
        # Convention: local_store implements get_metric_series(metric, days)
        # returning a list of floats. v11.x stores don't have this yet —
        # they'll grow it as the intelligence layer ships.
        fn = getattr(store, "get_metric_series", None)
        if fn is None:
            return []
        try:
            data = fn(metric, days=30)
            if not data:
                return []
            return [float(x) for x in data]
        except Exception:
            return []

    def _synthesize_baseline_series(self, metric: str, n_days: int = 30) -> list[float]:
        """Produce a steady-state baseline series at the metric's p50.

        This is deliberately non-synthetic-noisy: the baseline is a flat
        line at the published median for the vertical. The "intelligence"
        comes from how the customer's local data drifts away from that
        line — not from fake noise around it.
        """
        m = (self._baseline.get("metrics") or {}).get(metric) or {}
        p50 = m.get("p50")
        if p50 is None:
            return [0.0] * n_days
        return [float(p50)] * n_days


__all__ = [
    "MIN_LOCAL_DAYS", "LOCAL_PRIMARY_DAYS",
    "KNOWN_VERTICALS", "KNOWN_METRICS",
    "ReferenceCorpus",
]
