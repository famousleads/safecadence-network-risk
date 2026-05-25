"""
v14.1 — Per-host (or per-asset, per-account, per-anything) anomaly detection.

Two layered detectors, both pure stdlib, both honest about what they
can and can't see:

* **EWMA (Exponentially-Weighted Moving Average)** — smooths the
  recent observation stream, so brief spikes don't fire every time
  but persistent drift does.

* **Z-score against the EWMA baseline** — measures how far the
  current observation is from the smoothed mean, normalized by the
  rolling standard deviation. If z > threshold (default 3.0), flag.

The detector is *self-referential*: it compares the entity to its
own history, not to the corpus. The corpus is used only to seed the
baseline when there's no history yet (cold-start) — so a brand-new
host doesn't fire an anomaly on its first observation.

Public API
----------

* ``EWMAState(alpha=0.3, seed_mean=None, seed_var=None)``
* ``state.update(value)`` → ``{"mean", "var", "stddev", "n"}``
* ``state.zscore(value)`` → float
* ``detect(observations, *, alpha=0.3, z_threshold=3.0, corpus_seed=None)``
    → ``{"flags": [...], "final_state": {...}}``
* ``batch_detect_per_entity(observations_by_entity, ...)``
    → ``{entity_id: detect_result, ...}``
"""
from __future__ import annotations

import math
from dataclasses import dataclass


# Default sensitivity. 3.0 is a normal "outside 3 sigma" alert
# threshold; lower for noisier signals, higher for quieter ones.
DEFAULT_Z_THRESHOLD: float = 3.0
DEFAULT_ALPHA: float = 0.3
# Refuse to flag until the EWMA has seen at least this many observations.
# Prevents thin-sample false positives during the first few observations
# (when stddev is artificially tiny from one or two data points).
DEFAULT_MIN_N: int = 5


@dataclass
class EWMAState:
    """Single rolling state. One per entity (host, account, etc.)."""

    alpha: float = DEFAULT_ALPHA
    mean: float = 0.0
    var: float = 0.0
    n: int = 0

    def seed(self, seed_mean: float, seed_var: float = 1.0) -> None:
        """Initialize from a corpus baseline (or any prior estimate)."""
        self.mean = float(seed_mean)
        self.var = max(0.0, float(seed_var))
        self.n = 1  # treat the seed as one observation

    def update(self, value: float) -> dict:
        """Incorporate a new observation. Returns the new state."""
        v = float(value)
        if self.n == 0:
            self.mean = v
            self.var = 0.0
        else:
            prev_mean = self.mean
            self.mean = self.alpha * v + (1.0 - self.alpha) * prev_mean
            # Welford-flavored variance update for EWMA.
            self.var = (
                (1.0 - self.alpha) * (self.var + self.alpha * (v - prev_mean) ** 2)
            )
        self.n += 1
        return {
            "mean": self.mean,
            "var": self.var,
            "stddev": math.sqrt(max(0.0, self.var)),
            "n": self.n,
        }

    def zscore(self, value: float) -> float:
        """Return the z-score of `value` against the current EWMA state.

        Returns 0.0 when stddev is too small to meaningfully score —
        which is the right "I don't know yet" answer, not a spurious
        alert.
        """
        sd = math.sqrt(max(0.0, self.var))
        if sd < 1e-9:
            return 0.0
        return (float(value) - self.mean) / sd


def detect(
    observations: list[float],
    *,
    alpha: float = DEFAULT_ALPHA,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    corpus_seed: tuple[float, float] | None = None,
    min_n: int = DEFAULT_MIN_N,
) -> dict:
    """Walk `observations` through an EWMA detector. Flag any z >= threshold.

    Args:
        observations: time-ordered values (oldest → newest).
        alpha: EWMA smoothing factor (0 < alpha <= 1).
        z_threshold: z-score above which we flag.
        corpus_seed: optional (mean, var) seed from the corpus to
                     avoid cold-start false negatives.

    Returns:
        {
          "flags": [
            {"index": int, "value": float, "z": float,
             "mean_at_t": float, "stddev_at_t": float},
            ...
          ],
          "final_state": {"mean", "var", "stddev", "n"},
          "summary": {"observed": int, "flagged": int}
        }
    """
    state = EWMAState(alpha=alpha)
    if corpus_seed is not None:
        state.seed(*corpus_seed)

    flags: list[dict] = []
    for i, v in enumerate(observations):
        # Score against the existing state BEFORE incorporating the new value.
        z = state.zscore(v)
        if state.n >= min_n and abs(z) >= z_threshold:
            flags.append({
                "index": i,
                "value": float(v),
                "z": round(z, 3),
                "mean_at_t": round(state.mean, 3),
                "stddev_at_t": round(math.sqrt(max(0.0, state.var)), 3),
            })
        state.update(v)

    return {
        "flags": flags,
        "final_state": {
            "mean": round(state.mean, 3),
            "var": round(state.var, 6),
            "stddev": round(math.sqrt(max(0.0, state.var)), 3),
            "n": state.n,
        },
        "summary": {
            "observed": len(observations),
            "flagged": len(flags),
        },
    }


def batch_detect_per_entity(
    observations_by_entity: dict[str, list[float]],
    *,
    alpha: float = DEFAULT_ALPHA,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    corpus_seed_by_entity: dict[str, tuple[float, float]] | None = None,
    min_n: int = DEFAULT_MIN_N,
) -> dict[str, dict]:
    """Run `detect` for every entity in a dict. Convenience wrapper."""
    out: dict[str, dict] = {}
    seeds = corpus_seed_by_entity or {}
    for entity_id, obs in observations_by_entity.items():
        out[entity_id] = detect(
            obs, alpha=alpha, z_threshold=z_threshold,
            corpus_seed=seeds.get(entity_id), min_n=min_n,
        )
    return out


__all__ = [
    "DEFAULT_Z_THRESHOLD", "DEFAULT_ALPHA", "DEFAULT_MIN_N",
    "EWMAState",
    "detect", "batch_detect_per_entity",
]
