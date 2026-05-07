"""
v9.24 — unified scoring module.

Each score is a pure function over the data we already collect and
returns a 0..100 integer (higher = better) plus a list of contributing
reasons. No I/O happens inside the score functions themselves; callers
pass in `assets`, `findings`, etc. so tests + the daemon + the API
stay deterministic.

Modules:
  - safe.py — Safe Score: how exposed is this asset/fleet right now?

Coming in v9.25+:
  - health.py — operational fitness (uptime, EOL, license, drift)
  - trust.py — zero-trust posture (boot, EDR, MFA, attestations)
"""

from safecadence.scores.safe import (
    score_asset_safe,
    score_fleet_safe,
    weak_link,
    SafeScore,
)
from safecadence.scores.history import (
    append_snapshot,
    fleet_history,
    asset_history,
    trend,
)

__all__ = [
    "score_asset_safe",
    "score_fleet_safe",
    "weak_link",
    "SafeScore",
    "append_snapshot",
    "fleet_history",
    "asset_history",
    "trend",
]
