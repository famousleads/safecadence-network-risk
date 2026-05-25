"""
v13.0 — Continuous monitoring.

Replaces the "run a scan when you remember to" model with a daemon
that watches the fleet, computes deltas against the last known-good
baseline, and fires webhooks / tickets when posture moves.

Submodules
----------

* ``drift_daemon`` — scheduled-polling drift monitor with delta
                     computation, severity thresholds, maintenance-
                     window suppression, and webhook fire.

Future submodules (not yet built):
* ``filesystem_watch`` — inotify/FSEvents for declared config dirs
* ``api_poll``         — vendor-API polling for state changes
* ``git_watch``        — IaC repo change detection

These will land as separate releases when customer demand arrives.
The drift_daemon module already covers the highest-value case.
"""
from __future__ import annotations

from safecadence.monitoring.drift_daemon import (
    DEFAULT_INTERVAL_S,
    DriftDaemon,
    DriftMonitorConfig,
    compute_delta,
    is_in_maintenance_window,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_INTERVAL_S",
    "DriftDaemon",
    "DriftMonitorConfig",
    "compute_delta",
    "is_in_maintenance_window",
]
