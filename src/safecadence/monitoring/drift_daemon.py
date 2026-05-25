"""
v13.0 — Drift monitoring daemon.

Polls the platform state on a schedule, computes a delta against the
last-known-good baseline snapshot, and decides whether to fire alerts
+ tickets based on severity thresholds + maintenance windows.

How it differs from the v10.x scheduler
---------------------------------------

The v10.x report scheduler fires REPORTS on a cron. This daemon fires
ALERTS on a finer cadence (default 5 minutes) and only when something
*changed* — so a quiet fleet gets zero noise.

The compute_delta() function is pure + testable; the DriftDaemon
class is the thin orchestration layer that calls it on a loop.

Severity threshold
------------------

By default, only `critical` and `high` deltas fire webhooks. The
``severity_threshold`` config tightens or loosens this.

Maintenance windows
-------------------

A drift event that lands during a configured maintenance window is
logged but does not fire alerts. Windows are expressed as a list of
``{start, end}`` ISO timestamps (or recurring weekday+hour ranges).

Public API
----------

* ``DriftMonitorConfig(...)`` — dataclass with all tunables.
* ``DriftDaemon(config)``     — start()/stop()/tick() lifecycle.
* ``compute_delta(prev, current)`` → list of delta dicts.
* ``is_in_maintenance_window(now, windows)`` → bool.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, time as _time, timezone
from typing import Any

_log = logging.getLogger("safecadence.monitoring.drift_daemon")


DEFAULT_INTERVAL_S: int = 300   # 5 minutes


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


@dataclass
class DriftMonitorConfig:
    interval_seconds: int = DEFAULT_INTERVAL_S
    severity_threshold: str = "high"   # critical | high | medium | low
    maintenance_windows: list[dict] = field(default_factory=list)
    # Optional callback fired on each delta event. If None, the daemon
    # uses the v11.x notifier registry.
    on_drift: Any = None


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def compute_delta(
    prev_assets: list[dict],
    current_assets: list[dict],
) -> list[dict]:
    """Compute what changed between two asset snapshots.

    Returns a list of delta dicts:
      {
        "kind": "finding_added" | "finding_removed" | "asset_added"
                | "asset_removed" | "asset_severity_changed",
        "hostname": "...",
        "finding_id": "..." | None,
        "severity": "...",
        "detail": "..."
      }

    Pure function: no I/O, no side effects, fully testable.
    """
    prev_by_host = {a.get("hostname", ""): a for a in (prev_assets or [])}
    curr_by_host = {a.get("hostname", ""): a for a in (current_assets or [])}
    deltas: list[dict] = []

    # Asset added / removed
    for h in curr_by_host.keys() - prev_by_host.keys():
        deltas.append({
            "kind": "asset_added",
            "hostname": h,
            "finding_id": None,
            "severity": "info",
            "detail": f"{h} is new to the inventory",
        })
    for h in prev_by_host.keys() - curr_by_host.keys():
        deltas.append({
            "kind": "asset_removed",
            "hostname": h,
            "finding_id": None,
            "severity": "info",
            "detail": f"{h} dropped from the inventory",
        })

    # Per-host finding delta
    for h in prev_by_host.keys() & curr_by_host.keys():
        prev_ids = {f.get("id"): f for f in (prev_by_host[h].get("findings") or [])}
        curr_ids = {f.get("id"): f for f in (curr_by_host[h].get("findings") or [])}
        for fid in curr_ids.keys() - prev_ids.keys():
            f = curr_ids[fid]
            deltas.append({
                "kind": "finding_added",
                "hostname": h,
                "finding_id": fid,
                "severity": (f.get("severity") or "info").lower(),
                "detail": f.get("title") or "new finding",
            })
        for fid in prev_ids.keys() - curr_ids.keys():
            f = prev_ids[fid]
            deltas.append({
                "kind": "finding_removed",
                "hostname": h,
                "finding_id": fid,
                "severity": (f.get("severity") or "info").lower(),
                "detail": f.get("title") or "remediated",
            })
        # Severity changed (same finding id, different severity)
        for fid in prev_ids.keys() & curr_ids.keys():
            ps = (prev_ids[fid].get("severity") or "info").lower()
            cs = (curr_ids[fid].get("severity") or "info").lower()
            if ps != cs:
                deltas.append({
                    "kind": "asset_severity_changed",
                    "hostname": h,
                    "finding_id": fid,
                    "severity": cs,
                    "detail": f"severity {ps} → {cs}",
                })
    return deltas


def is_in_maintenance_window(
    now: datetime,
    windows: list[dict],
) -> bool:
    """True when ``now`` falls inside any configured window.

    Two window shapes supported:
      {"start": "2026-05-26T02:00Z", "end": "2026-05-26T05:00Z"}    one-shot
      {"weekday": "sun", "start_hour": 2, "end_hour": 5}             recurring
    """
    for w in windows or []:
        # One-shot
        if w.get("start") and w.get("end"):
            try:
                s = datetime.fromisoformat(
                    w["start"].replace("Z", "+00:00")
                ).replace(tzinfo=timezone.utc)
                e = datetime.fromisoformat(
                    w["end"].replace("Z", "+00:00")
                ).replace(tzinfo=timezone.utc)
                if s <= now <= e:
                    return True
            except Exception:
                continue
        # Recurring
        if "weekday" in w and "start_hour" in w and "end_hour" in w:
            wd_target = (w["weekday"] or "").lower()[:3]
            wd_now = now.strftime("%a").lower()
            if wd_now != wd_target:
                continue
            sh = int(w["start_hour"])
            eh = int(w["end_hour"])
            hour = now.hour
            if sh <= hour < eh:
                return True
    return False


def _passes_threshold(severity: str, threshold: str) -> bool:
    sv = _SEVERITY_RANK.get((severity or "").lower(), 0)
    tv = _SEVERITY_RANK.get((threshold or "").lower(), 0)
    return sv >= tv


# --------------------------------------------------------------------------
# Daemon
# --------------------------------------------------------------------------


class DriftDaemon:
    """Polling drift monitor. Honors @active_only via is_standby().

    Typical use::

        daemon = DriftDaemon(DriftMonitorConfig(interval_seconds=120))
        daemon.start()
        # ... main app runs ...
        daemon.stop()
    """

    def __init__(self, config: DriftMonitorConfig | None = None) -> None:
        self.config = config or DriftMonitorConfig()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_snapshot: list[dict] = []
        self._last_tick_at: float = 0.0
        self._tick_count: int = 0
        self._fired_count: int = 0

    # ---------- lifecycle ----------------------------------------- #

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="safecadence-drift-daemon",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._thread = None

    def status(self) -> dict:
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "interval_seconds": self.config.interval_seconds,
            "tick_count": self._tick_count,
            "fired_count": self._fired_count,
            "last_tick_at": self._last_tick_at,
        }

    # ---------- main loop ----------------------------------------- #

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                _log.exception("drift daemon tick failed: %s", exc)
            self._stop.wait(self.config.interval_seconds)

    def tick(self) -> dict:
        """One iteration. Returns a summary dict for tests + status."""
        self._tick_count += 1
        self._last_tick_at = time.time()

        # Active-only guard — standby never fires alerts.
        try:
            from safecadence.cluster.guards import is_standby
            if is_standby():
                return {"skipped": "standby", "deltas": 0}
        except Exception:
            pass

        # Load current snapshot.
        current = self._load_current_snapshot()

        # First tick: just store the baseline.
        if not self._last_snapshot:
            self._last_snapshot = current
            return {"baselined": True, "asset_count": len(current),
                    "deltas": 0}

        deltas = compute_delta(self._last_snapshot, current)
        self._last_snapshot = current

        if not deltas:
            return {"deltas": 0}

        now = datetime.now(timezone.utc)
        in_window = is_in_maintenance_window(
            now, self.config.maintenance_windows,
        )

        fired = 0
        for d in deltas:
            if not _passes_threshold(d["severity"], self.config.severity_threshold):
                continue
            if in_window:
                _log.info("drift suppressed (in maintenance window): %s", d)
                continue
            self._fire(d)
            fired += 1

        self._fired_count += fired
        return {
            "deltas": len(deltas),
            "fired": fired,
            "suppressed_for_window": in_window,
        }

    # ---------- hooks --------------------------------------------- #

    def _load_current_snapshot(self) -> list[dict]:
        """Defensive: any data-source error returns an empty list."""
        # Prefer the same platform_assets store every other v11.x
        # consumer reads from, so drift sees what reports see.
        try:
            from safecadence.reports.sections import _load_platform_assets
            return _load_platform_assets() or []
        except Exception:
            pass
        try:
            from safecadence.storage import sqlite_store
            return list(sqlite_store.list_assets() or [])
        except Exception:
            return []

    def _fire(self, delta: dict) -> None:
        """Hand a delta to the notifier. The on_drift callback overrides
        the default notifier path; useful for tests."""
        if self.config.on_drift is not None:
            try:
                self.config.on_drift(delta)
            except Exception:
                _log.exception("on_drift callback raised")
            return
        # Default: emit via the v11.x notifier registry.
        try:
            from safecadence.notifier.registry import deliver_event
            deliver_event({
                "kind": "drift",
                "title": f"Drift on {delta.get('hostname', '?')}",
                "summary": delta.get("detail", ""),
                "severity": delta.get("severity", "info"),
                "data": delta,
            })
        except Exception:
            _log.exception("notifier delivery raised")


__all__ = [
    "DEFAULT_INTERVAL_S",
    "DriftMonitorConfig",
    "DriftDaemon",
    "compute_delta",
    "is_in_maintenance_window",
]
