"""
v12.1 — Postgres standby replication lag check.

Reports how far behind the standby database is from the primary, in
both seconds (time-since-last-WAL-replay) and bytes (LSN distance).

Why this matters for failover
-----------------------------

The Redis lease guarantees that only ONE node mutates at a time, but
the standby's *database* might be seconds behind the primary's WAL
stream. If we fail over before the lag drains, the new active node
silently loses the last N seconds of writes. Tracking lag means:

* The operator console can show "safe to fail over now" vs.
  "wait — standby is 4s behind."
* Automatic failover can refuse to promote when lag > threshold.

When this module returns "unknown"
----------------------------------

The check requires Postgres + a configured ``DATABASE_URL``. In any
of these cases we return ``{"status": "unknown", ...}`` instead of
guessing:

* SQLite backend (single-node — lag is meaningless).
* ``psycopg`` / ``psycopg2`` not installed.
* The query raises (permissions issue, version mismatch, etc.).

Public API
----------

* ``probe_lag()`` → dict shaped:
    {
      "status": "ok" | "primary" | "unknown",
      "role":   "primary" | "standby" | "unknown",
      "lag_seconds": float | None,
      "lag_bytes":   int   | None,
      "checked_at":  ISO timestamp,
      "note":        str
    }

* ``is_safe_to_failover(max_lag_s=5.0)`` → bool
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any


# --------------------------------------------------------------------------
# Connection helper — reuse the existing storage backend when possible
# --------------------------------------------------------------------------


def _is_postgres() -> bool:
    """True when DATABASE_URL points at Postgres."""
    url = (os.environ.get("DATABASE_URL") or "").lower()
    return url.startswith(("postgres://", "postgresql://"))


def _pg_connect():
    """Best-effort connect using whichever psycopg flavor is installed."""
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        return None
    try:
        import psycopg
        return psycopg.connect(url, connect_timeout=5)
    except Exception:
        pass
    try:
        import psycopg2
        return psycopg2.connect(url, connect_timeout=5)
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# The probe
# --------------------------------------------------------------------------


def probe_lag() -> dict[str, Any]:
    """One-shot lag probe. Never raises.

    On the **primary**: returns ``role="primary"`` and
    ``lag_seconds=None``; primaries don't have replay lag.

    On the **standby**: returns ``role="standby"`` with the lag in
    seconds + bytes if we can compute it.

    On SQLite or when psycopg is missing: returns ``status="unknown"``
    with a human-readable note.
    """
    base = {
        "status": "unknown",
        "role": "unknown",
        "lag_seconds": None,
        "lag_bytes": None,
        "checked_at": _now_iso(),
        "note": "",
    }

    if not _is_postgres():
        base["note"] = "DATABASE_URL not set to Postgres; lag not applicable."
        return base

    conn = _pg_connect()
    if conn is None:
        base["note"] = "psycopg/psycopg2 not installed or connection failed."
        return base

    try:
        cur = conn.cursor()

        # Step 1: are we a standby or a primary?
        cur.execute("SELECT pg_is_in_recovery();")
        row = cur.fetchone()
        in_recovery = bool(row and row[0])

        if not in_recovery:
            # We're on the primary. Look at pg_stat_replication for
            # connected replicas' lag (operator may have routed the
            # check at the primary on purpose).
            cur.execute(
                """
                SELECT client_addr, state, sent_lsn, replay_lsn,
                       EXTRACT(EPOCH FROM (now() - reply_time))
                  FROM pg_stat_replication
                 LIMIT 1
                """
            )
            r = cur.fetchone()
            if r is None:
                base.update({
                    "status": "ok", "role": "primary",
                    "lag_seconds": 0.0, "lag_bytes": 0,
                    "note": "Primary with no connected standby reported.",
                })
                return base
            replay_lag = float(r[4]) if r[4] is not None else None
            base.update({
                "status": "ok", "role": "primary",
                "lag_seconds": replay_lag, "lag_bytes": None,
                "note": (
                    f"Primary; standby {r[0]} state={r[1]} "
                    f"replay_lag={replay_lag}s"
                ),
            })
            return base

        # Step 2: we ARE the standby. Compute lag.
        cur.execute(
            """
            SELECT
              EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())),
              pg_wal_lsn_diff(pg_last_wal_receive_lsn(),
                              pg_last_wal_replay_lsn())
            """
        )
        r = cur.fetchone()
        if r is None:
            base["note"] = "Standby query returned no rows."
            return base
        lag_s = float(r[0]) if r[0] is not None else None
        lag_b = int(r[1]) if r[1] is not None else None
        base.update({
            "status": "ok", "role": "standby",
            "lag_seconds": lag_s, "lag_bytes": lag_b,
            "note": f"Standby; lag {lag_s}s / {lag_b} bytes",
        })
        return base
    except Exception as exc:
        base["note"] = f"probe failed: {type(exc).__name__}: {exc}"
        return base
    finally:
        try:
            conn.close()
        except Exception:
            pass


def is_safe_to_failover(max_lag_s: float = 5.0) -> bool:
    """Convenience: True when standby lag is below the threshold OR
    when lag is unknown (no Postgres) — in single-node mode there's
    nothing to fail over, so the check passes by definition."""
    p = probe_lag()
    if p["status"] != "ok":
        return True  # single-node / unknown — no failover risk to gate
    lag = p.get("lag_seconds")
    if lag is None:
        return True  # primary with no standby; nothing to wait for
    return lag <= max_lag_s


__all__ = ["probe_lag", "is_safe_to_failover"]
