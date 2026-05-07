"""v9.47 — Activity tracking.

Append-only JSONL log of every authenticated mutation that lands on
the FastAPI app. Used by /audit to answer "who did what, when?"
without spelunking through systemd logs.

The store lives under ``$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl``.
One file per day so retention can be enforced by simple ``find …
-mtime +90 -delete``. Each line is a JSON record with at least:

    {
      "ts": "2026-05-07T13:42:11Z",
      "actor": "alice",
      "tenant": "default",
      "method": "POST",
      "path": "/api/users",
      "status": 200,
      "ip": "127.0.0.1",
      "duration_ms": 23,
      "request_id": "req_…"
    }

Reads (GET) are NOT logged by default — too noisy. The middleware
opts them in via ``SC_ACTIVITY_LOG_READS=1`` for forensic mode.

Stickiness lever — once an org has 30+ days of activity history,
turning SafeCadence off means losing the only audit trail their
auditor will accept.
"""

from .store import append, read_day, read_range, prune, ActivityRecord
from .middleware import ActivityMiddleware

__all__ = [
    "append",
    "read_day",
    "read_range",
    "prune",
    "ActivityRecord",
    "ActivityMiddleware",
]
