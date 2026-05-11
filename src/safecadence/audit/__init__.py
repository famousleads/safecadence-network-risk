"""v10.5 audit-log surface for per-org write events.

v11.3 adds the hash-chained variant (``log_event_chained`` / ``verify_chain``)
without touching the unchained API used by the existing callers.
"""

from safecadence.audit.log import (
    log_event,
    read_events,
    log_event_chained,
    verify_chain,
    read_chain,
)

__all__ = [
    "log_event",
    "read_events",
    "log_event_chained",
    "verify_chain",
    "read_chain",
]
