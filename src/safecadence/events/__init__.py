"""
safecadence.events — inbound event ingestion (DESAT).

The pivot from point-in-time scanning to continuous awareness:
  * canonical Event schema (schema.py)
  * append-only JSONL store with dedup + query (store.py)
  * syslog UDP listener + SNMPv2c trap receiver (listeners.py) —
    OFF by default, enabled with SC_EVENTS_LISTENERS=1
  * authenticated inbound webhook + query API (api.py)

Local-first: listeners bind to configurable local ports, nothing is
ever sent anywhere; the store lives under the NetRisk data dir.
"""

from safecadence.events.schema import Event, normalize_syslog, normalize_trap
from safecadence.events.store import (
    append_event, query_events, event_counts, link_asset_by_ip,
)

__all__ = [
    "Event", "normalize_syslog", "normalize_trap",
    "append_event", "query_events", "event_counts", "link_asset_by_ip",
]
