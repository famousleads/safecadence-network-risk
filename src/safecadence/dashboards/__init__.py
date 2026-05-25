"""
v13.0 — Live dashboard infrastructure.

One submodule today:

* ``sse`` — Server-Sent Events endpoint + JS poller, used by the
            operator UI to update KPIs without a full page refresh.

SSE was chosen over WebSocket because: stdlib-friendly (no extra
dep), works through most corporate proxies that block raw WS,
and our use case is one-way (server → browser) which is exactly
what SSE was designed for.
"""
from __future__ import annotations

from safecadence.dashboards.sse import (
    EventBus,
    get_event_bus,
    publish,
    register_routes,
)

__version__ = "0.1.0"

__all__ = ["EventBus", "get_event_bus", "publish", "register_routes"]
