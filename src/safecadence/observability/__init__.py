"""v10.5 observability — Prometheus /metrics, /healthz/detail, error log."""

from safecadence.observability.errors import record_error, recent_errors
from safecadence.observability.metrics import (
    MetricsMiddleware,
    REPORTS_GENERATED,
    REQUESTS_TOTAL,
    REQUEST_DURATION,
    record_report_generated,
    render_metrics_text,
    router,
)

__all__ = [
    "router",
    "MetricsMiddleware",
    "render_metrics_text",
    "record_report_generated",
    "record_error",
    "recent_errors",
    "REQUESTS_TOTAL",
    "REQUEST_DURATION",
    "REPORTS_GENERATED",
]
