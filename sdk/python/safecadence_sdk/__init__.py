"""SafeCadence NetRisk Python SDK.

A thin wrapper around the public REST API at ``/api/v1/*`` that makes the
common operations (inventory listing, report composition, findings, compliance
status, template management) ergonomic from Python.

Example
-------

    from safecadence_sdk import Client

    sc = Client("https://demo.safecadence.com", api_key="scapi_xxx")
    for host in sc.list_inventory():
        print(host["hostname"], host["risk_score"])

    report = sc.compose_report(preset="exec_brief", format="pdf")
    open("brief.pdf", "wb").write(report)
"""

from __future__ import annotations

from .client import Client
from .exceptions import (
    AuthError,
    NotFound,
    RateLimitError,
    SafeCadenceError,
)

__version__ = "0.1.0"

__all__ = [
    "Client",
    "SafeCadenceError",
    "AuthError",
    "RateLimitError",
    "NotFound",
    "__version__",
]
