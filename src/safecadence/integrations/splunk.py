"""
Splunk HTTP Event Collector (HEC) forwarder (v10.7).

Env-gated:

    SC_SPLUNK_HEC_URL     e.g. https://splunk.acme.com:8088/services/collector
    SC_SPLUNK_HEC_TOKEN   HEC token
    SC_SPLUNK_INDEX       optional, default "main"
    SC_SPLUNK_SOURCETYPE  optional, default "safecadence:finding"

Public:

    is_configured() -> bool
    forward_finding(finding) -> dict | None
    forward_event(event_dict, *, sourcetype=None) -> dict | None
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq

_log = logging.getLogger("safecadence.integrations.splunk")


def is_configured() -> bool:
    return bool(os.environ.get("SC_SPLUNK_HEC_URL") and os.environ.get("SC_SPLUNK_HEC_TOKEN"))


def _index() -> str:
    return os.environ.get("SC_SPLUNK_INDEX", "main")


def _default_sourcetype() -> str:
    return os.environ.get("SC_SPLUNK_SOURCETYPE", "safecadence:finding")


def forward_event(event: dict, *, sourcetype: str | None = None,
                  host: str | None = None, timeout: float = 6.0) -> dict | None:
    """Send a single event to Splunk HEC. Returns the JSON reply, or None."""
    if not is_configured():
        _log.info("splunk not configured — skipping")
        return None
    payload = {
        "time": time.time(),
        "host": host or os.environ.get("SC_NODE_NAME") or "safecadence",
        "source": "safecadence",
        "sourcetype": sourcetype or _default_sourcetype(),
        "index": _index(),
        "event": event,
    }
    url = os.environ["SC_SPLUNK_HEC_URL"]
    token = os.environ["SC_SPLUNK_HEC_TOKEN"]
    req = _urlreq.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "User-Agent": "safecadence/10.7",
        },
    )
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            try:
                return json.loads(resp.read() or b"{}")
            except ValueError:
                return {"status": getattr(resp, "status", 200)}
    except _urlerr.HTTPError as e:
        _log.warning("splunk HEC returned HTTP %s", e.code)
        return {"status": e.code, "error": True}
    except (_urlerr.URLError, OSError) as e:  # pragma: no cover
        _log.warning("splunk HEC network error: %s", e)
        raise


def forward_finding(finding: dict) -> dict | None:
    """Send a finding as a SafeCadence-shaped event."""
    if not is_configured():
        return None
    event = {
        "id": finding.get("id") or finding.get("finding_id"),
        "severity": (finding.get("severity") or "medium").lower(),
        "title": finding.get("title") or finding.get("summary"),
        "hostname": finding.get("hostname") or finding.get("asset"),
        "site": finding.get("site"),
        "cve": finding.get("cve") or finding.get("cve_id"),
        "description": finding.get("description") or finding.get("detail"),
        "score": finding.get("score"),
        "tags": finding.get("tags") or [],
    }
    return forward_event(event, sourcetype="safecadence:finding")


__all__ = ["is_configured", "forward_event", "forward_finding"]
