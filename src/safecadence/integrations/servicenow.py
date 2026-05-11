"""
ServiceNow integration (v10.7).

Posts findings as Incidents via the standard Table API.

Auth: basic auth over HTTPS. Env-gated:

    SC_SERVICENOW_INSTANCE   e.g. "acme" — becomes acme.service-now.com
    SC_SERVICENOW_USER       e.g. "safecadence.bot"
    SC_SERVICENOW_PASS       integration user password
    SC_SERVICENOW_TABLE      optional, default "incident"

Public:

    is_configured() -> bool
    create_servicenow_incident(finding) -> {"sys_id", "number", "url"} | None

The finding dict is the canonical SafeCadence finding shape — same one
:func:`safecadence.integrations.jira.create_jira_ticket` accepts.

Missing config returns ``None`` and logs at INFO level — never crashes.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq

_log = logging.getLogger("safecadence.integrations.servicenow")


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def is_configured() -> bool:
    return all(os.environ.get(k) for k in
               ("SC_SERVICENOW_INSTANCE", "SC_SERVICENOW_USER", "SC_SERVICENOW_PASS"))


def _instance_url() -> str:
    inst = os.environ.get("SC_SERVICENOW_INSTANCE", "").strip()
    if inst.startswith("http://") or inst.startswith("https://"):
        return inst.rstrip("/")
    return f"https://{inst}.service-now.com"


def _table() -> str:
    return os.environ.get("SC_SERVICENOW_TABLE", "incident")


def _auth_header() -> str:
    user = os.environ.get("SC_SERVICENOW_USER", "")
    pw = os.environ.get("SC_SERVICENOW_PASS", "")
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {token}"


# --------------------------------------------------------------------------
# Mapping
# --------------------------------------------------------------------------


_IMPACT_FROM_SEVERITY = {
    "critical": "1",   # ServiceNow: 1 = High
    "high":     "2",   # 2 = Medium
    "medium":   "3",   # 3 = Low
    "low":      "3",
    "info":     "3",
}

_URGENCY_FROM_SEVERITY = _IMPACT_FROM_SEVERITY  # same shape


def _payload_from_finding(finding: dict) -> dict:
    sev = (finding.get("severity") or "medium").lower()
    title = finding.get("title") or finding.get("summary") or "SafeCadence finding"
    desc = finding.get("description") or finding.get("detail") or ""
    host = finding.get("hostname") or finding.get("asset") or ""
    cve = finding.get("cve") or finding.get("cve_id") or ""

    return {
        "short_description": f"[SafeCadence] {title}"[:160],
        "description": (
            f"Host: {host}\n"
            f"CVE: {cve}\n"
            f"Severity: {sev}\n\n"
            f"{desc}"
        ).strip(),
        "impact": _IMPACT_FROM_SEVERITY.get(sev, "3"),
        "urgency": _URGENCY_FROM_SEVERITY.get(sev, "3"),
        "category": "Network",
        "u_safecadence_finding_id": finding.get("id") or finding.get("finding_id") or "",
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def create_servicenow_incident(finding: dict, *, timeout: float = 8.0) -> dict | None:
    """Create an incident from a SafeCadence finding.

    Returns ``{"sys_id", "number", "url"}`` on success, ``None`` if the
    integration isn't configured. Raises on HTTP failure so callers can
    decide whether to swallow it (we recommend they do).
    """
    if not is_configured():
        _log.info("servicenow not configured — skipping")
        return None

    payload = _payload_from_finding(finding)
    url = f"{_instance_url()}/api/now/table/{_table()}"
    req = _urlreq.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": _auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "safecadence/10.7",
        },
    )
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read() or b"{}")
    except _urlerr.HTTPError as e:
        _log.warning("servicenow create failed: HTTP %s", e.code)
        raise
    except (_urlerr.URLError, OSError) as e:  # pragma: no cover
        _log.warning("servicenow create network error: %s", e)
        raise

    result = body.get("result", {}) or {}
    sys_id = result.get("sys_id", "")
    number = result.get("number", "")
    return {
        "sys_id": sys_id,
        "number": number,
        "url": f"{_instance_url()}/nav_to.do?uri={_table()}.do?sys_id={sys_id}" if sys_id else "",
    }


__all__ = ["is_configured", "create_servicenow_incident"]
