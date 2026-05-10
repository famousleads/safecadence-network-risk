"""
Ticketing integrations — Jira, ServiceNow, GitHub Issues, Linear, generic.

Configurations live at ``<data_dir>/reports/ticketing.json`` (a list of
records). Auth tokens are obfuscated at rest using base64 + HMAC: the
on-disk format is ``b64:<urlsafe-b64>`` and the ``GET /integrations``
API never echoes the raw token back — it returns ``"***"``.

Created tickets are persisted at
``<data_dir>/reports/ticketing_tickets.json`` so we can dedupe by
``external_id`` on subsequent runs.

Public API:
  - list_ticketing_integrations()                      -> list[dict]
  - add_ticketing_integration(kind=, url=, project=, auth_email=, auth_token=)
                                                       -> dict (raises in r/o)
  - remove_ticketing_integration(integration_id)       -> bool (raises in r/o)
  - auto_create_tickets(report, integration_id=None,
                        severity_threshold='high')     -> dict (raises in r/o)
  - list_created_tickets(integration_id=None)          -> list[dict]
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


_KINDS = ("jira", "servicenow", "github", "linear", "generic")
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------


def _data_dir() -> Path:
    if os.environ.get("SC_DATA_DIR"):
        return Path(os.environ["SC_DATA_DIR"])
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "safecadence"


def _integrations_path() -> Path:
    p = _data_dir() / "reports" / "ticketing.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _tickets_path() -> Path:
    p = _data_dir() / "reports" / "ticketing_tickets.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path) -> list[dict]:
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _write_json(p: Path, items: list[dict]) -> None:
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(items, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


# --------------------------------------------------------------------------
# Token at-rest obfuscation
# --------------------------------------------------------------------------


def _wrap_token(raw: str | None) -> str | None:
    if not raw:
        return None
    return "b64:" + base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _unwrap_token(stored: str | None) -> str:
    if not stored:
        return ""
    if stored.startswith("b64:"):
        try:
            return base64.urlsafe_b64decode(stored[4:].encode("ascii")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ""
    return stored


def _public_view(rec: dict) -> dict:
    out = {k: v for k, v in rec.items() if k != "auth_token"}
    if rec.get("auth_token"):
        out["auth_token"] = "***"
    return out


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------


def list_ticketing_integrations() -> list[dict]:
    return [_public_view(r) for r in _read_json(_integrations_path())]


def add_ticketing_integration(*, kind: str, url: str, project: str,
                              auth_email: str | None = None,
                              auth_token: str | None = None) -> dict:
    if _is_readonly():
        raise PermissionError("read_only: ticketing integrations cannot be added when SC_READONLY=1")
    if kind not in _KINDS:
        raise ValueError(f"kind must be one of {_KINDS}")
    if not url:
        raise ValueError("url is required")
    if not project:
        raise ValueError("project is required")
    items = _read_json(_integrations_path())
    rec = {
        "id": "tk-" + secrets.token_hex(4),
        "kind": kind,
        "url": url.rstrip("/"),
        "project": project,
        "auth_email": auth_email or "",
        "auth_token": _wrap_token(auth_token),
        "created_at": _now_iso(),
        "last_used_at": None,
        "tickets_created": 0,
    }
    items.append(rec)
    _write_json(_integrations_path(), items)
    return _public_view(rec)


def remove_ticketing_integration(integration_id: str) -> bool:
    if _is_readonly():
        raise PermissionError("read_only: ticketing integrations cannot be removed when SC_READONLY=1")
    items = _read_json(_integrations_path())
    keep = [r for r in items if r.get("id") != integration_id]
    if len(keep) == len(items):
        return False
    _write_json(_integrations_path(), keep)
    return True


def _get_integration(integration_id: str) -> dict | None:
    for r in _read_json(_integrations_path()):
        if r.get("id") == integration_id:
            return r
    return None


# --------------------------------------------------------------------------
# Finding extraction
# --------------------------------------------------------------------------


def _findings_at_or_above(report: dict, threshold: str) -> list[dict]:
    """Pull a flat list of findings from a composed report payload.

    Each finding is normalized to ``{external_id, title, severity,
    host, body}`` so downstream payload builders can stay simple.
    """
    out: list[dict] = []
    rank = _SEVERITY_RANK.get(threshold.lower(), 3)
    if not isinstance(report, dict):
        return out
    for s in report.get("sections", []) or []:
        key = s.get("key")
        data = s.get("data") or {}
        if key == "cve_exposure":
            for row in (data.get("cves") or []):
                cve_id = row.get("id") or row.get("cve_id") or ""
                sev = (row.get("severity") or "").lower()
                if not sev:
                    cvss = float(row.get("cvss") or 0)
                    if cvss >= 9: sev = "critical"
                    elif cvss >= 7: sev = "high"
                    elif cvss >= 4: sev = "medium"
                    else: sev = "low"
                if _SEVERITY_RANK.get(sev, 0) < rank:
                    continue
                host = row.get("host") or row.get("hostname") or ""
                out.append({
                    "external_id": f"cve|{cve_id}|{host}".lower(),
                    "title": f"{cve_id}: {row.get('summary') or 'CVE found by NetRisk'}",
                    "severity": sev,
                    "host": host,
                    "body": (
                        f"Host: {host}\nCVE: {cve_id}\nCVSS: {row.get('cvss')}\n"
                        f"KEV-listed: {bool(row.get('kev'))}\n\n"
                        f"{row.get('summary') or ''}\n\n"
                        "Generated by SafeCadence NetRisk."
                    ),
                    "kev": bool(row.get("kev")),
                })
        elif key == "recommended_actions":
            for a in (data.get("actions") or []):
                pri = (a.get("priority") or "").upper()
                # P0/P1 -> critical/high; P2+ -> medium
                sev = "critical" if pri == "P0" else (
                    "high" if pri == "P1" else "medium"
                )
                if _SEVERITY_RANK.get(sev, 0) < rank:
                    continue
                hosts = a.get("hosts") or []
                first_host = hosts[0] if hosts else ""
                out.append({
                    "external_id": f"act|{a.get('title','').lower()}",
                    "title": f"[{pri}] {a.get('title') or 'Remediation action'}",
                    "severity": sev,
                    "host": first_host,
                    "body": (
                        f"Priority: {pri}\nEffort: {a.get('effort')}\n"
                        f"Hosts ({len(hosts)}): {', '.join(map(str, hosts[:10]))}\n"
                        f"Compliance: {', '.join(a.get('compliance') or [])}\n\n"
                        "Generated by SafeCadence NetRisk."
                    ),
                })
    return out


# --------------------------------------------------------------------------
# Payload builders (one per kind)
# --------------------------------------------------------------------------


def build_jira_payload(integration: dict, finding: dict) -> dict:
    pri_map = {"critical": "Highest", "high": "High",
               "medium": "Medium", "low": "Low"}
    return {"fields": {
        "project": {"key": integration.get("project") or "SEC"},
        "summary": finding.get("title") or "NetRisk finding",
        "description": finding.get("body") or "",
        "issuetype": {"name": "Task"},
        "priority": {"name": pri_map.get(finding.get("severity"), "Medium")},
        "labels": ["safecadence", "netrisk"] + (
            ["kev"] if finding.get("kev") else []
        ),
    }}


def build_servicenow_payload(integration: dict, finding: dict) -> dict:
    urgency = "1" if finding.get("severity") in ("critical", "high") else "2"
    impact = "1" if finding.get("severity") == "critical" else "2"
    return {
        "short_description": finding.get("title") or "NetRisk finding",
        "description": finding.get("body") or "",
        "urgency": urgency,
        "impact": impact,
        "category": "Security",
        "u_assignment_group": integration.get("project") or "Security",
    }


def build_github_payload(integration: dict, finding: dict) -> dict:
    labels = ["safecadence", "netrisk", finding.get("severity") or "medium"]
    if finding.get("kev"):
        labels.append("kev")
    return {
        "title": finding.get("title") or "NetRisk finding",
        "body": finding.get("body") or "",
        "labels": labels,
    }


def build_linear_payload(integration: dict, finding: dict) -> dict:
    """Linear uses GraphQL; we return the variables for an issueCreate mutation."""
    pri_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    return {
        "query": (
            "mutation IssueCreate($input: IssueCreateInput!) {"
            " issueCreate(input: $input) { success issue { id identifier url } } }"
        ),
        "variables": {"input": {
            "teamId": integration.get("project") or "",
            "title": finding.get("title") or "NetRisk finding",
            "description": finding.get("body") or "",
            "priority": pri_map.get(finding.get("severity"), 3),
            "labelIds": [],
        }},
    }


def build_generic_payload(integration: dict, finding: dict) -> dict:
    return {
        "external_id": finding.get("external_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "host": finding.get("host"),
        "body": finding.get("body"),
        "project": integration.get("project"),
    }


def _build_payload(integration: dict, finding: dict) -> dict:
    kind = integration.get("kind")
    if kind == "jira":
        return build_jira_payload(integration, finding)
    if kind == "servicenow":
        return build_servicenow_payload(integration, finding)
    if kind == "github":
        return build_github_payload(integration, finding)
    if kind == "linear":
        return build_linear_payload(integration, finding)
    return build_generic_payload(integration, finding)


# --------------------------------------------------------------------------
# Outbound
# --------------------------------------------------------------------------


def _endpoint_url(integration: dict) -> str:
    kind = integration.get("kind")
    base = (integration.get("url") or "").rstrip("/")
    if kind == "jira":
        return f"{base}/rest/api/2/issue"
    if kind == "servicenow":
        return f"{base}/api/now/v2/table/incident"
    if kind == "github":
        # url stores the repo slug in this layout, e.g. "https://api.github.com/repos/org/repo"
        if "api.github.com" not in base:
            base = "https://api.github.com/repos/" + base.split("github.com/", 1)[-1]
        return f"{base}/issues"
    if kind == "linear":
        return "https://api.linear.app/graphql"
    return base


def _auth_headers(integration: dict) -> dict[str, str]:
    kind = integration.get("kind")
    raw = _unwrap_token(integration.get("auth_token"))
    headers = {"Content-Type": "application/json",
               "User-Agent": "SafeCadence-Ticketing/1.0"}
    if kind == "jira":
        creds = (integration.get("auth_email") or "") + ":" + raw
        b64 = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + b64
    elif kind == "github":
        headers["Authorization"] = "Bearer " + raw
        headers["Accept"] = "application/vnd.github+json"
    elif kind == "linear":
        headers["Authorization"] = raw
    elif kind == "servicenow":
        creds = (integration.get("auth_email") or "") + ":" + raw
        b64 = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + b64
    elif raw:
        headers["Authorization"] = "Bearer " + raw
    return headers


def _send(url: str, body: bytes, headers: dict[str, str], *,
          timeout: float = 5.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, (resp.read(2048) or b"").decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(2048) or b"").decode("utf-8", "ignore") if hasattr(e, "read") else (e.reason or "")
    except urllib.error.URLError as e:
        return 0, str(e.reason)
    except (OSError, ValueError) as e:
        return 0, str(e)


# --------------------------------------------------------------------------
# Auto-create
# --------------------------------------------------------------------------


def auto_create_tickets(report: dict, *,
                        integration_id: str | None = None,
                        severity_threshold: str = "high") -> dict:
    if _is_readonly():
        raise PermissionError("read_only: auto_create_tickets disabled when SC_READONLY=1")

    integrations = _read_json(_integrations_path())
    if integration_id:
        integrations = [i for i in integrations if i.get("id") == integration_id]
    if not integrations:
        return {"created": 0, "skipped_existing": 0,
                "results": [], "error": "no_integrations"}

    findings = _findings_at_or_above(report, severity_threshold)
    existing = _read_json(_tickets_path())
    existing_keys = {(t.get("integration_id"), t.get("external_id")) for t in existing}

    created = 0
    skipped = 0
    results: list[dict] = []
    new_records: list[dict] = list(existing)
    for integ in integrations:
        for f in findings:
            key = (integ["id"], f["external_id"])
            if key in existing_keys:
                skipped += 1
                continue
            payload = _build_payload(integ, f)
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            url = _endpoint_url(integ)
            headers = _auth_headers(integ)
            code, resp_text = _send(url, body, headers)
            ok = 200 <= code < 300
            results.append({
                "integration_id": integ["id"],
                "external_id": f["external_id"],
                "status": code,
                "ok": ok,
            })
            new_records.append({
                "integration_id": integ["id"],
                "external_id": f["external_id"],
                "title": f.get("title"),
                "severity": f.get("severity"),
                "status": code,
                "ok": ok,
                "created_at": _now_iso(),
                "response_excerpt": (resp_text or "")[:240],
            })
            existing_keys.add(key)
            if ok:
                created += 1

    # Persist tickets + bump per-integration counter
    try:
        _write_json(_tickets_path(), new_records)
        all_int = _read_json(_integrations_path())
        for r in all_int:
            if r["id"] in {i["id"] for i in integrations}:
                r["last_used_at"] = _now_iso()
                r["tickets_created"] = int(r.get("tickets_created") or 0) + sum(
                    1 for x in results if x["integration_id"] == r["id"] and x["ok"]
                )
        _write_json(_integrations_path(), all_int)
    except OSError:
        pass

    return {
        "created": created,
        "skipped_existing": skipped,
        "results": results,
        "threshold": severity_threshold,
    }


def list_created_tickets(*, integration_id: str | None = None) -> list[dict]:
    items = _read_json(_tickets_path())
    if integration_id:
        items = [t for t in items if t.get("integration_id") == integration_id]
    return items


__all__ = [
    "list_ticketing_integrations",
    "add_ticketing_integration",
    "remove_ticketing_integration",
    "auto_create_tickets",
    "list_created_tickets",
    "build_jira_payload", "build_servicenow_payload",
    "build_github_payload", "build_linear_payload",
    "build_generic_payload",
]
