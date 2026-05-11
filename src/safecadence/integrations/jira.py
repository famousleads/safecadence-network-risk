"""
Atlassian Jira 3LO OAuth + issue create + bidirectional sync stub (v10.6).

Endpoints (wired by ``build_router``):

  GET /oauth/jira/install   → 302 to Atlassian consent
  GET /oauth/jira/callback  → trades the code, looks up the cloud-id, persists
                              the install to ~/.safecadence/orgs/<org>/jira_install.json

Programmatic helpers:

  is_configured()
  install_url(state="...")
  exchange_code(code) -> dict | None
  fetch_cloud_id(access_token) -> str | None
  create_jira_ticket(finding, *, org_id=None, project_key=None) -> {"issue_key","url"} | None
  poll_status_updates(org_id, *, project_key=None) -> list[dict]  (sync stub)

Env-gated on ``JIRA_CLIENT_ID``. Missing config returns "not_configured"
rather than crashing — keeps the demo healthy.
"""

from __future__ import annotations

import json as _json
import os
import time as _time
from typing import Any
from urllib import error as _urlerr
from urllib import parse as _urlparse
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def _install_path(org_id: str):
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "jira_install.json"


def save_install(org_id: str, payload: dict) -> dict:
    if not org_id:
        raise ValueError("org_id is required")
    path = _install_path(org_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    return payload


def load_install(org_id: str) -> dict | None:
    if not org_id:
        return None
    path = _install_path(org_id)
    if not path.exists():
        return None
    try:
        d = _json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def is_configured() -> bool:
    return bool(os.environ.get("JIRA_CLIENT_ID") and os.environ.get("JIRA_CLIENT_SECRET"))


def install_url(*, state: str = "") -> str:
    """Atlassian 3LO consent URL. ``""`` if not configured."""
    cid = os.environ.get("JIRA_CLIENT_ID")
    if not cid:
        return ""
    redirect_uri = os.environ.get(
        "JIRA_REDIRECT_URI", "https://app.safecadence.com/oauth/jira/callback")
    scope = os.environ.get(
        "JIRA_SCOPES",
        "read:jira-work write:jira-work read:jira-user offline_access",
    )
    params = {
        "audience": "api.atlassian.com",
        "client_id": cid,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "state": state or "noop",
        "response_type": "code",
        "prompt": "consent",
    }
    return "https://auth.atlassian.com/authorize?" + _urlparse.urlencode(params)


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


def _http_request(url: str, *, method: str = "GET",
                  data: dict | None = None,
                  headers: dict | None = None,
                  timeout: float = 15.0) -> dict | None:
    """Generic JSON HTTP helper. Returns parsed body or ``None``."""
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body: bytes | None = None
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")
        body = _json.dumps(data).encode("utf-8")
    req = _urlreq.Request(url, data=body, headers=hdrs, method=method)
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw:
                return {}
            try:
                return _json.loads(raw)
            except Exception:
                return None
    except (_urlerr.HTTPError, _urlerr.URLError, OSError):
        return None
    except Exception:                                  # pragma: no cover
        return None


# --------------------------------------------------------------------------
# OAuth code → access token → cloud id
# --------------------------------------------------------------------------


def exchange_code(code: str) -> dict | None:
    if not code or not is_configured():
        return None
    return _http_request(
        "https://auth.atlassian.com/oauth/token",
        method="POST",
        data={
            "grant_type": "authorization_code",
            "client_id": os.environ["JIRA_CLIENT_ID"],
            "client_secret": os.environ["JIRA_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": os.environ.get(
                "JIRA_REDIRECT_URI",
                "https://app.safecadence.com/oauth/jira/callback"),
        },
    )


def fetch_cloud_id(access_token: str) -> str | None:
    """Look up the first accessible Jira cloud id for this token."""
    if not access_token:
        return None
    resp = _http_request(
        "https://api.atlassian.com/oauth/token/accessible-resources",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if isinstance(resp, list) and resp:
        first = resp[0]
        if isinstance(first, dict):
            cid = first.get("id")
            if isinstance(cid, str):
                return cid
    return None


# --------------------------------------------------------------------------
# Issue creation
# --------------------------------------------------------------------------


_SEV_TO_PRIORITY = {
    "critical": "Highest",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Lowest",
}


def _adf(text: str) -> dict:
    """Wrap ``text`` in a minimal Atlassian Document Format (ADF) doc.
    Required because Jira Cloud REST API v3 expects ADF on description."""
    return {
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{"type": "text", "text": text}],
        }],
    }


def _build_issue_payload(finding: dict, *, project_key: str) -> dict:
    sev = (finding.get("severity") or "").lower()
    title = finding.get("title") or finding.get("id") or "SafeCadence finding"
    body_lines = [
        f"Host: {finding.get('host') or finding.get('hostname') or '-'}",
        f"Severity: {sev or '-'}",
    ]
    if finding.get("cve"):
        body_lines.append(f"CVE: {finding['cve']}")
    if finding.get("description"):
        body_lines.append("")
        body_lines.append(str(finding["description"]))
    if finding.get("fix_snippet"):
        body_lines.append("")
        body_lines.append("Remediation:")
        body_lines.append(str(finding["fix_snippet"]))
    body = "\n".join(body_lines)
    fields = {
        "project": {"key": project_key},
        "summary": title[:240],
        "description": _adf(body),
        "issuetype": {"name": "Task"},
    }
    if sev in _SEV_TO_PRIORITY:
        fields["priority"] = {"name": _SEV_TO_PRIORITY[sev]}
    if finding.get("labels"):
        fields["labels"] = list(finding["labels"])
    return {"fields": fields}


def create_jira_ticket(finding: dict, *, org_id: str | None = None,
                       project_key: str | None = None) -> dict | None:
    """POST /rest/api/3/issue. Returns ``{issue_key, url}`` or ``None``.

    The install record (token + cloud_id + base_url) is loaded from
    ``org_id``'s install file; pass ``org_id=None`` and ensure
    ``JIRA_ACCESS_TOKEN`` + ``JIRA_CLOUD_ID`` env vars are set if you
    want a tokenless path (mostly for tests).
    """
    project = (project_key or os.environ.get("JIRA_PROJECT_KEY") or "SAFE").strip()
    token: str | None = None
    cloud_id: str | None = None
    base_url: str | None = None
    if org_id:
        inst = load_install(org_id)
        if not inst:
            return None
        token = inst.get("access_token")
        cloud_id = inst.get("cloud_id")
        base_url = inst.get("base_url")
    if not token:
        token = os.environ.get("JIRA_ACCESS_TOKEN")
    if not cloud_id:
        cloud_id = os.environ.get("JIRA_CLOUD_ID")
    if not token or not cloud_id:
        return None
    url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue"
    resp = _http_request(
        url,
        method="POST",
        data=_build_issue_payload(finding, project_key=project),
        headers={"Authorization": f"Bearer {token}"},
    )
    if not isinstance(resp, dict):
        return None
    issue_key = resp.get("key")
    if not issue_key:
        return None
    base = base_url or f"https://api.atlassian.com/ex/jira/{cloud_id}"
    return {"issue_key": issue_key, "url": f"{base}/browse/{issue_key}"}


# --------------------------------------------------------------------------
# Sync stub — poll /search for created issues, infer status closures
# --------------------------------------------------------------------------


def poll_status_updates(org_id: str, *, project_key: str | None = None,
                        jql: str | None = None) -> list[dict]:
    """Poll Jira for status of issues we created. Returns a list of
    ``{issue_key, status, resolution}`` rows that the caller can use to
    update finding state.

    The implementation is intentionally minimal — Jira's webhooks are
    the long-term answer, but this read-only polling stub lets the demo
    show closed tickets without writing infra.
    """
    inst = load_install(org_id) or {}
    token = inst.get("access_token") or os.environ.get("JIRA_ACCESS_TOKEN")
    cloud_id = inst.get("cloud_id") or os.environ.get("JIRA_CLOUD_ID")
    if not token or not cloud_id:
        return []
    project = (project_key or os.environ.get("JIRA_PROJECT_KEY") or "SAFE")
    q = jql or f'project = "{project}" AND labels = "safecadence"'
    url = (
        f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/search"
        f"?jql={_urlparse.quote(q)}&fields=status,resolution&maxResults=100"
    )
    resp = _http_request(url, headers={"Authorization": f"Bearer {token}"})
    if not isinstance(resp, dict):
        return []
    out: list[dict] = []
    for issue in resp.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        fields = issue.get("fields") or {}
        status = (fields.get("status") or {}).get("name")
        resolution = fields.get("resolution")
        if isinstance(resolution, dict):
            resolution = resolution.get("name")
        out.append({
            "issue_key": issue.get("key"),
            "status": status,
            "resolution": resolution,
        })
    return out


# --------------------------------------------------------------------------
# FastAPI router
# --------------------------------------------------------------------------


def build_router():
    try:
        from fastapi import APIRouter, HTTPException, Request
        from fastapi.responses import JSONResponse, RedirectResponse
    except Exception:                                  # pragma: no cover
        return None

    router = APIRouter(tags=["jira"])

    @router.get("/oauth/jira/install")
    def jira_install(request: Request):
        if not is_configured():
            return JSONResponse(
                status_code=503,
                content={
                    "error": "not_configured",
                    "message": "Jira OAuth is not configured. Set JIRA_CLIENT_ID and JIRA_CLIENT_SECRET.",
                },
            )
        org_id = request.query_params.get("org_id") or ""
        return RedirectResponse(url=install_url(state=org_id), status_code=302)

    @router.get("/oauth/jira/callback")
    def jira_callback(request: Request):
        code = request.query_params.get("code") or ""
        state = request.query_params.get("state") or "default"
        if not code:
            raise HTTPException(400, "Missing code")
        if not is_configured():
            return JSONResponse(status_code=503, content={"error": "not_configured"})
        tok = exchange_code(code)
        if not tok or "access_token" not in tok:
            raise HTTPException(400, "OAuth exchange failed")
        access_token = tok["access_token"]
        cloud_id = fetch_cloud_id(access_token) or ""
        save_install(state, {
            "access_token": access_token,
            "refresh_token": tok.get("refresh_token"),
            "scope": tok.get("scope"),
            "expires_in": tok.get("expires_in"),
            "cloud_id": cloud_id,
            "installed_at": int(_time.time()),
        })
        return JSONResponse({"ok": True, "org_id": state, "cloud_id": cloud_id})

    return router


__all__ = [
    "is_configured",
    "install_url",
    "exchange_code",
    "fetch_cloud_id",
    "save_install",
    "load_install",
    "create_jira_ticket",
    "poll_status_updates",
    "build_router",
]
