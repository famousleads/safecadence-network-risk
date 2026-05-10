"""
Outgoing webhook delivery for report-generation events.

Supports three payload "kinds":

  * ``slack``    — Slack block-kit ``{text, blocks}``
  * ``teams``    — Microsoft Teams Adaptive Card
  * ``generic``  — flat ``{event, generated_at, summary, download_url}``

Endpoints are persisted at ``<data_dir>/reports/webhooks.json``. Each
record has the shape::

    {"id": "wh-<8>", "url": "...", "kind": "slack",
     "secret_hash": "sha256:<hex>" | null,
     "_secret": "<raw>",            # never returned by list API
     "created_at": "...",
     "last_fired_at": "..." | null,
     "last_status": <int> | null}

Outgoing requests carry ``X-SafeCadence-Signature: sha256=<hex>`` so
the receiver can verify the body. We use only stdlib ``urllib.request``
with a 5-second timeout — no new dependencies.

Public API:
  - list_webhook_endpoints()                     -> list[dict]   (no _secret)
  - add_webhook_endpoint(url=, kind=, secret=)   -> dict         (raises in r/o)
  - remove_webhook_endpoint(endpoint_id)         -> bool         (raises in r/o)
  - fire_webhook(endpoint_id=, event=, report_summary=) -> dict
  - fire_all_webhooks(event=, report_summary=)   -> list[dict]
  - notify_completion(report_summary)            -> list[dict]
  - test_webhook(endpoint_id=)                   -> dict
"""

from __future__ import annotations

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


# --------------------------------------------------------------------------
# storage helpers
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


def _store_path() -> Path:
    p = _data_dir() / "reports" / "webhooks.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _write_all(items: list[dict]) -> None:
    p = _store_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(items, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def _public_view(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "_secret"}


_KINDS = ("slack", "teams", "generic")


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------


def list_webhook_endpoints() -> list[dict]:
    return [_public_view(r) for r in _read_all()]


def add_webhook_endpoint(*, url: str, kind: str = "generic",
                         secret: str | None = None) -> dict:
    if _is_readonly():
        raise PermissionError("read_only: webhooks cannot be added when SC_READONLY=1")
    if not url or not isinstance(url, str):
        raise ValueError("url is required")
    if kind not in _KINDS:
        raise ValueError(f"kind must be one of {_KINDS}")
    items = _read_all()
    rec = {
        "id": "wh-" + secrets.token_hex(4),
        "url": url,
        "kind": kind,
        "secret_hash": (
            "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()
            if secret else None
        ),
        "_secret": secret or "",
        "created_at": _now_iso(),
        "last_fired_at": None,
        "last_status": None,
    }
    items.append(rec)
    _write_all(items)
    return _public_view(rec)


def remove_webhook_endpoint(endpoint_id: str) -> bool:
    if _is_readonly():
        raise PermissionError("read_only: webhooks cannot be removed when SC_READONLY=1")
    items = _read_all()
    keep = [r for r in items if r.get("id") != endpoint_id]
    if len(keep) == len(items):
        return False
    _write_all(keep)
    return True


def _get(endpoint_id: str) -> dict | None:
    for r in _read_all():
        if r.get("id") == endpoint_id:
            return r
    return None


# --------------------------------------------------------------------------
# Payload builders
# --------------------------------------------------------------------------


def _format_kpi_summary(summary: dict) -> str:
    kpi = (summary or {}).get("kpi") or {}
    return (
        f"{kpi.get('hosts', 0)} hosts · "
        f"{kpi.get('critical', 0)} critical · "
        f"{kpi.get('high', 0)} high · "
        f"{kpi.get('kev', 0)} KEV · "
        f"{kpi.get('eol', 0)} EOL"
    )


def build_slack_payload(event: str, summary: dict) -> dict:
    title = (summary or {}).get("title") or "SafeCadence NetRisk report"
    line = _format_kpi_summary(summary)
    url = (summary or {}).get("download_url") or ""
    blocks: list[dict] = [
        {"type": "header",
         "text": {"type": "plain_text", "text": f"NetRisk: {event.replace('_', ' ').title()}"}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*{title}*\n{line}"}},
    ]
    if url:
        blocks.append({
            "type": "actions", "elements": [
                {"type": "button",
                 "text": {"type": "plain_text", "text": "Open report"},
                 "url": url}
            ]
        })
    return {"text": f"NetRisk {event}: {line}", "blocks": blocks}


def build_teams_payload(event: str, summary: dict) -> dict:
    title = (summary or {}).get("title") or "SafeCadence NetRisk report"
    line = _format_kpi_summary(summary)
    url = (summary or {}).get("download_url") or ""
    body: list[dict] = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder",
         "text": f"NetRisk: {event.replace('_', ' ').title()}"},
        {"type": "TextBlock", "text": title, "wrap": True},
        {"type": "TextBlock", "text": line, "isSubtle": True, "wrap": True},
    ]
    actions: list[dict] = []
    if url:
        actions.append({"type": "Action.OpenUrl", "title": "Open report", "url": url})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
                "actions": actions,
            },
        }],
    }


def build_generic_payload(event: str, summary: dict) -> dict:
    return {
        "event": event,
        "generated_at": _now_iso(),
        "summary": summary or {},
        "download_url": (summary or {}).get("download_url") or "",
    }


def _payload_for_kind(kind: str, event: str, summary: dict) -> dict:
    if kind == "slack":
        return build_slack_payload(event, summary)
    if kind == "teams":
        return build_teams_payload(event, summary)
    return build_generic_payload(event, summary)


def _signature(secret: str | None, body: bytes) -> str | None:
    if not secret:
        return None
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


# --------------------------------------------------------------------------
# Outbound
# --------------------------------------------------------------------------


def _send(url: str, body: bytes, headers: dict[str, str], *,
          timeout: float = 5.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.reason or ""
    except urllib.error.HTTPError as e:
        return e.code, e.reason or ""
    except urllib.error.URLError as e:
        return 0, str(e.reason)
    except (OSError, ValueError) as e:
        return 0, str(e)


def fire_webhook(*, endpoint_id: str, event: str, report_summary: dict) -> dict:
    rec = _get(endpoint_id)
    if not rec:
        return {"ok": False, "error": "unknown_endpoint", "id": endpoint_id}
    payload = _payload_for_kind(rec.get("kind") or "generic", event, report_summary)
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = _signature(rec.get("_secret"), body)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SafeCadence-Webhooks/1.0",
    }
    if sig:
        headers["X-SafeCadence-Signature"] = sig
    code, reason = _send(rec["url"], body, headers)

    # Persist last-fired status (best effort, not in read-only).
    if not _is_readonly():
        items = _read_all()
        for r in items:
            if r.get("id") == endpoint_id:
                r["last_fired_at"] = _now_iso()
                r["last_status"] = code
                break
        try:
            _write_all(items)
        except OSError:
            pass
    return {
        "ok": 200 <= code < 300,
        "id": endpoint_id,
        "kind": rec.get("kind"),
        "status": code,
        "reason": reason,
        "signature_sent": bool(sig),
    }


def fire_all_webhooks(*, event: str, report_summary: dict) -> list[dict]:
    out: list[dict] = []
    for r in _read_all():
        try:
            out.append(fire_webhook(endpoint_id=r["id"], event=event,
                                    report_summary=report_summary))
        except Exception as exc:  # pragma: no cover
            out.append({"ok": False, "id": r.get("id"), "error": str(exc)})
    return out


def notify_completion(report_summary: dict) -> list[dict]:
    """Hook called when a report finishes generating."""
    return fire_all_webhooks(event="report.generated",
                             report_summary=report_summary)


def test_webhook(*, endpoint_id: str) -> dict:
    """Send a synthetic ``ping`` event — safe in read-only mode."""
    summary = {
        "title": "SafeCadence NetRisk webhook test",
        "kpi": {"hosts": 0, "critical": 0, "high": 0, "kev": 0, "eol": 0},
        "download_url": "",
    }
    return fire_webhook(endpoint_id=endpoint_id, event="webhook.test",
                        report_summary=summary)


__all__ = [
    "list_webhook_endpoints",
    "add_webhook_endpoint", "remove_webhook_endpoint",
    "fire_webhook", "fire_all_webhooks", "notify_completion", "test_webhook",
    "build_slack_payload", "build_teams_payload", "build_generic_payload",
]
