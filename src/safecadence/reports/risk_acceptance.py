"""Risk acceptance log — findings the org has signed off as accepted.

Persists a JSON list of acceptance entries at
``~/.safecadence/risk_acceptance.json``. Entries look like::

    {
      "id": "ra-001",
      "finding_id": "CVE-2024-12345",
      "host": "legacy-app-01",
      "accepted_by": "Jane Doe (CISO)",
      "accepted_at": "2026-05-10T00:00:00Z",
      "expires_at": "2026-11-10T00:00:00Z",
      "rationale": "Vendor patch not yet available; WAF rule X in place",
      "compensating_controls": ["WAF rule deployed", "Network segmentation"]
    }

The compliance sections look up findings by ``(finding_id, host)`` and
decorate accepted findings with a "RISK ACCEPTED" pill. A dedicated
``risk_acceptance_log`` report section lists every current acceptance.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import uuid
from pathlib import Path
from typing import Any


DEFAULT_PATH = "~/.safecadence/risk_acceptance.json"


def _store_path(path: str | None = None) -> Path:
    if path:
        return Path(path)
    env = os.environ.get("SAFECADENCE_RISK_ACCEPTANCE_PATH")
    if env:
        return Path(env)
    return Path(os.path.expanduser(DEFAULT_PATH))


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_all(path: str | None = None) -> list[dict]:
    p = _store_path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _write_all(entries: list[dict], path: str | None = None) -> None:
    p = _store_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2, default=str), encoding="utf-8")


def list_acceptances(path: str | None = None) -> list[dict]:
    """Return every persisted acceptance entry (including expired)."""
    return _read_all(path)


def add_acceptance(entry: dict, path: str | None = None) -> dict:
    """Persist a new acceptance. Auto-assigns ``id`` and ``accepted_at`` if
    missing. Returns the stored entry."""
    if not isinstance(entry, dict):
        raise TypeError("entry must be a dict")
    record = dict(entry)
    if not record.get("id"):
        record["id"] = "ra-" + uuid.uuid4().hex[:8]
    if not record.get("accepted_at"):
        record["accepted_at"] = _now_iso()
    # Normalize compensating_controls to list[str]
    cc = record.get("compensating_controls")
    if isinstance(cc, str):
        record["compensating_controls"] = [cc]
    elif cc is None:
        record["compensating_controls"] = []
    entries = _read_all(path)
    entries.append(record)
    _write_all(entries, path)
    # v10.8: emit a change_mgmt event so the workflow log + integrations
    # see the new acceptance. Best-effort.
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(
            record.get("org_id"),
            "risk_accepted",
            before=None,
            after={
                "id": record.get("id"),
                "finding_id": record.get("finding_id"),
                "host": record.get("host"),
                "expires_at": record.get("expires_at"),
            },
            actor=record.get("accepted_by"),
            asset_id=record.get("host"),
        )
    except Exception:                              # pragma: no cover
        pass
    return record


def remove_acceptance(id_: str, path: str | None = None) -> bool:
    """Remove an acceptance by id. Returns True if anything was removed."""
    entries = _read_all(path)
    keep = [e for e in entries if e.get("id") != id_]
    if len(keep) == len(entries):
        return False
    _write_all(keep, path)
    return True


def _expired(entry: dict, *, today: _dt.date | None = None) -> bool:
    expiry = entry.get("expires_at")
    if not expiry:
        return False
    try:
        d = _dt.date.fromisoformat(str(expiry)[:10])
    except Exception:
        return False
    now = today or _dt.date.today()
    return now > d


def is_accepted(
    finding_id: str,
    host: str | None = None,
    *,
    path: str | None = None,
    today: _dt.date | None = None,
) -> dict | None:
    """Return the matching unexpired acceptance entry, or ``None``.

    Matches on ``finding_id`` and (when ``host`` is provided) ``host``. A
    host of ``"*"`` or missing in the stored entry counts as a wildcard.
    """
    if not finding_id:
        return None
    for entry in _read_all(path):
        if entry.get("finding_id") != finding_id:
            continue
        ehost = entry.get("host")
        if host is not None and ehost not in (None, "", "*", host):
            continue
        if _expired(entry, today=today):
            continue
        return entry
    return None


def active_acceptances(
    *, path: str | None = None, today: _dt.date | None = None,
) -> list[dict]:
    """Return only acceptances that haven't expired."""
    return [e for e in _read_all(path) if not _expired(e, today=today)]


def expire(
    *, path: str | None = None, today: _dt.date | None = None,
) -> list[dict]:
    """Sweep + emit change_mgmt events for every acceptance that has
    passed its ``expires_at`` since the last sweep.

    The acceptance entries themselves are not deleted (auditors want the
    history). We track a per-id "expired_emitted" flag so re-running
    :func:`expire` is idempotent.

    Returns the list of acceptances whose expiry was emitted this call.
    """
    entries = _read_all(path)
    emitted: list[dict] = []
    changed = False
    for e in entries:
        if _expired(e, today=today) and not e.get("expired_emitted"):
            e["expired_emitted"] = True
            changed = True
            emitted.append(e)
            try:
                from safecadence.workflow.change_mgmt import record_change
                record_change(
                    e.get("org_id"),
                    "acceptance_expired",
                    before={"id": e.get("id"), "expires_at": e.get("expires_at")},
                    after=None,
                    actor=None,
                    asset_id=e.get("host"),
                )
            except Exception:                      # pragma: no cover
                pass
    if changed:
        _write_all(entries, path)
    return emitted


__all__ = [
    "DEFAULT_PATH",
    "list_acceptances",
    "add_acceptance",
    "remove_acceptance",
    "is_accepted",
    "active_acceptances",
    "expire",
]
