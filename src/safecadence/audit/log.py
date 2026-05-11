"""
Per-org append-only audit log.

One JSONL file per org at ``~/.safecadence/orgs/<org_id>/audit.jsonl``.
Each line is a single JSON object::

    {
      "ts": "2026-05-10T17:42:13Z",
      "user_email": "alice@acme.com",
      "action": "report.template.save",
      "target": "tpl_abc123",
      "metadata": {"name": "Quarterly Review"}
    }

Why JSONL instead of a SQL table:
  * Drop-in tail-able from any shell.
  * Trivially streams to SIEM via filebeat / vector.
  * Never blocks an HTTP request on a write lock.

Best-effort: if writing fails (disk full, permission), we don't raise —
we just drop the event. The product is still useful without a perfect
audit log; it's strictly worse with crashes on every write.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


def _audit_path(org_id: str) -> Path:
    """Resolve the audit.jsonl path for ``org_id``. Global fallback when
    org_id is empty / None (legacy single-tenant)."""
    if org_id:
        from safecadence.storage.org_store import org_data_dir
        return org_data_dir(org_id) / "audit.jsonl"
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base / "audit.jsonl"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_event(
    org_id: str | None,
    user_email: str,
    action: str,
    target: str | None = None,
    metadata: dict | None = None,
) -> bool:
    """Append a single event. Never raises. Returns True if written."""
    try:
        path = _audit_path(org_id or "")
        row = {
            "ts": _now_iso(),
            "user_email": user_email or "",
            "action": action or "",
            "target": target,
            "metadata": metadata or {},
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def read_events(
    org_id: str | None,
    *,
    limit: int = 100,
    since: str | None = None,
) -> list[dict]:
    """Return the most recent events (newest first), up to ``limit``.

    ``since`` filters to ts >= since (ISO-8601 string).
    Lines that fail to parse are skipped silently — never raises.
    """
    path = _audit_path(org_id or "")
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        # Read all lines — files are JSONL and typically small. For very
        # large orgs we'd swap this to seek-from-end; v10.5 keeps it simple.
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                if since and obj.get("ts", "") < since:
                    continue
                rows.append(obj)
    except Exception:
        return []
    rows.reverse()  # newest first
    if limit and limit > 0:
        return rows[:limit]
    return rows


def iter_events(org_id: str | None) -> Iterable[dict]:
    """Stream events oldest-first. For batch consumers / exporters."""
    path = _audit_path(org_id or "")
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except Exception:
                continue


# --------------------------------------------------------------------------- #
# v11.3 — Hash-chained audit log                                               #
#                                                                              #
# Each chained event includes ``prev_hash`` (the hash of the previous row in   #
# the chain) and ``hash`` (sha256 over the canonical JSON of the row WITHOUT   #
# the ``hash`` field itself). Tampering with any line breaks every line after  #
# it because the next ``prev_hash`` won't match. Storage is a separate JSONL   #
# at ``audit_chain.jsonl`` so the legacy ``audit.jsonl`` consumers (~6         #
# callers) keep their lightweight, unchained format.                           #
# --------------------------------------------------------------------------- #


GENESIS_PREV_HASH = "0" * 64


def _chain_path(org_id: str) -> Path:
    """Resolve audit_chain.jsonl path for ``org_id`` (sibling of audit.jsonl)."""
    parent = _audit_path(org_id or "").parent
    return parent / "audit_chain.jsonl"


def _canonical_json(obj: dict) -> str:
    """Deterministic JSON encoding for hash inputs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hash_event(row_without_hash: dict) -> str:
    return hashlib.sha256(
        _canonical_json(row_without_hash).encode("utf-8")
    ).hexdigest()


def _last_chain_hash(path: Path) -> str:
    """Return the ``hash`` of the last chain line, or GENESIS_PREV_HASH."""
    if not path.exists():
        return GENESIS_PREV_HASH
    last_hash = GENESIS_PREV_HASH
    try:
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                if isinstance(obj.get("hash"), str):
                    last_hash = obj["hash"]
    except Exception:
        return GENESIS_PREV_HASH
    return last_hash


def log_event_chained(
    org_id: str | None,
    user_email: str,
    action: str,
    target: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Append one event to the *chained* audit log.

    Returns the row that was written (including ``prev_hash`` and
    ``hash`` for the caller's convenience), or an empty dict on
    failure. Never raises.

    Stored at ``audit_chain.jsonl``, NOT ``audit.jsonl``. The two files
    are independent — call :func:`log_event` if you also want the row
    in the unchained log (e.g. for SIEM forwarding).
    """
    try:
        path = _chain_path(org_id or "")
        path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash = _last_chain_hash(path)
        body = {
            "ts": _now_iso(),
            "user_email": user_email or "",
            "action": action or "",
            "target": target,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }
        body["hash"] = _hash_event(body)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, separators=(",", ":")) + "\n")
        return body
    except Exception:
        return {}


def verify_chain(org_id: str | None) -> dict:
    """Walk the audit chain, return ``{ok, broken_at_line, line_count}``.

    ``broken_at_line`` is the 1-indexed line number of the first row
    whose hash doesn't match its content OR whose ``prev_hash`` doesn't
    match the prior row's ``hash``. ``None`` when the chain is intact.
    Empty chain ⇒ ``ok=True, line_count=0``.
    """
    path = _chain_path(org_id or "")
    if not path.exists():
        return {"ok": True, "broken_at_line": None, "line_count": 0}
    prev = GENESIS_PREV_HASH
    line_no = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw_stripped = raw.strip()
                if not raw_stripped:
                    continue
                line_no += 1
                try:
                    obj = json.loads(raw_stripped)
                except Exception:
                    return {"ok": False, "broken_at_line": line_no, "line_count": line_no}
                stored_hash = obj.get("hash")
                stored_prev = obj.get("prev_hash")
                if not isinstance(stored_hash, str) or not isinstance(stored_prev, str):
                    return {"ok": False, "broken_at_line": line_no, "line_count": line_no}
                if stored_prev != prev:
                    return {"ok": False, "broken_at_line": line_no, "line_count": line_no}
                body = {k: v for k, v in obj.items() if k != "hash"}
                if _hash_event(body) != stored_hash:
                    return {"ok": False, "broken_at_line": line_no, "line_count": line_no}
                prev = stored_hash
    except Exception:
        return {"ok": False, "broken_at_line": line_no or 1, "line_count": line_no}
    return {"ok": True, "broken_at_line": None, "line_count": line_no}


def read_chain(
    org_id: str | None,
    *,
    limit: int = 100,
) -> list[dict]:
    """Return up to ``limit`` chained events, newest first."""
    path = _chain_path(org_id or "")
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    continue
    except Exception:
        return []
    rows.reverse()
    if limit and limit > 0:
        return rows[:limit]
    return rows


__all__ = [
    "log_event",
    "read_events",
    "iter_events",
    # v11.3 chained additions
    "log_event_chained",
    "verify_chain",
    "read_chain",
    "GENESIS_PREV_HASH",
]
