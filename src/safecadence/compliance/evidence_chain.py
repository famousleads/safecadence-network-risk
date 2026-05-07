"""
v9.30 — Evidence tamper-evidence (sign + hash chain).

Every generated evidence pack is recorded in a hash chain. Each
record contains:

  * pack_id
  * framework (soc2 / iso27001 / nist-800-53 / pci / hipaa / zerotrust)
  * generated_at
  * generated_by
  * content_sha256  (the bytes the auditor will receive)
  * prev_hash       (the chain link)
  * record_hash     (sha256 of all the above) — what gets persisted

The chain is append-only. Verification walks the file and recomputes
each ``record_hash`` to confirm nothing was tampered with retroactively.
That's the WORM-like guarantee SOC 2 CC7 wants.

Storage: ``$SC_DATA_DIR/evidence_chain.jsonl`` (line-per-record so
appends are O(1)).
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


_GENESIS = "0" * 64


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "evidence_chain.jsonl"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_hash(payload: dict) -> str:
    """Deterministic hash over all non-record_hash fields."""
    canonical = json.dumps({k: v for k, v in payload.items()
                              if k != "record_hash"},
                              sort_keys=True, separators=(",", ":"))
    return _sha256(canonical.encode("utf-8"))


def _last_hash() -> str:
    p = _store_path()
    if not p.exists():
        return _GENESIS
    last = _GENESIS
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if row.get("record_hash"):
                    last = row["record_hash"]
            except Exception:
                continue
    return last


def append(*, framework: str, content: bytes,
            generated_by: str = "safecadence",
            note: str = "") -> dict:
    """Append a new evidence record to the chain. Returns the record."""
    pack_id = f"ev-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "pack_id": pack_id,
        "framework": framework,
        "generated_at": now,
        "generated_by": generated_by,
        "content_sha256": _sha256(content),
        "byte_size": len(content),
        "prev_hash": _last_hash(),
        "note": note,
    }
    payload["record_hash"] = _record_hash(payload)
    p = _store_path()
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":")) + "\n")
    return payload


def list_chain(*, framework: Optional[str] = None,
                 limit: int = 200) -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if framework and row.get("framework") != framework:
                continue
            out.append(row)
    out.sort(key=lambda r: r.get("generated_at", ""), reverse=True)
    return out[:limit]


def verify_chain() -> dict:
    """Walk the chain and confirm each link is intact.

    Returns ``{"ok": bool, "checked": int, "broken_at": index_or_none,
    "reason": ...}`` so the UI / auditor portal can render a green or
    red shield.
    """
    p = _store_path()
    if not p.exists():
        return {"ok": True, "checked": 0,
                "broken_at": None, "reason": "empty chain"}
    prev = _GENESIS
    checked = 0
    with p.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                return {"ok": False, "checked": checked,
                        "broken_at": idx,
                        "reason": "malformed JSON line"}
            if row.get("prev_hash") != prev:
                return {"ok": False, "checked": checked,
                        "broken_at": idx,
                        "reason": "prev_hash mismatch — chain broken"}
            expected = _record_hash(row)
            if row.get("record_hash") != expected:
                return {"ok": False, "checked": checked,
                        "broken_at": idx,
                        "reason": "record_hash mismatch — record altered"}
            prev = row["record_hash"]
            checked += 1
    return {"ok": True, "checked": checked,
            "broken_at": None, "reason": "all links verified"}


def verify_content(pack_id: str, content: bytes) -> dict:
    """After regenerating a pack from sources, verify it matches the
    chain entry. Used by the auditor portal's "download with proof"
    button to prove the served bytes are the bytes that were chained.
    """
    expected = _sha256(content)
    for row in list_chain(limit=10000):
        if row.get("pack_id") == pack_id:
            return {
                "pack_id": pack_id,
                "match": row.get("content_sha256") == expected,
                "chain_sha256": row.get("content_sha256"),
                "served_sha256": expected,
            }
    return {"pack_id": pack_id, "match": False,
            "reason": "pack_id not in chain"}
