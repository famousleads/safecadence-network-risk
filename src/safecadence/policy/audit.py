"""
Append-only audit log for policy actions.

JSONL file at ~/.safecadence/policy_audit.jsonl. Cross-platform via
pathlib + utf-8 explicit encoding. Files rotate daily.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _audit_dir() -> Path:
    p = Path.home() / ".safecadence"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _todays_file() -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _audit_dir() / f"policy_audit-{today}.jsonl"


def log(action: str, *, actor: str = "system", policy_id: str = "",
        detail: dict[str, Any] | None = None) -> None:
    """Append one audit entry. Never raises — audit is best-effort."""
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "policy_id": policy_id,
            "detail": detail or {},
        }
        with _todays_file().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass                                  # never let audit fail the caller


def read_recent(limit: int = 200) -> list[dict]:
    out: list[dict] = []
    files = sorted(_audit_dir().glob("policy_audit-*.jsonl"), reverse=True)
    for f in files:
        try:
            for line in reversed(f.read_text(encoding="utf-8").splitlines()):
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
                if len(out) >= limit:
                    return out
        except Exception:
            continue
    return out
