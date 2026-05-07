"""
v9.30 — Auditor portal.

Issues a time-bound, scope-restricted token an auditor can use to
view compliance + evidence pages without requiring an SSO login on
your IdP. Tokens are:

  * SHA-256-derived (the stored value is the hash, the issued value
    is the secret)
  * scoped to specific paths (compliance, evidence, scores by default)
  * expiring (default 30 days)
  * revocable
  * watermarked at render time (the page shows "Auditor view —
    issued to <name> — expires <date>" so screenshots are obvious)

Storage: ``$SC_DATA_DIR/auditor_tokens.json``.

Auth flow:
  GET /auditor?token=<secret>
    → server hashes <secret>, looks up the row, checks scope+expiry,
      sets a session cookie limited to the same scope, redirects to
      the requested compliance page.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


_DEFAULT_SCOPE = ["/compliance", "/evidence", "/scores", "/findings",
                    "/policies"]


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "auditor_tokens.json"


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write_all(rows: list[dict]) -> None:
    _store_path().write_text(
        json.dumps(rows, separators=(",", ":")), encoding="utf-8")


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class AuditorToken:
    id: str
    name: str
    issued_to: str
    issued_at: str
    expires_at: str
    scope: list[str] = field(default_factory=list)
    status: str = "active"  # active | revoked | expired
    last_used_at: Optional[str] = None
    use_count: int = 0
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def issue(*, name: str, issued_to: str,
            valid_for_days: int = 30,
            scope: Optional[list[str]] = None,
            note: str = "") -> tuple[AuditorToken, str]:
    """Mint a new token. Returns (record, secret).

    The SECRET is shown to the issuer once and never stored — only
    its SHA-256 hash is persisted. The name should reference the
    audit firm + engagement (e.g. "Acme CPA — Q4 2026 SOC 2").
    """
    if not name.strip() or not issued_to.strip():
        raise ValueError("name and issued_to are required")
    if valid_for_days <= 0 or valid_for_days > 180:
        raise ValueError("valid_for_days must be 1..180")

    secret = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    rec = AuditorToken(
        id=f"aud-{uuid.uuid4().hex[:12]}",
        name=name.strip(), issued_to=issued_to.strip(),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=valid_for_days)).isoformat(),
        scope=list(scope or _DEFAULT_SCOPE),
        status="active",
        note=note.strip(),
    )
    rows = _read_all()
    persist = rec.to_dict()
    persist["secret_hash"] = _hash(secret)
    rows.append(persist)
    _write_all(rows)
    return rec, secret


def list_tokens(*, include_revoked: bool = True) -> list[dict]:
    rows = []
    for r in _read_all():
        if not include_revoked and r.get("status") == "revoked":
            continue
        # Never return the hash externally.
        clean = {k: v for k, v in r.items() if k != "secret_hash"}
        rows.append(clean)
    return rows


def revoke(token_id: str) -> bool:
    rows = _read_all()
    for r in rows:
        if r.get("id") == token_id and r.get("status") == "active":
            r["status"] = "revoked"
            r["revoked_at"] = datetime.now(timezone.utc).isoformat()
            _write_all(rows)
            return True
    return False


def _parse(ts: str) -> datetime:
    s = (ts or "").replace("Z", "+00:00")
    try:
        out = datetime.fromisoformat(s)
        if out.tzinfo is None:
            out = out.replace(tzinfo=timezone.utc)
        return out
    except Exception:
        return datetime.now(timezone.utc) - timedelta(days=10000)


def verify(secret: str, *, path: str = "/compliance") -> Optional[dict]:
    """Resolve a presented token. Returns the (sanitized) record on
    success, ``None`` if the token is invalid/expired/revoked or the
    requested path isn't in scope.
    """
    if not secret:
        return None
    target = _hash(secret)
    rows = _read_all()
    now = datetime.now(timezone.utc)
    for r in rows:
        if not hmac.compare_digest(r.get("secret_hash", ""), target):
            continue
        if r.get("status") != "active":
            return None
        if _parse(r.get("expires_at", "")) <= now:
            r["status"] = "expired"
            _write_all(rows)
            return None
        scope = r.get("scope") or _DEFAULT_SCOPE
        if not any(path == s or path.startswith(s + "/") for s in scope):
            return None
        # Touch usage counters.
        r["last_used_at"] = now.isoformat()
        r["use_count"] = int(r.get("use_count", 0)) + 1
        _write_all(rows)
        clean = {k: v for k, v in r.items() if k != "secret_hash"}
        return clean
    return None
