"""
v8.0 — Public read-only share tokens.

Generates a short URL that exposes a curated read-only dashboard
without requiring login. Token is signed with the JWT secret so
revocation = rotate the secret.

Stickiness lever: when a CISO/auditor regularly opens
https://safecadence.acme.com/share/abc123 to check compliance, they
ask "what is this thing?" and the team's answer is "SafeCadence."

Use cases:
  * Send your auditor a link to the SOC 2 evidence pack
  * Send your CISO a daily compliance snapshot
  * Embed in an internal status page

Security model:
  * Tokens carry expiry (default 7 days)
  * Tokens carry a fixed scope (compliance / identity / evidence)
  * Token holders can NEVER write, mutate, or see anything outside scope
  * Each token is recorded in the audit log
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
import uuid
import base64
from dataclasses import dataclass, field
from typing import Iterable

from safecadence.intel._store import read, write


_SCOPES = {"compliance", "identity", "evidence", "summary"}


@dataclass
class ShareToken:
    token_id: str
    token: str            # the URL-safe string the user pastes into a browser
    scope: str            # compliance | identity | evidence | summary
    issued_to: str        # human-readable "auditor@biggrant.com"
    issued_by: str
    issued_at: float
    expires_at: float
    revoked: bool = False


def _secret() -> bytes:
    """Sign tokens with the same secret the JWT uses, persisted by the
    platform. We read from the same env / file the rest of the app does
    so revoking via JWT rotation revokes all share tokens too."""
    s = os.environ.get("SC_JWT_SECRET", "")
    if not s:
        try:
            from pathlib import Path
            p = Path.home() / ".safecadence" / "jwt_secret"
            if p.exists():
                s = p.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    if not s:
        s = "INSECURE-FALLBACK-SECRET-rotate-me"
    return s.encode("utf-8")


def create_share(*, scope: str, issued_to: str, issued_by: str,
                  ttl_seconds: int = 7 * 86400) -> ShareToken:
    if scope not in _SCOPES:
        raise ValueError(f"scope must be one of {sorted(_SCOPES)}")
    if ttl_seconds <= 0 or ttl_seconds > 90 * 86400:
        raise ValueError("ttl_seconds must be 1..90 days")
    now = time.time()
    payload = {
        "tid": uuid.uuid4().hex[:12],
        "scope": scope,
        "iat": int(now),
        "exp": int(now + ttl_seconds),
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = hmac.new(_secret(), raw, hashlib.sha256).digest()
    token = (base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
             + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode())

    record = ShareToken(
        token_id=payload["tid"], token=token,
        scope=scope, issued_to=issued_to, issued_by=issued_by,
        issued_at=now, expires_at=now + ttl_seconds,
    )
    data = read("share_tokens", {"tokens": []})
    data.setdefault("tokens", []).append(record.__dict__)
    write("share_tokens", data)
    return record


def list_shares() -> list[ShareToken]:
    data = read("share_tokens", {"tokens": []})
    return [ShareToken(**t) for t in (data.get("tokens") or [])]


def revoke_share(token_id: str) -> bool:
    data = read("share_tokens", {"tokens": []})
    found = False
    for t in (data.get("tokens") or []):
        if t.get("token_id") == token_id:
            t["revoked"] = True
            found = True
    if found:
        write("share_tokens", data)
    return found


def verify_share(token: str) -> dict | None:
    """Return the decoded payload if valid, else None."""
    if "." not in token:
        return None
    try:
        b64_payload, b64_sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(b64_payload + "=" * (-len(b64_payload) % 4))
        sig = base64.urlsafe_b64decode(b64_sig + "=" * (-len(b64_sig) % 4))
    except (ValueError, base64.binascii.Error):
        return None
    expected = hmac.new(_secret(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if payload.get("exp", 0) < time.time():
        return None

    # Cross-check against revocation list
    data = read("share_tokens", {"tokens": []})
    for t in (data.get("tokens") or []):
        if t.get("token_id") == payload.get("tid") and t.get("revoked"):
            return None
    return payload
