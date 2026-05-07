"""TOTP (RFC 6238) — pure-stdlib, no external deps.

We don't pull in pyotp because it adds a dep for ~80 lines of code we
can audit ourselves. The implementation matches Google Authenticator
and 1Password defaults: SHA1, 30-second window, 6 digits, ±1 step
clock-skew tolerance.

Used by:
  - Tier3 REST endpoint per-job challenge
  - Future v7.3 admin-action MFA gate
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from pathlib import Path
import json
import os


def generate_secret() -> str:
    """Return a fresh 160-bit base32 secret. Operators paste this
    into their authenticator app or scan the matching otpauth:// URI."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    # Pad to a multiple of 8 chars before base32 decode
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = ((mac[offset] & 0x7F) << 24
             | (mac[offset + 1] & 0xFF) << 16
             | (mac[offset + 2] & 0xFF) << 8
             | (mac[offset + 3] & 0xFF))
    return str(code % (10 ** digits)).zfill(digits)


def totp_now(secret_b32: str, *, period: int = 30, digits: int = 6,
              t: float | None = None) -> str:
    counter = int((t if t is not None else time.time()) // period)
    return _hotp(secret_b32, counter, digits)


def verify(secret_b32: str, code: str, *, period: int = 30,
           digits: int = 6, drift: int = 1) -> bool:
    """Constant-time compare across ±drift periods."""
    if not code or not code.isdigit():
        return False
    now = time.time()
    base = int(now // period)
    target = code.zfill(digits)
    for delta in range(-drift, drift + 1):
        candidate = _hotp(secret_b32, base + delta, digits)
        if hmac.compare_digest(candidate, target):
            return True
    return False


def otpauth_uri(*, secret_b32: str, account: str, issuer: str = "SafeCadence",
                period: int = 30, digits: int = 6) -> str:
    """Render the otpauth:// URI you put in a QR code. Authenticator
    apps that accept it: Google Authenticator, 1Password, Authy,
    Microsoft Authenticator, FreeOTP, Yubico Authenticator."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}")
    qs = (f"secret={secret_b32}&issuer={quote(issuer)}"
          f"&algorithm=SHA1&digits={digits}&period={period}")
    return f"otpauth://totp/{label}?{qs}"


# --------------------------------------------------------------------------
# Per-user enrollment store
# --------------------------------------------------------------------------

def _store_path() -> Path:
    base = Path(os.environ.get("SC_TOTP_STORE")
                or (Path.home() / ".safecadence" / "totp.json"))
    base.parent.mkdir(parents=True, exist_ok=True)
    return base


def _load_store() -> dict:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_store(d: dict) -> None:
    p = _store_path()
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def enroll(username: str) -> dict:
    """Generate + persist a TOTP secret for a user. Returns the
    secret + otpauth URI; the caller renders both for the operator
    to add to their authenticator app."""
    secret = generate_secret()
    store = _load_store()
    store[username] = {"secret": secret, "enrolled_at": time.time()}
    _save_store(store)
    return {
        "username": username,
        "secret": secret,
        "otpauth_uri": otpauth_uri(secret_b32=secret, account=username),
    }


def is_enrolled(username: str) -> bool:
    return username in _load_store()


def verify_user(username: str, code: str) -> bool:
    rec = _load_store().get(username)
    if not rec:
        return False
    return verify(rec.get("secret", ""), code)


def revoke(username: str) -> bool:
    store = _load_store()
    if username in store:
        del store[username]
        _save_store(store)
        return True
    return False
