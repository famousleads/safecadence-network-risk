"""
Auth + RBAC for the SafeCadence API.

User store is a tiny YAML file (`safecadence-users.yaml`) so air-gapped
deployments don't need a separate user DB. For HA / multi-instance, swap
the user store for the SQL one in v2.1.

YAML format:
    tenants:
      acme:
        users:
          - username: alice
            password_hash: $2b$...   # bcrypt
            roles: [admin]
          - username: bob
            password_hash: $2b$...
            roles: [analyst, viewer]

JWT-bearer auth. Tokens include {sub, tenant, roles}.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import yaml

try:
    import bcrypt
    from fastapi import HTTPException
    from jose import JWTError, jwt
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    bcrypt = None
    HTTPException = None
    JWTError = None
    jwt = None


VALID_ROLES = {"admin", "analyst", "viewer"}


@dataclass
class CurrentUser:
    username: str
    tenant: str
    roles: List[str] = field(default_factory=list)


def _bcrypt_safe(plain: str) -> bytes:
    """bcrypt has a 72-byte hard limit; truncate (UTF-8 safe) longer inputs."""
    raw = plain.encode("utf-8")
    return raw[:72]


def hash_password(plain: str) -> str:
    if not _AUTH_AVAILABLE:
        raise RuntimeError("bcrypt unavailable; install with [server] extras.")
    return bcrypt.hashpw(_bcrypt_safe(plain), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    if not _AUTH_AVAILABLE:
        return False
    try:
        return bcrypt.checkpw(_bcrypt_safe(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def load_users(path=None) -> dict:
    p = Path(path) if path else Path(os.environ.get("SC_USERS_FILE", "safecadence-users.yaml"))
    if not p.exists():
        # bootstrap: create a single-tenant single-admin file with a strong random password
        import secrets
        pw = secrets.token_urlsafe(20)
        users = {
            "tenants": {
                "default": {
                    "users": [{
                        "username": "admin",
                        "password_hash": hash_password(pw),
                        "roles": ["admin"],
                    }],
                }
            }
        }
        p.write_text(yaml.safe_dump(users), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        # Bootstrap creds get printed once to stderr; logs only.
        import sys
        print(f"[bootstrap] Wrote {p} — initial login: admin / {pw}", file=sys.stderr)
        return users
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def authenticate(users: dict, *, username: str, password: str) -> Optional[CurrentUser]:
    for tenant_id, t in (users.get("tenants") or {}).items():
        for u in t.get("users", []):
            if u.get("username") == username and verify_password(password, u.get("password_hash", "")):
                roles = [r for r in (u.get("roles") or []) if r in VALID_ROLES]
                if not roles:
                    roles = ["viewer"]
                return CurrentUser(username=username, tenant=tenant_id, roles=roles)
    return None


def make_jwt(user: CurrentUser, *, secret: str, ttl_minutes: int = 60) -> str:
    payload = {
        "sub":    user.username,
        "tenant": user.tenant,
        "roles":  user.roles,
        "iat":    datetime.now(timezone.utc),
        "exp":    datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_jwt(token: str, *, secret: str) -> CurrentUser:
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"])
        return CurrentUser(
            username=data["sub"], tenant=data["tenant"],
            roles=list(data.get("roles") or []),
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")


def require_role(*roles: str):
    """FastAPI dependency factory enforcing one or more required roles."""
    required = set(roles)

    def _dep(user: CurrentUser):
        if not (set(user.roles) & required):
            raise HTTPException(status_code=403, detail=f"Requires role: {sorted(required)}")
        return user
    return _dep
