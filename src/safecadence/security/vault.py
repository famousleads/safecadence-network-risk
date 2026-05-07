"""
Encrypted credential vault.

Stores SSH passwords / API keys / device credentials encrypted on disk
using Fernet (AES-128-CBC + HMAC-SHA-256). Master key is derived from
either:
  - an environment variable (SC_VAULT_KEY base64) — for automation
  - a passphrase via PBKDF2 — for interactive use

Usage:
    from safecadence.security import EncryptedVault, derive_key
    key = derive_key("my-passphrase", salt_path=".vault.salt")
    vault = EncryptedVault("creds.vault", key=key)
    vault.set("DC-CORE-01.password", "secret-pw")
    vault.set("api.openai", "sk-...")
    vault.save()
    pw = vault.get("DC-CORE-01.password")
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any


class VaultError(RuntimeError):
    pass


def _import_crypto():
    try:
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        return Fernet, InvalidToken, hashes, PBKDF2HMAC
    except ImportError as exc:
        raise VaultError(
            "Vault requires the `cryptography` package. "
            "Install with: pip install 'safecadence-network-risk[vault]'"
        ) from exc


def generate_key() -> str:
    """Return a fresh URL-safe base64 key suitable for SC_VAULT_KEY."""
    Fernet, _, _, _ = _import_crypto()
    return Fernet.generate_key().decode("ascii")


def derive_key(passphrase: str, *, salt_path: str | os.PathLike,
               iterations: int = 600_000) -> str:
    """
    Derive a Fernet key from a passphrase using PBKDF2-HMAC-SHA256.
    The salt is auto-created at salt_path on first call and reused after.
    """
    Fernet, _, hashes, PBKDF2HMAC = _import_crypto()
    sp = Path(salt_path)
    if sp.exists():
        salt = sp.read_bytes()
    else:
        salt = secrets.token_bytes(16)
        sp.write_bytes(salt)
        try:
            os.chmod(sp, 0o600)
        except OSError:
            pass
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=iterations,
    )
    raw = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw).decode("ascii")


class EncryptedVault:
    """A simple key/value store of secrets, encrypted at rest with Fernet."""

    HEADER = b"SCVAULT1"

    def __init__(self, path: str | os.PathLike, *, key: str):
        Fernet, InvalidToken, _, _ = _import_crypto()
        self._fernet_cls = Fernet
        self._invalid = InvalidToken
        self.path = Path(path)
        self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        self._data: dict[str, Any] = {}
        if self.path.exists():
            self._load()

    # ---- public API ---------------------------------------------- #
    def set(self, name: str, value: str) -> None:
        self._data[name] = value

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._data.get(name, default)

    def delete(self, name: str) -> bool:
        return self._data.pop(name, None) is not None

    def list(self) -> list[str]:
        return sorted(self._data.keys())

    def save(self) -> None:
        body = json.dumps(self._data).encode("utf-8")
        token = self._fernet.encrypt(body)
        with open(self.path, "wb") as fh:
            fh.write(self.HEADER + b"\n" + token)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ---- internals ----------------------------------------------- #
    def _load(self) -> None:
        raw = self.path.read_bytes()
        if not raw.startswith(self.HEADER):
            raise VaultError(f"{self.path} is not a SafeCadence vault file.")
        token = raw[len(self.HEADER) + 1:]
        try:
            body = self._fernet.decrypt(token)
        except self._invalid as exc:
            raise VaultError("Vault decryption failed (wrong key or corrupted file).") from exc
        try:
            self._data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError("Vault contents are not valid JSON.") from exc
