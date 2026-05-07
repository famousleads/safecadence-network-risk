"""Security primitives — vault, RBAC, audit log."""

from safecadence.security.vault import (
    EncryptedVault, VaultError, derive_key, generate_key,
)

__all__ = ["EncryptedVault", "VaultError", "derive_key", "generate_key"]
