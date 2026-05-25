"""
v15.2.0 — Operator-facing peer configuration persistence.

The HA env vars (`SC_HA_MODE`, `SC_PEER_HOST`, `SC_REDIS_URL`, etc.)
have always been settable via systemd unit overrides. v15.2.0 adds
a WebUI form that writes them to a user-owned env file the systemd
unit sources at boot — no root required, no privilege escalation.

Storage
-------

``~/.safecadence/cluster.env`` (mode 0600; owned by the same user
the SafeCadence process runs as). Format is the standard
``KEY=value`` env-file syntax that systemd's ``EnvironmentFile=``
directive understands.

The systemd unit gains one line at install time:

::

    EnvironmentFile=-/home/safecadence/.safecadence/cluster.env

The leading ``-`` means "ignore if missing," so single-node installs
that never visit the WebUI form are unaffected.

Secret handling
---------------

* On READ, ``SC_PEER_SECRET`` is masked to its last 4 characters.
  The full value never leaves the file.
* On WRITE, an empty incoming secret means "keep current" — useful
  when the form posts back with the masked placeholder.
* The file is created with mode 0600 (owner-only read/write).

Validation
----------

* ``SC_HA_MODE``  must be in {``""``, ``"none"``, ``"shared-stores"``,
  ``"peer-sync"``}.
* ``SC_PEER_PORT`` must be 1–65535 if set.
* ``SC_PEER_SECRET`` must be ≥ 24 chars if HA_MODE=peer-sync.
* ``SC_REDIS_URL`` must start with ``redis://`` or ``rediss://`` if set.
* ``SC_PEER_HOST`` must be non-empty if HA_MODE=peer-sync.

Public API
----------

* ``DEFAULT_CONFIG_PATH``
* ``KNOWN_KEYS``
* ``read_config(path=None)`` → dict (secrets masked)
* ``write_config(values, path=None)`` → list[str] of warnings
* ``validate(values)`` → list[str] of errors (empty = OK)
* ``mask_secret(s)`` → str
* ``is_readonly()`` → bool  (True when SC_READONLY=1 in current env)
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path.home() / ".safecadence" / "cluster.env"


# The keys the form exposes. Order matters — the form renders in this order.
KNOWN_KEYS: tuple[str, ...] = (
    "SC_HA_MODE",
    "SC_NODE_NAME",
    # Architecture A (shared stores)
    "SC_REDIS_URL",
    "SC_CLUSTER_PEERS",
    "DATABASE_URL",
    "SC_S3_BUCKET",
    "SC_S3_ENDPOINT",
    # Architecture B (peer-sync)
    "SC_PEER_HOST",
    "SC_PEER_PORT",
    "SC_PEER_LISTEN_HOST",
    "SC_PEER_LISTEN_PORT",
    "SC_PEER_SECRET",
)


SECRET_KEYS: tuple[str, ...] = (
    "SC_PEER_SECRET",
    # DATABASE_URL may contain passwords; we leave it visible because
    # an empty placeholder doesn't compose well, but the form should
    # warn when it's set. (Future: parse out the password component.)
)


VALID_MODES = ("", "none", "shared-stores", "peer-sync")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def is_readonly() -> bool:
    return (os.getenv("SC_READONLY") or "").strip() in ("1", "true", "yes")


def mask_secret(s: str | None) -> str:
    """Show only the last 4 characters of a secret."""
    if not s:
        return ""
    s = str(s)
    if len(s) <= 4:
        return "•" * len(s)
    return "•" * (len(s) - 4) + s[-4:]


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------


def _parse_env_file(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        # Strip surrounding quotes if both ends match
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        out[k] = v
    return out


def read_config(path: Path | str | None = None) -> dict[str, Any]:
    """Read cluster.env. Secrets come back masked.

    Returns:
        {
          "values":     {KEY: value, ...},
          "masked":     {KEY: masked_value, ...},   # secrets masked, others verbatim
          "has_secrets":{KEY: bool, ...},
          "path":       str,
          "exists":     bool,
        }
    """
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    values: dict[str, str] = {}
    if p.exists():
        try:
            values = _parse_env_file(p.read_text("utf-8"))
        except Exception:
            values = {}
    masked = {}
    has_secrets = {}
    for k in KNOWN_KEYS:
        raw = values.get(k, "")
        has = bool(raw)
        if k in SECRET_KEYS and raw:
            masked[k] = mask_secret(raw)
        else:
            masked[k] = raw
        has_secrets[k] = has
    return {
        "values": {k: values.get(k, "") for k in KNOWN_KEYS},
        "masked": masked,
        "has_secrets": has_secrets,
        "path": str(p),
        "exists": p.exists(),
    }


# --------------------------------------------------------------------------
# Validate
# --------------------------------------------------------------------------


_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def validate(values: dict[str, Any]) -> list[str]:
    """Return a list of error strings. Empty = OK."""
    errors: list[str] = []
    mode = (values.get("SC_HA_MODE") or "").strip().lower()
    if mode not in VALID_MODES:
        errors.append(
            f"SC_HA_MODE must be one of {VALID_MODES!r}, got {mode!r}"
        )

    # Port checks
    for port_key in ("SC_PEER_PORT", "SC_PEER_LISTEN_PORT"):
        raw = (values.get(port_key) or "").strip()
        if raw:
            try:
                p = int(raw)
                if not (1 <= p <= 65535):
                    errors.append(f"{port_key} must be 1–65535, got {p}")
            except ValueError:
                errors.append(f"{port_key} must be a number, got {raw!r}")

    # Mode-specific requirements
    if mode == "peer-sync":
        secret = (values.get("SC_PEER_SECRET") or "").strip()
        if secret and len(secret) < 24:
            errors.append(
                "SC_PEER_SECRET must be ≥ 24 chars for peer-sync mode "
                f"(got {len(secret)})"
            )
        host = (values.get("SC_PEER_HOST") or "").strip()
        if not host:
            errors.append(
                "SC_PEER_HOST is required when SC_HA_MODE=peer-sync"
            )

    if mode == "shared-stores":
        redis = (values.get("SC_REDIS_URL") or "").strip()
        if redis and not redis.startswith(("redis://", "rediss://")):
            errors.append(
                "SC_REDIS_URL must start with redis:// or rediss://"
            )

    # Generic URL prefix sanity check
    db = (values.get("DATABASE_URL") or "").strip()
    if db and not _URL_RE.match(db):
        errors.append("DATABASE_URL must include a scheme:// prefix")

    return errors


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------


def write_config(
    values: dict[str, Any],
    path: Path | str | None = None,
) -> dict[str, Any]:
    """Persist values to the config file. Returns a status dict.

    Validation runs first; if there are errors, nothing is written.
    Empty SECRET values are interpreted as "keep current."

    Returns:
        {
          "ok":       bool,
          "path":     str,
          "errors":   list[str],
          "warnings": list[str],
          "wrote":    bool,
        }
    """
    if is_readonly():
        return {
            "ok": False,
            "path": str(path or DEFAULT_CONFIG_PATH),
            "errors": ["SC_READONLY=1 — cannot save peer config in demo mode"],
            "warnings": [],
            "wrote": False,
        }

    p = Path(path) if path else DEFAULT_CONFIG_PATH

    # Merge with existing — empty secrets mean "keep current"
    current = read_config(p)["values"]
    merged: dict[str, str] = {}
    warnings: list[str] = []
    for k in KNOWN_KEYS:
        incoming = (values.get(k) or "").strip()
        if k in SECRET_KEYS and not incoming:
            # Keep current secret
            merged[k] = current.get(k, "")
        elif incoming:
            merged[k] = incoming
        # else: dropped (k not present in output)

    errors = validate(merged)
    if errors:
        return {
            "ok": False, "path": str(p), "errors": errors,
            "warnings": warnings, "wrote": False,
        }

    # Atomic write: temp file in same dir, then rename
    p.parent.mkdir(parents=True, exist_ok=True)
    body_lines = [
        "# SafeCadence cluster configuration",
        "# Managed by the WebUI (/cluster-status/configure)",
        "# Manual edits are preserved but the form will rewrite this file",
        "",
    ]
    for k in KNOWN_KEYS:
        v = merged.get(k, "")
        if v:
            # Quote if value contains whitespace or special chars
            needs_quote = any(c in v for c in (" ", "\t", "#", '"', "'"))
            if needs_quote:
                v_out = '"' + v.replace('"', r"\"") + '"'
            else:
                v_out = v
            body_lines.append(f"{k}={v_out}")
    body = "\n".join(body_lines) + "\n"

    fd, tmp_path = tempfile.mkstemp(
        prefix=".cluster.env.", dir=str(p.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, p)
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return {
            "ok": False, "path": str(p),
            "errors": [f"write failed: {type(exc).__name__}: {exc}"],
            "warnings": warnings, "wrote": False,
        }

    if (values.get("SC_HA_MODE") or "").strip().lower() in ("shared-stores", "peer-sync"):
        warnings.append(
            "Saved. Restart the SafeCadence service to apply: "
            "`systemctl restart safecadence` (or `safecadence-demo` on the demo droplet)."
        )

    return {
        "ok": True, "path": str(p), "errors": [],
        "warnings": warnings, "wrote": True,
    }


__all__ = [
    "DEFAULT_CONFIG_PATH",
    "KNOWN_KEYS",
    "SECRET_KEYS",
    "VALID_MODES",
    "is_readonly",
    "mask_secret",
    "read_config",
    "validate",
    "write_config",
]
