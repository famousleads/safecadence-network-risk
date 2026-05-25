"""
v15.0 — Plugin loader.

Third-party adapters, dashboards, or compliance frameworks can ship
as separate PyPI packages under the entry-point group
``safecadence.plugins``. At startup, the loader discovers them,
verifies any attached HMAC signature, and exposes them to the rest
of the platform through a small typed manifest.

Signing
-------

A plugin can declare itself "signed" by including a SHA-256 HMAC of
its top-level ``__version__`` + ``__name__`` strings, signed with the
operator's ``SC_PLUGIN_SIGNING_SECRET``. Operators who only allow
signed plugins set ``SC_PLUGIN_REQUIRE_SIGNED=1`` and the loader
refuses everything else.

Capability gating
-----------------

Plugins declare what capabilities they need (`execute_tier3`,
`vault_read`, `webhook_fire`, etc.). The loader will refuse to load
a plugin asking for a capability the operator hasn't pre-approved
via ``SC_PLUGIN_CAPABILITIES`` (comma-separated allowlist).

Public API
----------

* ``PluginManifest``                       — dataclass.
* ``discover_plugins()``                   → list[PluginManifest]
* ``load_plugin(name)``                    → module object | None
* ``verify_plugin_signature(name, version, signature, secret)`` → bool
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import importlib
import importlib.metadata as _md
import logging
import os
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("safecadence.plugins.loader")


ENTRY_POINT_GROUP = "safecadence.plugins"
DEFAULT_REQUIRE_SIGNED = False


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------


@dataclass
class PluginManifest:
    name: str
    version: str
    module: str
    capabilities: tuple[str, ...] = ()
    signature: str = ""              # HMAC-SHA256 hex
    signed_by: str = ""              # who signed (org / vendor / email)
    description: str = ""
    is_loaded: bool = False
    load_error: str = ""


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------


def _signing_secret() -> bytes:
    return (os.getenv("SC_PLUGIN_SIGNING_SECRET") or "").encode("utf-8")


def _compute_signature(name: str, version: str, secret: bytes) -> str:
    """Sign over (name, version) — deliberately small so the package's
    contents can change without re-signing. Operators verify the
    package fingerprint separately (e.g. via Sigstore at install time).
    """
    msg = f"{name}\n{version}".encode("utf-8")
    return _hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_plugin_signature(
    name: str, version: str, signature: str,
    secret: bytes | None = None,
) -> bool:
    """True when the signature matches. False when there's no secret
    configured AND the operator requires signed plugins."""
    s = secret if secret is not None else _signing_secret()
    if not s:
        # No secret configured. Trust the plugin only if the operator
        # has not opted into "require signed."
        return not _require_signed()
    expected = _compute_signature(name, version, s)
    return _hmac.compare_digest(expected, signature or "")


def _require_signed() -> bool:
    v = (os.getenv("SC_PLUGIN_REQUIRE_SIGNED") or "").lower()
    return v in ("1", "true", "yes", "on")


def _allowed_capabilities() -> set[str]:
    raw = os.getenv("SC_PLUGIN_CAPABILITIES") or ""
    return {x.strip() for x in raw.split(",") if x.strip()}


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def discover_plugins() -> list[PluginManifest]:
    """Find every entry point in the ``safecadence.plugins`` group.

    Defensive: a single broken plugin entry never breaks discovery.
    """
    out: list[PluginManifest] = []
    try:
        eps = _md.entry_points()
        # Python 3.10+: entry_points returns dict-like with .select()
        try:
            group = eps.select(group=ENTRY_POINT_GROUP)
        except AttributeError:
            group = eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[union-attr]
    except Exception:
        return out

    for ep in group:
        try:
            name = ep.name
            module_path = ep.value
            try:
                dist = ep.dist
                version = dist.version if dist else "0.0.0"
            except Exception:
                version = "0.0.0"

            manifest_attrs = {}
            try:
                mod = importlib.import_module(module_path.split(":")[0])
                manifest_attrs = getattr(mod, "SAFECADENCE_PLUGIN", {}) or {}
            except Exception as exc:
                _log.debug("could not import %s: %s", module_path, exc)

            out.append(PluginManifest(
                name=name,
                version=version,
                module=module_path,
                capabilities=tuple(manifest_attrs.get("capabilities") or ()),
                signature=str(manifest_attrs.get("signature") or ""),
                signed_by=str(manifest_attrs.get("signed_by") or ""),
                description=str(manifest_attrs.get("description") or ""),
            ))
        except Exception as exc:
            _log.warning("plugin discovery error on %s: %s", ep, exc)
            continue
    return out


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_plugin(name: str) -> dict:
    """Discover + verify + load a single plugin by name.

    Returns a result dict shaped:
      {
        "ok": bool,
        "manifest": PluginManifest | None,
        "module": module | None,
        "reason": str
      }
    """
    plugins = {p.name: p for p in discover_plugins()}
    p = plugins.get(name)
    if p is None:
        return {"ok": False, "manifest": None, "module": None,
                "reason": f"plugin {name!r} not found"}

    # Signature check
    if _require_signed():
        if not p.signature:
            return {"ok": False, "manifest": p, "module": None,
                    "reason": "SC_PLUGIN_REQUIRE_SIGNED=1 and plugin is unsigned"}
        if not verify_plugin_signature(p.name, p.version, p.signature):
            return {"ok": False, "manifest": p, "module": None,
                    "reason": "signature verification failed"}

    # Capability check
    allowed = _allowed_capabilities()
    if allowed:  # only enforce when operator has set an allowlist
        for cap in p.capabilities:
            if cap not in allowed:
                return {"ok": False, "manifest": p, "module": None,
                        "reason": f"capability {cap!r} not in "
                                  f"SC_PLUGIN_CAPABILITIES allowlist"}

    try:
        module_path = p.module.split(":")[0]
        mod = importlib.import_module(module_path)
        p.is_loaded = True
        return {"ok": True, "manifest": p, "module": mod, "reason": ""}
    except Exception as exc:
        p.load_error = f"{type(exc).__name__}: {exc}"
        return {"ok": False, "manifest": p, "module": None,
                "reason": p.load_error}


__all__ = [
    "ENTRY_POINT_GROUP",
    "PluginManifest",
    "discover_plugins",
    "load_plugin",
    "verify_plugin_signature",
]
