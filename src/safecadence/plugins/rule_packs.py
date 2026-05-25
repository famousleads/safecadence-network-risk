"""
v15.0 — Community rule pack registry.

Today, all SafeCadence rules live in ``data/rules/``. Rule packs let
third parties ship vertical-specific bundles (HIPAA-Cisco-IOS,
PCI-Fortinet, NIST-800-171-AWS, etc.) as standalone tarballs that
the operator can install with::

    safecadence rules add /path/to/pack.tgz
    safecadence rules add https://packs.example.com/healthcare.tgz

Manifest format
---------------

Each pack is a tarball or directory containing a ``manifest.json``::

    {
      "name": "hipaa-cisco-ios",
      "version": "1.2.0",
      "description": "HIPAA-aligned rules for Cisco IOS-XE 17.x",
      "author": "Example Compliance Co",
      "license": "MIT",
      "rules": ["rules/hipaa-acl-deny.yaml", "rules/hipaa-snmpv3.yaml"],
      "frameworks": ["hipaa", "nist-800-53"],
      "signature": "<HMAC-SHA256 hex over (name, version)>"
    }

Signing follows the same pattern as the plugin loader — operators
who only allow signed packs set ``SC_PLUGIN_REQUIRE_SIGNED=1`` and
unsigned packs are refused.

Storage layout
--------------

Installed packs live under ``~/.safecadence/rule_packs/<name>-<version>/``.
The platform's rule loader (existing v9.x) is unchanged; we just
augment the search path.

Public API
----------

* ``RulePackManifest`` — dataclass
* ``add_rule_pack(source)`` → ``{ok, manifest, installed_path, reason}``
* ``list_rule_packs()`` → list[RulePackManifest]
* ``verify_rule_pack(manifest)`` → bool
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import shutil
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger("safecadence.plugins.rule_packs")


PACKS_DIR_DEFAULT = Path.home() / ".safecadence" / "rule_packs"


@dataclass
class RulePackManifest:
    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    rules: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    signature: str = ""
    installed_path: str = ""

    @classmethod
    def from_json(cls, raw: dict, installed_path: str = "") -> "RulePackManifest":
        return cls(
            name=str(raw.get("name", "")),
            version=str(raw.get("version", "0.0.0")),
            description=str(raw.get("description", "")),
            author=str(raw.get("author", "")),
            license=str(raw.get("license", "")),
            rules=tuple(raw.get("rules") or ()),
            frameworks=tuple(raw.get("frameworks") or ()),
            signature=str(raw.get("signature", "")),
            installed_path=installed_path,
        )


def _packs_dir() -> Path:
    return Path(os.getenv("SC_RULE_PACKS_DIR") or PACKS_DIR_DEFAULT)


def _signing_secret() -> bytes:
    return (os.getenv("SC_PLUGIN_SIGNING_SECRET") or "").encode("utf-8")


def _require_signed() -> bool:
    v = (os.getenv("SC_PLUGIN_REQUIRE_SIGNED") or "").lower()
    return v in ("1", "true", "yes", "on")


def _compute_signature(name: str, version: str, secret: bytes) -> str:
    msg = f"{name}\n{version}".encode("utf-8")
    return _hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_rule_pack(manifest: RulePackManifest) -> bool:
    secret = _signing_secret()
    if not secret:
        return not _require_signed()
    expected = _compute_signature(manifest.name, manifest.version, secret)
    return _hmac.compare_digest(expected, manifest.signature or "")


# --------------------------------------------------------------------------
# add_rule_pack — accepts a tarball path, a directory path, or a URL
# --------------------------------------------------------------------------


def _is_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))


def _download(url: str, dest: Path) -> Path:
    """Download with a 30s timeout. Never follows file:// URLs."""
    if url.startswith("file://"):
        raise ValueError("file:// URLs not allowed (use a local path instead)")
    req = urllib.request.Request(url, headers={"User-Agent": "safecadence-rule-pack/15.0"})
    with urllib.request.urlopen(req, timeout=30) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    return dest


def _extract_tarball(src: Path, dest_dir: Path) -> Path:
    """Extract a tarball into dest_dir. Returns the dir holding the manifest.

    Refuses any path traversal — entries with absolute paths or '..'
    components are skipped.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(src, "r:*") as tf:
        for member in tf.getmembers():
            n = member.name
            if n.startswith("/") or ".." in n.split("/"):
                _log.warning("skipping unsafe path: %s", n)
                continue
            tf.extract(member, path=dest_dir)
    # Find manifest.json
    for p in dest_dir.rglob("manifest.json"):
        return p.parent
    raise ValueError("no manifest.json found inside tarball")


def add_rule_pack(source: str) -> dict:
    """Install a rule pack from a tarball, directory, or URL.

    Returns ``{"ok": bool, "manifest": RulePackManifest | None,
                "installed_path": str, "reason": str}``.
    Never raises.
    """
    try:
        src_path: Path
        with tempfile.TemporaryDirectory(prefix="sc_rp_") as workdir:
            wd = Path(workdir)
            if _is_url(source):
                tgz_path = wd / "pack.tgz"
                _download(source, tgz_path)
                src_path = _extract_tarball(tgz_path, wd / "unpacked")
            else:
                p = Path(source)
                if not p.exists():
                    return {"ok": False, "manifest": None,
                            "installed_path": "",
                            "reason": f"source not found: {source}"}
                if p.is_dir():
                    src_path = p
                else:
                    src_path = _extract_tarball(p, wd / "unpacked")

            manifest_path = src_path / "manifest.json"
            if not manifest_path.exists():
                return {"ok": False, "manifest": None,
                        "installed_path": "",
                        "reason": "manifest.json missing"}

            try:
                raw = json.loads(manifest_path.read_text("utf-8"))
            except Exception as exc:
                return {"ok": False, "manifest": None,
                        "installed_path": "",
                        "reason": f"manifest.json malformed: {exc}"}

            m = RulePackManifest.from_json(raw)
            if not m.name or not m.version:
                return {"ok": False, "manifest": m,
                        "installed_path": "",
                        "reason": "manifest must declare name + version"}

            if not verify_rule_pack(m):
                return {"ok": False, "manifest": m,
                        "installed_path": "",
                        "reason": "signature verification failed"}

            # Install into ~/.safecadence/rule_packs/<name>-<version>/
            target = _packs_dir() / f"{m.name}-{m.version}"
            if target.exists():
                shutil.rmtree(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_path, target)
            m.installed_path = str(target)
            return {"ok": True, "manifest": m,
                    "installed_path": str(target),
                    "reason": "installed"}
    except Exception as exc:
        _log.exception("add_rule_pack failed: %s", exc)
        return {"ok": False, "manifest": None, "installed_path": "",
                "reason": f"{type(exc).__name__}: {exc}"}


def list_rule_packs() -> list[RulePackManifest]:
    base = _packs_dir()
    if not base.exists():
        return []
    out: list[RulePackManifest] = []
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        mp = d / "manifest.json"
        if not mp.exists():
            continue
        try:
            raw = json.loads(mp.read_text("utf-8"))
            out.append(RulePackManifest.from_json(raw, installed_path=str(d)))
        except Exception:
            continue
    return out


__all__ = [
    "PACKS_DIR_DEFAULT",
    "RulePackManifest",
    "add_rule_pack",
    "list_rule_packs",
    "verify_rule_pack",
]
