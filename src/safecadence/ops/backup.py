"""
v11.3 — Backup, verify, restore.

A backup is a single gzip'd tarball with this top-level layout::

    MANIFEST.json
    orgs/<org_id>/...              (verbatim copy of org_data_dir)
    state/schedules.yaml           (if present at $SAFECADENCE_HOME/)
    state/risk_acceptance.json     (if present)
    state/audit_trail.jsonl        (if present)
    state/audit_chain.jsonl        (if present)
    state/orgs.json                (the org index)
    state/portal.db                (sqlite, if present)

``MANIFEST.json`` lists every member file + its SHA-256 digest so that
:func:`verify_backup` can confirm the tarball is intact without
extracting it. The manifest also carries the SafeCadence version that
produced the archive, the timestamp, and the list of org ids included.

Design choices that mattered:

* Streaming tar (``tarfile.open(..., mode="w:gz")``) — no temp dir
  required, no double-disk-space requirement.
* SHA-256 computed *as we add the file* — single read pass.
* ``include_orgs=None`` means "all orgs"; pass a list to subset.
* :func:`verify_backup` re-hashes from the tar without writing to disk.
* :func:`restore_backup` rebuilds into ``target_dir`` (defaults to the
  live SafeCadence home), with ``dry_run=True`` short-circuiting before
  any disk writes.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
from typing import Iterable

from safecadence import __version__ as _SC_VERSION


# Files in $SAFECADENCE_HOME (NOT inside an org dir) that travel with the
# backup. Each is optional; if missing on disk we simply skip it.
_GLOBAL_STATE_FILES = (
    "schedules.yaml",
    "risk_acceptance.json",
    "audit_trail.jsonl",
    "audit_chain.jsonl",
    "orgs.json",
    "portal.db",
)


def _home_dir() -> Path:
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _sha256_bytes(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def _sha256_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _iter_org_files(org_id: str, home: Path) -> Iterable[Path]:
    """Yield every regular file under ``home/orgs/<org_id>/``."""
    base = home / "orgs" / org_id
    if not base.exists():
        return
    for root, _dirs, files in os.walk(base):
        for fn in files:
            p = Path(root) / fn
            if p.is_file():
                yield p


def _now_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _list_org_ids(home: Path) -> list[str]:
    orgs_dir = home / "orgs"
    if not orgs_dir.exists():
        return []
    return sorted([p.name for p in orgs_dir.iterdir() if p.is_dir()])


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def create_backup(
    out_dir: Path | str,
    *,
    include_orgs: list[str] | None = None,
    home: Path | None = None,
) -> Path:
    """Create a ``.tar.gz`` backup at ``out_dir`` and return its path.

    :param out_dir: destination directory; created if missing.
    :param include_orgs: optional whitelist of org ids; ``None`` = all.
    :param home: override the SafeCadence home dir (mainly for tests).
    """
    home = Path(home) if home is not None else _home_dir()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    org_ids = include_orgs if include_orgs is not None else _list_org_ids(home)
    stamp = _now_stamp()
    out_path = out_dir / f"safecadence-backup-{stamp}.tar.gz"

    manifest: dict = {
        "schema_version": 1,
        "safecadence_version": _SC_VERSION,
        "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat() + "Z",
        "org_ids": list(org_ids),
        "files": [],   # list of {path, size, sha256}
    }

    # We build the tar in two passes:
    #   pass 1 — write every member, recording sha256 + size into manifest
    #   pass 2 — write MANIFEST.json itself
    # We use a temp tar without manifest, then re-pack with manifest first.
    # Single-pass with manifest-last is also fine and simpler — readers
    # iterate the whole archive anyway. We choose single-pass-last so we
    # can stream without buffering.

    with tarfile.open(out_path, mode="w:gz") as tar:
        # Org dirs
        for org_id in org_ids:
            for fpath in _iter_org_files(org_id, home):
                rel = fpath.relative_to(home).as_posix()
                arcname = rel  # "orgs/<id>/..."
                digest = _sha256_file(fpath)
                size = fpath.stat().st_size
                tar.add(str(fpath), arcname=arcname)
                manifest["files"].append({
                    "path": arcname,
                    "size": size,
                    "sha256": digest,
                })

        # Global state files
        for fname in _GLOBAL_STATE_FILES:
            src = home / fname
            if not src.exists() or not src.is_file():
                continue
            arcname = f"state/{fname}"
            digest = _sha256_file(src)
            size = src.stat().st_size
            tar.add(str(src), arcname=arcname)
            manifest["files"].append({
                "path": arcname,
                "size": size,
                "sha256": digest,
            })

        # Manifest LAST (so the writer can record everything that came
        # before). Readers don't care about ordering.
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(name="MANIFEST.json")
        info.size = len(manifest_bytes)
        info.mtime = int(_dt.datetime.now(_dt.timezone.utc).timestamp())
        tar.addfile(info, io.BytesIO(manifest_bytes))

    return out_path


def _read_manifest(tar: tarfile.TarFile) -> dict:
    try:
        m = tar.getmember("MANIFEST.json")
    except KeyError:
        raise ValueError("MANIFEST.json missing from backup")
    fh = tar.extractfile(m)
    if fh is None:
        raise ValueError("MANIFEST.json unreadable")
    return json.loads(fh.read().decode("utf-8"))


def verify_backup(path: Path | str) -> dict:
    """Recompute every member's SHA-256 and compare with the manifest.

    Returns ``{ok: bool, errors: [str], file_count: int, manifest: dict}``.
    Never raises on tampering — surfaces the failure in ``errors`` so
    callers can present a readable report.
    """
    p = Path(path)
    errors: list[str] = []
    manifest: dict = {}
    file_count = 0
    try:
        with tarfile.open(p, mode="r:gz") as tar:
            try:
                manifest = _read_manifest(tar)
            except Exception as exc:
                return {"ok": False, "errors": [str(exc)], "file_count": 0, "manifest": {}}

            declared = {f["path"]: f for f in manifest.get("files", [])}
            seen: set[str] = set()
            for m in tar.getmembers():
                if m.name == "MANIFEST.json":
                    continue
                if not m.isfile():
                    continue
                file_count += 1
                seen.add(m.name)
                spec = declared.get(m.name)
                if spec is None:
                    errors.append(f"file not in manifest: {m.name}")
                    continue
                fh = tar.extractfile(m)
                if fh is None:
                    errors.append(f"unreadable: {m.name}")
                    continue
                data = fh.read()
                if len(data) != int(spec.get("size", -1)):
                    errors.append(
                        f"size mismatch: {m.name} "
                        f"(expected {spec.get('size')}, got {len(data)})"
                    )
                digest = _sha256_bytes(data)
                if digest != spec.get("sha256"):
                    errors.append(f"sha256 mismatch: {m.name}")

            for declared_path in declared.keys():
                if declared_path not in seen:
                    errors.append(f"missing file: {declared_path}")
    except (tarfile.TarError, OSError, gzip.BadGzipFile) as exc:
        return {
            "ok": False,
            "errors": [f"archive unreadable: {exc}"],
            "file_count": 0,
            "manifest": {},
        }
    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "file_count": file_count,
        "manifest": manifest,
    }


def restore_backup(
    path: Path | str,
    *,
    target_dir: Path | str | None = None,
    dry_run: bool = False,
) -> dict:
    """Extract ``path`` into ``target_dir`` (default: live SafeCadence home).

    Returns ``{ok: bool, restored: int, errors: [str], target: str}``.

    ``dry_run=True`` runs :func:`verify_backup` only — no files are
    touched, no directories are created.
    """
    verification = verify_backup(path)
    if not verification["ok"]:
        return {
            "ok": False,
            "restored": 0,
            "errors": ["verification failed:"] + verification["errors"],
            "target": "",
        }
    if dry_run:
        return {
            "ok": True,
            "restored": verification["file_count"],
            "errors": [],
            "target": "(dry-run)",
            "dry_run": True,
        }

    target = Path(target_dir) if target_dir is not None else _home_dir()
    target.mkdir(parents=True, exist_ok=True)
    restored = 0
    errors: list[str] = []
    with tarfile.open(Path(path), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.name == "MANIFEST.json":
                continue
            if not m.isfile():
                continue
            # state/<file> → target/<file>; orgs/... stays nested
            if m.name.startswith("state/"):
                dest = target / m.name[len("state/"):]
            else:
                dest = target / m.name
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                fh = tar.extractfile(m)
                if fh is None:
                    errors.append(f"unreadable: {m.name}")
                    continue
                dest.write_bytes(fh.read())
                restored += 1
            except Exception as exc:
                errors.append(f"{m.name}: {exc}")
    return {
        "ok": len(errors) == 0,
        "restored": restored,
        "errors": errors,
        "target": str(target),
    }


__all__ = ["create_backup", "verify_backup", "restore_backup"]
