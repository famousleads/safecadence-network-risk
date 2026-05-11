"""
SOC 2 / NIST / HIPAA evidence collection (v10.8).

Auditors want a folder of receipts. This module provides the folder
and indexes every receipt by the control it satisfies.

On-disk layout
--------------
::

    ~/.safecadence/orgs/<org_id>/evidence/
       <framework_slug>/
         <control_id>/
           <item_id>_<filename>
       evidence_index.jsonl    # append-only metadata

Public surface
--------------
* :class:`EvidenceItem`              — dataclass for a single piece of evidence
* :func:`attach_evidence`            — persist + index a file
* :func:`list_evidence`              — query the index
* :func:`export_evidence_pack`       — return a ZIP for a framework
* :func:`record_report_as_evidence`  — auto-capture hook called by the
  reports module when a compliance report is generated; writes a
  ``kind="report"`` evidence entry for every control covered by the
  report's scope.

Allowed ``kind`` values: ``screenshot`` / ``log`` / ``config`` /
``report`` / ``attestation``.

Read-only mode (``SC_READONLY=1``) refuses ``attach_evidence`` /
``record_report_as_evidence`` with ``PermissionError``. Listing +
exporting remain available so a demo deployment can still demo the
collected evidence.
"""

from __future__ import annotations

import csv
import dataclasses
import datetime as _dt
import io
import json
import os
import re
import secrets
import zipfile
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------


ALLOWED_KINDS = ("screenshot", "log", "config", "report", "attestation")


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _slugify(text: str) -> str:
    s = _SLUG.sub("-", (text or "").strip()).strip("-")
    return s or "default"


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def _org_dir(org_id: str) -> Path:
    if not org_id:
        raise ValueError("org_id is required")
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id)


def _evidence_root(org_id: str) -> Path:
    return _org_dir(org_id) / "evidence"


def _index_path(org_id: str) -> Path:
    return _evidence_root(org_id) / "evidence_index.jsonl"


def _file_dir(org_id: str, framework: str, control_id: str) -> Path:
    return _evidence_root(org_id) / _slugify(framework) / _slugify(control_id)


# --------------------------------------------------------------------------
# Dataclass
# --------------------------------------------------------------------------


@dataclasses.dataclass
class EvidenceItem:
    id: str
    org_id: str
    control_id: str
    framework: str
    kind: str
    file_ref: str        # absolute path inside the org's evidence tree
    captured_at: str
    captured_by: str | None = None
    note: str | None = None
    filename: str | None = None
    bytes_size: int = 0

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceItem":
        return cls(
            id=str(d.get("id") or ""),
            org_id=str(d.get("org_id") or ""),
            control_id=str(d.get("control_id") or ""),
            framework=str(d.get("framework") or ""),
            kind=str(d.get("kind") or ""),
            file_ref=str(d.get("file_ref") or ""),
            captured_at=str(d.get("captured_at") or ""),
            captured_by=d.get("captured_by"),
            note=d.get("note"),
            filename=d.get("filename"),
            bytes_size=int(d.get("bytes_size") or 0),
        )


# --------------------------------------------------------------------------
# Index
# --------------------------------------------------------------------------


def _append_index(org_id: str, item: EvidenceItem) -> None:
    p = _index_path(org_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(item.to_dict(), default=str) + "\n")


def _read_index(org_id: str) -> list[EvidenceItem]:
    p = _index_path(org_id)
    if not p.exists():
        return []
    out: list[EvidenceItem] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(EvidenceItem.from_dict(obj))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def attach_evidence(
    org_id: str,
    control_id: str,
    framework: str,
    kind: str,
    file_data: bytes,
    filename: str,
    note: str | None = None,
    user: str | None = None,
) -> EvidenceItem:
    """Persist a file under the org's evidence tree and index it."""
    if _is_readonly():
        raise PermissionError(
            "read_only: evidence cannot be attached when SC_READONLY=1"
        )
    if not control_id:
        raise ValueError("control_id is required")
    if not framework:
        raise ValueError("framework is required")
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"kind must be one of {ALLOWED_KINDS}, got {kind!r}")
    if not isinstance(file_data, (bytes, bytearray)):
        raise TypeError("file_data must be bytes")
    safe_name = _slugify(filename or "evidence.bin")
    item_id = "ev_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
    target_dir = _file_dir(org_id, framework, control_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / f"{item_id}_{safe_name}"
    target_path.write_bytes(bytes(file_data))
    item = EvidenceItem(
        id=item_id,
        org_id=org_id,
        control_id=control_id,
        framework=framework,
        kind=kind,
        file_ref=str(target_path),
        captured_at=_now_iso(),
        captured_by=user,
        note=note,
        filename=safe_name,
        bytes_size=len(file_data),
    )
    _append_index(org_id, item)
    # Hook into change_mgmt so the auditor's change log shows new
    # evidence as it lands. Best-effort.
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(
            org_id, "evidence_attached",
            before=None,
            after={
                "id": item.id, "framework": framework,
                "control_id": control_id, "kind": kind,
            },
            actor=user,
        )
    except Exception:  # pragma: no cover
        pass
    return item


def list_evidence(
    org_id: str,
    *,
    framework: str | None = None,
    control_id: str | None = None,
) -> list[EvidenceItem]:
    items = _read_index(org_id)
    if framework:
        items = [i for i in items if i.framework == framework]
    if control_id:
        items = [i for i in items if i.control_id == control_id]
    items.sort(key=lambda i: i.captured_at, reverse=True)
    return items


def export_evidence_pack(org_id: str, framework: str) -> bytes:
    """Return a ZIP containing every evidence file for ``framework`` plus
    a MANIFEST.csv listing each control + evidence file.

    The ZIP is built in-memory and is safe to stream to an HTTP
    response. Always returns at least the manifest (which may be
    empty-but-headed) so a downstream HTTP handler can serve a
    deterministic file shape.
    """
    items = list_evidence(org_id, framework=framework)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Manifest first so callers can preview without unpacking.
        manifest = io.StringIO()
        writer = csv.writer(manifest)
        writer.writerow([
            "id", "framework", "control_id", "kind",
            "captured_at", "captured_by", "filename", "bytes_size", "note",
        ])
        for it in items:
            writer.writerow([
                it.id, it.framework, it.control_id, it.kind,
                it.captured_at, it.captured_by or "",
                it.filename or "", it.bytes_size, (it.note or "").replace("\n", " "),
            ])
        zf.writestr("MANIFEST.csv", manifest.getvalue())
        for it in items:
            p = Path(it.file_ref)
            if not p.exists():
                continue
            arcname = f"{_slugify(it.framework)}/{_slugify(it.control_id)}/{p.name}"
            zf.write(p, arcname=arcname)
    return buf.getvalue()


def record_report_as_evidence(
    org_id: str,
    framework: str,
    control_ids: list[str],
    *,
    report_blob: bytes | None = None,
    report_filename: str | None = None,
    captured_by: str | None = None,
    note: str | None = None,
) -> list[EvidenceItem]:
    """Auto-capture hook fired when a report is generated.

    For each control in ``control_ids`` we attach a ``kind="report"``
    evidence item. When the same byte blob is shared across controls we
    still write one file per control so the manifest stays
    deterministic (auditors love deterministic).
    """
    if _is_readonly():
        return []
    items: list[EvidenceItem] = []
    blob = report_blob if isinstance(report_blob, (bytes, bytearray)) else b""
    fname = report_filename or f"report-{_now_iso()[:10]}.bin"
    for cid in control_ids or []:
        try:
            it = attach_evidence(
                org_id, cid, framework, "report",
                bytes(blob), fname,
                note=note or f"Auto-captured from {framework} report",
                user=captured_by,
            )
            items.append(it)
        except Exception:  # pragma: no cover
            continue
    return items


__all__ = [
    "ALLOWED_KINDS",
    "EvidenceItem",
    "attach_evidence",
    "list_evidence",
    "export_evidence_pack",
    "record_report_as_evidence",
]
