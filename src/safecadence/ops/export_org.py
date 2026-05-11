"""
v11.3 — GDPR-style per-org data export.

``export_org(org_id, out_path)`` writes one JSON file containing every
piece of data the platform stores for that org:

* members + roles
* report templates (and saved-report metadata, not the rendered blobs
  unless ``include_blobs=True``)
* audit trail (both the legacy unchained log and the v11.3 chained log)
* risk acceptances
* pentest history
* change log entries
* scan history (summaries; the full configs are only inlined when
  ``include_blobs=True``)
* evidence index (file paths + sha256 only by default)
* the org row itself (name, owner, created_at)

The output is schema-versioned so we can evolve it without breaking
downstream consumers (Data Protection Officers will rely on this for
subject-access-request fulfilment).

This module is deliberately conservative about *reading* — every load
is wrapped in a try/except that falls back to an empty value. Producing
*some* export is always better than crashing because one auxiliary file
is malformed.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat() + "Z"


def _safe_read_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _safe_read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    continue
    except Exception:
        return rows
    return rows


def _org_dir(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id)


def _get_org_row(org_id: str) -> dict:
    try:
        from safecadence.storage.org_store import get_org
        org = get_org(org_id)
        if org is None:
            return {"id": org_id, "name": "(unknown)", "owner_email": "", "created_at": 0}
        return org.to_dict()
    except Exception:
        return {"id": org_id, "name": "(unknown)", "owner_email": "", "created_at": 0}


def _collect_files_index(base: Path, include_blobs: bool) -> list[dict]:
    """Walk ``base`` and return a manifest of every file under it.

    Each entry has ``{path, size, sha256}`` and, when
    ``include_blobs=True``, an additional ``content_b64`` field.
    """
    items: list[dict] = []
    if not base.exists():
        return items
    for root, _dirs, files in os.walk(base):
        for fn in files:
            p = Path(root) / fn
            if not p.is_file():
                continue
            try:
                data = p.read_bytes()
            except Exception:
                continue
            entry = {
                "path": p.relative_to(base).as_posix(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            if include_blobs:
                entry["content_b64"] = base64.b64encode(data).decode("ascii")
            items.append(entry)
    return items


def export_org(
    org_id: str,
    out_path: Path | str,
    *,
    include_blobs: bool = False,
) -> Path:
    """Serialize the org's full dataset to ``out_path``.

    The output is a single JSON file::

        {
          "schema_version": 1,
          "exported_at": "2026-05-11T12:34:56Z",
          "include_blobs": false,
          "org": {...},
          "data": {
            "members": [...],
            "templates": [...],
            "reports": [...],
            "audit_trail": [...],
            "audit_chain": [...],
            "risk_acceptances": [...],
            "pentest_history": [...],
            "change_log": [...],
            "scan_history": [...],
            "evidence_index": [{path, size, sha256, [content_b64]}],
          }
        }
    """
    if not org_id:
        raise ValueError("org_id is required")
    base = _org_dir(org_id)
    org_row = _get_org_row(org_id)

    members = _safe_read_json(base / "members.json", [])
    templates_dir = base / "reports" / "templates"
    templates: list[dict] = []
    if templates_dir.exists():
        for fp in sorted(templates_dir.glob("*.json")):
            obj = _safe_read_json(fp, None)
            if isinstance(obj, dict):
                templates.append(obj)

    saved_reports_dir = base / "reports" / "saved"
    saved_reports: list[dict] = []
    if saved_reports_dir.exists():
        for fp in sorted(saved_reports_dir.glob("*.json")):
            obj = _safe_read_json(fp, None)
            if isinstance(obj, dict):
                saved_reports.append(obj)

    audit_trail = _safe_read_jsonl(base / "audit.jsonl")
    audit_chain = _safe_read_jsonl(base / "audit_chain.jsonl")
    risk_acceptances = _safe_read_json(base / "risk_acceptance.json", [])
    pentest_history = _safe_read_jsonl(base / "pentest_history.jsonl")
    change_log = _safe_read_jsonl(base / "change_log.jsonl")
    scan_history = _safe_read_jsonl(base / "scan_history.jsonl")

    evidence_dir = base / "evidence"
    evidence_index = _collect_files_index(evidence_dir, include_blobs=include_blobs)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "exported_at": _now_iso(),
        "include_blobs": bool(include_blobs),
        "org": org_row,
        "data": {
            "members": members,
            "templates": templates,
            "reports": saved_reports,
            "audit_trail": audit_trail,
            "audit_chain": audit_chain,
            "risk_acceptances": risk_acceptances,
            "pentest_history": pentest_history,
            "change_log": change_log,
            "scan_history": scan_history,
            "evidence_index": evidence_index,
        },
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return out


__all__ = ["export_org", "SCHEMA_VERSION"]
