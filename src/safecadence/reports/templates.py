"""
Report template persistence.

Templates live as one JSON file per template under
``<data_dir>/reports/templates/<id>.json``. Schema:

    {
      "id":            "<slug>",
      "name":          "<display>",
      "description":   "...",
      "sections":      ["kpi_summary", "host_inventory", ...],
      "scope":         {...},
      "schedule_cron": "0 9 * * 1" | null,
      "share_token":   "<urlsafe-token>" | null,
      "created_at":    "<ISO-8601>",
      "updated_at":    "<ISO-8601>",
    }

When ``SC_READONLY=1`` is set in the environment, ``save_template`` and
``delete_template`` raise :class:`PermissionError` so the demo droplet
can mount the wizard without anyone mutating template files.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# data dir / path helpers
# --------------------------------------------------------------------------


def _data_dir() -> Path:
    """Return the user-level safecadence data dir, mirror of storage._data_dir()."""
    if os.environ.get("SC_DATA_DIR"):
        return Path(os.environ["SC_DATA_DIR"])
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "safecadence"


def _templates_dir() -> Path:
    d = _data_dir() / "reports" / "templates"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SLUG = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    s = _SLUG.sub("-", (name or "").lower()).strip("-")
    return s or "report"


def new_template_id(name: str | None = None) -> str:
    """Return a fresh, filesystem-safe id for a new template."""
    base = _slugify(name or "report")
    suffix = secrets.token_hex(4)
    return f"{base}-{suffix}"


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------


def _path_for(tpl_id: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]*", tpl_id or ""):
        raise ValueError(f"invalid template id: {tpl_id!r}")
    return _templates_dir() / f"{tpl_id}.json"


def save_template(template: dict) -> dict:
    """Persist `template`. Returns the saved dict (with id/timestamps filled)."""
    if _is_readonly():
        raise PermissionError("read_only: templates cannot be saved when SC_READONLY=1")
    if not isinstance(template, dict):
        raise TypeError("template must be a dict")
    tpl = dict(template)
    tpl_id = tpl.get("id") or new_template_id(tpl.get("name"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]*", tpl_id):
        tpl_id = new_template_id(tpl.get("name"))
    tpl["id"] = tpl_id
    tpl.setdefault("name", "Untitled report")
    tpl.setdefault("description", "")
    tpl.setdefault("sections", [])
    tpl.setdefault("scope", {})
    tpl.setdefault("schedule_cron", None)
    tpl.setdefault("share_token", None)
    tpl.setdefault("created_at", _now_iso())
    tpl["updated_at"] = _now_iso()

    path = _path_for(tpl_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(tpl, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    # v10.8: surface the save in the change log so hooks (jira/servicenow)
    # can react. Best-effort; never blocks the save.
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(
            tpl.get("org_id"),
            "template_saved",
            before=None,
            after={"id": tpl_id, "name": tpl.get("name")},
            actor=tpl.get("updated_by"),
        )
    except Exception:                              # pragma: no cover
        pass
    return tpl


def load_template(tpl_id: str) -> dict | None:
    path = _path_for(tpl_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_templates() -> list[dict]:
    out: list[dict] = []
    for p in sorted(_templates_dir().glob("*.json")):
        try:
            tpl = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(tpl, dict):
            out.append(tpl)
    out.sort(key=lambda t: t.get("updated_at") or t.get("created_at") or "", reverse=True)
    return out


def delete_template(tpl_id: str) -> bool:
    if _is_readonly():
        raise PermissionError("read_only: templates cannot be deleted when SC_READONLY=1")
    path = _path_for(tpl_id)
    if not path.exists():
        return False
    path.unlink()
    return True


# --------------------------------------------------------------------------
# share-link helpers
# --------------------------------------------------------------------------


def find_by_share_token(token: str) -> dict | None:
    if not token:
        return None
    for tpl in list_templates():
        if tpl.get("share_token") == token:
            return tpl
    return None


def ensure_share_token(tpl_id: str) -> dict:
    if _is_readonly():
        raise PermissionError("read_only: share tokens cannot be issued when SC_READONLY=1")
    tpl = load_template(tpl_id)
    if not tpl:
        raise KeyError(tpl_id)
    if not tpl.get("share_token"):
        tpl["share_token"] = secrets.token_urlsafe(24)
        tpl = save_template(tpl)
    return tpl


# --------------------------------------------------------------------------
# Rendered-report persistence (v10.7) — optional S3 / DO Spaces target
# --------------------------------------------------------------------------


def _rendered_dir() -> Path:
    d = _data_dir() / "reports" / "rendered"
    d.mkdir(parents=True, exist_ok=True)
    return d


def put_rendered_report(filename: str, body: bytes, content_type: str = "application/octet-stream") -> str:
    """Persist a freshly rendered report bundle.

    If ``SC_S3_BUCKET`` is set we PUT to object storage and return the
    canonical URL. Otherwise we write to ``<data_dir>/reports/rendered/``
    and return the local file:// URI. Demo / single-node installs keep
    using local disk with zero new dependencies.

    Always silently falls back to local disk on any S3 failure so a
    misconfigured bucket can't take the wizard down.
    """
    safe_name = re.sub(r"[^a-zA-Z0-9._\-/]", "_", filename or "report.bin")
    try:
        from safecadence.storage import s3_store as _s3
        if _s3.is_configured() and os.environ.get("SC_S3_BUCKET"):
            client = _s3.S3Store()
            key = f"reports/{_now_iso()[:10]}/{safe_name}"
            return client.put_object(key, body, content_type)
    except Exception:  # pragma: no cover
        pass

    # Local fallback
    if _is_readonly():
        # In read-only demos we don't persist — just return a synthetic URL.
        return f"memory:///{safe_name}"
    path = _rendered_dir() / safe_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path.as_uri()


__all__ = [
    "save_template", "load_template", "list_templates", "delete_template",
    "new_template_id", "find_by_share_token", "ensure_share_token",
    "put_rendered_report",
]
