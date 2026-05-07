"""
v9.25 — file-backed settings store.

A single JSON file at ``$SAFECADENCE_HOME/settings.json`` holding
runtime-configurable values that operators want to set from the UI
instead of from env vars. Currently scoped to outbound notification
endpoints (Splunk HEC); future versions can grow it.

Design choices:
  - File-backed; no DB, no migration.
  - Env vars still win — `SC_*` env vars override the stored value.
    This means Docker / k8s deployments stay declarative if they want.
  - Sensitive values (tokens) are returned MASKED on read so they
    don't leak via the API. The full value is only used internally
    by the notifier.
  - Read is best-effort: missing file → empty dict, malformed →
    empty dict, never raises.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _settings_path() -> Path:
    home = os.environ.get("SAFECADENCE_HOME") or str(Path.home() / ".safecadence")
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "settings.json"


def _read_all() -> dict[str, Any]:
    p = _settings_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _write_all(data: dict[str, Any]) -> None:
    p = _settings_path()
    p.write_text(json.dumps(data, indent=2, sort_keys=True),
                  encoding="utf-8")


# ---------------------------------------------------------- Splunk HEC


def _mask(token: str) -> str:
    """Return a UI-safe preview that proves a value exists without
    leaking the secret. Empty/short tokens render as empty string."""
    if not token:
        return ""
    if len(token) <= 8:
        return "********"
    return token[:4] + "…" + token[-4:]


def get_splunk_config(*, masked: bool = True) -> dict[str, Any]:
    """Read Splunk HEC config. Env vars override stored values:
        SC_SPLUNK_HEC_URL, SC_SPLUNK_HEC_TOKEN, SC_SPLUNK_INDEX,
        SC_SPLUNK_SOURCE, SC_SPLUNK_SOURCETYPE.

    With ``masked=True`` (default for the UI), the token is replaced
    by a previewable mask. The notifier uses ``masked=False``.
    """
    s = _read_all().get("splunk", {}) or {}
    cfg = {
        "hec_url":     os.environ.get("SC_SPLUNK_HEC_URL")    or s.get("hec_url", ""),
        "hec_token":   os.environ.get("SC_SPLUNK_HEC_TOKEN")  or s.get("hec_token", ""),
        "index":       os.environ.get("SC_SPLUNK_INDEX")      or s.get("index", ""),
        "source":      os.environ.get("SC_SPLUNK_SOURCE")     or s.get("source", "safecadence"),
        "sourcetype":  os.environ.get("SC_SPLUNK_SOURCETYPE") or s.get("sourcetype", "safecadence:event"),
        "enabled":     bool(s.get("enabled", False)),
    }
    if masked:
        cfg["hec_token"] = _mask(cfg["hec_token"])
    return cfg


def set_splunk_config(*, hec_url: str | None = None,
                       hec_token: str | None = None,
                       index: str | None = None,
                       source: str | None = None,
                       sourcetype: str | None = None,
                       enabled: bool | None = None) -> dict[str, Any]:
    """Persist Splunk HEC config. Only fields explicitly passed are
    updated; pass ``None`` to leave a field alone.

    Special case: ``hec_token`` is preserved on UI saves where the
    submitted value is the masked string (i.e. caller didn't change
    it). Detection is "the value contains '…' or is all asterisks."
    """
    data = _read_all()
    s = data.get("splunk", {}) or {}

    if hec_url is not None:
        s["hec_url"] = hec_url.strip()
    if hec_token is not None:
        token = hec_token.strip()
        if token and "…" not in token and not _looks_like_mask(token):
            s["hec_token"] = token
        elif token == "":
            s["hec_token"] = ""
    if index is not None:
        s["index"] = index.strip()
    if source is not None:
        s["source"] = source.strip() or "safecadence"
    if sourcetype is not None:
        s["sourcetype"] = sourcetype.strip() or "safecadence:event"
    if enabled is not None:
        s["enabled"] = bool(enabled)

    data["splunk"] = s
    _write_all(data)
    return get_splunk_config(masked=True)


def _looks_like_mask(s: str) -> bool:
    return bool(s) and all(c == "*" for c in s)


# ---------------------------------------------------------- compliance mode


def get_compliance_mode() -> dict[str, Any]:
    """v9.31 — Compliance-off mode.

    SafeCadence shipped a heavy compliance suite in v9.27..v9.30. For
    shops that just want network/server hardening without auditor-
    facing surfaces, this flag hides /compliance, /risks, /evidence,
    and the framework picker on /policies.

    Three sources, in priority order:
      1. SC_COMPLIANCE_MODE env var (`off` | `on`)
      2. settings.json `compliance.enabled`
      3. default: on (preserves existing behavior)
    """
    env = (os.environ.get("SC_COMPLIANCE_MODE") or "").strip().lower()
    if env == "off":
        return {"enabled": False, "source": "env"}
    if env == "on":
        return {"enabled": True, "source": "env"}
    s = (_read_all().get("compliance") or {})
    if "enabled" in s:
        return {"enabled": bool(s["enabled"]), "source": "settings"}
    return {"enabled": True, "source": "default"}


def set_compliance_mode(enabled: bool) -> dict[str, Any]:
    """Persist the compliance-mode flag."""
    data = _read_all()
    data["compliance"] = {**(data.get("compliance") or {}),
                            "enabled": bool(enabled)}
    _write_all(data)
    return get_compliance_mode()
