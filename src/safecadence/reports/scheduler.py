"""
Schedule report generation + delivery — stdlib-only cron-style scheduler.

Schedules live in ``~/.safecadence/schedules.yaml`` (overridable via
``SC_SCHEDULES_PATH``). Each schedule is a small dict::

    {
      "id": "weekly-exec-monday",
      "name": "Weekly exec brief",
      "cron": "0 8 * * MON",
      "preset": "exec_brief",
      "format": "pdf",
      "to": ["ciso@acme.com"],
      "cc": [],
      "subject": "Weekly exec brief — {{date}}",
      "prepared_for": "Acme Corp",
      "enabled": true,
      "last_run": null,
      "last_status": null,
    }

The cron parser supports the canonical 5-field expression
``minute hour day month weekday`` with the following grammar per field:

  * ``*``            — wildcard
  * ``N``            — single integer
  * ``A,B,C``        — comma list of integers
  * ``A-B``          — inclusive range
  * ``*/N``          — step (every N units starting at 0)
  * ``MON TUE …``    — 3-letter weekday names (case insensitive)

This is intentionally narrower than full crontab semantics — it covers
every shape an analyst plausibly wants for a scheduled report without
pulling in croniter / APScheduler. Day-of-month and month fields are
parsed but day-of-week always wins for weekday-only schedules.

Running the scheduler
---------------------

Three options, in order of "would you like this to be managed for you":

  * ``safecadence report schedule run-due``     — invoke once, return.
  * ``safecadence report schedule daemon``      — loop forever, sleep.
  * A systemd unit and timer (recommended for prod):

.. code-block:: ini

    # /etc/systemd/system/safecadence-reports.service
    [Unit]
    Description=SafeCadence scheduled report runner
    After=network-online.target

    [Service]
    Type=simple
    Environment=SC_SMTP_HOST=smtp.example.com
    Environment=SC_SMTP_USER=relay
    Environment=SC_SMTP_PASS=...
    Environment=SC_SMTP_FROM=reports@example.com
    ExecStart=/usr/bin/safecadence report schedule daemon --interval 60
    User=safecadence
    Restart=on-failure
    RestartSec=10s

    [Install]
    WantedBy=multi-user.target

Then ``systemctl enable --now safecadence-reports.service``.
"""

from __future__ import annotations

import datetime as _dt
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml  # PyYAML is already a hard dep
    _YAML_OK = True
except Exception:  # pragma: no cover - PyYAML missing
    yaml = None
    _YAML_OK = False


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------


def _schedules_path() -> Path:
    """Return the canonical schedules file path, creating the parent dir."""
    override = os.environ.get("SC_SCHEDULES_PATH", "").strip()
    if override:
        p = Path(override)
    else:
        p = Path.home() / ".safecadence" / "schedules.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _serialize(items: list[dict]) -> str:
    """Render the schedules file. Falls back to a minimal YAML-like writer
    if PyYAML is missing (it never is in this repo, but be safe)."""
    payload = {"schedules": items}
    if _YAML_OK:
        return yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    # Minimal fallback — JSON is also valid YAML 1.2
    import json as _json
    return _json.dumps(payload, indent=2, sort_keys=False)


def _deserialize(raw: str) -> list[dict]:
    if not raw.strip():
        return []
    if _YAML_OK:
        try:
            data = yaml.safe_load(raw)
        except Exception:
            return []
    else:
        import json as _json
        try:
            data = _json.loads(raw)
        except Exception:
            return []
    if not isinstance(data, dict):
        return []
    items = data.get("schedules")
    return list(items) if isinstance(items, list) else []


def load_schedules() -> list[dict]:
    """Load all schedules from the persistence file. Returns [] if missing."""
    p = _schedules_path()
    if not p.exists():
        return []
    try:
        return _deserialize(p.read_text(encoding="utf-8"))
    except OSError:
        return []


def save_schedules(items: Iterable[dict]) -> None:
    """Persist the schedule list atomically."""
    p = _schedules_path()
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(_serialize(list(items)), encoding="utf-8")
    tmp.replace(p)


def _gen_id(name: str | None) -> str:
    base = "sched"
    if name:
        base = "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-")
        base = base or "sched"
    return f"{base}-{secrets.token_hex(3)}"


def add_schedule(item: dict) -> dict:
    """Append a schedule, generating an id if absent.

    Required keys: ``preset``, ``format``, ``to`` (list), ``cron``.
    Optional: ``name``, ``cc``, ``subject``, ``prepared_for``, ``enabled``.
    Returns the stored record (with id, defaults filled in).
    """
    if not isinstance(item, dict):
        raise TypeError("schedule must be a dict")
    rec = dict(item)
    rec.setdefault("name", rec.get("preset") or "Scheduled report")
    rec.setdefault("enabled", True)
    rec.setdefault("cc", [])
    rec.setdefault("subject", f"SafeCadence report — {{{{date}}}}")
    rec.setdefault("prepared_for", "")
    rec.setdefault("last_run", None)
    rec.setdefault("last_status", None)
    if not rec.get("id"):
        rec["id"] = _gen_id(rec.get("name"))
    if not rec.get("cron"):
        raise ValueError("schedule.cron is required (e.g. '0 8 * * MON')")
    if not rec.get("preset"):
        raise ValueError("schedule.preset is required")
    if not rec.get("format"):
        raise ValueError("schedule.format is required")
    if not rec.get("to"):
        raise ValueError("schedule.to (recipients list) is required")
    # Validate cron once so bad rows fail at add-time, not at run-time.
    parse_cron(rec["cron"])
    items = load_schedules()
    items.append(rec)
    save_schedules(items)
    return rec


def remove_schedule(sched_id: str) -> bool:
    """Remove a schedule by id. Returns True if a record was removed."""
    if not sched_id:
        return False
    items = load_schedules()
    new_items = [s for s in items if s.get("id") != sched_id]
    if len(new_items) == len(items):
        return False
    save_schedules(new_items)
    return True


def update_schedule(sched_id: str, **changes: Any) -> dict | None:
    """Patch fields on a schedule by id. Returns the updated record."""
    items = load_schedules()
    updated: dict | None = None
    for s in items:
        if s.get("id") == sched_id:
            s.update(changes)
            updated = s
            break
    if updated is None:
        return None
    save_schedules(items)
    return updated


# --------------------------------------------------------------------------
# Cron parser
# --------------------------------------------------------------------------


_DOW_NAMES = {
    "SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}


def _parse_field(expr: str, lo: int, hi: int, names: dict[str, int] | None = None) -> set[int]:
    """Parse one cron field into a set of ints (inclusive bounds [lo,hi])."""
    if expr is None:
        raise ValueError("empty cron field")
    expr = expr.strip()
    if not expr:
        raise ValueError("empty cron field")

    # Wildcard
    if expr == "*":
        return set(range(lo, hi + 1))

    out: set[int] = set()
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        # */N step on wildcard
        if part.startswith("*/"):
            try:
                step = int(part[2:])
            except ValueError as exc:
                raise ValueError(f"bad step in cron field: {part!r}") from exc
            if step <= 0:
                raise ValueError(f"step must be positive: {part!r}")
            out.update(range(lo, hi + 1, step))
            continue
        # A-B range, optionally with /step
        if "-" in part:
            range_part, _, step_part = part.partition("/")
            a, _, b = range_part.partition("-")
            try:
                ai = _to_int(a, names)
                bi = _to_int(b, names)
            except ValueError as exc:
                raise ValueError(f"bad range in cron field: {part!r}") from exc
            if ai > bi:
                raise ValueError(f"range start > end in {part!r}")
            step = int(step_part) if step_part else 1
            if step <= 0:
                raise ValueError(f"step must be positive in {part!r}")
            out.update(range(ai, bi + 1, step))
            continue
        # bare value or name
        try:
            out.add(_to_int(part, names))
        except ValueError as exc:
            raise ValueError(f"bad value in cron field: {part!r}") from exc

    valid = {v for v in out if lo <= v <= hi}
    if not valid:
        raise ValueError(f"cron field {expr!r} produced no values in [{lo},{hi}]")
    return valid


def _to_int(tok: str, names: dict[str, int] | None) -> int:
    tok = tok.strip()
    if names is not None:
        up = tok.upper()
        if up in names:
            return names[up]
    return int(tok)


def parse_cron(expr: str) -> dict[str, set[int]]:
    """Parse a 5-field cron expression. Raises ``ValueError`` on garbage."""
    if not isinstance(expr, str):
        raise ValueError("cron expression must be a string")
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(
            f"cron expression must have 5 fields (got {len(parts)}): {expr!r}"
        )
    minute, hour, dom, month, dow = parts
    return {
        "minute":  _parse_field(minute, 0, 59),
        "hour":    _parse_field(hour, 0, 23),
        "dom":     _parse_field(dom, 1, 31),
        "month":   _parse_field(month, 1, 12),
        "dow":     _parse_field(dow, 0, 6, _DOW_NAMES),
    }


def cron_matches(expr: str, when: _dt.datetime) -> bool:
    """Return True if the cron expression fires at ``when`` (UTC-aware)."""
    fields = parse_cron(expr)
    # Convert Python's weekday() (Mon=0..Sun=6) to cron-style (Sun=0..Sat=6)
    py_dow = when.weekday()
    cron_dow = (py_dow + 1) % 7
    return (
        when.minute in fields["minute"]
        and when.hour in fields["hour"]
        and when.day in fields["dom"]
        and when.month in fields["month"]
        and cron_dow in fields["dow"]
    )


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _render_subject(template: str, *, date: _dt.datetime) -> str:
    if not template:
        return f"SafeCadence report — {date.strftime('%Y-%m-%d')}"
    return (
        template
        .replace("{{date}}", date.strftime("%Y-%m-%d"))
        .replace("{{datetime}}", date.strftime("%Y-%m-%d %H:%M UTC"))
    )


def _compose_render_send(schedule: dict, *, now: _dt.datetime) -> dict:
    """Compose + render + send a single schedule. Returns a result dict.

    Imports are deferred so a smoke test or unit test can stub them at
    monkeypatch time.
    """
    from safecadence.reports.builder import compose_report
    from safecadence.reports.presets import apply_preset
    from safecadence.reports import renderers as _r
    from safecadence.reports import email_delivery as _email

    preset_id = schedule.get("preset") or "exec_brief"
    fmt = (schedule.get("format") or "pdf").lower()
    recipients = list(schedule.get("to") or [])
    cc = list(schedule.get("cc") or [])

    applied = apply_preset(preset_id, schedule.get("scope") or {})
    report = compose_report(
        sections=applied["sections"],
        scope=applied["scope"],
        title=f"SafeCadence NetRisk — {applied['name']}",
    )
    prep = (schedule.get("prepared_for") or "").strip()
    if prep:
        report.setdefault("brand", {})["prepared_for"] = prep

    render_map = {
        "html":  ("render_html", "html",  True),
        "pdf":   ("render_pdf",  "pdf",   True),
        "json":  ("render_json", "json",  False),
        "docx":  ("render_docx", "docx",  True),
        "pptx":  ("render_pptx", "pptx",  True),
        "xlsx":  ("render_xlsx", "xlsx",  True),
    }
    if fmt not in render_map:
        return {
            "id": schedule.get("id"),
            "ok": False,
            "error": f"unsupported format: {fmt}",
        }
    fn_name, ext, accepts_preset = render_map[fmt]
    fn = getattr(_r, fn_name)
    rendered = fn(report, preset=applied) if accepts_preset else fn(report)
    if isinstance(rendered, str):
        body_bytes = rendered.encode("utf-8")
    else:
        body_bytes = rendered

    subject = _render_subject(schedule.get("subject") or "", date=now)
    filename = f"safecadence-{preset_id}-{now.strftime('%Y%m%d')}.{ext}"
    err = _email.send_report(
        recipients=recipients,
        cc=cc,
        subject=subject,
        body_text=(
            f"Attached: SafeCadence NetRisk {applied['name']} "
            f"({fmt.upper()}, generated {now.strftime('%Y-%m-%d %H:%M UTC')})."
        ),
        attachment_bytes=body_bytes,
        attachment_filename=filename,
        attachment_mimetype=_email.mimetype_for_format(fmt),
    )
    return {
        "id": schedule.get("id"),
        "ok": err is None,
        "error": err,
        "format": fmt,
        "size_bytes": len(body_bytes),
        "preset": preset_id,
        "recipients": recipients,
    }


def _builtin_retention_pass(now_min: _dt.datetime) -> list[dict]:
    """v11.3 — built-in daily 03:00 UTC retention pass for every org.

    Walks every org under ``~/.safecadence/orgs/`` and runs
    :func:`safecadence.ops.retention.apply_retention` against each.
    Never raises; per-org failures are recorded in the result list.
    Only fires once per UTC day, at the configured hour:minute.
    """
    if now_min.hour != 3 or now_min.minute != 0:
        return []
    try:
        from safecadence.ops.retention import apply_retention
        from safecadence.storage.org_store import list_orgs
    except Exception:
        return []
    results: list[dict] = []
    try:
        orgs = list_orgs()
    except Exception:
        orgs = []
    for org in orgs:
        try:
            rep = apply_retention(org.id)
            results.append({
                "kind": "retention",
                "org_id": org.id,
                "ok": True,
                "total_purged": int(rep.get("total_purged") or 0),
            })
        except Exception as exc:                  # pragma: no cover
            results.append({
                "kind": "retention",
                "org_id": org.id,
                "ok": False,
                "error": str(exc),
            })
    return results


def run_due(now: _dt.datetime | None = None) -> list[dict]:
    """Find all enabled schedules whose cron expression matches ``now``
    (minute granularity) and execute them, persisting last_run/last_status.

    Returns a list of result dicts (one per schedule that fired). Also
    runs the v11.3 built-in daily retention pass at 03:00 UTC.
    """
    # v12.1 — HA guard: only the active cluster node fires scheduled
    # reports. Otherwise both nodes would each generate + deliver the
    # same report (and double-charge LLM tokens).
    try:
        from safecadence.cluster.guards import is_standby
        if is_standby():
            return [{"skipped": "standby cluster node"}]
    except Exception:
        pass

    # v12.2 — peer-sync: announce the scheduler tick to the standby.
    try:
        from safecadence.cluster.peer_sync import record_replicated_event
        record_replicated_event("scheduled_reports_tick", {
            "tick_at": int(_dt.datetime.now(_dt.timezone.utc).timestamp()),
        })
    except Exception:
        pass

    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)
    # Drop sub-minute precision so a schedule cannot fire twice in one minute.
    now_min = now.replace(second=0, microsecond=0)
    items = load_schedules()
    results: list[dict] = list(_builtin_retention_pass(now_min))
    changed = False
    for sched in items:
        if not sched.get("enabled", True):
            continue
        if not sched.get("cron"):
            continue
        try:
            matches = cron_matches(sched["cron"], now_min)
        except Exception as exc:
            sched["last_status"] = f"bad_cron: {exc}"
            changed = True
            continue
        if not matches:
            continue
        # Avoid double-firing in the same minute if run_due is called twice.
        if sched.get("last_run_minute") == now_min.strftime("%Y-%m-%dT%H:%M"):
            continue
        try:
            result = _compose_render_send(sched, now=now_min)
        except Exception as exc:  # pragma: no cover - defensive
            result = {"id": sched.get("id"), "ok": False, "error": str(exc)}
        sched["last_run"] = now_min.strftime("%Y-%m-%dT%H:%MZ")
        sched["last_run_minute"] = now_min.strftime("%Y-%m-%dT%H:%M")
        sched["last_status"] = "ok" if result.get("ok") else f"error: {result.get('error')}"
        results.append(result)
        changed = True
    if changed:
        save_schedules(items)
    return results


def daemon_loop(interval_seconds: int = 60, *, max_iterations: int | None = None) -> None:
    """Blocking loop — call :func:`run_due` every ``interval_seconds``.

    ``max_iterations`` is for tests; ``None`` means loop forever.
    """
    n = 0
    while True:
        try:
            run_due()
        except Exception:  # pragma: no cover - keep daemon alive
            pass
        n += 1
        if max_iterations is not None and n >= max_iterations:
            return
        time.sleep(max(1, int(interval_seconds)))


__all__ = [
    "load_schedules",
    "save_schedules",
    "add_schedule",
    "remove_schedule",
    "update_schedule",
    "parse_cron",
    "cron_matches",
    "run_due",
    "daemon_loop",
]
