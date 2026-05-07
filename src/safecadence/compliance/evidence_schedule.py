"""
v9.32 — Scheduled evidence pack generation.

Cron-style configuration: tell SafeCadence "generate the SOC 2 pack
on the 1st of every month and email it to security@acme.com." The
daemon picks up the schedule each cycle, generates the pack, signs
the hash chain (we already auto-chain in v9.31), optionally emails it.

Trust posture:
  * Schedules live in $SC_DATA_DIR/evidence_schedule.json — local file,
    never transmitted.
  * No outbound email unless SMTP env vars are explicitly set; if
    they're not, the pack is written to disk and the run is logged.
  * Every generation appends to the tamper-evident chain so an
    auditor can verify "this pack was generated on $date and not
    altered since."
  * Past-due schedules don't fire-and-forget: each run records
    last_run_at + last_status so the operator can see history.

Schedules are simple and safe by design — every-day, every-week,
every-month, every-quarter. No arbitrary cron expressions (avoid the
"someone wrote `* * * * *` and now we generate 1440 PDFs / day"
foot-gun).
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


_VALID_FREQS = ("daily", "weekly", "monthly", "quarterly")
_VALID_FRAMEWORKS = ("soc2", "iso27001", "nist-800-53", "pci",
                       "hipaa", "zerotrust")


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "evidence_schedule.json"


def _read() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write(rows: list[dict]) -> None:
    _store_path().write_text(
        json.dumps(rows, indent=2), encoding="utf-8")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _next_run_for(freq: str, *, from_ts: Optional[datetime] = None
                    ) -> datetime:
    base = from_ts or _now()
    if freq == "daily":
        return base + timedelta(days=1)
    if freq == "weekly":
        return base + timedelta(days=7)
    if freq == "monthly":
        return base + timedelta(days=30)
    if freq == "quarterly":
        return base + timedelta(days=92)
    return base + timedelta(days=30)


@dataclass
class EvidenceSchedule:
    id: str
    framework: str
    freq: str
    enabled: bool = True
    next_run_at: str = ""
    last_run_at: str = ""
    last_status: str = ""           # ok | error | never
    last_error: str = ""
    last_pack_id: str = ""
    notify_email: str = ""          # comma-separated
    created_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------- crud


def create(*, framework: str, freq: str,
             notify_email: str = "") -> EvidenceSchedule:
    if framework not in _VALID_FRAMEWORKS:
        raise ValueError(f"framework must be one of {_VALID_FRAMEWORKS}")
    if freq not in _VALID_FREQS:
        raise ValueError(f"freq must be one of {_VALID_FREQS}")
    rec = EvidenceSchedule(
        id=f"sch-{uuid.uuid4().hex[:12]}",
        framework=framework, freq=freq,
        next_run_at=_next_run_for(freq).isoformat(),
        last_status="never",
        notify_email=notify_email.strip(),
        created_at=_now().isoformat(),
    )
    rows = _read()
    rows.append(rec.to_dict())
    _write(rows)
    return rec


def list_schedules() -> list[dict]:
    return _read()


def update_enabled(schedule_id: str, enabled: bool) -> bool:
    rows = _read()
    for r in rows:
        if r.get("id") == schedule_id:
            r["enabled"] = bool(enabled)
            _write(rows)
            return True
    return False


def delete(schedule_id: str) -> bool:
    rows = _read()
    new = [r for r in rows if r.get("id") != schedule_id]
    if len(new) == len(rows):
        return False
    _write(new)
    return True


# ---------------------------------------------------------- daemon hook


def _parse(ts: str) -> datetime:
    s = (ts or "").replace("Z", "+00:00")
    try:
        out = datetime.fromisoformat(s)
        if out.tzinfo is None:
            out = out.replace(tzinfo=timezone.utc)
        return out
    except Exception:
        return _now() - timedelta(days=10000)


def _email_pack(recipients: str, pack_bytes: bytes,
                  framework: str) -> tuple[bool, str]:
    """Send the pack as an email attachment. SMTP env vars must be
    set explicitly; otherwise we silently no-op (trust posture: no
    outbound by default)."""
    if not recipients.strip():
        return False, "no recipients configured"
    host = os.environ.get("SC_SMTP_HOST") or ""
    if not host:
        return False, "SC_SMTP_HOST not set — saved to disk only"
    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = (os.environ.get("SC_SMTP_FROM")
                          or "safecadence@localhost")
        msg["To"] = recipients
        msg["Subject"] = (f"SafeCadence evidence pack: {framework} "
                           f"({_now().strftime('%Y-%m-%d')})")
        msg.set_content(
            f"Attached: scheduled {framework} evidence pack.\n"
            "Pack hashed + chained — verify via "
            "/api/compliance/evidence-chain.")
        msg.add_attachment(pack_bytes, maintype="application",
                            subtype="pdf",
                            filename=f"{framework}-evidence.pdf")
        port = int(os.environ.get("SC_SMTP_PORT", "25"))
        with smtplib.SMTP(host, port, timeout=10) as s:
            user = os.environ.get("SC_SMTP_USER")
            pw = os.environ.get("SC_SMTP_PASS")
            if user and pw:
                s.starttls()
                s.login(user, pw)
            s.send_message(msg)
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def run_due_schedules() -> list[dict]:
    """Daemon hook: fire any schedule whose next_run_at has passed.

    Returns a per-schedule report dict. Best-effort: an exception in
    one schedule never aborts the others.
    """
    rows = _read()
    out: list[dict] = []
    now = _now()
    for r in rows:
        if not r.get("enabled", True):
            continue
        nxt = _parse(r.get("next_run_at", ""))
        if now < nxt:
            continue
        report = {"id": r.get("id"), "framework": r.get("framework"),
                    "fired_at": now.isoformat()}
        try:
            from safecadence.evidence_pack import generate as _gen
            pack = _gen(r["framework"])
            r["last_run_at"] = now.isoformat()
            r["last_status"] = "ok"
            r["last_error"] = ""
            # The chain auto-append happened inside generate().
            from safecadence.compliance.evidence_chain import list_chain
            chain = list_chain(framework=r["framework"], limit=1)
            if chain:
                r["last_pack_id"] = chain[0].get("pack_id", "")
            # Email if configured
            if r.get("notify_email"):
                ok, why = _email_pack(r["notify_email"], pack,
                                          r["framework"])
                report["emailed"] = ok
                report["email_status"] = why
            r["next_run_at"] = _next_run_for(
                r["freq"], from_ts=now).isoformat()
        except Exception as e:                          # pragma: no cover
            r["last_run_at"] = now.isoformat()
            r["last_status"] = "error"
            r["last_error"] = f"{type(e).__name__}: {e}"
            report["error"] = r["last_error"]
        out.append(report)
    if out:
        _write(rows)
    return out
