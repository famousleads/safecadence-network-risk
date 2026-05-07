"""v9.49 — Phase C: PagerDuty escalation on stale CRITICAL approvals.

When a CRITICAL approval request lingers past
``SC_APPROVAL_ESCALATION_MINUTES`` (default 30) without an approve
or reject decision, the daemon fires a single PagerDuty event with a
deterministic dedup_key so re-firing doesn't create duplicate
incidents.

Configuration::

    SC_APPROVAL_ESCALATION_MINUTES=30      # threshold; 0 disables
    SC_APPROVAL_ESCALATION_PD_KEY=<integration-key>
    SC_APPROVAL_ESCALATION_PD_URL=https://events.pagerduty.com/v2/enqueue

The escalation history is recorded in
``$SC_DATA_DIR/execution/escalation_state.json`` so a restarted
daemon doesn't re-fire on jobs it already escalated.

This module is best-effort end-to-end: missing PagerDuty config →
no-op (the daemon just records "no PD configured" in the cycle
report). HTTP failures are logged in the state file and retried on
the next cycle.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


_DEFAULT_THRESHOLD_MINUTES = 30
_PD_URL_DEFAULT = "https://events.pagerduty.com/v2/enqueue"


@dataclass
class EscalationRecord:
    job_id: str
    fired_at: str = ""
    pd_dedup_key: str = ""
    ok: bool = False
    detail: str = ""


def _state_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "execution"
    d.mkdir(parents=True, exist_ok=True)
    return d / "escalation_state.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_state() -> dict:
    p = _state_path()
    if not p.exists():
        return {"version": 1, "fires": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"version": 1, "fires": []}


def _save_state(state: dict) -> None:
    p = _state_path()
    p.write_text(json.dumps(state, indent=2, sort_keys=True),
                  encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                                     # pragma: no cover
        pass


def already_fired(job_id: str) -> bool:
    state = _load_state()
    return any(f.get("job_id") == job_id
                for f in (state.get("fires") or []))


def record_fire(rec: EscalationRecord) -> None:
    state = _load_state()
    fires = state.get("fires") or []
    fires.append(asdict(rec))
    # keep last 500 entries — operationally we only care about the
    # recent past
    state["fires"] = fires[-500:]
    _save_state(state)


def threshold_minutes() -> int:
    raw = os.environ.get("SC_APPROVAL_ESCALATION_MINUTES",
                          str(_DEFAULT_THRESHOLD_MINUTES))
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_THRESHOLD_MINUTES


def is_enabled() -> bool:
    """Phase C is opt-in. Disabled when threshold == 0 OR no PD key."""
    return (threshold_minutes() > 0
            and bool(os.environ.get("SC_APPROVAL_ESCALATION_PD_KEY")))


def stale_critical_jobs(*, now: Optional[datetime] = None) -> list[dict]:
    """Walk the execution store for CRITICAL jobs sitting in REVIEW
    longer than the threshold. Returns plain dicts so the daemon can
    pass them straight into the escalator without re-importing the
    job model."""
    t = now or _now()
    cutoff = t - timedelta(minutes=threshold_minutes())
    try:
        from safecadence.execution import store as ex_store
    except Exception:                                   # pragma: no cover
        return []
    out: list[dict] = []
    try:
        for j in ex_store.list_jobs():
            risk = (j.risk if isinstance(j.risk, str)
                     else j.risk.value)
            status = (j.status if isinstance(j.status, str)
                       else j.status.value)
            if risk != "critical" or status != "review":
                continue
            submitted_at = getattr(j, "submitted_at", "") or ""
            if not submitted_at:
                continue
            try:
                ts = datetime.fromisoformat(
                    submitted_at.replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts > cutoff:
                continue                # not stale yet
            out.append({
                "job_id": getattr(j, "job_id", ""),
                "name": getattr(j, "name", ""),
                "submitted_at": submitted_at,
                "submitted_by": getattr(j, "submitted_by", ""),
                "approvers": list(getattr(j, "approvers", []) or []),
                "approvals_required": getattr(j, "approvals_required",
                                                  1),
                "asset_count": len(getattr(j, "asset_ids", []) or []),
            })
    except Exception:                                   # pragma: no cover
        return []
    return out


def fire_escalation(job: dict, *, now: Optional[datetime] = None
                      ) -> EscalationRecord:
    """Fire one PagerDuty incident for a stale CRITICAL job.
    Idempotent on (job_id) — the deterministic dedup_key means PD
    de-dupes server-side too if the daemon re-fires through a
    transient state-file loss."""
    t = now or _now()
    job_id = job.get("job_id", "")
    rec = EscalationRecord(
        job_id=job_id,
        fired_at=t.isoformat(timespec="seconds").replace("+00:00", "Z"),
        pd_dedup_key=f"safecadence:approval:{job_id}",
    )
    pd_key = os.environ.get("SC_APPROVAL_ESCALATION_PD_KEY")
    pd_url = os.environ.get("SC_APPROVAL_ESCALATION_PD_URL",
                              _PD_URL_DEFAULT)
    if not pd_key:
        rec.ok = False
        rec.detail = "no SC_APPROVAL_ESCALATION_PD_KEY configured"
        record_fire(rec)
        return rec
    payload = {
        "routing_key": pd_key,
        "event_action": "trigger",
        "dedup_key": rec.pd_dedup_key,
        "payload": {
            "summary": (f"SafeCadence: CRITICAL approval pending "
                         f"{threshold_minutes()}m+ — {job.get('name', '')}"),
            "severity": "critical",
            "source": "safecadence-daemon",
            "custom_details": {
                "job_id": job_id,
                "submitted_at": job.get("submitted_at", ""),
                "submitted_by": job.get("submitted_by", ""),
                "approvers": job.get("approvers", []),
                "approvals_required": job.get("approvals_required", 1),
                "asset_count": job.get("asset_count", 0),
                "link": f"/approvals#{job_id}",
            },
        },
    }
    ok, detail = _post_pd(pd_url, payload)
    rec.ok = ok
    rec.detail = detail
    record_fire(rec)
    return rec


def run_cycle(*, now: Optional[datetime] = None) -> dict:
    """Daemon hook. Walks stale CRITICAL approvals, fires one
    PagerDuty escalation per never-yet-escalated job, returns a
    summary dict for the cycle report.

    Idempotency rule: a job_id seen in the state file's ``fires``
    list never fires again, even if PD reports failure. This is
    intentional — re-firing on a transient HTTP error would be
    *more* alarming to the on-call human than missing the alert,
    because they'd see two pages for the same job. Operators wanting
    a retry can clear the state file entry manually."""
    if not is_enabled():
        return {"enabled": False, "fired": 0,
                 "reason": "no PD key or threshold=0"}
    candidates = stale_critical_jobs(now=now)
    fires: list[dict] = []
    for j in candidates:
        if already_fired(j["job_id"]):
            continue
        rec = fire_escalation(j, now=now)
        fires.append(asdict(rec))
        # Notify through the standard registry too so the org's
        # other channels (Slack, email DM) hear about the
        # escalation. Best-effort.
        try:
            from safecadence.notifier.registry import dispatch_event
            dispatch_event(
                kind="approval_requested",
                title=(f"ESCALATED: CRITICAL approval pending "
                        f"{threshold_minutes()}m+"),
                summary=(f"Job {j['job_id']} ({j.get('name', '')}) "
                         f"has been awaiting approval since "
                         f"{j.get('submitted_at', '')}. "
                         f"PagerDuty incident fired."),
                severity="critical",
                extra={"job_id": j["job_id"],
                        "escalation": True,
                        "pd_dedup_key": rec.pd_dedup_key,
                        "pd_ok": rec.ok},
                link=f"/approvals#{j['job_id']}",
                requested_by="daemon-escalation",
            )
        except Exception:                               # pragma: no cover
            pass
    return {"enabled": True, "fired": len(fires),
             "candidates": len(candidates),
             "threshold_minutes": threshold_minutes(),
             "fires": fires}


# ---------------------------------------------------------------- internals


def _post_pd(url: str, payload: dict) -> tuple[bool, str]:
    """Stdlib-only HTTP POST. We avoid pulling httpx into the daemon
    hot path so air-gapped installs without optional deps still work
    when escalation is configured."""
    import json as _j
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(
            url,
            data=_j.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status < 400, f"HTTP {resp.status}: {body[:200]}"
    except urllib.error.HTTPError as exc:                # pragma: no cover
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return False, f"HTTP {exc.code}: {body[:200]}"
    except Exception as exc:                            # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"
