"""
Scheduled policy re-evaluation + alerting.

Background loop that:
  1. Wakes up on a configurable interval (default: hourly)
  2. Re-evaluates every saved policy against the current asset store
  3. Persists the new evaluation (so drift detection has history)
  4. Compares to the previous evaluation; if there are regressions
     (PASS → FAIL), fires the configured webhooks
  5. Logs every wake-up to the audit trail

Two run modes:
  - Foreground: `safecadence schedule run --interval 3600`
                Blocks the terminal, useful for systemd / launchd / PM2.
  - One-shot:   `safecadence schedule once`
                Runs the cycle exactly once and exits. For cron / Windows
                Task Scheduler users who'd rather schedule from the OS.

Cross-platform: pure Python, no fork(), no signal handlers — works on
Windows, Linux, macOS identically. Foreground loop honors Ctrl-C.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from safecadence.policy.audit import log as audit_log
from safecadence.policy.drift import detect_drift, persist_evaluation
from safecadence.policy.evaluator import evaluate
from safecadence.policy.store import get, list_policies
from safecadence.policy.webhooks import fire_for_evaluation


def _load_assets() -> list[dict]:
    """Read collected platform assets from the local store."""
    base = Path.home() / ".safecadence" / "platform_assets"
    if not base.exists():
        return []
    out = []
    for f in base.glob("*.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def run_cycle(*, actor: str = "scheduler",
              on_regression: Optional[Callable[[str, list], None]] = None) -> dict:
    """Run one re-evaluation cycle across every saved policy.

    Returns a summary dict so the caller (CLI / API / systemd unit) can log
    or surface it. `on_regression` is invoked once per policy that regressed
    with (policy_id, list_of_regressions).
    """
    assets = _load_assets()
    summaries = []
    total_regressions = 0
    fired_webhooks = 0

    for meta in list_policies():
        pid = meta.get("policy_id")
        if not pid:
            continue
        p = get(pid)
        if not p:
            continue

        ev = evaluate(p, assets)
        persist_evaluation(ev)

        drift = detect_drift(pid)
        regressions = drift.get("regressions") or []
        if regressions:
            total_regressions += len(regressions)
            if on_regression:
                try: on_regression(pid, regressions)
                except Exception: pass
            try:
                res = fire_for_evaluation(ev, actor=actor)
                fired_webhooks += res.get("sent", 0)
            except Exception:
                pass

        summaries.append({
            "policy_id": pid,
            "policy_name": p.policy_name,
            "pass": ev.pass_count, "fail": ev.fail_count, "na": ev.na_count,
            "regressions": len(regressions),
        })

    summary = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "policies_evaluated": len(summaries),
        "assets_scanned": len(assets),
        "regressions_detected": total_regressions,
        "webhooks_fired": fired_webhooks,
        "per_policy": summaries,
    }
    audit_log("scheduler_cycle", actor=actor, detail={
        k: v for k, v in summary.items() if k != "per_policy"
    })
    return summary


def run_loop(*, interval_seconds: int = 3600, actor: str = "scheduler",
             max_cycles: Optional[int] = None) -> None:
    """Block forever (or until max_cycles), running run_cycle() on interval.

    Honors KeyboardInterrupt cleanly. `max_cycles` is for tests.
    """
    interval = max(60, int(interval_seconds))    # don't allow < 60s in production
    cycle = 0
    audit_log("scheduler_started", actor=actor,
              detail={"interval_seconds": interval, "max_cycles": max_cycles})
    try:
        while True:
            cycle += 1
            summary = run_cycle(actor=actor)
            print(f"[scheduler] cycle {cycle} — "
                  f"policies={summary['policies_evaluated']} "
                  f"assets={summary['assets_scanned']} "
                  f"regressions={summary['regressions_detected']} "
                  f"webhooks={summary['webhooks_fired']}",
                  flush=True)
            if max_cycles is not None and cycle >= max_cycles:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        audit_log("scheduler_stopped", actor=actor, detail={"cycles_completed": cycle})
