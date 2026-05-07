"""SafeCadence continuous daemon.

Runs in the background, re-evaluates every active policy + cross-system
drift detector + attack-path graph on a schedule, persists deltas to
``~/.safecadence/daemon.log`` (one JSON object per cycle), and fires
Slack alerts on new critical findings.

This is the piece that turns SafeCadence from "a CLI tool you remember
to run" into "a platform that monitors continuously." Without it the
intelligence layer is dead between scans.

Design choices:
  - Pure stdlib + already-required deps. No celery, no apscheduler.
  - Cross-platform (Linux/macOS/Windows) — uses ``time.sleep`` with a
    KeyboardInterrupt fast path so Ctrl+C exits cleanly.
  - Idempotent state file: each cycle writes a fresh snapshot AND
    appends a delta, so an operator can answer "what changed in the
    last hour" without scrolling raw findings.
  - Network-free by default: if no webhook is configured the daemon
    simply logs locally — useful for air-gapped sites.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# State file — captures the latest snapshot + a rolling delta history
# --------------------------------------------------------------------------

def _state_path() -> Path:
    base = Path(os.environ.get("SC_DAEMON_STATE")
                or (Path.home() / ".safecadence" / "daemon.json"))
    base.parent.mkdir(parents=True, exist_ok=True)
    return base


def _log_path() -> Path:
    return Path(os.environ.get("SC_DAEMON_LOG")
                or (Path.home() / ".safecadence" / "daemon.log"))


def _load_state() -> dict[str, Any]:
    p = _state_path()
    if not p.exists():
        return {"first_run": True, "last_cycle": None,
                "previous_findings": []}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"first_run": True, "last_cycle": None,
                "previous_findings": []}


def _save_state(state: dict[str, Any]) -> None:
    _state_path().write_text(json.dumps(state, indent=2, default=str),
                              encoding="utf-8")


def _append_log(entry: dict[str, Any]) -> None:
    p = _log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


# --------------------------------------------------------------------------
# A single cycle — runs every component and returns a flat finding list
# --------------------------------------------------------------------------

def run_cycle() -> dict[str, Any]:
    """Execute one full evaluation pass. Returns a structured report."""
    started = datetime.now(timezone.utc)
    findings: list[dict] = []

    # 1) Pull the current asset inventory.
    try:
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
    except Exception as e:                     # pragma: no cover
        return {"started_at": started.isoformat(), "error": str(e),
                "findings": []}

    # 2) Evaluate every saved policy.
    # v6.5.1 — Each evaluation is persisted via drift.persist_evaluation()
    # so the Drift tab actually accumulates a comparable history. Without
    # this call the daemon could run for a week and Drift would still
    # report "History: 0 evaluations" because every snapshot was thrown
    # away after the cycle finished.
    try:
        from safecadence.policy.evaluator import evaluate
        from safecadence.policy.store import (
            list_policies as _list, get as _get,
        )
        from safecadence.policy.drift import persist_evaluation
        for meta in _list():
            p = _get(meta["policy_id"])
            if not p:
                continue
            ev = evaluate(p, assets)
            # Persist for drift detection; non-fatal if the disk write
            # fails (read-only mount, full disk) — operators see the
            # cycle's findings either way.
            try:
                persist_evaluation(ev)
            except Exception:                       # pragma: no cover
                pass
            for v in (ev.violations or []):
                sev = v.severity.value if hasattr(v.severity, "value") else v.severity
                findings.append({
                    "source": "policy",
                    "type": "policy_violation",
                    "severity": sev,
                    "asset_id": v.asset_id,
                    "control_id": v.control_id,
                    "policy_id": p.policy_id,
                    "policy_name": p.policy_name,
                    "title": f"{p.policy_name} :: {v.control_id}",
                    "evidence": v.evidence,
                })
    except Exception:                           # pragma: no cover
        pass

    # 3) Run all 17 cross-system drift detectors.
    try:
        from safecadence.policy.cross_system_drift import detect_all
        d = detect_all(assets)
        for f in (d.get("findings") or []):
            findings.append({
                "source": "drift",
                "type": f.get("type", "drift"),
                "severity": f.get("severity", "medium"),
                "asset_id": (f.get("right") or {}).get("asset_id"),
                "title": f.get("type", "cross-system drift"),
                "conflict": f.get("conflict"),
                "resolution": f.get("resolution"),
            })
    except Exception:                           # pragma: no cover
        pass

    # 4) Compute internet → crown-jewel reachability.
    try:
        from safecadence.platform.attack_paths import top_k_paths_to_crown_jewels
        paths = top_k_paths_to_crown_jewels(assets, k=5, max_hops=4)
        for p in paths:
            findings.append({
                "source": "attack_path",
                "type": "internet_to_crown_jewel",
                "severity": "critical" if p["hops"] <= 2 else "high",
                "asset_id": p["target_asset_id"],
                "title": f"Reachable internet → {p['target_asset_id']} in {p['hops']} hops",
                "why": p.get("summary"),
            })
    except Exception:                           # pragma: no cover
        pass

    # v7.7 — auto-revoke expired JIT grants. Each expired grant carries
    # the revoke IR computed at creation time; the daemon doesn't have
    # IdP credentials by default so it just marks them expired and adds
    # a finding for the operator. Real-world auto-revoke happens when
    # the operator wires OKTA_API_TOKEN etc. and runs `safecadence
    # identity jit expire-due` (or this same cycle picks them up here).
    try:
        from safecadence.identity.jit import expire_due as _jit_expire
        expired = _jit_expire()
        for g in expired:
            findings.append({
                "source": "identity",
                "type": "jit_grant_expired",
                "severity": "info",
                "asset_id": g.resource,
                "principal": g.principal,
                "title": f"JIT grant {g.grant_id} expired — revoke pending",
                "why": (f"Grant for {g.principal} → {g.action} → "
                        f"{g.resource} via {g.target}"),
                "revoke_ir": g.revoke_ir,
            })
    except Exception:                           # pragma: no cover
        pass

    # v9.21 — fire any scheduled discovery jobs whose next_run_at has passed.
    # Each fire records mark_run() with ok/error so the UI shows status
    # and the next_run_at is bumped forward for the next cycle.
    discovery_jobs_run: list[dict] = []
    try:
        discovery_jobs_run = _run_due_discovery_jobs()
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] discovery-jobs cycle failed: {e}\n")

    # v9.25 — Safe Score snapshot. One row per cycle, retained 90 days.
    # The /home sparkline + /api/scores/safe/history endpoint both read
    # from this. Best-effort; failure here never aborts the cycle.
    score_snapshot = None
    try:
        from safecadence.scores import score_fleet_safe, append_snapshot
        fleet = score_fleet_safe(assets, findings=findings)
        score_snapshot = append_snapshot(fleet)
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] score snapshot failed: {e}\n")

    # v9.31 — compliance lifecycle hooks. All best-effort; a failure
    # here NEVER aborts the cycle — daemon resilience is the priority.
    compliance_hooks = {
        "exceptions_expired": 0,
        "expiring_findings_emitted": 0,
        "drift_findings_emitted": 0,
        "control_history_records": 0,
        "evidence_schedules_fired": 0,
    }
    try:
        from safecadence.compliance.evidence_schedule import (
            run_due_schedules,
        )
        fired = run_due_schedules()
        compliance_hooks["evidence_schedules_fired"] = len(fired)
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] evidence-schedule hook failed: {e}\n")

    # v9.32.2 — persist a PolicyEvaluation per policy this cycle so
    # detect_drift() has at least 2 history points to compare and
    # /drift's "Policy drift" tab actually populates. Best-effort.
    pe_count = 0
    try:
        from safecadence.policy.store import list_policies
        from safecadence.policy.evaluator import evaluate_policy
        from safecadence.policy.drift import persist_evaluation
        for p in (list_policies() or []):
            pid = p.get("id") or p.get("policy_id") or ""
            if not pid:
                continue
            try:
                ev = evaluate_policy(p, assets)
                persist_evaluation(ev)
                pe_count += 1
            except Exception:
                continue
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] policy-eval hook failed: {e}\n")
    compliance_hooks["policy_evaluations_persisted"] = pe_count
    try:
        from safecadence.compliance.exception_lifecycle import (
            auto_expire_past_due, expiring_exceptions_as_findings,
        )
        compliance_hooks["exceptions_expired"] = auto_expire_past_due()
        more = expiring_exceptions_as_findings(within_days=14)
        compliance_hooks["expiring_findings_emitted"] = len(more)
        # Append synthetic findings to the cycle's findings list so
        # the existing notifier path picks them up automatically.
        findings.extend(more)
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] exception-lifecycle hook failed: {e}\n")

    try:
        from safecadence.compliance.baseline_drift import (
            drift_findings_for_fleet,
        )
        drift = drift_findings_for_fleet(assets)
        compliance_hooks["drift_findings_emitted"] = len(drift)
        findings.extend(drift)
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] baseline-drift hook failed: {e}\n")

    # v9.31 — Type 2 evidence: record one test result per (asset,
    # control) when we evaluated something this cycle. We use the
    # existing per-asset findings to derive pass/fail per control.
    try:
        from safecadence.compliance.control_history import record as _rec
        # Build {(asset_id, control_id): outcome} from current findings.
        # No finding for an asset+control = pass. Finding present = fail.
        seen: set[tuple[str, str]] = set()
        for f in findings:
            cid = f.get("control_id") or ""
            aid = f.get("asset_id") or ""
            if not cid or not aid:
                continue
            seen.add((aid, cid))
            _rec(cid, aid, "fail",
                 method="config_inspection",
                 evidence_ref=f.get("id", ""),
                 evaluator="daemon")
            compliance_hooks["control_history_records"] += 1
        # Pass records: every (asset, mapped-control) that wasn't in seen.
        try:
            from safecadence.compliance.mappings import load_mappings
            controls = list(load_mappings().keys())
        except Exception:
            controls = []
        for a in assets:
            aid = (a.get("identity") or {}).get("asset_id") or ""
            if not aid or not controls:
                continue
            for cid in controls:
                if (aid, cid) in seen:
                    continue
                # Don't write a 'pass' for every (asset, control) pair —
                # that's noise. Only record a pass when the control
                # nominally applies to this asset's domain.
                # Cheap heuristic: skip — the v9.32 cycle will refine
                # applicability. For now, pass-records are written by
                # the policy evaluator when it explicitly tests a
                # control on an asset.
                pass
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] control-history hook failed: {e}\n")

    # v9.34.1 #1 — NHI stale-finder hook. Best-effort; never aborts.
    try:
        from safecadence.identity import nhi_store
        nhi_findings = nhi_store.stale_findings()
        for nf in nhi_findings:
            findings.append(nf)
        compliance_hooks["nhi_stale_findings_emitted"] = len(nhi_findings)
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] nhi-stale hook failed: {e}\n")
        compliance_hooks["nhi_stale_findings_emitted"] = 0

    # v9.34.1 #2 — Identity auto-resync. Iterates connected systems
    # from the IdentityVault and runs collect+normalize+save_asset.
    # Each system isolated — one slow Okta cycle never blocks AD.
    # Read-only against targets; never mutates them.
    resync_count = 0
    resync_errors: dict[str, str] = {}
    try:
        from safecadence.identity.vault import IdentityVault
        from safecadence.platform.adapters.identity_adapters import (
            ActiveDirectoryAdapter, CiscoISEAdapter, EntraIDAdapter,
            HPEClearPassAdapter, OktaAdapter,
        )
        from safecadence.server.platform_api import save_asset as _save_asset
        adapter_class = {
            "okta": OktaAdapter, "ise": CiscoISEAdapter,
            "ad": ActiveDirectoryAdapter, "entra": EntraIDAdapter,
            "clearpass": HPEClearPassAdapter,
        }
        vault = IdentityVault()
        for connected in (vault.list_connected() or []):
            sys_name = connected.get("system", "")
            cls = adapter_class.get(sys_name)
            if cls is None:
                continue
            try:
                rec = vault.load_creds(sys_name)
                if rec is None:
                    continue
                adapter = cls(target=rec.target,
                                credentials=dict(rec.credentials))
                asset_id = f"{sys_name}:{rec.target}"
                raw = adapter.collect(asset_id) or {}
                if isinstance(raw, dict) and raw.get("error"):
                    resync_errors[sys_name] = str(raw["error"])
                    continue
                unified = adapter.normalize(asset_id, raw)
                _save_asset(unified)
                vault.mark_synced(sys_name)
                resync_count += 1
            except Exception as exc:
                resync_errors[sys_name] = f"{type(exc).__name__}: {exc}"
                continue
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] identity-resync hook failed: {e}\n")
    compliance_hooks["identity_systems_resynced"] = resync_count
    if resync_errors:
        compliance_hooks["identity_resync_errors"] = resync_errors

    # v9.49 — Phase B: refresh the IdP-sourced approver-group cache.
    # @group:NAME invitees in approval flows resolve against this
    # snapshot. Best-effort; one slow IdP never aborts the cycle.
    try:
        from safecadence.identity.groups import refresh_from_adapters
        compliance_hooks["identity_groups_refresh"] = refresh_from_adapters()
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] identity-groups refresh failed: {e}\n")

    # v9.49 — Phase C: PagerDuty escalation on stale CRITICAL
    # approvals. Disabled unless SC_APPROVAL_ESCALATION_PD_KEY is
    # set. Idempotent — same job_id never fires twice.
    try:
        from safecadence.execution.escalation import run_cycle as _esc
        compliance_hooks["approval_escalation"] = _esc()
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] approval-escalation failed: {e}\n")

    # v9.55 — fire automation rules against this cycle's findings. The
    # whole point of automation is "if the daemon sees X, do Y" — and
    # before this hook the rules sat in automation.json doing nothing
    # unless someone clicked /api/intel/automation/preview by hand.
    #
    # Best-effort. A bad rule can't break the cycle: each fire is
    # caught inside evaluate_rules; this outer try is for the import +
    # scan_findings call. SC_AUTOMATION_DISABLED=1 short-circuits the
    # hook so deployments doing audit-only mode don't silently fire
    # actions.
    try:
        if os.environ.get("SC_AUTOMATION_DISABLED", "") not in ("1", "true"):
            from safecadence.intel.automation import evaluate_rules
            from safecadence.identity.findings import scan_findings
            ident_findings = scan_findings(assets)
            fires = evaluate_rules(ident_findings, apply_actions=True)
            compliance_hooks["automation_fires"] = len(fires)
        else:
            compliance_hooks["automation_fires"] = 0
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] automation hook failed: {e}\n")
        compliance_hooks["automation_fires"] = 0

    # v9.54 — activity-log retention. Pip-install deployments don't
    # have logrotate or the v9.53 systemd timer; this daemon hook
    # makes sure the JSONL directory doesn't grow forever.
    #
    # Retention defaults to 90 days. Override via
    # ``SC_ACTIVITY_RETENTION_DAYS=N`` in the environment. Set to 0
    # to disable (the systemd-timer / logrotate path is preferred
    # for production deployments — this is a safety net).
    try:
        retention = int(os.environ.get("SC_ACTIVITY_RETENTION_DAYS",
                                          "90") or "0")
        if retention > 0:
            from safecadence.activity import prune as _prune_activity
            compliance_hooks["activity_prune"] = _prune_activity(
                retention_days=retention,
            )
    except Exception as e:                          # pragma: no cover
        sys.stderr.write(f"[daemon] activity-prune failed: {e}\n")

    finished = datetime.now(timezone.utc)
    by_sev: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    return {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_sec": round((finished - started).total_seconds(), 2),
        "asset_count": len(assets),
        "finding_count": len(findings),
        "by_severity": by_sev,
        "findings": findings,
        "discovery_jobs": discovery_jobs_run,
        "score_snapshot": score_snapshot,
        "compliance_hooks": compliance_hooks,
    }


# --------------------------------------------------------------------------
# v9.21 — discovery-job runner
# --------------------------------------------------------------------------

def _run_due_discovery_jobs() -> list[dict]:
    """Read every persisted discovery job, fire any whose next_run_at has
    passed, mark_run() with ok/error. Returns a brief report per job
    that ran this cycle."""
    from datetime import datetime as _dt, timezone as _tz
    try:
        from safecadence.intel.discovery_jobs import (
            list_jobs, mark_run,
        )
    except Exception:
        return []
    now = _dt.now(_tz.utc)
    out: list[dict] = []
    for j in list_jobs():
        if not j.enabled:
            continue
        # Parse next_run_at; if blank or unparsable, treat as "due now"
        next_run = None
        if j.next_run_at:
            try:
                next_run = _dt.fromisoformat(j.next_run_at.replace("Z", "+00:00"))
                if next_run.tzinfo is None:
                    next_run = next_run.replace(tzinfo=_tz.utc)
            except Exception:
                next_run = None
        if next_run and next_run > now:
            continue                # not yet due
        # Fire the job. Each source has its own runner.
        ok, err = _fire_discovery_job(j)
        try:
            mark_run(j.job_id, ok=ok, error=err)
        except Exception:                           # pragma: no cover
            pass
        out.append({"job_id": j.job_id, "name": j.name,
                     "source": j.source, "ok": ok,
                     "error": err if not ok else ""})
    return out


def _fire_discovery_job(job) -> tuple[bool, str]:
    """v9.36 — thin shim over intel.discovery_jobs.fire_job.

    Kept as a module-level name for the daemon's existing call site and
    for any test that monkey-patches it. The real dispatcher lives in
    intel/discovery_jobs.py so the HTTP `run-now` endpoint can call the
    same code path (before v9.36 it didn't, which made Run Now a
    fake-success).
    """
    from safecadence.intel.discovery_jobs import fire_job
    try:
        return fire_job(job)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# --------------------------------------------------------------------------
# Delta — what's NEW since the previous cycle
# --------------------------------------------------------------------------

def _finding_key(f: dict) -> str:
    """Stable identity for dedupe across cycles."""
    return "|".join(str(f.get(k, "")) for k in
                    ("source", "type", "asset_id", "control_id", "policy_id"))


def diff_findings(previous: list[dict], current: list[dict]) -> dict[str, list[dict]]:
    """Return the set of findings that are NEW vs the previous cycle, plus
    the ones that have RESOLVED. Operators care about the delta — not the
    full snapshot every time."""
    prev_keys = {_finding_key(f) for f in (previous or [])}
    cur_keys = {_finding_key(f) for f in (current or [])}
    new = [f for f in current if _finding_key(f) not in prev_keys]
    resolved = [f for f in (previous or []) if _finding_key(f) not in cur_keys]
    return {"new": new, "resolved": resolved}


# --------------------------------------------------------------------------
# Public entry — one-shot or loop
# --------------------------------------------------------------------------

_RUNNING = True


def _install_signal_handlers() -> None:
    def _stop(signum, frame):                  # noqa: ARG001
        global _RUNNING
        _RUNNING = False
    try:
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
    except (ValueError, AttributeError):       # pragma: no cover
        # SIGTERM not available on Windows in some contexts; not fatal.
        pass


def run_daemon(*, interval: int = 1800, once: bool = False,
               slack_webhook: str | None = None) -> dict[str, Any]:
    """Run the daemon loop. ``once=True`` runs a single cycle (cron mode).

    Returns the last cycle's report so callers and tests can inspect it.
    """
    _install_signal_handlers()
    state = _load_state()
    last_cycle: dict[str, Any] = {}
    cycle_n = 0
    print(f"[safecadence-daemon] starting "
          f"(interval={interval}s, once={once}, "
          f"slack_alerts={'on' if slack_webhook else 'off'})", flush=True)
    while _RUNNING:
        cycle_n += 1
        try:
            report = run_cycle()
        except Exception as e:                  # pragma: no cover
            report = {"error": f"{type(e).__name__}: {e}"}
        delta = diff_findings(state.get("previous_findings") or [],
                              report.get("findings") or [])
        report["delta"] = {
            "new": len(delta["new"]),
            "resolved": len(delta["resolved"]),
        }
        report["cycle"] = cycle_n
        _append_log(report)
        crit_new = [f for f in delta["new"]
                    if (f.get("severity") or "").lower() == "critical"]
        if crit_new:
            # v9.44 — fan-out via dispatch_event so the email + per-user
            # routing built in v9.42-v9.43 fires the same way for every
            # CRITICAL finding the daemon spots. The legacy
            # ``--slack-webhook`` arg is honoured as the fallback
            # channel so existing deployments don't have to migrate.
            from safecadence.notifier.registry import dispatch_event
            fires = []
            for f in crit_new[:10]:        # cap noise
                title = f.get("title") or "New CRITICAL finding"
                summary = (f.get("summary") or
                            f.get("description") or "")
                res = dispatch_event(
                    kind="finding_critical",
                    title=title, summary=summary,
                    severity="critical",
                    extra={"asset_id": f.get("asset_id", ""),
                            "control_id": f.get("control_id", "")},
                    link="/findings",
                    requested_by="daemon",
                    channel_webhook=slack_webhook,   # back-compat
                )
                fires.append(res.to_audit_dict())
            report["dispatch"] = fires

        # v9.45 — fan out drift findings on the dedicated drift_detected
        # category so users who only care about cross-system drift can
        # opt in without subscribing to the firehose finding_critical
        # category. We send one notification per cycle (aggregated)
        # rather than one per finding so a noisy detector run doesn't
        # spam Slack.
        drift_new = [f for f in delta["new"]
                     if (f.get("source") or "").lower() in ("drift", "baseline_drift")]
        if drift_new:
            try:
                from safecadence.notifier.registry import dispatch_event
                by_sev: dict[str, int] = {}
                for f in drift_new:
                    s = (f.get("severity") or "info").lower()
                    by_sev[s] = by_sev.get(s, 0) + 1
                _SEV_ORDER = ["critical", "high", "medium", "low", "info"]
                summary = ", ".join(
                    f"{k}: {by_sev[k]}" for k in _SEV_ORDER if k in by_sev
                )
                worst = next((s for s in _SEV_ORDER if s in by_sev), "info")
                dispatch_event(
                    kind="drift_detected",
                    title=f"{len(drift_new)} new drift finding(s) this cycle",
                    summary=summary,
                    severity=worst,
                    extra={"count": len(drift_new),
                            "by_severity": by_sev,
                            "cycle": cycle_n},
                    link="/drift",
                    requested_by="daemon",
                )
            except Exception:                       # pragma: no cover
                pass
        state["previous_findings"] = report.get("findings") or []
        state["last_cycle"] = report
        state["first_run"] = False
        _save_state(state)
        last_cycle = report
        print(f"[safecadence-daemon] cycle {cycle_n}: "
              f"{report.get('finding_count', 0)} findings, "
              f"{report['delta']['new']} new, "
              f"{report['delta']['resolved']} resolved", flush=True)
        if once:
            break
        # Sleep in 1-second slices so Ctrl+C is responsive.
        for _ in range(int(interval)):
            if not _RUNNING:
                break
            time.sleep(1)
    print("[safecadence-daemon] stopped", flush=True)
    return last_cycle
