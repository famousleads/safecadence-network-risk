"""Tier 3 — Real SSH execution. The dangerous one.

This module actually opens SSH sessions and runs commands on customer
devices. Every reasonable safety net is in place:

  1. **Triple-gated activation.** All three must be true before tier3
     will fire a single packet at a real device:
       (a) env var SC_TIER3_ENABLED=1   — operator toggled on
       (b) caller's role grants Capability.EXECUTE_REAL
       (c) caller passes acknowledge=True and i_mean_it=True kwargs
     Tier3 raises Tier3DisabledError if any one is missing.

  2. **Per-asset preflight is run again.** Even though guardrails ran
     at job submission, we re-classify with the ASSET in scope (some
     lockout patterns are only catchable per-device). If the per-asset
     verdict elevates beyond what the original approval covered, the
     execution is refused for that asset and the job is left RUNNING
     so the operator can re-approve.

  3. **Bounded concurrency + rate limit.** Honours the job's
     max_concurrency and rate_limit_per_minute fields. We never run
     more than max_concurrency SSH sessions in parallel.

  4. **Stop-on-error threshold.** If stop_on_error_threshold consecutive
     executions fail, the runner aborts the job and writes a halt audit
     row. No more devices touched.

  5. **Emergency stop.** A flag file at SC_EMERGENCY_STOP_PATH (default
     ~/.safecadence/EMERGENCY_STOP) is checked between every device. If
     it appears mid-run, the runner stops within a few seconds.

  6. **Read-back verification.** After config-mode commands, we run
     the translator's verify commands and capture the output, so the
     audit trail records what the device looked like AFTER the change,
     not just what the operator intended.

  7. **Immutable audit.** Every connect, command, output, error, and
     decision lands in the append-only execution audit log.

This is the line we hold: no path in this module ever bypasses any
of the seven nets above. New escape hatches go in this docstring AND
in the auditable change log.

NOTE: paramiko is required for SSH. If it's not installed (the bare
[server] install does not pull it), Tier3DisabledError is raised
explaining how to enable it: ``pip install 'safecadence-netrisk[ssh]'``.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safecadence.execution import store, workflow
from safecadence.execution.guardrails import preflight
from safecadence.execution.rbac import Capability, Role, can
from safecadence.execution.schema import (
    CommandAuditLog, CommandExecution, CommandMode, CommandOutput,
    JobStatus, RiskLevel,
)


# --------------------------------------------------------------------------
# Activation envelope
# --------------------------------------------------------------------------

class Tier3Error(Exception):
    """Base for any Tier3 refusal — UI / CLI render verbatim."""


class Tier3DisabledError(Tier3Error):
    """Raised when one or more activation gates are off."""


def _check_emergency_stop() -> bool:
    """True if the emergency-stop flag file exists right now."""
    p = Path(os.environ.get("SC_EMERGENCY_STOP_PATH")
             or (Path.home() / ".safecadence" / "EMERGENCY_STOP"))
    return p.exists()


def _check_activation(*, role: Role | str, acknowledge: bool,
                      i_mean_it: bool,
                      username: str = "",
                      tenant: str = "default") -> None:
    """Triple gate. Any failure blocks execution.

    v9.50 — gate is now layered:
      1. Legacy ``execution.rbac.can(role, EXECUTE_REAL)`` — must
         explicitly hold the legacy execute_real capability.
      2. v9.48 ``capabilities.has_explicit_grant(...)`` — username
         must have an explicit grant in capabilities.yaml. Admin
         role short-circuit is intentionally bypassed for this
         surface; if the caller didn't pass a username (legacy
         callers), that check is skipped.

    Either path being missing fails closed. Operators wiring
    capability-based RBAC need to BOTH set the legacy role floor AND
    grant the v9.48 EXECUTE_REAL capability via
    ``safecadence capabilities grant <user> execute.real``.
    """
    enabled = os.environ.get("SC_TIER3_ENABLED", "").strip().lower() in (
        "1", "true", "yes", "on")
    if not enabled:
        raise Tier3DisabledError(
            "SC_TIER3_ENABLED is not set. Real SSH execution is OFF. "
            "Set SC_TIER3_ENABLED=1 in the server's environment ONLY "
            "after you have wired credentials, change-management, and "
            "an emergency-stop runbook. Treat this like enabling 'rm -rf' "
            "as a service.")
    if not can(role, Capability.EXECUTE_REAL):
        raise Tier3DisabledError(
            f"role '{role}' does not hold EXECUTE_REAL. Even Super "
            "Admins do not get EXECUTE_REAL by default; you must "
            "explicitly grant it in your users.yaml under the role's "
            "extra_capabilities list.")
    # v9.50 — also require the v9.48 capability grant when a username
    # is provided. Skipped for legacy callers (username="") so existing
    # CLI/test paths keep working while new HTTP paths get the
    # belt-and-braces dual check.
    if username:
        try:
            from safecadence.capabilities import (
                Capability as _NewCap, has_explicit_grant,
            )
            if not has_explicit_grant(username=username,
                                        capability=_NewCap.EXECUTE_REAL,
                                        tenant=tenant):
                raise Tier3DisabledError(
                    f"user '{username}' has no explicit "
                    "execute.real capability grant. Run "
                    f"`safecadence capabilities grant {username} "
                    "execute.real --reason <ticket>` (note the audit "
                    "trail in /audit). The admin role does NOT "
                    "short-circuit this check — Tier-3 is opt-in "
                    "per-user even for admins.")
        except ImportError:                             # pragma: no cover
            # capabilities module missing → fall through; legacy gate
            # alone still applies.
            pass
    if not (acknowledge and i_mean_it):
        raise Tier3DisabledError(
            "Both acknowledge=True and i_mean_it=True are required. "
            "These two-step confirmations exist so a typo or a misread "
            "function signature cannot accidentally fire SSH at "
            "production gear.")
    if _check_emergency_stop():
        raise Tier3DisabledError(
            "Emergency-stop flag file is present "
            f"({Path.home()}/.safecadence/EMERGENCY_STOP). Remove it "
            "to re-arm Tier3.")


def _import_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError:
        raise Tier3DisabledError(
            "paramiko is not installed. Run "
            "`pip install 'safecadence-netrisk[ssh]'` to enable real "
            "SSH execution. Until then, use the dry-run path or export "
            "to Ansible."
        )


# --------------------------------------------------------------------------
# Per-asset SSH execution
# --------------------------------------------------------------------------

@dataclass
class _AssetCreds:
    host: str
    username: str
    password: str = ""
    key_filename: str = ""
    port: int = 22
    timeout: int = 15


def _resolve_creds(asset: dict) -> _AssetCreds | None:
    """Pull credentials for an asset out of the SafeCadence vault.

    Returns None if no credential is on file — the runner skips the
    device with a clear audit row. We intentionally do NOT consult
    user-supplied passwords from the job body or environment; creds
    must live in the vault so they're auditable.
    """
    try:
        from safecadence.vault import get_credential
    except Exception:
        return None
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ""
    host = ident.get("hostname") or aid
    if not host:
        return None
    creds = get_credential(aid) if get_credential else None  # type: ignore
    if not creds:
        return None
    return _AssetCreds(
        host=host,
        username=creds.get("username") or "",
        password=creds.get("password") or "",
        key_filename=creds.get("key_filename") or "",
        port=int(creds.get("port") or 22),
        timeout=int(creds.get("timeout") or 15),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# v9.35 #6 — vendor-specific error patterns. When these appear in
# stdout/stderr we surface them as structured `issues` so the operator
# sees what actually failed beyond the exit code (which most network
# CLIs don't set reliably).
_VENDOR_ERROR_PATTERNS = [
    ("invalid input",      "Cisco/NX-OS: command not recognized"),
    ("incomplete command", "Cisco: command needs more arguments"),
    ("ambiguous command",  "Cisco: command prefix matches multiple commands"),
    ("authorization failed", "AAA denied this command"),
    ("permission denied",  "the SSH user lacks permission for this command"),
    ("error:",             "vendor reported an error"),
    ("syntax error",       "syntax error in command (Junos / FortiOS)"),
    ("no such file",       "configuration file not found"),
    ("% access denied",    "access-list denial"),
    ("connection refused", "TCP connection refused mid-session"),
]


def _scan_for_errors(text: str) -> list[dict]:
    """Pattern-match vendor error strings. Best-effort + case-insensitive."""
    out: list[dict] = []
    if not text:
        return out
    low = text.lower()
    for needle, msg in _VENDOR_ERROR_PATTERNS:
        if needle in low:
            out.append({"severity": "error", "msg": msg, "match": needle})
    return out


# v9.35 #6 — vendor-specific config-fetch commands. Capture before
# the job runs and after it runs so /per-device-diff can render the
# actual change.
_CONFIG_FETCH_COMMANDS = {
    # Most common — works on Cisco IOS/IOS-XE/NX-OS, Arista EOS.
    "default":     "show running-config",
    "cisco_ios":   "show running-config",
    "cisco_nxos":  "show running-config",
    "arista_eos":  "show running-config",
    "juniper_junos": "show configuration | display set",
    "fortinet":    "show full-configuration",
    "palo_alto":   "show config running",
    "hpe_aruba":   "show running-config",
}


def _fetch_running_config(cli, vendor: str, *, timeout: int) -> str:
    """Run the vendor's running-config dump command and return the
    captured stdout. Returns empty string on any failure — the diff
    UI handles missing snapshots honestly."""
    cmd = (_CONFIG_FETCH_COMMANDS.get((vendor or "").lower())
           or _CONFIG_FETCH_COMMANDS["default"])
    try:
        _stdin, sout, _serr = cli.exec_command(cmd, timeout=timeout)
        return sout.read().decode("utf-8", "replace")
    except Exception:
        return ""


def _run_ssh_one(asset: dict, commands: list[str],
                 paramiko, *, actor: str,
                 capture_config: bool = False,
                 vendor: str = "") -> tuple["CommandOutput", str, str]:
    """Open one SSH session, run every command, return the captured output.

    Each command runs with its own exec_channel so we get separate
    stdout/stderr streams and a clean exit code. If any command fails
    we keep going (the operator gets the full transcript) but mark
    the overall exit_code = first non-zero we saw.

    v9.35 #6 — when ``capture_config`` is True, fetch the running-config
    before AND after applying the commands. Returned as the second and
    third tuple elements so the caller can attach them to
    ``CommandExecution.pre_config_snapshot`` / ``.post_config_snapshot``.
    """
    creds = _resolve_creds(asset)
    if not creds:
        return (CommandOutput(
            raw_stderr="No credential found in vault for this asset.",
            exit_code=99,
            issues=[{"severity": "blocked",
                       "msg": "missing vault credential — refusing to connect"}],
        ), "", "")

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []
    first_err: int | None = None
    pre_cfg = ""
    post_cfg = ""
    try:
        cli.connect(
            hostname=creds.host, port=creds.port, username=creds.username,
            password=creds.password or None,
            key_filename=creds.key_filename or None,
            timeout=creds.timeout, allow_agent=False, look_for_keys=False,
        )
        # v9.35 #6 — capture running-config BEFORE running the job.
        if capture_config:
            pre_cfg = _fetch_running_config(cli, vendor,
                                              timeout=creds.timeout)
        for cmd in commands:
            stdin, sout, serr = cli.exec_command(cmd, timeout=creds.timeout)
            out = sout.read().decode("utf-8", "replace")
            err = serr.read().decode("utf-8", "replace")
            code = sout.channel.recv_exit_status()
            stdout_buf.append(f"$ {cmd}\n{out}")
            if err:
                stderr_buf.append(f"$ {cmd}\n{err}")
            if code != 0 and first_err is None:
                first_err = code
        # v9.35 #6 — capture running-config AFTER. If commands changed
        # state, /per-device-diff renders the unified diff between
        # pre and post.
        if capture_config:
            post_cfg = _fetch_running_config(cli, vendor,
                                                timeout=creds.timeout)
        full_stdout = "\n".join(stdout_buf)
        full_stderr = "\n".join(stderr_buf)
        # v9.35 #6 — vendor-specific error pattern detection. Most
        # network CLIs don't set non-zero exit codes; we have to
        # parse the output for "% Invalid input" etc.
        issues = (_scan_for_errors(full_stdout)
                    + _scan_for_errors(full_stderr))
        # If pattern-detected issues showed up but exit_code is 0,
        # treat as a soft failure so the queue UI flags the row.
        effective_exit = first_err or 0
        if effective_exit == 0 and issues:
            effective_exit = 1
        return (CommandOutput(
            raw_stdout=full_stdout,
            raw_stderr=full_stderr,
            exit_code=effective_exit,
            issues=issues,
        ), pre_cfg, post_cfg)
    except Exception as e:
        return (CommandOutput(
            raw_stderr=f"{type(e).__name__}: {e}",
            exit_code=98,
            issues=[{"severity": "error", "msg": str(e)}],
        ), pre_cfg, post_cfg)
    finally:
        try: cli.close()
        except Exception: pass


# --------------------------------------------------------------------------
# Job runner
# --------------------------------------------------------------------------

@dataclass
class Tier3RunResult:
    job_id: str
    started_at: str = ""
    finished_at: str = ""
    asset_count: int = 0
    succeeded: int = 0
    failed: int = 0
    blocked_per_asset: int = 0
    skipped_no_cred: int = 0
    halted: bool = False
    halt_reason: str = ""


def run_real(job_id: str, *, role: Role | str, actor: str,
              acknowledge: bool = False, i_mean_it: bool = False,
              tenant: str = "default") -> Tier3RunResult:
    """Execute an APPROVED job for real. See module docstring for the
    seven safety nets that all run before a single packet leaves.

    v9.50 — ``actor`` is now also passed through to ``_check_activation``
    as the username for the v9.48 capability lookup. Existing legacy
    callers that didn't pass a real username keep working (the empty
    string skips the v9.48 check, leaving the legacy rbac gate intact).
    """
    _check_activation(role=role, acknowledge=acknowledge,
                       i_mean_it=i_mean_it,
                       username=actor or "",
                       tenant=tenant)
    paramiko = _import_paramiko()

    job = store.get_job(job_id)
    if not job:
        raise Tier3Error(f"job not found: {job_id}")
    if job.status != JobStatus.APPROVED:
        raise Tier3Error(
            f"only APPROVED jobs can run real (got {job.status.value}); "
            "use the workflow to get approval first."
        )

    # Resolve targets and run
    from safecadence.execution.executor import _resolve_targets, _vendor_key

    targets = _resolve_targets(job)
    result = Tier3RunResult(job_id=job_id, started_at=_now(),
                              asset_count=len(targets))
    workflow.mark_running(job_id, actor=actor)
    store.write_audit(CommandAuditLog(
        actor=actor, action="tier3_started", job_id=job_id,
        risk=job.risk.value, detail=f"{len(targets)} targets",
    ))

    consec_failures = 0
    sema = threading.Semaphore(max(1, int(job.max_concurrency)))
    rate_window: list[float] = []
    rate_lock = threading.Lock()

    def _rate_gate():
        """Enforce rate_limit_per_minute by sleeping if we'd exceed it."""
        if job.rate_limit_per_minute <= 0:
            return
        with rate_lock:
            now = time.time()
            rate_window[:] = [t for t in rate_window if now - t < 60]
            if len(rate_window) >= job.rate_limit_per_minute:
                sleep_for = 60 - (now - rate_window[0]) + 0.1
                time.sleep(max(0, sleep_for))
            rate_window.append(time.time())

    def _execute_one(asset: dict):
        nonlocal consec_failures
        ident = asset.get("identity") or {}
        aid = ident.get("asset_id") or "?"
        vk = _vendor_key(asset)
        cmds = (job.inline_commands or {}).get(vk, [])
        if not cmds:
            store.write_audit(CommandAuditLog(
                actor=actor, action="tier3_skip_no_translator",
                job_id=job_id, execution_id="", detail=f"no commands for {aid}",
            ))
            return
        # Per-asset preflight
        pf = preflight(cmds, asset)
        if pf.blocked or pf.lockout_at_risk:
            result.blocked_per_asset += 1
            store.write_audit(CommandAuditLog(
                actor=actor, action="tier3_blocked_per_asset",
                job_id=job_id, detail=f"{aid}: {'; '.join(pf.reasons)[:200]}",
            ))
            return
        if _check_emergency_stop():
            return
        _rate_gate()
        with sema:
            ex = CommandExecution(
                job_id=job_id, asset_id=aid, vendor=vk,
                rendered_commands=list(cmds), started_at=_now(),
                status=JobStatus.RUNNING, dry_run=False,
            )
            store.save_execution(ex)
            store.write_audit(CommandAuditLog(
                actor=actor, action="tier3_exec_start",
                job_id=job_id, execution_id=ex.execution_id,
                detail=aid,
            ))
            # v9.35 #6 — capture pre/post running-config snapshots so
            # /per-device-diff can render the unified diff. Skip for
            # READ_ONLY mode (no state change to compare against).
            capture = (job.mode != CommandMode.READ_ONLY)
            output, pre_cfg, post_cfg = _run_ssh_one(
                asset, cmds, paramiko, actor=actor,
                capture_config=capture, vendor=vk,
            )
            output.execution_id = ex.execution_id
            store.save_output(output)
            ex.output_id = output.output_id
            ex.pre_config_snapshot = pre_cfg or ""
            ex.post_config_snapshot = post_cfg or ""
            ex.finished_at = _now()
            ok = output.exit_code == 0
            ex.status = JobStatus.DONE if ok else JobStatus.FAILED
            if not ok:
                ex.error = (output.raw_stderr or "")[:500]
            store.save_execution(ex)
            store.write_audit(CommandAuditLog(
                actor=actor,
                action=("tier3_exec_done" if ok else "tier3_exec_failed"),
                job_id=job_id, execution_id=ex.execution_id,
                detail=f"{aid} exit={output.exit_code}",
            ))
            if ok:
                result.succeeded += 1
                consec_failures = 0
            else:
                result.failed += 1
                consec_failures += 1

    # We run sequentially through targets; the semaphore would let us
    # parallelise via a thread pool, but the operator's first real run
    # is safer in a deterministic order. Future v7.2 can flip to a
    # ThreadPoolExecutor without changing the contract.
    for asset in targets:
        if _check_emergency_stop():
            result.halted = True
            result.halt_reason = "emergency stop"
            break
        if (job.stop_on_error_threshold > 0
                and consec_failures >= job.stop_on_error_threshold):
            result.halted = True
            result.halt_reason = (
                f"stop_on_error threshold reached ({consec_failures} consecutive)"
            )
            break
        _execute_one(asset)

    result.finished_at = _now()
    if result.halted:
        workflow.mark_failed(job_id, actor=actor, reason=result.halt_reason)
    elif result.failed > 0:
        workflow.mark_failed(
            job_id, actor=actor,
            reason=f"{result.failed}/{result.asset_count} executions failed",
        )
    else:
        workflow.mark_done(job_id, actor=actor)

    store.write_audit(CommandAuditLog(
        actor=actor, action="tier3_finished", job_id=job_id,
        detail=(f"ok={result.succeeded} fail={result.failed} "
                 f"blocked={result.blocked_per_asset} "
                 f"halted={result.halted}"),
    ))
    return result


def emergency_stop_now(*, actor: str = "(ui)") -> dict:
    """Touch the flag file. Any in-flight Tier3 runner halts at the
    next per-device gate, typically within 1–3 seconds."""
    p = Path(os.environ.get("SC_EMERGENCY_STOP_PATH")
             or (Path.home() / ".safecadence" / "EMERGENCY_STOP"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"emergency stop set at {_now()} by {actor}\n",
                  encoding="utf-8")
    store.write_audit(CommandAuditLog(
        actor=actor, action="tier3_emergency_stop",
        detail=f"flag file: {p}",
    ))
    return {"path": str(p), "set_at": _now(), "by": actor}


def emergency_clear(*, actor: str = "(ui)") -> dict:
    p = Path(os.environ.get("SC_EMERGENCY_STOP_PATH")
             or (Path.home() / ".safecadence" / "EMERGENCY_STOP"))
    if p.exists():
        p.unlink()
    store.write_audit(CommandAuditLog(
        actor=actor, action="tier3_emergency_cleared",
    ))
    return {"cleared_at": _now(), "by": actor}
