"""Execution-engine dataclasses.

Naming + shape mirrors the database tables called for in the v7 spec:
command_templates, command_jobs, command_executions, command_outputs,
command_audit_logs, command_approvals, rollback_plans. We persist them
as JSON files (same pattern as policy_store) instead of a relational
DB so air-gapped + container deployments work without Postgres.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------
# Enumerations — kept str-valued for trivial JSON round-trip
# --------------------------------------------------------------------------

class JobStatus(str, enum.Enum):
    """Lifecycle of a command job."""

    DRAFT     = "draft"          # author still editing
    REVIEW    = "review"         # submitted, awaiting approval
    APPROVED  = "approved"       # ready to run; held in queue
    SCHEDULED = "scheduled"      # approved + scheduled for change window
    RUNNING   = "running"        # dry-run / execution in progress
    DONE      = "done"           # finished successfully
    FAILED    = "failed"         # finished with errors
    REJECTED  = "rejected"       # approver said no
    BLOCKED   = "blocked"        # guardrail killed it before execution
    ROLLED_BACK = "rolled_back"  # rollback plan applied after a bad run
    CANCELED  = "canceled"       # author or admin pulled the plug


class RiskLevel(str, enum.Enum):
    """Per-command risk used by guardrails + approval routing."""

    SAFE     = "safe"        # read-only show / get
    LOW      = "low"         # diagnostic, no state change
    MEDIUM   = "medium"      # operational, reversible
    HIGH     = "high"        # config change, real impact
    CRITICAL = "critical"    # disruptive, can lock out / lose data


class CommandMode(str, enum.Enum):
    """The kind of work a job does — controls UI and routing."""

    READ_ONLY    = "read_only"
    DIAGNOSTIC   = "diagnostic"
    CONFIG       = "config"
    REMEDIATION  = "remediation"
    ROLLBACK     = "rollback"
    VERIFICATION = "verification"
    EMERGENCY    = "emergency"


class ExecutionMethod(str, enum.Enum):
    """How the customer's automation tool will reach the device.

    SafeCadence does not perform the connection itself; we record
    the intended method so the exporter can render an Ansible playbook
    with the right `connection:` field, an NSO service with the right
    transport, etc.
    """

    SSH        = "ssh"
    REST_API   = "rest"
    NETCONF    = "netconf"
    GNMI       = "gnmi"
    POWERSHELL = "powershell"
    WINRM      = "winrm"
    REDFISH    = "redfish"
    IPMI       = "ipmi"
    CLOUD_API  = "cloud_api"
    MANUAL     = "manual"     # operator pastes into a CLI session


# --------------------------------------------------------------------------
# Core dataclasses
# --------------------------------------------------------------------------

@dataclass
class CommandTemplate:
    """A reusable per-vendor command set that a job can reference.

    Templates let an operator say 'use the standard BGP-health check'
    instead of pasting commands. Templates are version-pinned so a
    review approving v3 doesn't quietly start running v4 next week.
    """

    template_id: str = field(default_factory=lambda: _new_id("ctmpl"))
    name: str = ""
    description: str = ""
    mode: CommandMode = CommandMode.READ_ONLY
    risk: RiskLevel = RiskLevel.SAFE
    # Per-vendor command sets — keyed by translator vendor_target
    commands: dict[str, list[str]] = field(default_factory=dict)
    # Optional regex/parse rules to extract structured data from output
    parse_rules: dict[str, Any] = field(default_factory=dict)
    # Tags for search + filter in the UI
    tags: list[str] = field(default_factory=list)
    version: int = 1
    created_at: str = field(default_factory=_utc_iso)
    created_by: str = ""


@dataclass
class CommandJob:
    """The unit of intent — 'run this command set against these assets'.

    A job may target a single asset, a list of asset_ids, or an asset
    group. The guardrails layer expands the target into the concrete
    set of executions before approval.
    """

    job_id: str = field(default_factory=lambda: _new_id("job"))
    name: str = ""
    description: str = ""
    mode: CommandMode = CommandMode.READ_ONLY
    risk: RiskLevel = RiskLevel.SAFE
    status: JobStatus = JobStatus.DRAFT

    # Targeting — exactly one of these should be set, but the guardrail
    # layer resolves all three into a final list of asset_ids so the
    # executor doesn't need to care which form was used.
    target_asset_ids: list[str] = field(default_factory=list)
    target_asset_group_ids: list[str] = field(default_factory=list)
    target_filter: dict[str, Any] = field(default_factory=dict)

    # Either inline commands (per vendor) or a template reference
    template_id: str = ""
    inline_commands: dict[str, list[str]] = field(default_factory=dict)

    method: ExecutionMethod = ExecutionMethod.MANUAL

    # Bulk-execution controls
    max_concurrency: int = 5
    rate_limit_per_minute: int = 30
    stop_on_error_threshold: int = 3
    retries: int = 0

    # Change-window scheduling (None = run as soon as approved)
    scheduled_for: str | None = None

    # Approval state — populated during workflow
    approvals_required: int = 1
    approvers: list[str] = field(default_factory=list)
    # v9.42 — explicit invitation list (who got pinged when the job
    # was submitted). NOT an authorization list — the role gate in
    # workflow.approve() still enforces who can actually approve.
    # Empty = open queue (any qualified approver), preserving v9.41
    # default behaviour.
    approvers_invited: list[str] = field(default_factory=list)
    rejected_by: str = ""
    rejected_reason: str = ""

    # Linkage to the policy that motivated this job, if any
    source_policy_id: str = ""
    source_evaluation_id: str = ""

    # Rollback artefact created at approval time
    rollback_plan_id: str = ""

    # Authorship + tenant
    created_by: str = ""
    tenant: str = "local"
    created_at: str = field(default_factory=_utc_iso)
    updated_at: str = ""

    # Free-form tags (env=prod, team=netops, ticket=INC-1234)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        # Coerce enum-typed fields back from str payloads (JSON
        # round-trip drops the type). Without this, code that does
        # ``job.status.value`` blows up when the job came off disk.
        if isinstance(self.status, str):
            try: self.status = JobStatus(self.status)
            except ValueError: self.status = JobStatus.DRAFT
        if isinstance(self.mode, str):
            try: self.mode = CommandMode(self.mode)
            except ValueError: self.mode = CommandMode.READ_ONLY
        if isinstance(self.risk, str):
            try: self.risk = RiskLevel(self.risk)
            except ValueError: self.risk = RiskLevel.SAFE
        if isinstance(self.method, str):
            try: self.method = ExecutionMethod(self.method)
            except ValueError: self.method = ExecutionMethod.MANUAL


@dataclass
class CommandExecution:
    """A single (job, asset) pair — the row in the queue.

    Created by the guardrail layer when a job is approved: one
    execution per resolved asset target. Records lifecycle, the actual
    commands rendered for that asset's vendor, and a pointer to the
    captured output once the job has run.
    """

    execution_id: str = field(default_factory=lambda: _new_id("exec"))
    job_id: str = ""
    asset_id: str = ""
    vendor: str = ""
    status: JobStatus = JobStatus.APPROVED
    rendered_commands: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    output_id: str = ""
    error: str = ""
    # Set to True when this execution was simulated (dry-run) instead
    # of really executed by an external automation tool.
    dry_run: bool = True

    # v9.35 #3 — running-config snapshots for the diff viewer.
    # Populated by Tier-3 SSH (or any executor that can fetch them)
    # before and after applying the job. Empty for dry-runs and for
    # executions that didn't capture them.
    pre_config_snapshot: str = ""
    post_config_snapshot: str = ""


@dataclass
class CommandOutput:
    """Captured stdout/stderr + parsed structured data for one execution."""

    output_id: str = field(default_factory=lambda: _new_id("out"))
    execution_id: str = ""
    raw_stdout: str = ""
    raw_stderr: str = ""
    exit_code: int | None = None
    parsed: dict[str, Any] = field(default_factory=dict)
    issues: list[dict[str, Any]] = field(default_factory=list)
    captured_at: str = field(default_factory=_utc_iso)


@dataclass
class RollbackPlan:
    """Generated at approval time, applied if execution fails or the
    operator fires the emergency-stop button.

    The plan is per-asset because different vendors need different
    rollback strategies (Cisco IOS uses `do copy startup running`,
    NX-OS uses `rollback running-config`, AWS uses Terraform state).
    """

    plan_id: str = field(default_factory=lambda: _new_id("rb"))
    job_id: str = ""
    asset_rollbacks: dict[str, list[str]] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_iso)


@dataclass
class ApprovalRequest:
    """One approver decision on one job. A job needs N of these to
    transition from REVIEW → APPROVED, where N is risk-dependent."""

    approval_id: str = field(default_factory=lambda: _new_id("apr"))
    job_id: str = ""
    requested_by: str = ""
    requested_at: str = field(default_factory=_utc_iso)
    decided_by: str = ""
    decided_at: str = ""
    decision: str = "pending"   # pending | approved | rejected
    note: str = ""


@dataclass
class CommandAuditLog:
    """Append-only audit row. The store enforces no-edit / no-delete.
    Backwards-compat with the existing policy audit table."""

    audit_id: str = field(default_factory=lambda: _new_id("audit"))
    timestamp: str = field(default_factory=_utc_iso)
    actor: str = ""
    tenant: str = "local"
    action: str = ""              # state-change verb (e.g. job_approved)
    job_id: str = ""
    execution_id: str = ""
    risk: str = ""
    detail: str = ""
    before_state: str = ""
    after_state: str = ""
    approval_id: str = ""
