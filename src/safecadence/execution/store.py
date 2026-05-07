"""File-backed JSON store for execution-engine artefacts.

One subdirectory per object type under ``~/.safecadence/execution/``:

    jobs/             {job_id}.json
    executions/       {execution_id}.json
    outputs/          {output_id}.json
    rollbacks/        {plan_id}.json
    approvals/        {approval_id}.json
    audit/            audit.log         (append-only JSONL)
    templates/        {template_id}.json

Same path-traversal protection as policy_store: every id passes
through the safe-path regex before any filesystem operation.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

from safecadence.execution.schema import (
    ApprovalRequest, CommandAuditLog, CommandExecution, CommandJob,
    CommandOutput, CommandTemplate, RollbackPlan,
)


_SAFE_ID = re.compile(r"^[A-Za-z0-9._\-:@]+$")


def _root() -> Path:
    base = Path(os.environ.get("SC_EXECUTION_STORE")
                or (Path.home() / ".safecadence" / "execution"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def _subdir(name: str) -> Path:
    p = _root() / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe_path(subdir: str, ident: str) -> Path:
    if not ident or not isinstance(ident, str):
        raise ValueError("id is required")
    if ".." in ident or "/" in ident or "\\" in ident:
        raise ValueError("id contains illegal characters")
    if not _SAFE_ID.match(ident):
        raise ValueError("id contains illegal characters")
    base = _subdir(subdir).resolve()
    target = (base / f"{ident}.json").resolve()
    try:
        target.relative_to(base)
    except ValueError as e:
        raise ValueError("id escapes store directory") from e
    return target


def _to_dict(obj: Any) -> dict:
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return dict(obj)


def _read_dataclass(cls: type, path: Path):
    if not path.exists():
        return None
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        # Trim keys that aren't on the dataclass (forwards-compat) AND
        # coerce enum-typed fields back from their str payload — JSON
        # round-trips str-valued enums as plain strings, and downstream
        # code (workflow, executor) expects the enum type so attribute
        # access like ``job.status.value`` keeps working.
        valid = cls.__dataclass_fields__
        kwargs: dict = {}
        import enum
        for k, v in d.items():
            if k not in valid:
                continue
            ftype = valid[k].type
            try:
                # Field type may be a string forward-ref. Resolve only
                # the simple case: it's an actual class object.
                if isinstance(ftype, type) and issubclass(ftype, enum.Enum):
                    kwargs[k] = ftype(v)
                    continue
            except Exception:
                pass
            kwargs[k] = v
        return cls(**kwargs)
    except Exception:
        return None


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------

def save_job(job: CommandJob) -> CommandJob:
    target = _safe_path("jobs", job.job_id)
    target.write_text(json.dumps(_to_dict(job), indent=2, default=str),
                       encoding="utf-8")
    return job


def get_job(job_id: str) -> CommandJob | None:
    try:
        return _read_dataclass(CommandJob, _safe_path("jobs", job_id))
    except ValueError:
        return None


def list_jobs(*, status: str | None = None,
              tenant: str | None = None) -> list[CommandJob]:
    out: list[CommandJob] = []
    for f in _subdir("jobs").glob("*.json"):
        j = _read_dataclass(CommandJob, f)
        if not j:
            continue
        if status and j.status != status:
            continue
        if tenant and j.tenant != tenant:
            continue
        out.append(j)
    out.sort(key=lambda j: j.created_at, reverse=True)
    return out


def delete_job(job_id: str) -> bool:
    try:
        p = _safe_path("jobs", job_id)
    except ValueError:
        return False
    if p.exists():
        p.unlink()
        return True
    return False


# --------------------------------------------------------------------------
# Executions / outputs / rollbacks / approvals
# --------------------------------------------------------------------------

def save_execution(ex: CommandExecution) -> CommandExecution:
    p = _safe_path("executions", ex.execution_id)
    p.write_text(json.dumps(_to_dict(ex), indent=2, default=str),
                  encoding="utf-8")
    return ex


def get_execution(execution_id: str) -> CommandExecution | None:
    try:
        return _read_dataclass(CommandExecution,
                                _safe_path("executions", execution_id))
    except ValueError:
        return None


def list_executions(job_id: str | None = None) -> list[CommandExecution]:
    out: list[CommandExecution] = []
    for f in _subdir("executions").glob("*.json"):
        e = _read_dataclass(CommandExecution, f)
        if not e:
            continue
        if job_id and e.job_id != job_id:
            continue
        out.append(e)
    out.sort(key=lambda e: e.started_at or "", reverse=True)
    return out


def save_output(out: CommandOutput) -> CommandOutput:
    p = _safe_path("outputs", out.output_id)
    p.write_text(json.dumps(_to_dict(out), indent=2, default=str),
                  encoding="utf-8")
    return out


def get_output(output_id: str) -> CommandOutput | None:
    try:
        return _read_dataclass(CommandOutput,
                                _safe_path("outputs", output_id))
    except ValueError:
        return None


def save_rollback(plan: RollbackPlan) -> RollbackPlan:
    p = _safe_path("rollbacks", plan.plan_id)
    p.write_text(json.dumps(_to_dict(plan), indent=2, default=str),
                  encoding="utf-8")
    return plan


def get_rollback(plan_id: str) -> RollbackPlan | None:
    try:
        return _read_dataclass(RollbackPlan,
                                _safe_path("rollbacks", plan_id))
    except ValueError:
        return None


def save_approval(req: ApprovalRequest) -> ApprovalRequest:
    p = _safe_path("approvals", req.approval_id)
    p.write_text(json.dumps(_to_dict(req), indent=2, default=str),
                  encoding="utf-8")
    return req


def list_approvals(job_id: str | None = None) -> list[ApprovalRequest]:
    out: list[ApprovalRequest] = []
    for f in _subdir("approvals").glob("*.json"):
        a = _read_dataclass(ApprovalRequest, f)
        if not a:
            continue
        if job_id and a.job_id != job_id:
            continue
        out.append(a)
    out.sort(key=lambda a: a.requested_at or "", reverse=True)
    return out


# --------------------------------------------------------------------------
# Audit log — append-only; we never rewrite or delete
# --------------------------------------------------------------------------

def _audit_path() -> Path:
    base = _subdir("audit")
    return base / "audit.log"


def write_audit(entry: CommandAuditLog) -> None:
    """Append a single JSON line. Never raises — audit failures must
    never block a privileged operation, but we make the failure visible
    via stderr so an operator can investigate."""
    try:
        with _audit_path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(_to_dict(entry), default=str) + "\n")
    except Exception as e:
        import sys
        print(f"[execution.audit] write failed: {e}", file=sys.stderr)


def read_audit(*, job_id: str | None = None,
                limit: int = 200) -> list[dict]:
    """Read the audit log. Filter by job_id if provided."""
    p = _audit_path()
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if job_id and row.get("job_id") != job_id:
                continue
            out.append(row)
    out.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return out[:limit]


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

def save_template(t: CommandTemplate) -> CommandTemplate:
    p = _safe_path("templates", t.template_id)
    p.write_text(json.dumps(_to_dict(t), indent=2, default=str),
                  encoding="utf-8")
    return t


def get_template(template_id: str) -> CommandTemplate | None:
    try:
        return _read_dataclass(CommandTemplate,
                                _safe_path("templates", template_id))
    except ValueError:
        return None


def list_templates() -> list[CommandTemplate]:
    out: list[CommandTemplate] = []
    for f in _subdir("templates").glob("*.json"):
        t = _read_dataclass(CommandTemplate, f)
        if t:
            out.append(t)
    out.sort(key=lambda t: t.name.lower())
    return out
