"""Secure Command Execution Engine — v7.0.

The privileged control plane that closes the biggest gap in the v6.x
line: a way to *act* on policy violations beyond emitting fix snippets.

Design principle (the one we will not compromise on):
  SafeCadence DOES NOT directly SSH into customer devices to run
  commands. That responsibility lives in the customer's existing
  automation tooling — Ansible, Salt, NSO, Cisco DNAC, etc. We are
  the brain (intent → vendor commands → approval → audit) and they
  are the hands (actually pushing config). This is the only sane
  position for a small open-source security platform: pretending we
  can replicate Ansible's safety story is how customers get locked
  out of their own datacenters.

What this engine DOES provide, end-to-end:

  1. AI Command Builder — natural language ("check BGP on all Cisco
     routers") becomes per-vendor command sets + execution plans.
  2. Risk classification — every command tagged safe / low / medium
     / high / critical with the heuristics documented per type.
  3. Blocked-command list — the 'reload', 'erase config', 'no aaa
     new-model' family of commands are hard-blocked or require a
     2-of-N approval flow.
  4. RBAC matrix — six tiers (Viewer / Auditor / Operator / Engineer
     / Security Admin / Super Admin) with a capability table.
  5. Approval workflow — Draft → Review → Approve → Deploy state
     machine, with multi-approver for critical and emergency override.
  6. Dry-run executor — simulates each job against the platform's
     asset snapshot, predicts which commands would PASS / FAIL / be
     blocked, surfaces lockout risk before any real execution.
  7. Export to real automation — every approved job can be exported
     as an Ansible playbook, NSO service, Salt state, or raw command
     list, with full rollback artefacts.
  8. Immutable audit trail — every state change captured in an
     append-only file. No edits, no deletes.

The submodules:
  schema    — dataclasses (CommandJob, CommandExecution, etc.)
  rbac      — 6-tier role matrix + capability checks
  guardrails — risk classifier + blocked-command list + lockout check
  builder   — AI command builder (intent → vendor commands)
  workflow  — approval state machine
  executor  — dry-run engine (no real SSH)
  store     — file-backed JSON persistence

Public API: import from this package; submodules are implementation
details that may move between releases.
"""

from __future__ import annotations

# Schema is the public contract; expose at the package level.
from safecadence.execution.schema import (        # noqa: F401
    CommandJob, CommandExecution, CommandOutput,
    RollbackPlan, ApprovalRequest, JobStatus, RiskLevel,
)
from safecadence.execution.rbac import (          # noqa: F401
    Role, Capability, can,
)
from safecadence.execution.guardrails import (    # noqa: F401
    classify_risk, is_blocked, lockout_risk,
)

__all__ = [
    "CommandJob", "CommandExecution", "CommandOutput",
    "RollbackPlan", "ApprovalRequest", "JobStatus", "RiskLevel",
    "Role", "Capability", "can",
    "classify_risk", "is_blocked", "lockout_risk",
]
