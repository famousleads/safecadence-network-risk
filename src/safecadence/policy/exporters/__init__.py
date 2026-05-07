"""
Exporters — turn a RemediationPlan into a deliverable the user feeds
into their existing change-management process.

Each exporter is a pure text generator: in → bytes/str out. No I/O.
The CLI/API write the result; the exporters never touch disk.

Available formats:
  raw         per-asset config snippets, copy-paste friendly
  ansible     vendor-aware playbook (cisco.ios, arista.eos, junipernetworks.junos, ...)
  terraform   HCL fragments for the cloud controls
  powershell  Windows + Azure PowerShell scripts
  bash        Linux + AWS/GCP CLI scripts
  markdown    human-readable runbook with sections per asset
  pdf         polished PDF (uses reportlab if installed; falls back to a
              text representation that the CLI can print)
"""

from __future__ import annotations

from typing import Callable

from safecadence.policy.schema import RemediationPlan, SecurityPolicy


_EXPORTERS: dict[str, Callable[[SecurityPolicy, RemediationPlan], str | bytes]] = {}


def register_exporter(name: str):
    def deco(fn):
        _EXPORTERS[name] = fn
        return fn
    return deco


def export(format_name: str, policy: SecurityPolicy, plan: RemediationPlan):
    fn = _EXPORTERS.get(format_name)
    if not fn:
        raise KeyError(f"unknown export format: {format_name}. "
                       f"Available: {sorted(_EXPORTERS)}")
    return fn(policy, plan)


def list_exporters() -> list[str]:
    return sorted(_EXPORTERS)


# Auto-load all exporter modules.
from safecadence.policy.exporters import (  # noqa: E402,F401
    raw, ansible, terraform, powershell, bash, markdown, pdf,
)
