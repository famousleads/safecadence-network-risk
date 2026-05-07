"""
v7.6 — Conflict-resolution rules.

When two identity systems disagree about the same principal+action+
resource, what does SafeCadence do? Without an explicit rule, the
effective-permission resolver already does "most-specific deny wins";
that's safe but isn't always right. This module lets a tenant declare:

  * "AD always wins over Okta"
  * "ISE wins for network-edge actions"
  * "always escalate to human — log a finding, return DENY"

Configuration lives at ~/.safecadence/identity_conflict.yaml. We
ship a default that biases toward DENY-when-ambiguous to fail closed.

The effective-permission resolver is unchanged for backwards compat;
callers that want conflict resolution import `resolve_conflict()`
explicitly or pass a `precedence` argument to `decide()` (added in
v7.6).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from safecadence.identity.ir import Decision, Rule


@dataclass
class PrecedenceRule:
    """One precedence row: when these two systems disagree, this one wins."""
    winner: str                   # 'ad' | 'okta' | 'ise' | 'entra' | 'clearpass'
                                  # | 'human'  (escalate, return DENY+finding)
    when_systems: list[str] = field(default_factory=list)
    on_actions: list[str] = field(default_factory=list)   # empty = all
    on_environments: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class ConflictPolicy:
    rules: list[PrecedenceRule] = field(default_factory=list)
    default_winner: str = "human"                          # fail-closed default

    def select(self, systems: list[str], action: str = "",
               environment: str = "") -> PrecedenceRule:
        sysset = set(systems)
        for r in self.rules:
            if not (set(r.when_systems) <= sysset):
                continue
            if r.on_actions and action and action not in r.on_actions:
                continue
            if (r.on_environments and environment
                    and environment not in r.on_environments):
                continue
            return r
        return PrecedenceRule(winner=self.default_winner,
                               when_systems=list(systems),
                               note="default precedence")


# ---------------------------------------------------------------- public api


def load_policy(path: str | None = None) -> ConflictPolicy:
    """Load conflict-resolution rules from YAML. Returns the safe default
    if the file doesn't exist or can't be parsed."""
    if path is None:
        path = os.environ.get(
            "SC_IDENTITY_CONFLICT_FILE",
            str(Path.home() / ".safecadence" / "identity_conflict.yaml"))
    p = Path(path)
    if not p.exists():
        return _default_policy()
    try:
        import yaml
    except ImportError:
        return _default_policy()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return _default_policy()
    rules = []
    for r in (data.get("rules") or []):
        if not isinstance(r, dict):
            continue
        rules.append(PrecedenceRule(
            winner=str(r.get("winner", "human")),
            when_systems=list(r.get("when_systems") or []),
            on_actions=list(r.get("on_actions") or []),
            on_environments=list(r.get("on_environments") or []),
            note=str(r.get("note") or ""),
        ))
    return ConflictPolicy(
        rules=rules,
        default_winner=str(data.get("default_winner") or "human"),
    )


def resolve_conflict(decisions_by_system: dict[str, Decision],
                     *, policy: ConflictPolicy | None = None,
                     action: str = "",
                     environment: str = "") -> Decision:
    """Given per-system Decisions, pick a winner per the policy.

    Inputs
    ------
    decisions_by_system   { 'okta': Decision, 'ad': Decision, ... }
    policy                Loaded ConflictPolicy. If None, load_policy().

    Returns
    -------
    A single Decision with `chain` extended to include all consulted
    systems' rules and `reasons` augmented with the precedence note.
    If they all agree, returns the agreed decision unchanged.
    """
    if not decisions_by_system:
        return Decision(allowed=False, reasons=["no decisions provided"])

    pol = policy or load_policy()
    systems = sorted(decisions_by_system.keys())

    # Are they unanimous?
    allowed_set = {d.allowed for d in decisions_by_system.values()}
    if len(allowed_set) == 1:
        # All agree — collapse, but keep the chain merged
        d0 = next(iter(decisions_by_system.values()))
        merged_chain: list[Rule] = []
        merged_reasons = list(d0.reasons)
        merged_reasons.append("unanimous across: " + ", ".join(systems))
        for sys_, d in sorted(decisions_by_system.items()):
            merged_chain.extend(d.chain)
        return Decision(
            allowed=d0.allowed, chain=merged_chain,
            systems_consulted=systems, reasons=merged_reasons,
            requires_step_up=any(d.requires_step_up
                                  for d in decisions_by_system.values()),
            principal=d0.principal, action=d0.action, resource=d0.resource,
        )

    # Disagree — apply policy
    rule = pol.select(systems, action=action, environment=environment)
    chain: list[Rule] = []
    for d in decisions_by_system.values():
        chain.extend(d.chain)

    if rule.winner == "human":
        # Fail closed; emit a finding-style reason
        return Decision(
            allowed=False, chain=chain, systems_consulted=systems,
            reasons=[f"systems disagreed ({systems}); precedence=human → "
                      "DENY pending human review",
                      *([rule.note] if rule.note else [])],
            requires_step_up=False,
            principal=next(iter(decisions_by_system.values())).principal,
            action=next(iter(decisions_by_system.values())).action,
            resource=next(iter(decisions_by_system.values())).resource,
        )

    # Specific system wins
    winner_decision = decisions_by_system.get(rule.winner)
    if winner_decision is None:
        # Configured winner wasn't consulted — fall back to fail-closed
        return Decision(
            allowed=False, chain=chain, systems_consulted=systems,
            reasons=[f"precedence rule named '{rule.winner}' but it "
                      "didn't return a decision; failing closed"],
        )
    return Decision(
        allowed=winner_decision.allowed,
        chain=chain,
        systems_consulted=systems,
        reasons=[f"precedence rule winner: {rule.winner}",
                  *([rule.note] if rule.note else []),
                  *winner_decision.reasons],
        requires_step_up=winner_decision.requires_step_up,
        principal=winner_decision.principal,
        action=winner_decision.action,
        resource=winner_decision.resource,
    )


# ---------------------------------------------------------------- defaults


def _default_policy() -> ConflictPolicy:
    """Conservative default: AD wins for AD-vs-Okta on prod, otherwise
    fail-closed pending human review."""
    return ConflictPolicy(
        rules=[
            PrecedenceRule(
                winner="ad", when_systems=["ad", "okta"],
                on_environments=["prod"],
                note="In prod, AD GPO is authoritative for SSH/RDP access."),
            PrecedenceRule(
                winner="ise", when_systems=["ise", "okta"],
                on_actions=["network-admin"],
                note="ISE is authoritative for NAC posture."),
        ],
        default_winner="human",
    )
