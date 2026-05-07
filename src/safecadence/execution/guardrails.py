"""Pre-execution guardrails.

Three independent checks run on every job before it can transition
from REVIEW → APPROVED:

  1. **Risk classification** — every command is tagged safe / low /
     medium / high / critical based on a heuristic match against
     known patterns. Unknown commands default UP, never down.
  2. **Blocked-command list** — operations that would lock an
     operator out of their device, destroy data, or break out-of-
     band access are hard-blocked or require a 2-of-N approval.
  3. **Lockout-risk detection** — looks for combinations like
     'no aaa new-model' on a TACACS-only device, or 'no transport
     input ssh' on a remote box, that would silently brick the
     management plane. These can't be auto-approved at any tier.

This module is pure-Python, has no I/O, and is safe to import in
the air-gapped agent path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from safecadence.execution.schema import RiskLevel


# --------------------------------------------------------------------------
# Risk classification
# --------------------------------------------------------------------------

# Patterns are evaluated in order; first match wins. Each pattern is a
# (compiled regex, RiskLevel, human-readable reason).
_RISK_RULES: list[tuple[re.Pattern, RiskLevel, str]] = [
    # ---- CRITICAL — disruptive, can lock you out, can lose data ----
    (re.compile(r"\bwrite\s+erase\b", re.I), RiskLevel.CRITICAL,
     "write erase wipes startup config"),
    (re.compile(r"\berase\s+(start|nvram|flash)", re.I), RiskLevel.CRITICAL,
     "erases persistent storage"),
    (re.compile(r"\breload\b(?!\s+in)", re.I), RiskLevel.CRITICAL,
     "device reload"),
    (re.compile(r"\breload\s+(at|in)\b", re.I), RiskLevel.HIGH,
     "scheduled reload"),
    (re.compile(r"\bdelete\s+/force\b|\bformat\b", re.I), RiskLevel.CRITICAL,
     "destructive filesystem operation"),
    (re.compile(r"\brm\s+(-rf|-fr)\s+/(?!tmp|var/log)", re.I),
     RiskLevel.CRITICAL, "destructive Linux delete"),
    (re.compile(r"\bDROP\s+TABLE\b|\bTRUNCATE\b", re.I), RiskLevel.CRITICAL,
     "SQL DDL"),
    (re.compile(r"\baws\s+ec2\s+terminate-instances\b", re.I),
     RiskLevel.CRITICAL, "AWS EC2 terminate"),
    (re.compile(r"\baz\s+vm\s+delete\b|\bgcloud\s+\S+\s+delete\b", re.I),
     RiskLevel.CRITICAL, "cloud resource delete"),

    # ---- HIGH — config change, real impact, but reversible ----
    (re.compile(r"\bno\s+aaa\s+new-model\b", re.I), RiskLevel.HIGH,
     "removes AAA — lockout risk"),
    (re.compile(r"\bno\s+username\b|\bno\s+enable\s+secret\b", re.I),
     RiskLevel.HIGH, "removes local admin — lockout risk"),
    (re.compile(r"\bshutdown\b", re.I), RiskLevel.HIGH,
     "interface shutdown"),
    (re.compile(r"\bno\s+ip\s+route\s+0\.0\.0\.0", re.I), RiskLevel.HIGH,
     "removes default route"),
    (re.compile(r"\bclear\s+(ip\s+)?bgp\s+\*\b", re.I), RiskLevel.HIGH,
     "clears BGP sessions"),
    (re.compile(r"^(set|configure|conf t|configure terminal)\b", re.I),
     RiskLevel.HIGH, "entering config mode"),
    (re.compile(r"\baaa\s+authentication\b|\baaa\s+authorization\b", re.I),
     RiskLevel.HIGH, "AAA configuration change"),
    (re.compile(r"\baccess-list\b|\bip\s+access-group\b", re.I),
     RiskLevel.HIGH, "ACL change — traffic impact"),

    # ---- MEDIUM — operational, contained ----
    (re.compile(r"\bclear\s+(counters|interface|arp|mac)\b", re.I),
     RiskLevel.MEDIUM, "clears operational counters"),
    (re.compile(r"\b(restart|systemctl\s+restart)\b", re.I), RiskLevel.MEDIUM,
     "service restart"),
    (re.compile(r"\bcopy\s+running\s+startup\b", re.I), RiskLevel.MEDIUM,
     "saves running config"),

    # ---- LOW — diagnostic only, makes a small state change ----
    (re.compile(r"\bping\b|\btraceroute\b|\btracepath\b", re.I),
     RiskLevel.LOW, "active probe"),
    (re.compile(r"\btest\s+aaa\b|\btest\s+tacacs\b", re.I), RiskLevel.LOW,
     "AAA probe"),

    # ---- SAFE — read-only show / get / get-config ----
    (re.compile(r"^\s*show\b", re.I), RiskLevel.SAFE, "show command"),
    (re.compile(r"^\s*display\b", re.I), RiskLevel.SAFE,
     "display (NX-OS / Junos)"),
    (re.compile(r"^\s*get\b", re.I), RiskLevel.SAFE, "get (PAN-OS / API)"),
    (re.compile(r"^\s*describe\b", re.I), RiskLevel.SAFE,
     "describe (cloud SDK)"),
    (re.compile(r"^\s*list-\S+\b|^\s*aws\s+\S+\s+list", re.I),
     RiskLevel.SAFE, "list (AWS SDK)"),
]


# Higher-of two risk levels — used when a job has multiple commands.
_RISK_ORDER = {
    RiskLevel.SAFE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4,
}


@dataclass
class RiskClassification:
    risk: RiskLevel
    reasons: list[str]
    matched_lines: list[str]


def classify_risk(commands: list[str]) -> RiskClassification:
    """Classify a list of commands; returns the maximum risk found.

    Unknown commands (no pattern match) default to MEDIUM — never SAFE.
    'Default up' is the only safe posture for a privileged engine.
    """
    max_risk = RiskLevel.SAFE
    reasons: list[str] = []
    matched: list[str] = []
    for raw in commands or []:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        line_risk = RiskLevel.MEDIUM
        line_reason = "unrecognised command — defaults to MEDIUM"
        for pattern, risk, reason in _RISK_RULES:
            if pattern.search(line):
                line_risk = risk
                line_reason = reason
                break
        if _RISK_ORDER[line_risk] > _RISK_ORDER[max_risk]:
            max_risk = line_risk
        if line_risk != RiskLevel.SAFE:
            reasons.append(f"{line_reason}: {line[:80]}")
            matched.append(line)
    return RiskClassification(risk=max_risk, reasons=reasons,
                               matched_lines=matched)


# --------------------------------------------------------------------------
# Blocked-command list — hard refuse or escalate to 2-of-N approval
# --------------------------------------------------------------------------

# (regex, hard_block_or_require_approval, reason). Hard-blocked commands
# are refused at job submission. The 'require approval' ones are allowed
# but force the job's risk up to CRITICAL.
_BLOCKED_PATTERNS: list[tuple[re.Pattern, bool, str]] = [
    # Hard blocks
    (re.compile(r"\b(?:rm\s+-rf?\s+/|rm\s+-rf?\s+/\*)\s*$", re.I), True,
     "rm -rf / would destroy the OS"),
    (re.compile(r":\(\)\{\s*:\|:&\s*\};:", re.I), True, "fork bomb"),
    (re.compile(r"\bdd\s+if=/dev/zero\s+of=/dev/(sda|sdb|nvme\d|hda)", re.I),
     True, "wipes the boot disk"),
    (re.compile(r"\bmkfs\.\S+\s+/dev/(sda|sdb|nvme\d|hda)", re.I), True,
     "reformats the boot disk"),
    (re.compile(r"\bsudo\s+chmod\s+-R\s+0?00\s+/", re.I), True,
     "makes the system unreachable"),
    # Escalate-to-CRITICAL
    (re.compile(r"\bwrite\s+erase\b", re.I), False, "wipes startup config"),
    (re.compile(r"\breload\b(?!\s+(at|in))", re.I), False, "device reload"),
    (re.compile(r"\bno\s+aaa\s+new-model\b", re.I), False, "removes AAA"),
    (re.compile(r"\bno\s+(?:line|transport)\s+input\s+ssh\b", re.I), False,
     "removes SSH access"),
    (re.compile(r"\b(?:terminate-instances|delete-cluster|delete-rds)", re.I),
     False, "destroys cloud resource"),
    (re.compile(r"\bno\s+logging\b", re.I), False, "disables logging"),
    (re.compile(r"\bno\s+ntp\b", re.I), False, "disables NTP"),
]


@dataclass
class BlockResult:
    blocked: bool
    requires_critical_approval: bool
    reasons: list[str]


def is_blocked(commands: list[str]) -> BlockResult:
    """Return whether any command is hard-blocked or escalation-only.

    Operators see hard-blocked jobs refused at submission with the
    matching reason. Escalation-only matches force the job's risk to
    CRITICAL, which means a 2-of-N approval is required.
    """
    blocked = False
    escalate = False
    reasons: list[str] = []
    for raw in commands or []:
        line = raw.strip()
        if not line:
            continue
        for pattern, hard, reason in _BLOCKED_PATTERNS:
            if pattern.search(line):
                if hard:
                    blocked = True
                    reasons.append(f"BLOCKED: {reason} :: {line[:80]}")
                else:
                    escalate = True
                    reasons.append(f"ESCALATE: {reason} :: {line[:80]}")
    return BlockResult(blocked=blocked,
                        requires_critical_approval=escalate,
                        reasons=reasons)


# --------------------------------------------------------------------------
# Lockout-risk detection — combinations that brick the management plane
# --------------------------------------------------------------------------

@dataclass
class LockoutAssessment:
    at_risk: bool
    reasons: list[str]


def lockout_risk(commands: list[str], asset: dict | None = None
                 ) -> LockoutAssessment:
    """Detect command sets that would silently brick a device's mgmt
    plane. The asset's collected raw_collection can override default
    assumptions (e.g. only flag 'no aaa new-model' if the device is
    actually using TACACS, otherwise it just falls back to local).
    """
    reasons: list[str] = []
    text = "\n".join(commands or []).lower()
    cfg_text = ""
    if asset:
        rc = asset.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str):
                    cfg_text += v.lower() + "\n"

    # Pattern 1 — removing the only auth path
    if "no aaa new-model" in text:
        if "tacacs" in cfg_text and "username" not in cfg_text:
            reasons.append(
                "removes 'aaa new-model' on a TACACS-only device — no fallback"
            )
        elif "username" not in cfg_text:
            reasons.append(
                "removes 'aaa new-model' but no local user is configured"
            )

    # Pattern 2 — removing SSH on a remote-mgmt device
    if ("no transport input ssh" in text
            or "no line vty" in text
            or "no ip ssh" in text):
        if "ip http server" not in cfg_text and "console" not in text:
            reasons.append(
                "removes SSH without enabling another mgmt path "
                "(console-only is not a mgmt path for remote devices)"
            )

    # Pattern 3 — shutting the management interface
    if re.search(r"interface\s+(mgmt|management|gigabitethernet0/0)\b", text):
        if "shutdown" in text:
            reasons.append(
                "shutdown on a management-bearing interface — operator "
                "loses access immediately"
            )

    # Pattern 4 — default route deletion
    if "no ip route 0.0.0.0" in text or "no default-router" in text:
        reasons.append(
            "removes default route — remote management path likely lost"
        )

    # Pattern 5 — disabling logging on a regulated asset
    if "no logging" in text:
        if asset and (asset.get("identity") or {}).get("criticality") == "crown-jewel":
            reasons.append(
                "disables logging on a crown-jewel asset — likely violates "
                "PCI / HIPAA / SOX baseline"
            )

    return LockoutAssessment(at_risk=bool(reasons), reasons=reasons)


# --------------------------------------------------------------------------
# Combined pre-flight — what every endpoint should call
# --------------------------------------------------------------------------

@dataclass
class PreflightResult:
    """What you get back from the unified guardrail call."""
    risk: RiskLevel
    blocked: bool
    escalated_to_critical: bool
    lockout_at_risk: bool
    reasons: list[str]


def preflight(commands: list[str], asset: dict | None = None) -> PreflightResult:
    """Single front door: runs all three checks, returns one verdict.

    UI / CLI / API call this; never the underlying functions directly.
    Future additions (compliance-window check, change-freeze check,
    seasonal blackout) get plugged in here so callers are insulated.
    """
    rc = classify_risk(commands)
    bl = is_blocked(commands)
    lr = lockout_risk(commands, asset)
    risk = rc.risk
    if bl.requires_critical_approval:
        risk = RiskLevel.CRITICAL
    if lr.at_risk and _RISK_ORDER[risk] < _RISK_ORDER[RiskLevel.HIGH]:
        risk = RiskLevel.HIGH
    return PreflightResult(
        risk=risk,
        blocked=bl.blocked,
        escalated_to_critical=bl.requires_critical_approval,
        lockout_at_risk=lr.at_risk,
        reasons=rc.reasons + bl.reasons + lr.reasons,
    )
