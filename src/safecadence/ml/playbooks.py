"""
Threat-hunting playbooks (v11.0).

Deterministic, code-as-config workflows that walk an operator through a
known response procedure. Each playbook is a list of ``Step``s — they
read context (affected assets, attack paths, etc.) and produce a
short, copy-pasteable action list.

Three baseline playbooks:

* ``kev_response`` — a CISA KEV CVE was published or is now present in
  the fleet. Identify affected assets, check patch availability, score
  exposure, propose isolation.
* ``lateral_movement`` — a suspicious finding may be a foothold. Trace
  reachability to crown jewels through the v9.x attack-path graph.
* ``credential_compromise`` — a privileged account may be compromised.
  Containment + audit-log review + key/credential rotation guidance.

All playbooks are deterministic. Where the v10.6 :mod:`safecadence.ai`
client is available we call it for *explanation* of a step (e.g. why
an exposure is critical), but the playbook itself is reproducible
without any LLM key.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Callable


# --------------------------------------------------------------------------
# Step dataclass
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Step:
    id: str
    title: str
    description: str
    actions: list[str]
    severity: str = "medium"   # info | low | medium | high | critical
    requires_human: bool = False
    artifacts: dict | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "actions": list(self.actions or []),
            "severity": self.severity,
            "requires_human": self.requires_human,
            "artifacts": self.artifacts or {},
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _org_dir(org_id: str | None) -> Path:
    if org_id:
        try:
            from safecadence.storage.org_store import org_data_dir

            return org_data_dir(org_id)
        except Exception:
            pass
    root = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME")
    return Path(root) if root else Path.home() / ".safecadence"


def _all_assets(org_id: str | None) -> list[dict]:
    base = _org_dir(org_id) / "platform_assets"
    if not base.exists():
        return []
    out = []
    for f in base.glob("*.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def _affected_by_cve(assets: list[dict], cve_id: str) -> list[dict]:
    cve_id = (cve_id or "").upper()
    out = []
    for a in assets:
        for c in a.get("cves") or a.get("vulnerabilities") or []:
            if isinstance(c, dict) and str(c.get("id") or "").upper() == cve_id:
                out.append(a)
                break
    return out


# --------------------------------------------------------------------------
# KEV response playbook
# --------------------------------------------------------------------------


def _playbook_kev_response(ctx: dict) -> list[Step]:
    cve_id = str(ctx.get("cve_id") or ctx.get("cve") or "").upper()
    org_id = ctx.get("org_id")
    assets = ctx.get("assets") or _all_assets(org_id)
    affected = (
        ctx.get("affected_assets")
        or (_affected_by_cve(assets, cve_id) if cve_id else [])
    )
    public_affected = [
        a
        for a in affected
        if a.get("public_exposure") or (a.get("identity") or {}).get("public_exposure")
    ]
    crown = [
        a
        for a in affected
        if str(
            a.get("criticality") or (a.get("identity") or {}).get("criticality") or ""
        )
        .lower()
        .replace(" ", "_")
        in {"crown_jewel", "tier_1"}
    ]
    patched = any(
        c.get("patch_available") or c.get("fixed_in")
        for a in affected
        for c in a.get("cves") or []
        if isinstance(c, dict) and str(c.get("id") or "").upper() == cve_id
    )

    steps: list[Step] = []
    steps.append(
        Step(
            id="kev.identify",
            title=f"Identify assets affected by {cve_id or 'the KEV CVE'}",
            description=(
                f"Sweep platform_assets for the CVE. Found {len(affected)} "
                f"affected host(s), {len(public_affected)} internet-facing, "
                f"{len(crown)} crown-jewel."
            ),
            actions=[
                f"Confirm match list: {', '.join((a.get('identity') or {}).get('hostname','?') for a in affected[:10])}",
                "Cross-reference against EDR / vulnerability scanner findings.",
            ],
            severity="high" if affected else "info",
            requires_human=False,
            artifacts={"affected_count": len(affected), "cve_id": cve_id},
        )
    )
    steps.append(
        Step(
            id="kev.patch",
            title="Check patch availability",
            description=(
                "Confirm whether a vendor fix is available. KEV CVEs typically "
                "have known fixes; if not, isolation is the only short-term "
                "control."
            ),
            actions=[
                "Pull vendor advisory + fixed-in version.",
                "Open a P1 patch ticket per affected asset.",
            ]
            + (
                ["Vendor patch indicator present in CVE record."]
                if patched
                else ["No patch indicator on record — confirm with vendor."]
            ),
            severity="high",
            artifacts={"patch_available": bool(patched)},
        )
    )
    steps.append(
        Step(
            id="kev.exposure",
            title="Score exposure",
            description=(
                f"{len(public_affected)} affected asset(s) are internet-facing; "
                f"{len(crown)} carry crown-jewel criticality."
            ),
            actions=[
                "Run attack-path graph from each affected asset toward crown jewels.",
                "Confirm WAF / firewall coverage in front of internet-facing hosts.",
            ],
            severity="critical" if public_affected or crown else "medium",
            artifacts={
                "public_count": len(public_affected),
                "crown_count": len(crown),
            },
        )
    )
    steps.append(
        Step(
            id="kev.isolate",
            title="Isolation + compensating controls",
            description=(
                "Apply containment if patching cannot land within SLA. "
                "Internet-facing crown-jewel assets are the priority."
            ),
            actions=[
                "Move affected hosts behind a maintenance ACL until patched.",
                "Disable affected service / port where business-permissible.",
                "Increase EDR sensitivity on the cluster for 14 days.",
            ],
            severity="high",
            requires_human=True,
        )
    )
    steps.append(
        Step(
            id="kev.communicate",
            title="Notify stakeholders + log decision",
            description=(
                "Open an incident record, notify the on-call CISO, and write "
                "the risk-acceptance entry for any host that won't be patched "
                "in 72 hours."
            ),
            actions=[
                "Open ticket in Jira / ServiceNow (workflow.change_mgmt hook).",
                "Post to #sec-ops Slack with affected host list + ETA.",
                "Snapshot evidence to SOC 2 evidence store (workflow.soc2_evidence).",
            ],
            severity="medium",
            requires_human=True,
        )
    )
    return steps


# --------------------------------------------------------------------------
# Lateral-movement playbook
# --------------------------------------------------------------------------


def _playbook_lateral_movement(ctx: dict) -> list[Step]:
    finding_id = str(ctx.get("finding_id") or "")
    starting_asset = ctx.get("asset") or ctx.get("starting_asset") or {}
    org_id = ctx.get("org_id")
    assets = ctx.get("assets") or _all_assets(org_id)
    crown = [
        a
        for a in assets
        if str(
            a.get("criticality") or (a.get("identity") or {}).get("criticality") or ""
        )
        .lower()
        .replace(" ", "_")
        in {"crown_jewel", "tier_1"}
    ]
    return [
        Step(
            id="lat.scope",
            title="Scope the foothold",
            description=(
                "Identify the originating finding + asset and capture the "
                "current process tree / network connections."
            ),
            actions=[
                f"Finding: {finding_id or 'n/a'}",
                f"Starting asset: {(starting_asset.get('identity') or {}).get('hostname') or starting_asset.get('id') or 'n/a'}",
                "Pull EDR process tree + recent egress.",
            ],
            severity="high",
        ),
        Step(
            id="lat.reach",
            title="Trace reachable paths to crown jewels",
            description=(
                f"{len(crown)} crown-jewel asset(s) in the fleet. Run the "
                "v9.x attack-path graph from the starting asset."
            ),
            actions=[
                "safecadence attack-paths --from {starting} --to crown-jewels",
                "Annotate paths that traverse a single hop firewall vs. flat L2.",
            ],
            severity="critical" if crown else "medium",
            artifacts={"crown_count": len(crown)},
        ),
        Step(
            id="lat.contain",
            title="Contain east-west movement",
            description=(
                "Cut off the foothold from neighbours and from crown-jewel "
                "segments."
            ),
            actions=[
                "Apply VLAN ACL: deny new TCP from {starting} to crown-jewel VLANs.",
                "Force re-auth of any active session originating from {starting}.",
                "Quarantine endpoint in EDR.",
            ],
            severity="high",
            requires_human=True,
        ),
        Step(
            id="lat.hunt",
            title="Hunt for additional footholds",
            description=(
                "Assume the attacker landed elsewhere too. Look for shared TTPs."
            ),
            actions=[
                "Search EDR for the same parent process across the fleet.",
                "Search logs for the same user-agent / C2 domain.",
                "Re-run the finding rule across the fleet.",
            ],
            severity="medium",
        ),
        Step(
            id="lat.review",
            title="Write incident postmortem stub",
            description="Capture the path, blast radius, and remediation timeline.",
            actions=[
                "File an incident in the operator console.",
                "Schedule a 5-day after-action review.",
            ],
            severity="low",
            requires_human=True,
        ),
    ]


# --------------------------------------------------------------------------
# Credential-compromise playbook
# --------------------------------------------------------------------------


def _playbook_credential_compromise(ctx: dict) -> list[Step]:
    user = str(ctx.get("user") or ctx.get("account") or "")
    privileged = bool(ctx.get("privileged") or ctx.get("admin"))
    return [
        Step(
            id="cred.identify",
            title="Identify the account + scope",
            description=(
                f"Account: {user or 'unknown'} (privileged={privileged}). "
                "Pull the user's group memberships and recent auth events."
            ),
            actions=[
                f"safecadence identity show {user}" if user else "safecadence identity list --recent",
                "Pull last 30d auth log from IdP.",
            ],
            severity="high" if privileged else "medium",
        ),
        Step(
            id="cred.session",
            title="Revoke active sessions + force rotation",
            description=(
                "Burn current tokens and require a password + MFA reset before "
                "next login."
            ),
            actions=[
                f"Force logout {user} in IdP and remove all OAuth grants.",
                "Reset password + require MFA re-enrollment.",
                "Rotate API tokens and SSH keys associated with the account.",
            ],
            severity="critical" if privileged else "high",
            requires_human=True,
        ),
        Step(
            id="cred.audit",
            title="Audit recent actions",
            description=(
                "Trace every action the account took in the last 24h across "
                "the fleet."
            ),
            actions=[
                "Pull audit log for the account from v10.3 audit store.",
                "Diff config changes against baseline; flag anything not in a CR.",
                "Check for new service principals / API keys the account created.",
            ],
            severity="high",
        ),
        Step(
            id="cred.contain",
            title="Contain blast radius",
            description=(
                "If the account had admin rights, treat downstream resources "
                "as potentially compromised."
            ),
            actions=[
                "Rotate any secrets the account could read (vaults, KMS keys).",
                "Disable inbound webhooks signed with shared secrets the account managed.",
                "Snapshot affected VMs / pods for forensic analysis.",
            ],
            severity="critical" if privileged else "medium",
            requires_human=True,
        ),
        Step(
            id="cred.report",
            title="Report + log decision",
            description="Open the incident and record evidence.",
            actions=[
                "Open ServiceNow / Jira incident.",
                "Notify the data-privacy officer if customer data was reachable.",
                "Attach forensic snapshots to SOC 2 evidence store.",
            ],
            severity="medium",
            requires_human=True,
        ),
    ]


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


_PLAYBOOKS: dict[str, dict] = {
    "kev_response": {
        "name": "KEV CVE response",
        "description": "Walk through identify → patch → exposure → isolate → notify for a CISA KEV CVE.",
        "fn": _playbook_kev_response,
    },
    "lateral_movement": {
        "name": "Lateral-movement trace",
        "description": "Starting from a finding, trace reachable attack paths to crown jewels and contain.",
        "fn": _playbook_lateral_movement,
    },
    "credential_compromise": {
        "name": "Credential compromise containment",
        "description": "Containment + audit-log review + key rotation for a (possibly privileged) account.",
        "fn": _playbook_credential_compromise,
    },
}


def list_playbooks() -> list[dict]:
    """Return the registered playbook metadata."""
    return [
        {"id": pid, "name": p["name"], "description": p["description"]}
        for pid, p in _PLAYBOOKS.items()
    ]


def run_playbook(playbook_id: str, context: dict | None = None) -> list[dict]:
    """Run a playbook and return the list of step dicts."""
    pb = _PLAYBOOKS.get(playbook_id)
    if not pb:
        raise KeyError(f"unknown playbook: {playbook_id}")
    fn: Callable[[dict], list[Step]] = pb["fn"]
    steps = fn(context or {})
    return [s.to_dict() for s in steps]


__all__ = ["Step", "list_playbooks", "run_playbook"]
