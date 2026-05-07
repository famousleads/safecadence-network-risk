"""
CVE-driven policy generator.

Reads the platform's existing CVE matcher output (per-asset) and produces
a temporary SecurityPolicy whose controls require either:
  - patch-level compliance, OR
  - the documented workaround (passed in as control parameters).

Generated policies have source='cve' so they're easy to filter in the UI
and auto-expire when the underlying CVE is patched.
"""

from __future__ import annotations

import uuid
from typing import Iterable

from safecadence.policy.schema import (
    EnforcementMode, PolicyControl, SecurityPolicy, Severity,
)


def policy_from_cves(cves: Iterable[dict], *, target_asset_types: list[str] | None = None,
                     name: str = "") -> SecurityPolicy:
    """
    cves: iterable of {cve_id, severity, kev: bool, affected_vendors: [...], notes}.

    Produces a single SecurityPolicy that asserts enforce_patch_level
    against assets matching the affected vendors. Severity escalates to
    CRITICAL if any CVE is on CISA KEV.
    """
    cves = list(cves)
    has_kev = any(c.get("kev") for c in cves)
    has_critical = any((c.get("severity") or "").lower() == "critical" for c in cves)
    sev = (Severity.CRITICAL if has_kev or has_critical else Severity.HIGH)
    affected_vendors = sorted({v.lower() for c in cves for v in (c.get("affected_vendors") or [])})

    return SecurityPolicy(
        policy_id=f"cve_{uuid.uuid4().hex[:8]}",
        policy_name=name or f"CVE compliance ({len(cves)} CVEs)",
        description=("Auto-generated from active CVE matches: "
                     + ", ".join(c.get("cve_id", "?") for c in cves[:6])
                     + (" ..." if len(cves) > 6 else "")),
        scope={"vendor": affected_vendors} if affected_vendors else {},
        target_asset_types=target_asset_types or ["server", "network", "storage"],
        controls=[
            PolicyControl(
                control_id="enforce_patch_level",
                description="Patch level must address all active CVEs.",
                severity=sev,
                framework_refs=["nist:SI-2", "cis:1.8", "pci:6.2"],
                parameters={"cve_ids": [c.get("cve_id") for c in cves if c.get("cve_id")]},
            )
        ],
        severity=sev,
        compliance_frameworks=["cisa-kev"] if has_kev else ["nist-800-53"],
        enforcement_mode=EnforcementMode.WARN,
        source="cve",
    )
