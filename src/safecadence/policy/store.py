"""
Local policy store — JSON files, cross-platform via pathlib.

Lives at ~/.safecadence/policies/. Pure-Python, no external DB required.
Each policy is one JSON file: <policy_id>.json.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from safecadence.policy.audit import log as audit_log
from safecadence.policy.schema import (
    EnforcementMode, PolicyControl, PolicyException, PolicyState, SecurityPolicy,
    Severity,
)


def _store_dir() -> Path:
    p = Path.home() / ".safecadence" / "policies"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _policy_path(policy_id: str) -> Path:
    return _store_dir() / f"{policy_id}.json"


def save(policy: SecurityPolicy, *, actor: str = "system") -> Path:
    p = _policy_path(policy.policy_id)
    payload = _to_dict(policy)
    p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    audit_log("policy_saved", actor=actor, policy_id=policy.policy_id,
              detail={"name": policy.policy_name, "version": policy.version})
    return p


def get(policy_id: str) -> Optional[SecurityPolicy]:
    p = _policy_path(policy_id)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return _from_dict(d)
    except Exception:
        return None


def list_policies() -> list[dict]:
    out = []
    for f in sorted(_store_dir().glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({
            "policy_id": d.get("policy_id"),
            "policy_name": d.get("policy_name"),
            "version": d.get("version", 1),
            "state": d.get("state", "draft"),
            "severity": d.get("severity"),
            "enforcement_mode": d.get("enforcement_mode"),
            "control_count": len(d.get("controls") or []),
            "frameworks": d.get("compliance_frameworks") or [],
            "updated_at": d.get("updated_at") or d.get("created_at"),
        })
    return out


def delete(policy_id: str, *, actor: str = "system") -> bool:
    p = _policy_path(policy_id)
    if not p.exists():
        return False
    p.unlink()
    audit_log("policy_deleted", actor=actor, policy_id=policy_id)
    return True


# --------------------------------------------------------------------------
# (de)serializers — straightforward asdict + enum-rehydration
# --------------------------------------------------------------------------

def _to_dict(p: SecurityPolicy) -> dict:
    d = asdict(p)
    d["severity"] = p.severity.value if isinstance(p.severity, Severity) else p.severity
    d["enforcement_mode"] = p.enforcement_mode.value if isinstance(p.enforcement_mode, EnforcementMode) else p.enforcement_mode
    d["state"] = p.state.value if isinstance(p.state, PolicyState) else p.state
    for c in d["controls"]:
        c["severity"] = c["severity"].value if hasattr(c["severity"], "value") else c["severity"]
    return d


def _from_dict(d: dict) -> SecurityPolicy:
    sev = {s.value: s for s in Severity}
    enf = {e.value: e for e in EnforcementMode}
    st = {s.value: s for s in PolicyState}
    controls = []
    for c in d.get("controls") or []:
        controls.append(PolicyControl(
            control_id=c.get("control_id", ""),
            description=c.get("description", ""),
            parameters=c.get("parameters") or {},
            severity=sev.get(c.get("severity", "medium"), Severity.MEDIUM),
            framework_refs=c.get("framework_refs") or [],
        ))
    exceptions = [PolicyException(**e) for e in (d.get("exceptions") or [])]
    return SecurityPolicy(
        policy_id=d.get("policy_id", ""),
        policy_name=d.get("policy_name", ""),
        description=d.get("description", ""),
        version=int(d.get("version", 1)),
        scope=d.get("scope") or {},
        target_asset_types=d.get("target_asset_types") or [],
        required_state=d.get("required_state") or {},
        prohibited_state=d.get("prohibited_state") or {},
        controls=controls,
        severity=sev.get(d.get("severity", "medium"), Severity.MEDIUM),
        compliance_frameworks=d.get("compliance_frameworks") or [],
        enforcement_mode=enf.get(d.get("enforcement_mode", "observe"), EnforcementMode.OBSERVE),
        state=st.get(d.get("state", "draft"), PolicyState.DRAFT),
        environment_variants=d.get("environment_variants") or {},
        exceptions=exceptions,
        tags=d.get("tags") or [],
        owner=d.get("owner", ""),
        created_at=d.get("created_at") or "",
        updated_at=d.get("updated_at") or "",
        source=d.get("source", "ui"),
    )
