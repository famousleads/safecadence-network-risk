"""
v9.31 — quick-policy authoring + dry-run + live vendor preview +
per-asset sandbox.

Four small features that share the same machinery, so they live in
one file rather than four:

  * ``mode_for_policy``     — read enforce | report_only | disabled
  * ``set_mode``            — write the mode flag
  * ``quick_author``        — author a policy in one shot from a
                              target group + control list
  * ``render_for_vendor``   — emit vendor-native config snippet
                              for a policy spec (live preview)
  * ``simulate_on_asset``   — apply a policy to one asset and return
                              the diff/findings — sandbox without
                              touching real config

Policy mode storage: piggybacks on the existing per-policy YAML; we
add a ``mode:`` field with a default of ``enforce``. The evaluator
reads it and skips remediation when ``report_only``.

Quick storage: file-backed at ``$SC_DATA_DIR/quick_policies.json``
so authoring works in local mode without a DB.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


_VALID_MODES = ("enforce", "report_only", "disabled")


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "quick_policies.json"


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write_all(rows: list[dict]) -> None:
    _store_path().write_text(
        json.dumps(rows, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- modes


def mode_for_policy(policy_id: str) -> str:
    for r in _read_all():
        if r.get("id") == policy_id:
            return r.get("mode", "enforce")
    return "enforce"


def set_mode(policy_id: str, mode: str) -> dict:
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}")
    rows = _read_all()
    for r in rows:
        if r.get("id") == policy_id:
            r["mode"] = mode
            r["updated_at"] = datetime.now(timezone.utc).isoformat()
            _write_all(rows)
            return r
    # Auto-create a stub row so the mode setting persists even before
    # the operator clicks "save" on the policy.
    row = {"id": policy_id, "mode": mode,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()}
    rows.append(row)
    _write_all(rows)
    return row


# ---------------------------------------------------------------- quick author


@dataclass
class QuickPolicy:
    id: str
    name: str
    target_group: str
    control_ids: list[str] = field(default_factory=list)
    mode: str = "report_only"   # quick policies start in dry mode by default
    created_at: str = ""
    created_by: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def quick_author(*, name: str, target_group: str,
                   control_ids: Iterable[str],
                   mode: str = "report_only",
                   created_by: str = "") -> QuickPolicy:
    """Author a policy in one shot — no five-step wizard.

    Returns the persisted record. Mode defaults to ``report_only`` so
    operators see what the policy WOULD do for a few cycles before
    flipping to enforce. That's the safe rollout pattern.
    """
    name = (name or "").strip()
    if len(name) < 3:
        raise ValueError("name must be at least 3 characters")
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}")
    cids = [c for c in (control_ids or []) if c]
    if not cids:
        raise ValueError("at least one control_id is required")

    rec = QuickPolicy(
        id=f"qp-{uuid.uuid4().hex[:12]}",
        name=name, target_group=target_group.strip(),
        control_ids=list(cids), mode=mode,
        created_at=datetime.now(timezone.utc).isoformat(),
        created_by=(created_by or "").strip(),
    )
    rows = _read_all()
    rows.append(rec.to_dict())
    _write_all(rows)
    return rec


def list_quick_policies() -> list[dict]:
    return _read_all()


def delete_quick_policy(policy_id: str) -> bool:
    rows = _read_all()
    new = [r for r in rows if r.get("id") != policy_id]
    if len(new) == len(rows):
        return False
    _write_all(new)
    return True


# ------------------------------------------------------ live vendor preview


# Tiny stand-in for a full translator — the existing translators are
# heavyweight enough that for a *preview* we just emit a canonical
# snippet per (vendor, control). The real translators kick in at
# enforcement time. The point of preview is "what's the shape of the
# config change?" not "exact production-ready snippet".

_PREVIEW_SNIPPETS: dict[str, dict[str, list[str]]] = {
    "cisco-ios": {
        "disable_telnet":            ["line vty 0 15", " transport input ssh"],
        "enforce_ssh_v2":            ["ip ssh version 2"],
        "require_aaa":               ["aaa new-model",
                                       "aaa authentication login default group tacacs+ local"],
        "enforce_snmpv3":            ["no snmp-server community public",
                                       "snmp-server group SC_GROUP v3 priv",
                                       "snmp-server user audit SC_GROUP v3 auth sha PASSWD"],
        "enable_syslog":             ["logging host {{ siem_ip }}",
                                       "logging trap informational"],
        "enable_ntp":                ["ntp server {{ ntp_ip }}"],
        "block_insecure_crypto":     ["ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"],
        "restrict_management_access":["access-list 99 permit {{ mgmt_subnet }}",
                                       "line vty 0 15", " access-class 99 in"],
    },
    "juniper-junos": {
        "disable_telnet":            ["delete system services telnet"],
        "enforce_ssh_v2":            ["set system services ssh protocol-version v2"],
        "require_aaa":               ["set system tacplus-server {{ tacacs_ip }} secret \"<secret>\"",
                                       "set system authentication-order [ tacplus password ]"],
        "enforce_snmpv3":            ["delete snmp community",
                                       "set snmp v3 usm local-engine user audit authentication-sha"],
        "enable_syslog":             ["set system syslog host {{ siem_ip }} any info"],
        "enable_ntp":                ["set system ntp server {{ ntp_ip }}"],
        "block_insecure_crypto":     ["set system services ssh ciphers aes256-ctr"],
        "restrict_management_access":["set firewall family inet filter mgmt-acl term allow source-prefix-list mgmt-subnets"],
    },
    "paloalto-panos": {
        "enforce_ssh_v2":            ["set deviceconfig system ssh enable-ssh yes ssh-protocol-version 2"],
        "require_aaa":               ["set shared authentication-profile SC_AAA method tacplus"],
        "enable_syslog":             ["set shared log-settings syslog SC_SIEM server {{ siem_ip }}"],
        "enable_ntp":                ["set deviceconfig system ntp-servers primary-ntp-server ntp-server-address {{ ntp_ip }}"],
        "block_insecure_crypto":     ["set deviceconfig setting ssl-tls-service-profile SC_TLS protocol-settings min-version tls1-2"],
        "restrict_management_access":["set deviceconfig system permitted-ip {{ mgmt_subnet }}"],
    },
    "fortinet-fortios": {
        "enforce_ssh_v2":            ["config system global", " set ssh-mac-algos hmac-sha2-256"],
        "enable_syslog":             ["config log syslogd setting", " set status enable",
                                       " set server {{ siem_ip }}"],
        "enable_ntp":                ["config system ntp", " set server {{ ntp_ip }}"],
        "block_insecure_crypto":     ["config system global", " set strong-crypto enable"],
        "restrict_management_access":["config system interface", " edit mgmt",
                                       " set trusthost1 {{ mgmt_subnet }}"],
    },
    "arista-eos": {
        "enforce_ssh_v2":            ["management ssh", " ssh server protocol version 2"],
        "require_aaa":               ["aaa authentication login default group tacacs+ local"],
        "enable_syslog":             ["logging host {{ siem_ip }}",
                                       "logging trap informational"],
        "enable_ntp":                ["ntp server {{ ntp_ip }}"],
    },
}


def supported_vendors() -> list[str]:
    return sorted(_PREVIEW_SNIPPETS.keys())


def render_for_vendor(vendor_key: str,
                        control_ids: Iterable[str]) -> dict:
    """Render a vendor-native config snippet preview for the given
    set of controls. Non-prescriptive — these are templates with
    ``{{ ... }}`` placeholders the operator fills in.
    """
    vk = (vendor_key or "").lower()
    pack = _PREVIEW_SNIPPETS.get(vk)
    if not pack:
        return {
            "vendor": vk, "supported": False,
            "rendered": "", "controls_covered": [], "controls_missing": list(control_ids or []),
            "note": "No preview pack for this vendor — full translator runs at enforce-time.",
        }
    rendered_lines: list[str] = []
    covered: list[str] = []
    missing: list[str] = []
    for cid in (control_ids or []):
        snippet = pack.get(cid)
        if snippet is None:
            missing.append(cid)
            continue
        rendered_lines.append(f"! --- {cid} ---")
        rendered_lines.extend(snippet)
        rendered_lines.append("")
        covered.append(cid)
    return {
        "vendor": vk, "supported": True,
        "rendered": "\n".join(rendered_lines).rstrip(),
        "controls_covered": covered,
        "controls_missing": missing,
    }


# ------------------------------------------------------ per-asset sandbox


def _vendor_key_for_asset(asset: dict) -> str:
    ident = asset.get("identity") or {}
    family = (ident.get("product_family") or "").lower()
    vendor = (ident.get("vendor") or "").lower()
    if "ios xe" in family or "ios-xe" in family:
        return "cisco-ios"   # same preview pack covers both
    if "ios" in family or vendor == "cisco":
        return "cisco-ios"
    if vendor == "juniper":
        return "juniper-junos"
    if vendor in ("palo alto", "paloalto", "palo-alto"):
        return "paloalto-panos"
    if vendor == "fortinet":
        return "fortinet-fortios"
    if vendor == "arista":
        return "arista-eos"
    return ""


def simulate_on_asset(asset: dict,
                        control_ids: Iterable[str]) -> dict:
    """Sandbox: apply a list of controls to one asset and return what
    would happen, without touching anything.

    Returns:
      ``{
        "asset_id": ...,
        "vendor": "cisco-ios",
        "rendered_preview": "...",
        "would_pass": [control_id, ...],   # already satisfied
        "would_change": [control_id, ...], # not currently satisfied
        "would_fail_to_render": [...],     # no preview pack covers
      }``
    """
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ident.get("hostname") or ""
    vk = _vendor_key_for_asset(asset)

    # Reuse the v9.26 best-practice evaluator for "what's already
    # satisfied" — that's the most accurate signal we have.
    already_passing: set[str] = set()
    try:
        from safecadence.scores.best_practice import evaluate_asset as _bp
        bp = _bp(asset)
        for row in bp.passed:
            # best-practice IDs are vendor-prefixed (cisco-ios-aaa-enabled);
            # we map them back to logical control IDs by stripping the
            # "cisco-ios-" prefix and applying a small alias table.
            alias = {
                "aaa-enabled": "require_aaa",
                "no-telnet": "disable_telnet",
                "ssh-v2": "enforce_ssh_v2",
                "snmpv3": "enforce_snmpv3",
                "logging-host": "enable_syslog",
                "ntp-configured": "enable_ntp",
                "no-ip-source-route": "block_insecure_crypto",
            }
            short = re.sub(r"^cisco[\-_]ios[\-_]", "", row.get("id", ""))
            if short in alias:
                already_passing.add(alias[short])
    except Exception:
        pass

    rendered = render_for_vendor(vk, control_ids)
    cids = list(control_ids or [])
    would_pass = [c for c in cids if c in already_passing]
    would_change = [c for c in cids
                      if c not in already_passing
                      and c in rendered.get("controls_covered", [])]
    would_fail = list(rendered.get("controls_missing") or [])

    return {
        "asset_id": aid,
        "vendor": vk,
        "rendered_preview": rendered.get("rendered", ""),
        "would_pass": would_pass,
        "would_change": would_change,
        "would_fail_to_render": would_fail,
    }
