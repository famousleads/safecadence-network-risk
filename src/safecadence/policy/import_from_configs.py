"""
v9.32 — brownfield policy import.

Point at one or more existing vendor configs and get back the
*implicit* policy — the set of SafeCadence controls those configs
already enforce. This is the "we have 500 Cisco devices, what's
our policy" workflow.

How it works:
  1. Detect vendor from the config text (we already have this in
     adapters/_detector.py for the audit path).
  2. Run the v9.26 best_practice evaluator's checks in REVERSE —
     instead of "did this asset pass?", "which checks does this
     asset's config satisfy?"
  3. Aggregate across configs: a control is in the implied policy
     if a quorum of devices (default 60%) already enforce it.
  4. Emit a SecurityPolicy YAML (or dict) the operator can review,
     prune, and save.

Why this is high-leverage: brownfield policy capture is the single
biggest pain point for "we want to formalize what we have." Every
other tool assumes greenfield.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# Map from "best-practice check id" → "abstract SafeCadence control id"
# so the importer can speak the same vocabulary as the policy engine.
# Vendor packs use vendor-prefixed ids (cisco-ios-ssh-v2, …); the
# abstract controls live in policy/controls/. We translate here.
_BP_TO_CONTROL: dict[str, str] = {
    "cisco-ios-aaa-enabled":         "require_aaa",
    "cisco-ios-no-telnet":           "disable_telnet",
    "cisco-ios-ssh-v2":              "enforce_ssh_v2",
    "cisco-ios-no-http-server":      "block_insecure_crypto",  # closest abstract control
    "cisco-ios-https-secure-server": "enforce_encryption_in_transit",
    "cisco-ios-logging-host":        "enable_syslog",
    "cisco-ios-ntp-configured":      "enable_ntp",
    "cisco-ios-no-ip-source-route":  "block_insecure_crypto",
    "cisco-ios-service-password-encryption": "restrict_default_creds",
    "cisco-ios-no-snmp-community-public":    "enforce_snmpv3",
    "cisco-ios-snmpv3":              "enforce_snmpv3",
    "cisco-ios-login-block":         "restrict_management_access",
    "cisco-ios-enable-secret":       "restrict_default_creds",
}


@dataclass
class ConfigSummary:
    """One config's contribution to the inferred policy."""
    asset_id: str
    vendor_key: str
    controls_satisfied: list[str] = field(default_factory=list)
    controls_missing: list[str] = field(default_factory=list)
    raw_check_results: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "vendor_key": self.vendor_key,
            "controls_satisfied": list(self.controls_satisfied),
            "controls_missing": list(self.controls_missing),
        }


@dataclass
class InferredPolicy:
    """The aggregate output."""
    name: str
    description: str
    controls: list[str] = field(default_factory=list)
    quorum_pct: int = 60
    sample_size: int = 0
    per_control_adoption: dict[str, int] = field(default_factory=dict)
    per_config: list[ConfigSummary] = field(default_factory=list)

    def to_yaml_dict(self) -> dict:
        """Shape ready for safecadence policy save."""
        return {
            "name": self.name,
            "description": self.description,
            "mode": "report_only",   # always start brownfield in dry mode
            "controls": list(self.controls),
            "metadata": {
                "source": "brownfield_import",
                "sample_size": self.sample_size,
                "quorum_pct": self.quorum_pct,
                "adoption": dict(self.per_control_adoption),
            },
        }

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "controls": list(self.controls),
            "quorum_pct": self.quorum_pct,
            "sample_size": self.sample_size,
            "per_control_adoption": dict(self.per_control_adoption),
            "per_config": [c.to_dict() for c in self.per_config],
        }


# ---------------------------------------------------------------- helpers


def _detect_vendor(config_text: str) -> str:
    """Heuristic vendor detection. We don't need anything fancy: a
    handful of unique syntax markers separates the major vendors.
    Returns empty string when unknown."""
    if not config_text:
        return ""
    head = config_text[:8000].lower()

    # Cisco IOS / IOS-XE: "!" comments / "line vty" / "aaa new-model" /
    # "service password-encryption" / "ip ssh" — all classic IOS markers.
    # MULTILINE so ^ matches at every line start, not just the file start.
    if re.search(
        r"^(?:!|line vty\b|aaa new-model\b|service password-encryption\b|ip ssh\b)",
        head, re.MULTILINE,
    ):
        return "cisco-ios"
    # Juniper: "set system" or "system { ... }"
    if re.search(r"\bset system\b|\nsystem\s*{", head, re.MULTILINE):
        return "juniper-junos"
    # Palo Alto: hierarchy with "set deviceconfig"
    if re.search(r"\bset deviceconfig\b", head):
        return "paloalto-panos"
    # Fortinet: "config system global"
    if re.search(r"^config system global\b", head, re.MULTILINE):
        return "fortinet-fortios"
    # Arista EOS: very Cisco-ish but also "transceiver qsfp default-mode"
    if "arista" in head or "transceiver qsfp default-mode" in head:
        return "arista-eos"
    return ""


def _evaluate_via_best_practice(asset: dict) -> dict:
    """Run the v9.26 best-practice evaluator and return its result
    dict. Returns empty when no pack exists for the vendor."""
    try:
        from safecadence.scores.best_practice import evaluate_asset
        return evaluate_asset(asset).to_dict()
    except Exception:
        return {}


def _config_to_asset(config_text: str, asset_id: str,
                       vendor_key: str) -> dict:
    """Wrap a raw config string in the minimal asset shape the rest
    of the platform expects so we can reuse the existing evaluators."""
    family_map = {
        "cisco-ios": "Cisco IOS Software",
        "juniper-junos": "Juniper JUNOS",
        "paloalto-panos": "PAN-OS",
        "fortinet-fortios": "FortiOS",
        "arista-eos": "Arista EOS",
    }
    vendor_map = {
        "cisco-ios": "Cisco",
        "juniper-junos": "Juniper",
        "paloalto-panos": "Palo Alto",
        "fortinet-fortios": "Fortinet",
        "arista-eos": "Arista",
    }
    return {
        "identity": {
            "asset_id": asset_id, "hostname": asset_id,
            "vendor": vendor_map.get(vendor_key, ""),
            "product_family": family_map.get(vendor_key, ""),
            "asset_type": "network",
        },
        "raw_collection": {"running": config_text},
    }


# ---------------------------------------------------------------- public


def import_one_config(config_text: str, *,
                       asset_id: str = "imported") -> ConfigSummary:
    """Infer the per-config control adoption for a single config."""
    vk = _detect_vendor(config_text)
    asset = _config_to_asset(config_text, asset_id, vk)
    bp = _evaluate_via_best_practice(asset)

    satisfied: list[str] = []
    missing: list[str] = []
    for row in bp.get("passed", []) or []:
        ctrl = _BP_TO_CONTROL.get(row.get("id", ""))
        if ctrl and ctrl not in satisfied:
            satisfied.append(ctrl)
    for row in bp.get("failed", []) or []:
        ctrl = _BP_TO_CONTROL.get(row.get("id", ""))
        if ctrl and ctrl not in missing and ctrl not in satisfied:
            missing.append(ctrl)
    return ConfigSummary(
        asset_id=asset_id, vendor_key=vk,
        controls_satisfied=satisfied,
        controls_missing=missing,
        raw_check_results=bp,
    )


def import_fleet(configs: Iterable[tuple[str, str]],
                   *,
                   policy_name: str = "Inferred fleet policy",
                   description: str = ("Implicit policy reverse-engineered "
                                          "from existing configs."),
                   quorum_pct: int = 60) -> InferredPolicy:
    """Aggregate across many ``(asset_id, config_text)`` pairs.

    A control makes the policy if it's satisfied by ≥ ``quorum_pct``
    of inputs. Anything below quorum but above 30% gets returned in
    the per-config detail so the operator can see "this is *almost*
    there, decide whether to add it."
    """
    summaries: list[ConfigSummary] = []
    counter: Counter[str] = Counter()
    for aid, text in configs:
        s = import_one_config(text, asset_id=aid)
        summaries.append(s)
        for c in s.controls_satisfied:
            counter[c] += 1

    n = len(summaries)
    threshold = max(1, int(n * quorum_pct / 100))
    in_policy = sorted(c for c, k in counter.items() if k >= threshold)

    return InferredPolicy(
        name=policy_name, description=description,
        controls=in_policy, quorum_pct=quorum_pct,
        sample_size=n,
        per_control_adoption={c: counter[c] for c in counter},
        per_config=summaries,
    )


def import_directory(path: Path, *,
                       glob: str = "*.txt",
                       quorum_pct: int = 60) -> InferredPolicy:
    """Convenience: glob a directory for config files and import them
    all. Filename (sans extension) becomes the asset_id."""
    configs: list[tuple[str, str]] = []
    for f in sorted(Path(path).glob(glob)):
        try:
            configs.append((f.stem, f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return import_fleet(configs, quorum_pct=quorum_pct)
