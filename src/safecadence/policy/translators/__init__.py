"""
Multi-vendor config translators.

Each translator takes a (PolicyControl, asset) pair and returns:
  - fix_commands       — config snippets to apply the control
  - rollback_commands  — config snippets to undo the change
  - verify_commands    — read-only commands to confirm the fix worked

Translators are pure (no I/O), platform-agnostic (no shell calls),
and grounded in published vendor documentation. The library never
SSHes anywhere — the user takes the snippets and applies them through
their own change-management process.

Adding a translator:
  1. Create vendor_target.py
  2. Subclass BaseTranslator
  3. Decorate with @register_translator('cisco_ios')
  4. Implement translate(control, asset) → TranslatedFix
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from safecadence.policy.schema import PolicyControl


@dataclass
class TranslatedFix:
    fix: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)
    notes: str = ""
    applicable: bool = True                   # False if this translator can't satisfy this control


class BaseTranslator:
    """Subclass + register_translator. Override translate()."""
    vendor_target: str = ""
    asset_match: list[str] = []               # asset_type values this translator handles

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        raise NotImplementedError

    def supports(self, control_id: str) -> bool:
        """Override to declare which controls this translator covers."""
        return True


_TRANSLATORS: dict[str, BaseTranslator] = {}


def register_translator(name: str) -> Callable[[type[BaseTranslator]], type[BaseTranslator]]:
    def deco(cls: type[BaseTranslator]) -> type[BaseTranslator]:
        cls.vendor_target = name
        _TRANSLATORS[name] = cls()
        return cls
    return deco


def get_translator(name: str) -> BaseTranslator | None:
    return _TRANSLATORS.get(name)


def all_translators() -> list[BaseTranslator]:
    return sorted(_TRANSLATORS.values(), key=lambda t: t.vendor_target)


def pick_translator_for_asset(asset: dict) -> BaseTranslator | None:
    """Auto-pick a translator from asset identity (vendor + os_type + asset_type)."""
    ident = asset.get("identity") or {}
    vendor = (ident.get("vendor") or "").lower()
    os_type = ((asset.get("os") or {}).get("os_type") or "").lower()
    atype = ident.get("asset_type") or ""

    table = [
        (("cisco",), ("ios", "ios-xe"), "network", "cisco_ios"),
        (("cisco",), ("nxos", "nx-os"), "network", "cisco_nxos"),
        (("cisco",), ("asa",), "network", "cisco_asa"),
        (("arista",), (), "network", "arista_eos"),
        (("juniper",), (), "network", "juniper_junos"),
        (("fortinet",), (), "network", "fortinet_fortios"),
        (("palo-alto", "palo_alto", "paloalto"), (), "network", "paloalto_panos"),
        (("microsoft",), ("windows",), "server", "windows"),
        (("aws", "amazon"), (), "cloud", "aws_iam"),
        (("azure", "microsoft"), (), "cloud", "azure"),
        (("google", "gcp"), (), "cloud", "gcp"),
        # v6.2.1 — backup-platform translators
        (("veeam",), (), "backup", "veeam"),
        (("aws", "amazon"), (), "backup", "aws_s3_lock"),
        (("azure", "microsoft"), (), "backup", "azure_blob_immutable"),
        # v7.0 — identity / IdP translators (close the orphaned-controls gap)
        (("microsoft",), (), "identity", "azure_ca"),
        (("okta",), (), "identity", "okta_idp"),
        (("cisco",), (), "identity", "cisco_ise"),
        (("hpe", "aruba"), (), "identity", "clearpass_role"),
    ]
    for vendors, oses, atype_match, name in table:
        if any(v in vendor for v in vendors) and (not oses or any(o in os_type for o in oses)) \
                and (not atype_match or atype_match == atype):
            return _TRANSLATORS.get(name)
    # Generic fallback
    if atype == "server":
        return _TRANSLATORS.get("linux")
    return None


# Auto-load all translators
from safecadence.policy.translators import (  # noqa: E402,F401
    cisco_ios, cisco_nxos, cisco_asa, arista_eos, juniper_junos,
    fortinet_fortios, paloalto_panos, linux, windows,
    aws_iam, azure, gcp,
    # v6.0 — identity-system translators
    identity_translators,
    # v6.2.1 — backup-platform translators (Veeam + S3 Object Lock + Azure Blob)
    backup_translators,
)
