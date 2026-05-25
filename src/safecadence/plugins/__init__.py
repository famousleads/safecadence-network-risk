"""
v15.0 — Ecosystem.

Two submodules:

* ``loader`` — entry-point-based plugin discovery + signature
               verification + capability gating.
* ``rule_packs`` — community rule pack manifest format + add/list/
                   verify helpers; CLI integration at
                   `safecadence rules add <url>`.

The plugin SDK itself stays in the MIT-licensed open-source repo.
Anyone can publish a plugin without going through a marketplace; the
marketplace (if it ever ships) is just a discovery + payments layer.
"""
from __future__ import annotations

from safecadence.plugins.loader import (
    PluginManifest,
    discover_plugins,
    load_plugin,
    verify_plugin_signature,
)
from safecadence.plugins.rule_packs import (
    RulePackManifest,
    add_rule_pack,
    list_rule_packs,
    verify_rule_pack,
)

__version__ = "0.1.0"

__all__ = [
    "PluginManifest", "discover_plugins", "load_plugin",
    "verify_plugin_signature",
    "RulePackManifest", "add_rule_pack", "list_rule_packs",
    "verify_rule_pack",
]
