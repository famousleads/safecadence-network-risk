"""
v9.32 — cross-vendor policy migration.

Take a policy authored for Vendor A (or our abstract policy schema)
and emit equivalent configuration for Vendor B. Uses the v9.31 live
preview snippets as the rendering layer — the *real* enforcement
translators kick in at execute-time.

Common use case: "we're switching from Palo Alto to Fortinet — give
me the equivalent rule shape so the netops team has a starting
point." This isn't a perfect 1:1 (security policy semantics differ
between vendors) but it gets the team to "review this draft" instead
of "rewrite from scratch."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass
class MigrationResult:
    source_vendor: str
    target_vendor: str
    source_controls: list[str] = field(default_factory=list)
    target_rendered: str = ""
    controls_migrated: list[str] = field(default_factory=list)
    controls_lost: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_vendor": self.source_vendor,
            "target_vendor": self.target_vendor,
            "source_controls": list(self.source_controls),
            "target_rendered": self.target_rendered,
            "controls_migrated": list(self.controls_migrated),
            "controls_lost": list(self.controls_lost),
            "notes": list(self.notes),
            "migration_pct": (
                round(100.0 * len(self.controls_migrated)
                       / max(1, len(self.source_controls)), 1)
            ),
        }


def migrate(source_vendor: str, target_vendor: str,
              source_controls: Iterable[str]) -> MigrationResult:
    """Render the same logical control list against the target vendor.

    The source vendor only matters for the report (we don't actually
    parse source configs here — we operate on the abstract control
    list). For real config-to-config translation, run import_one_config
    first to get the abstract control list, then call this.
    """
    cids = list(source_controls)
    notes: list[str] = []

    if not target_vendor:
        return MigrationResult(
            source_vendor=source_vendor, target_vendor="",
            source_controls=cids,
            notes=["target_vendor required"],
        )

    try:
        from safecadence.policy.quick import render_for_vendor
    except Exception:                                       # pragma: no cover
        return MigrationResult(
            source_vendor=source_vendor, target_vendor=target_vendor,
            source_controls=cids,
            notes=["render_for_vendor unavailable"],
        )

    rendered = render_for_vendor(target_vendor, cids)
    if not rendered.get("supported"):
        notes.append(rendered.get("note") or "no preview pack for target")

    if source_vendor and source_vendor != target_vendor:
        notes.append(
            f"Migration from {source_vendor} → {target_vendor}: "
            f"semantic differences may exist; review every rule "
            f"before pushing to production."
        )

    return MigrationResult(
        source_vendor=source_vendor or "",
        target_vendor=target_vendor,
        source_controls=cids,
        target_rendered=rendered.get("rendered", ""),
        controls_migrated=list(rendered.get("controls_covered") or []),
        controls_lost=list(rendered.get("controls_missing") or []),
        notes=notes,
    )


def migrate_from_configs(source_configs: list[tuple[str, str]],
                           target_vendor: str) -> MigrationResult:
    """Convenience: import configs, then migrate the inferred control
    list to the target vendor. Single call for the "switch our entire
    fleet from Palo Alto to Fortinet" workflow."""
    from safecadence.policy.import_from_configs import import_fleet
    inferred = import_fleet(source_configs, quorum_pct=50)
    src_vendor = (inferred.per_config[0].vendor_key
                    if inferred.per_config else "")
    return migrate(src_vendor, target_vendor, inferred.controls)
