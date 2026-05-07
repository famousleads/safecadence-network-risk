"""
v9.32 — Data classification.

Tag assets with the categories of regulated data they handle:
PII, PHI, PCI, IP, CUI (Controlled Unclassified Info), or PUBLIC.
That tag answers two questions auditors and the policy engine
need to answer correctly:

  1. Scope. "Encrypt sensitive data at rest" doesn't apply to a
     PUBLIC bulletin board; it does apply to a PHI database. Without
     classification, we can't tell.
  2. Risk weighting. A finding on a PHI-tagged asset is higher
     impact than the same finding on a PUBLIC asset. The Safe Score
     (v9.26) already weights by criticality; this adds a second
     dimension — *what data is at stake*.

Storage: the tag lives directly on the asset under
``identity.data_classification`` (existing schema slot). This module
provides the validation + summary helpers.

Multi-tag is supported (an asset can be both PII + PCI). The score
penalty stacks but is capped so a kitchen-sink labelling doesn't
bottom out the score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


_VALID_CLASSES = {
    "public":   {"label": "Public",
                   "description": "Public-facing, no regulated data",
                   "weight": 0},
    "internal": {"label": "Internal use",
                   "description": "Company-confidential but not regulated",
                   "weight": 1},
    "pii":      {"label": "PII",
                   "description": "Personally Identifiable Information",
                   "weight": 4},
    "phi":      {"label": "PHI / HIPAA",
                   "description": "Protected Health Information (HIPAA scope)",
                   "weight": 5},
    "pci":      {"label": "PCI",
                   "description": "Payment-card data (PCI-DSS scope)",
                   "weight": 5},
    "ip":       {"label": "IP / trade secret",
                   "description": "Source code, designs, formulas",
                   "weight": 4},
    "cui":      {"label": "CUI",
                   "description": "Controlled Unclassified Information (federal)",
                   "weight": 5},
}


_RISK_MULTIPLIER_CAP = 1.6   # max ×1.6 risk amplification per asset


def normalize(value) -> list[str]:
    """Accept a string or list, return a normalized lowercase list of
    valid classification keys. Unknown tags are dropped."""
    if not value:
        return []
    if isinstance(value, str):
        items = [s.strip().lower() for s in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = [str(s).strip().lower() for s in value]
    else:
        return []
    out: list[str] = []
    for s in items:
        if s in _VALID_CLASSES and s not in out:
            out.append(s)
    return out


def classes() -> dict:
    """Public catalog for the UI to render the picker."""
    return {k: dict(v) for k, v in _VALID_CLASSES.items()}


def risk_multiplier_for(asset: dict) -> float:
    """How much to amplify a finding's severity weight on this asset.

    Returns 1.0 for unclassified or public. Up to ``_RISK_MULTIPLIER_CAP``
    for assets with multiple high-weight tags.
    """
    if not isinstance(asset, dict):
        return 1.0
    ident = asset.get("identity") or {}
    tags = normalize(ident.get("data_classification"))
    if not tags:
        return 1.0
    total_weight = sum(_VALID_CLASSES[t]["weight"] for t in tags)
    # Map weight 0..15+ to 1.0..1.6 sensibly.
    mult = 1.0 + min(0.6, total_weight / 12.0)
    return round(min(_RISK_MULTIPLIER_CAP, mult), 2)


def fleet_summary(assets: Iterable[dict]) -> dict:
    """Roll up classification counts across a fleet — feeds /scope
    and the evidence pack."""
    counts: dict[str, int] = {k: 0 for k in _VALID_CLASSES}
    untagged = 0
    classified = 0
    for a in assets:
        tags = normalize((a.get("identity") or {}).get("data_classification"))
        if not tags:
            untagged += 1
            continue
        classified += 1
        for t in tags:
            counts[t] = counts.get(t, 0) + 1
    return {
        "total": untagged + classified,
        "classified": classified,
        "untagged": untagged,
        "by_class": counts,
    }
