"""
v13 — Knowledge Graph node + edge type definitions.

This is the small, fixed vocabulary the rest of the platform uses to
talk to the graph. Adding a new node or edge type is intentionally a
*deliberate* change (one PR, schema bump, documented), not something
that can grow organically — that's how graph data models stay
queryable instead of degenerating into "everyone made up their own
edge names."

Node types
----------

* ``asset``        — anything in the inventory (router, server, etc.)
* ``identity``     — human user (AD, Entra, Okta)
* ``nhi``          — non-human identity (service account, API key)
* ``finding``      — a current security finding
* ``control``      — a compliance control (e.g. NIST 800-53 AC-2)
* ``framework``    — a parent framework (e.g. NIST 800-53, SOC 2)
* ``vendor``       — gear vendor (Cisco, Fortinet, Okta)
* ``site``         — physical location
* ``risk``         — formal risk register entry
* ``ticket``       — external ITSM ticket (Jira/ServiceNow/etc.)
* ``crown_jewel``  — asset explicitly flagged as crown jewel

Edge types
----------

* ``exposes``      — asset → finding
* ``violates``     — finding → control
* ``mapped_to``    — control → framework
* ``depends_on``   — asset → asset (link / dataflow)
* ``grants_access_to`` — identity → asset
* ``owns``         — identity → nhi
* ``remediates``   — ticket → finding
* ``escalates_to`` — risk → finding
* ``produced_by``  — asset → vendor
* ``located_at``   — asset → site
* ``reaches``      — asset → crown_jewel  (attack-path terminal edge)

Public API
----------

* ``NODE_TYPES`` / ``EDGE_TYPES`` constants
* ``Node`` / ``Edge`` dataclasses (typed, hashable)
* ``valid_edge(src_type, edge_type, dst_type)`` — schema validator
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


NODE_TYPES: frozenset[str] = frozenset({
    "asset", "identity", "nhi", "finding", "control", "framework",
    "vendor", "site", "risk", "ticket", "crown_jewel",
})

EDGE_TYPES: frozenset[str] = frozenset({
    "exposes", "violates", "mapped_to", "depends_on",
    "grants_access_to", "owns", "remediates", "escalates_to",
    "produced_by", "located_at", "reaches",
})

# Schema rules: which (src_type → edge_type → dst_type) tuples are valid.
# Anything outside this set is rejected by valid_edge() and add_edge().
_EDGE_SCHEMA: dict[tuple[str, str, str], None] = {
    ("asset", "exposes", "finding"):              None,
    ("finding", "violates", "control"):           None,
    ("control", "mapped_to", "framework"):        None,
    ("asset", "depends_on", "asset"):             None,
    ("identity", "grants_access_to", "asset"):    None,
    ("identity", "owns", "nhi"):                  None,
    ("nhi", "grants_access_to", "asset"):         None,
    ("ticket", "remediates", "finding"):          None,
    ("risk", "escalates_to", "finding"):          None,
    ("asset", "produced_by", "vendor"):           None,
    ("asset", "located_at", "site"):              None,
    ("asset", "reaches", "crown_jewel"):          None,
}


@dataclass(frozen=True)
class Node:
    type: str            # one of NODE_TYPES
    id: str              # caller-supplied, unique within type
    label: str = ""      # human-readable
    attrs: tuple = field(default_factory=tuple)  # ((k, v), ...) — hashable

    def __post_init__(self) -> None:
        if self.type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {self.type!r}")
        if not self.id:
            raise ValueError("Node id must be non-empty")

    @property
    def key(self) -> tuple[str, str]:
        """Composite key used by the store."""
        return (self.type, self.id)


@dataclass(frozen=True)
class Edge:
    src_type: str
    src_id: str
    edge_type: str
    dst_type: str
    dst_id: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not valid_edge(self.src_type, self.edge_type, self.dst_type):
            raise ValueError(
                f"Invalid edge: {self.src_type!r} --{self.edge_type!r}--> "
                f"{self.dst_type!r}"
            )


def valid_edge(src_type: str, edge_type: str, dst_type: str) -> bool:
    """True when (src_type, edge_type, dst_type) is in the schema."""
    return (src_type, edge_type, dst_type) in _EDGE_SCHEMA


def attrs_to_tuple(d: dict[str, Any] | None) -> tuple:
    """Helper for Node(attrs=...); produces a hashable, sorted tuple."""
    if not d:
        return ()
    return tuple(sorted((k, str(v)) for k, v in d.items()))


__all__ = [
    "NODE_TYPES", "EDGE_TYPES",
    "Node", "Edge",
    "valid_edge", "attrs_to_tuple",
]
