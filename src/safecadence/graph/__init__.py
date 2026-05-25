"""
v13 — Security Knowledge Graph.

Schema, SQLite-backed store, builder from existing v11.x asset data,
high-level query helpers, and BFS traversal. This is the foundation
v14 AI-driven features (predictive forecasting, conversational
assistant) sit on top of.

Submodules
----------

* ``schema``    — node + edge type vocabulary (Node, Edge dataclasses).
* ``store``     — GraphStore: SQLite-backed graph with add/get/neighbors.
* ``build``     — ``build_graph_from_assets()`` + ``rebuild()`` helpers.
* ``query``     — high-level "what touches X?" question wrappers.
* ``traverse``  — ``shortest_path`` (BFS) + ``walk`` (bounded reachable set).

Public re-exports
-----------------

Importing ``safecadence.graph`` is enough for the common case::

    from safecadence.graph import GraphStore, Node, Edge, build_graph_from_assets
    from safecadence.graph import shortest_path

Backends other than SQLite (NetworkX in-memory, Neo4j, Memgraph) are
v15+ work items — the abstraction sits on the GraphStore class so
those can swap in without changing call sites.
"""
from __future__ import annotations

from safecadence.graph.build import build_graph_from_assets, rebuild
from safecadence.graph.query import (
    assets_exposing_finding,
    crown_jewel_reachers,
    frameworks_affected,
    violations_for_framework,
    what_touches,
)
from safecadence.graph.schema import (
    EDGE_TYPES,
    NODE_TYPES,
    Edge,
    Node,
    attrs_to_tuple,
    valid_edge,
)
from safecadence.graph.store import GraphStore
from safecadence.graph.traverse import shortest_path, walk

__version__ = "0.1.0-alpha"

__all__ = [
    "GraphStore",
    "Node", "Edge", "NODE_TYPES", "EDGE_TYPES",
    "valid_edge", "attrs_to_tuple",
    "build_graph_from_assets", "rebuild",
    "what_touches", "assets_exposing_finding",
    "frameworks_affected", "violations_for_framework",
    "crown_jewel_reachers",
    "shortest_path", "walk",
]
