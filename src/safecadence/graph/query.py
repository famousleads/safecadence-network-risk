"""
v13 — High-level question helpers over the Knowledge Graph.

These are the "what would I actually ask" wrappers that the rest of
the platform calls. Each one is a thin composition of ``GraphStore``
primitives — no business logic, just shapes.

Public API
----------

* ``what_touches(graph, ntype, nid)``      — all neighbors, in + out
* ``violations_for_framework(graph, fw)``  — findings tied to controls in fw
* ``assets_exposing_finding(graph, fid)``  — reverse: who's hit by this finding?
* ``frameworks_affected(graph, finding_id)`` — chain finding → control → framework
* ``crown_jewel_reachers(graph)``          — every (asset → crown_jewel) edge
"""
from __future__ import annotations

from safecadence.graph.store import GraphStore


def what_touches(graph: GraphStore, ntype: str, nid: str) -> list[dict]:
    """Every neighbor, both directions, regardless of edge type."""
    return graph.neighbors(ntype, nid, direction="both")


def assets_exposing_finding(graph: GraphStore, finding_id: str) -> list[dict]:
    """Reverse lookup: which assets `exposes` this finding?"""
    return graph.neighbors(
        "finding", finding_id, edge_type="exposes", direction="in",
    )


def frameworks_affected(graph: GraphStore, finding_id: str) -> list[str]:
    """finding → violates → control → mapped_to → framework. Deduped."""
    out: set[str] = set()
    for ctrl in graph.neighbors(
        "finding", finding_id, edge_type="violates", direction="out",
    ):
        for fw in graph.neighbors(
            ctrl["type"], ctrl["id"],
            edge_type="mapped_to", direction="out",
        ):
            out.add(fw["id"])
    return sorted(out)


def violations_for_framework(graph: GraphStore, framework: str) -> list[dict]:
    """All findings whose violated control maps to `framework`.

    Returned shape: ``[{"finding_id": ..., "control_id": ...}, ...]``
    Deduped on (finding_id, control_id).
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    # framework -> mapped_to (inbound) -> control -> violates (inbound) -> finding
    for ctrl in graph.neighbors(
        "framework", framework.lower(),
        edge_type="mapped_to", direction="in",
    ):
        for f in graph.neighbors(
            ctrl["type"], ctrl["id"],
            edge_type="violates", direction="in",
        ):
            key = (f["id"], ctrl["id"])
            if key in seen:
                continue
            seen.add(key)
            out.append({"finding_id": f["id"], "control_id": ctrl["id"]})
    return out


def crown_jewel_reachers(graph: GraphStore) -> list[dict]:
    """Every (asset → crown_jewel) edge. Used by attack-path v2."""
    # SQLite: cheaper than iterating in Python.
    rows = graph._conn.execute(
        "SELECT src_id AS asset, dst_id AS crown FROM g_edges "
        "WHERE edge_type = 'reaches'"
    ).fetchall()
    return [{"asset": r["asset"], "crown_jewel": r["crown"]} for r in rows]


__all__ = [
    "what_touches",
    "assets_exposing_finding",
    "frameworks_affected",
    "violations_for_framework",
    "crown_jewel_reachers",
]
