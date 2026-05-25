"""
v13 — Populate the Knowledge Graph from existing v11.x stores.

Reads from the existing SQLite asset store + platform_assets JSON
fallback and turns each finding / control / vendor / site into a node
+ the edges between them. Idempotent — re-running on an existing graph
upserts; does not double-insert.

The graph is intentionally derived (not the source of truth). On every
build we wipe + repopulate so the graph never drifts from the
underlying stores.

Public API
----------

* ``build_graph_from_assets(graph, assets=None)`` → ``{"nodes": N, "edges": M}``
* ``rebuild(graph)`` → reads from sqlite_store + platform_assets, wipes,
                       rebuilds. Convenience for daemon mode.
"""
from __future__ import annotations

from typing import Any

from safecadence.graph.schema import Edge, Node, attrs_to_tuple
from safecadence.graph.store import GraphStore


def build_graph_from_assets(
    graph: GraphStore,
    assets: list[dict] | None = None,
) -> dict:
    """Insert nodes + edges for every asset in `assets`.

    `assets` schema matches what ``sqlite_store.list_assets()`` returns:
    each asset dict has ``hostname``, ``vendor``, ``site``, optionally
    ``findings`` (each finding has ``id``, ``title``, ``severity``,
    optionally ``controls`` with ``control_id`` + ``framework``).
    """
    assets = list(assets or [])
    for a in assets:
        hostname = a.get("hostname") or a.get("id")
        if not hostname:
            continue
        graph.add_node(Node(
            "asset", hostname,
            label=a.get("display_name") or hostname,
            attrs=attrs_to_tuple({
                "criticality": a.get("criticality") or "",
                "asset_type":  a.get("asset_type") or "",
            }),
        ))
        vendor = (a.get("vendor") or "").strip()
        if vendor:
            graph.add_node(Node("vendor", vendor, label=vendor))
            graph.add_edge(Edge(
                "asset", hostname, "produced_by", "vendor", vendor,
            ))
        site = (a.get("site") or "").strip()
        if site:
            graph.add_node(Node("site", site, label=site))
            graph.add_edge(Edge(
                "asset", hostname, "located_at", "site", site,
            ))
        if a.get("crown_jewel"):
            cj_id = f"cj-{hostname}"
            graph.add_node(Node(
                "crown_jewel", cj_id, label=f"Crown jewel: {hostname}",
            ))
            graph.add_edge(Edge(
                "asset", hostname, "reaches", "crown_jewel", cj_id,
            ))

        for f in (a.get("findings") or []):
            fid = f.get("id") or f.get("rule_id")
            if not fid:
                continue
            graph.add_node(Node(
                "finding", str(fid),
                label=f.get("title") or "Finding",
                attrs=attrs_to_tuple({
                    "severity": (f.get("severity") or "").lower(),
                }),
            ))
            graph.add_edge(Edge(
                "asset", hostname, "exposes", "finding", str(fid),
            ))
            for ctrl in (f.get("controls") or []):
                cid = ctrl.get("control_id")
                fw = (ctrl.get("framework") or "").lower()
                if not cid or not fw:
                    continue
                graph.add_node(Node(
                    "control", cid,
                    label=ctrl.get("title") or cid,
                    attrs=attrs_to_tuple({"framework": fw}),
                ))
                graph.add_node(Node("framework", fw, label=fw.upper()))
                graph.add_edge(Edge(
                    "finding", str(fid), "violates", "control", cid,
                ))
                graph.add_edge(Edge(
                    "control", cid, "mapped_to", "framework", fw,
                ))

    return graph.count()


def rebuild(graph: GraphStore) -> dict:
    """Wipe + repopulate from sqlite_store. Defensive: never raises."""
    graph.clear()
    assets: list[dict] = []
    try:
        from safecadence.storage import sqlite_store
        assets = list(sqlite_store.list_assets() or [])
    except Exception:
        assets = []
    if not assets:
        try:
            from safecadence.reports.sections import _load_platform_assets
            assets = _load_platform_assets() or []
        except Exception:
            assets = []
    return build_graph_from_assets(graph, assets)


__all__ = ["build_graph_from_assets", "rebuild"]
