"""
v13 — SQLite backend for the Knowledge Graph.

Stdlib-only. Two tables: ``g_nodes`` + ``g_edges``. Both keyed by
(type, id) tuples so the rest of the platform's existing string ids
(asset hostname, finding id, control_id) plug straight in.

Why not Neo4j: SafeCadence is local-first and ships in a single
``pip install``. SQLite covers fleets up to ~50k nodes / 200k edges
with sub-second BFS — well above the size of any real customer fleet
today. A Neo4j backend is a v15 line item if + when fleets need it.

Public API
----------

* ``GraphStore(db_path=None)``
* ``add_node(node)``  /  ``add_edge(edge)``
* ``get_node(type, id)``
* ``neighbors(type, id, edge_type=None, direction="out")``
* ``count()`` → ``{"nodes": N, "edges": M}``
* ``clear()`` — wipe both tables (test helper)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from safecadence.graph.schema import Edge, Node


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS g_nodes (
    type   TEXT NOT NULL,
    id     TEXT NOT NULL,
    label  TEXT NOT NULL DEFAULT '',
    attrs  TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (type, id)
);

CREATE TABLE IF NOT EXISTS g_edges (
    src_type   TEXT NOT NULL,
    src_id     TEXT NOT NULL,
    edge_type  TEXT NOT NULL,
    dst_type   TEXT NOT NULL,
    dst_id     TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY (src_type, src_id, edge_type, dst_type, dst_id)
);

CREATE INDEX IF NOT EXISTS idx_g_edges_src
    ON g_edges(src_type, src_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_g_edges_dst
    ON g_edges(dst_type, dst_id, edge_type);
"""


class GraphStore:
    """In-process Knowledge Graph backed by SQLite."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        # Default: in-memory; pass a Path for persistent.
        self.db_path = str(db_path) if db_path else ":memory:"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    # ---------- mutation ------------------------------------------- #

    def add_node(self, node: Node) -> None:
        attrs_json = json.dumps(dict(node.attrs))
        self._conn.execute(
            "INSERT OR REPLACE INTO g_nodes (type, id, label, attrs) "
            "VALUES (?, ?, ?, ?)",
            (node.type, node.id, node.label, attrs_json),
        )
        self._conn.commit()

    def add_edge(self, edge: Edge) -> None:
        # Edge() ctor already validated schema; trust it here.
        # Ensure both endpoints exist as placeholder nodes so traversal
        # never finds a dangling edge.
        for nt, nid in ((edge.src_type, edge.src_id),
                        (edge.dst_type, edge.dst_id)):
            self._conn.execute(
                "INSERT OR IGNORE INTO g_nodes (type, id) VALUES (?, ?)",
                (nt, nid),
            )
        self._conn.execute(
            "INSERT OR REPLACE INTO g_edges "
            "(src_type, src_id, edge_type, dst_type, dst_id, weight) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (edge.src_type, edge.src_id, edge.edge_type,
             edge.dst_type, edge.dst_id, edge.weight),
        )
        self._conn.commit()

    def add_edges(self, edges: Iterable[Edge]) -> int:
        n = 0
        for e in edges:
            self.add_edge(e)
            n += 1
        return n

    def clear(self) -> None:
        self._conn.executescript(
            "DELETE FROM g_edges; DELETE FROM g_nodes;"
        )
        self._conn.commit()

    # ---------- read ---------------------------------------------- #

    def get_node(self, ntype: str, nid: str) -> dict | None:
        row = self._conn.execute(
            "SELECT type, id, label, attrs FROM g_nodes WHERE type=? AND id=?",
            (ntype, nid),
        ).fetchone()
        if row is None:
            return None
        return {
            "type": row["type"],
            "id": row["id"],
            "label": row["label"],
            "attrs": json.loads(row["attrs"] or "{}"),
        }

    def neighbors(
        self,
        ntype: str,
        nid: str,
        *,
        edge_type: str | None = None,
        direction: str = "out",
    ) -> list[dict]:
        """Return neighbor nodes plus the edge that connects them.

        direction: "out" (follow edges leaving the node),
                   "in"  (follow edges entering the node),
                   "both" (union of the two).
        """
        out: list[dict] = []
        if direction in ("out", "both"):
            sql = (
                "SELECT dst_type as t, dst_id as i, edge_type as e, weight as w "
                "FROM g_edges WHERE src_type=? AND src_id=?"
            )
            params: list = [ntype, nid]
            if edge_type:
                sql += " AND edge_type=?"
                params.append(edge_type)
            for r in self._conn.execute(sql, params).fetchall():
                out.append({
                    "type": r["t"], "id": r["i"],
                    "via_edge": r["e"], "direction": "out", "weight": r["w"],
                })
        if direction in ("in", "both"):
            sql = (
                "SELECT src_type as t, src_id as i, edge_type as e, weight as w "
                "FROM g_edges WHERE dst_type=? AND dst_id=?"
            )
            params = [ntype, nid]
            if edge_type:
                sql += " AND edge_type=?"
                params.append(edge_type)
            for r in self._conn.execute(sql, params).fetchall():
                out.append({
                    "type": r["t"], "id": r["i"],
                    "via_edge": r["e"], "direction": "in", "weight": r["w"],
                })
        return out

    def count(self) -> dict:
        n = self._conn.execute("SELECT COUNT(*) FROM g_nodes").fetchone()[0]
        e = self._conn.execute("SELECT COUNT(*) FROM g_edges").fetchone()[0]
        return {"nodes": n, "edges": e}


__all__ = ["GraphStore"]
