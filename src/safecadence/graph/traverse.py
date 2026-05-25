"""
v13 — Graph traversal (BFS + path-finding).

Two primitives:

* ``shortest_path(graph, src, dst, max_depth)`` — BFS hop-count path.
* ``walk(graph, src, max_depth, edge_filter)`` — generator yielding
  every node reachable from `src` within `max_depth` hops.

Both follow edges as a *directed* graph; for undirected traversal,
pass ``direction="both"`` to the underlying ``neighbors()`` via the
helper below.

Path-finding is intentionally simple — single source, single
destination, hop-count (not weighted). Weighted Dijkstra over the
``weight`` field arrives in v14 when AI-driven remediation needs to
rank candidate paths by likely fix cost.

Public API
----------

* ``shortest_path(graph, src, dst, max_depth=8, direction="out")``
* ``walk(graph, src, max_depth=4, direction="out", edge_filter=None)``
"""
from __future__ import annotations

from collections import deque
from typing import Iterable

from safecadence.graph.store import GraphStore


def shortest_path(
    graph: GraphStore,
    src: tuple[str, str],
    dst: tuple[str, str],
    *,
    max_depth: int = 8,
    direction: str = "out",
) -> list[tuple[str, str]] | None:
    """Return the shortest hop-count path from `src` to `dst`.

    Each node is a ``(type, id)`` tuple. Returns ``None`` if no path
    within `max_depth` hops.
    """
    if src == dst:
        return [src]

    visited: set[tuple[str, str]] = {src}
    # Queue items: (current_node, path_so_far)
    queue: deque = deque([(src, [src])])
    while queue:
        node, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for n in graph.neighbors(node[0], node[1], direction=direction):
            nkey = (n["type"], n["id"])
            if nkey in visited:
                continue
            new_path = path + [nkey]
            if nkey == dst:
                return new_path
            visited.add(nkey)
            queue.append((nkey, new_path))
    return None


def walk(
    graph: GraphStore,
    src: tuple[str, str],
    *,
    max_depth: int = 4,
    direction: str = "out",
    edge_filter: Iterable[str] | None = None,
) -> list[dict]:
    """Return every node reachable from `src` within `max_depth` hops.

    Each result entry: ``{"type", "id", "depth", "via_edge"}``.
    ``edge_filter`` (when given) restricts traversal to those edge types.
    """
    filt = set(edge_filter) if edge_filter else None
    seen: set[tuple[str, str]] = {src}
    out: list[dict] = []
    queue: deque = deque([(src, 0, None)])
    while queue:
        node, depth, via = queue.popleft()
        if depth > 0:
            out.append({
                "type": node[0], "id": node[1],
                "depth": depth, "via_edge": via,
            })
        if depth >= max_depth:
            continue
        for n in graph.neighbors(node[0], node[1], direction=direction):
            if filt is not None and n["via_edge"] not in filt:
                continue
            nkey = (n["type"], n["id"])
            if nkey in seen:
                continue
            seen.add(nkey)
            queue.append((nkey, depth + 1, n["via_edge"]))
    return out


__all__ = ["shortest_path", "walk"]
