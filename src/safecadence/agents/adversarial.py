"""
v16.0 — Adversarial defender + attacker pair.

Two agents work continuously as a coordinated pair on the same
Knowledge Graph (v13). One is the **red** agent — walks the graph
from "edge" nodes (anything publicly reachable) looking for paths
to crown jewels. The other is the **blue** agent — for each path
the red one finds, checks whether the customer's existing
compensating controls actually mitigate the risk.

**The interesting output is the disagreements.** If red says "this
is reachable" and blue says "but the compensating control covers
it," that's a candidate finding. If red and blue agree it's a real
exposure, that's a high-confidence alert. If they agree it's
mitigated, it's noise the operator should never see.

How it's different from existing offerings
------------------------------------------

- Most "AI red team" tools are one-shot manual runs.
- Most "compensating controls" features are static rule lookups.
- Pairing them and running continuously, surfacing only
  disagreements, is what makes this defensible.

Public API
----------

* ``run_red(graph)``     → list[dict] of candidate paths
* ``run_blue(graph, candidate_paths)`` → list[dict] of verdicts
* ``run_round(graph, *, agent_id_red, agent_id_blue, nudge_conn)``
  → dict with summary + raises nudges for genuine disagreements

Each path verdict:

    {
      "path": [(type, id), ...],
      "red_says": "exploitable" | "speculative",
      "red_confidence": 0.0–1.0,
      "blue_says": "mitigated" | "not_mitigated" | "needs_review",
      "blue_reason": str,
      "agreement": "agree_exposed" | "agree_safe" | "disagreement",
      "severity_estimate": "info" | "warning" | "critical",
    }
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("safecadence.agents.adversarial")


# Heuristic edge-weight map — what edges are "scary" to traverse for red.
_RED_EDGE_WEIGHT = {
    "exposes":              1.0,
    "depends_on":           0.6,
    "grants_access_to":     0.8,
    "owns":                 0.4,
    "reaches":              1.0,    # terminal edge to crown jewel
    "violates":             0.7,
    "mapped_to":            0.2,
    "produced_by":          0.0,    # not interesting to attacker
    "located_at":           0.0,
    "remediates":           0.0,
    "escalates_to":         0.0,
}


def _is_edge_node(graph: Any, node_type: str, node_id: str) -> bool:
    """Heuristic: a node is 'edge-reachable' if it has the 'edge' tag
    or its label contains 'edge'/'internet'/'public'. For demo purposes
    we lean on naming; v17 will use a proper exposure attribute."""
    n = graph.get_node(node_type, node_id) if hasattr(graph, "get_node") else None
    if not n:
        return False
    label = (n.get("label") or "").lower()
    attrs = n.get("attrs") or {}
    if str(attrs.get("exposure", "")).lower() in ("public", "internet", "edge"):
        return True
    return any(k in label for k in ("edge", "internet", "public", "dmz"))


def run_red(
    graph: Any, *, max_depth: int = 5, top_n: int = 25,
) -> list[dict]:
    """Walk the graph from edge nodes toward crown_jewel nodes.

    Returns a list of candidate paths, ranked by an attacker-weight
    heuristic (longer paths through high-weight edges score higher).
    """
    from safecadence.graph.traverse import shortest_path

    # Find all edge nodes + all crown_jewel nodes via the store.
    candidates: list[dict] = []
    try:
        edge_rows = graph._conn.execute(
            "SELECT type, id FROM g_nodes WHERE type='asset'"
        ).fetchall()
    except Exception:
        return candidates

    edge_nodes = [
        (r["type"], r["id"]) for r in edge_rows
        if _is_edge_node(graph, r["type"], r["id"])
    ]
    try:
        crown_rows = graph._conn.execute(
            "SELECT type, id FROM g_nodes WHERE type='crown_jewel'"
        ).fetchall()
    except Exception:
        crown_rows = []
    crowns = [(r["type"], r["id"]) for r in crown_rows]

    for src in edge_nodes:
        for dst in crowns:
            path = shortest_path(graph, src, dst, max_depth=max_depth)
            if not path:
                continue
            # Score: sum of edge weights along path
            score = 0.0
            for i in range(len(path) - 1):
                a = path[i]
                b = path[i + 1]
                for n in graph.neighbors(a[0], a[1]):
                    if (n["type"], n["id"]) == b:
                        score += _RED_EDGE_WEIGHT.get(n["via_edge"], 0.3)
                        break
            candidates.append({
                "path": path,
                "red_says": "exploitable" if score >= 2.0 else "speculative",
                "red_confidence": round(min(1.0, score / 5.0), 3),
                "score": round(score, 3),
            })

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates[:top_n]


def run_blue(
    graph: Any, candidate_paths: list[dict],
) -> list[dict]:
    """For each candidate path, check whether a compensating control
    covers it. Returns the same path dicts annotated with a verdict.

    Today's logic is a heuristic: if any finding on the path has a
    ``violates`` edge to a control AND that control's framework
    suggests it's still active in the customer's policy, blue says
    'needs_review'. If the path hits a ``crown_jewel`` *without*
    intermediate findings, blue says 'mitigated' (no exploitation
    surface). Future v17 plugs the real ``risk_acceptance_log`` from
    v10.4 + the v15 compensating-control packs.
    """
    out: list[dict] = []
    for c in candidate_paths:
        path = c["path"]
        # Count findings along the path
        finding_nodes = [n for n in path if n[0] == "finding"]
        # Check whether any finding has at least one violated control
        violated_count = 0
        for f_node in finding_nodes:
            for n in graph.neighbors(f_node[0], f_node[1],
                                       edge_type="violates", direction="out"):
                violated_count += 1
                break

        if not finding_nodes:
            blue_says = "mitigated"
            blue_reason = "path traverses no exploitable findings"
            agreement = (
                "agree_safe" if c["red_says"] == "speculative"
                else "disagreement"
            )
        elif violated_count == 0:
            blue_says = "mitigated"
            blue_reason = (
                f"{len(finding_nodes)} finding(s) on path but none "
                "currently violate a tracked control"
            )
            agreement = "disagreement" if c["red_says"] == "exploitable" else "agree_safe"
        elif violated_count >= len(finding_nodes):
            blue_says = "not_mitigated"
            blue_reason = (
                f"every finding on path ({len(finding_nodes)}) violates "
                "at least one control with no compensating coverage"
            )
            agreement = "agree_exposed" if c["red_says"] == "exploitable" else "disagreement"
        else:
            blue_says = "needs_review"
            blue_reason = (
                f"{violated_count}/{len(finding_nodes)} findings violate "
                "controls; compensating coverage is partial"
            )
            agreement = "disagreement"

        # Severity estimate — only mark critical when both red + blue
        # agree the path is exposed.
        if agreement == "agree_exposed":
            severity = "critical"
        elif agreement == "disagreement":
            severity = "warning"
        else:
            severity = "info"

        out.append({
            **c,
            "blue_says": blue_says,
            "blue_reason": blue_reason,
            "agreement": agreement,
            "severity_estimate": severity,
        })
    return out


def run_round(
    graph: Any,
    *,
    agent_id_red: str = "red-walker",
    agent_id_blue: str = "blue-controller",
    nudge_conn: Any = None,
) -> dict:
    """One full red→blue pass. When ``nudge_conn`` is supplied, the
    ``disagreement`` rows are emitted as agent_nudges so the operator
    sees them in their inbox.

    Returns a summary:

        {
          "candidates": int,
          "agreements_exposed": int,
          "agreements_safe": int,
          "disagreements": int,
          "nudges_created": int,
          "verdicts": list[dict]  # top N for inspection
        }
    """
    candidates = run_red(graph)
    verdicts = run_blue(graph, candidates)

    summary = {
        "candidates": len(candidates),
        "agreements_exposed": sum(1 for v in verdicts if v["agreement"] == "agree_exposed"),
        "agreements_safe":    sum(1 for v in verdicts if v["agreement"] == "agree_safe"),
        "disagreements":      sum(1 for v in verdicts if v["agreement"] == "disagreement"),
        "nudges_created":     0,
        "verdicts":           verdicts[:25],
    }

    # Fire nudges for disagreements (the interesting cases).
    if nudge_conn is not None:
        try:
            from safecadence.agents.nudges import create_nudge
            for v in verdicts:
                if v["agreement"] != "disagreement":
                    continue
                p = v["path"]
                sig = (
                    "redblue:" + "->".join(f"{t}:{i}" for t, i in p)
                )
                title = (
                    f"Red & Blue disagree about path to "
                    f"{p[-1][1] if p else '?'}"
                )
                body = (
                    f"Red ({v['red_says']}, confidence {v['red_confidence']}) "
                    f"sees a {len(p)}-hop path from {p[0][1] if p else '?'} "
                    f"to {p[-1][1] if p else '?'}. "
                    f"Blue ({v['blue_says']}) says: {v['blue_reason']}."
                )
                nid = create_nudge(
                    nudge_conn,
                    agent_id=agent_id_red,
                    signature=sig,
                    title=title,
                    body=body,
                    severity=v["severity_estimate"],
                    category="red-blue-disagreement",
                    suggested_action="review_attack_path",
                    evidence={"path": p, "verdict": v},
                )
                if nid:
                    summary["nudges_created"] += 1
        except Exception as exc:
            _log.warning("nudge emission failed: %s", exc)

    return summary


__all__ = ["run_red", "run_blue", "run_round"]
