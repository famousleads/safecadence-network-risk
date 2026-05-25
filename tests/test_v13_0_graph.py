"""
Tests for v13.0 — Knowledge Graph (schema + store + build + query + traverse).
"""
from __future__ import annotations

import pytest

from safecadence.graph.build import build_graph_from_assets
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


# ---- schema ----------------------------------------------------- #


def test_schema_node_types_complete():
    assert {"asset", "identity", "nhi", "finding", "control",
            "framework", "vendor", "site"} <= NODE_TYPES


def test_schema_edge_types_complete():
    assert {"exposes", "violates", "mapped_to",
            "depends_on", "reaches"} <= EDGE_TYPES


def test_node_rejects_unknown_type():
    with pytest.raises(ValueError):
        Node("not-a-type", "x")


def test_node_rejects_empty_id():
    with pytest.raises(ValueError):
        Node("asset", "")


def test_edge_rejects_invalid_schema():
    # finding cannot "exposes" anything
    with pytest.raises(ValueError):
        Edge("finding", "F1", "exposes", "asset", "A1")


def test_valid_edge_accepts_known():
    assert valid_edge("asset", "exposes", "finding")
    assert valid_edge("finding", "violates", "control")


def test_valid_edge_rejects_unknown():
    assert not valid_edge("asset", "violates", "finding")


def test_attrs_to_tuple_is_hashable_and_sorted():
    t = attrs_to_tuple({"b": 2, "a": 1})
    assert t == (("a", "1"), ("b", "2"))
    hash(t)  # must be hashable


# ---- store ------------------------------------------------------ #


def test_store_add_and_count():
    g = GraphStore()
    g.add_node(Node("asset", "a1"))
    g.add_node(Node("finding", "f1"))
    g.add_edge(Edge("asset", "a1", "exposes", "finding", "f1"))
    assert g.count() == {"nodes": 2, "edges": 1}


def test_store_neighbors_directions():
    g = GraphStore()
    g.add_edge(Edge("asset", "a1", "exposes", "finding", "f1"))
    out = g.neighbors("asset", "a1")
    assert out and out[0]["id"] == "f1"
    inn = g.neighbors("finding", "f1", direction="in")
    assert inn and inn[0]["id"] == "a1"


def test_store_clear():
    g = GraphStore()
    g.add_node(Node("asset", "a1"))
    g.clear()
    assert g.count() == {"nodes": 0, "edges": 0}


def test_store_get_node_returns_attrs():
    g = GraphStore()
    g.add_node(Node("asset", "a1", "Edge FW",
                    attrs=attrs_to_tuple({"criticality": "high"})))
    n = g.get_node("asset", "a1")
    assert n is not None
    assert n["label"] == "Edge FW"
    assert n["attrs"]["criticality"] == "high"


def test_store_edge_endpoints_autocreated():
    g = GraphStore()
    g.add_edge(Edge("asset", "a1", "exposes", "finding", "f1"))
    # both endpoints were created by add_edge even though we never called add_node
    assert g.get_node("asset", "a1") is not None
    assert g.get_node("finding", "f1") is not None


# ---- build ------------------------------------------------------ #


def _sample_assets():
    return [
        {"hostname": "fw-01", "vendor": "Cisco", "site": "HQ",
         "crown_jewel": False, "criticality": "high",
         "findings": [{"id": "F001", "title": "SSH open", "severity": "high",
                       "controls": [{"control_id": "AC-2",
                                     "framework": "nist-800-53",
                                     "title": "Account Mgmt"}]}]},
        {"hostname": "db-01", "vendor": "Dell", "site": "HQ",
         "crown_jewel": True,
         "findings": [{"id": "F002", "title": "Patch lag",
                       "severity": "critical",
                       "controls": [{"control_id": "CC6.1",
                                     "framework": "soc2",
                                     "title": "Access"}]}]},
    ]


def test_build_produces_expected_node_and_edge_counts():
    g = GraphStore()
    r = build_graph_from_assets(g, _sample_assets())
    # 2 assets + 2 vendors + 1 site + 1 crown_jewel + 2 findings + 2 controls + 2 frameworks = 12
    assert r == {"nodes": 12, "edges": 11}


def test_build_skips_assets_without_hostname():
    g = GraphStore()
    build_graph_from_assets(g, [{"hostname": "", "vendor": "x"}])
    assert g.count()["nodes"] == 0


# ---- query ------------------------------------------------------ #


def test_query_what_touches():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    n = {(x["type"], x["id"]) for x in what_touches(g, "asset", "fw-01")}
    assert ("finding", "F001") in n
    assert ("vendor", "Cisco") in n
    assert ("site", "HQ") in n


def test_query_assets_exposing_finding():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    r = assets_exposing_finding(g, "F002")
    assert any(x["id"] == "db-01" for x in r)


def test_query_frameworks_affected():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    assert frameworks_affected(g, "F001") == ["nist-800-53"]
    assert frameworks_affected(g, "F002") == ["soc2"]


def test_query_violations_for_framework():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    v = violations_for_framework(g, "soc2")
    assert v == [{"finding_id": "F002", "control_id": "CC6.1"}]


def test_query_crown_jewel_reachers():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    r = crown_jewel_reachers(g)
    assert r == [{"asset": "db-01", "crown_jewel": "cj-db-01"}]


# ---- traverse --------------------------------------------------- #


def test_traverse_shortest_path_basic():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    p = shortest_path(g, ("asset", "fw-01"), ("framework", "nist-800-53"))
    assert p == [
        ("asset", "fw-01"),
        ("finding", "F001"),
        ("control", "AC-2"),
        ("framework", "nist-800-53"),
    ]


def test_traverse_shortest_path_returns_none_when_unreachable():
    g = GraphStore()
    g.add_node(Node("asset", "a1"))
    g.add_node(Node("framework", "soc2"))
    assert shortest_path(g, ("asset", "a1"), ("framework", "soc2")) is None


def test_traverse_walk_depth_capped():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    out = walk(g, ("asset", "db-01"), max_depth=1)
    # depth=1 should only return direct neighbors
    depths = {n["depth"] for n in out}
    assert depths == {1}


def test_traverse_walk_edge_filter():
    g = GraphStore()
    build_graph_from_assets(g, _sample_assets())
    out = walk(g, ("asset", "fw-01"), max_depth=3,
               edge_filter={"exposes", "violates", "mapped_to"})
    # Should reach framework via exposes -> violates -> mapped_to chain
    keys = {(n["type"], n["id"]) for n in out}
    assert ("framework", "nist-800-53") in keys
    # Should NOT reach vendor (filtered out via "produced_by")
    assert ("vendor", "Cisco") not in keys
