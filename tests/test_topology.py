"""Topology engine — graph, parser, renderer tests."""

from pathlib import Path

import pytest

from safecadence.topology import (
    Edge, Node, Topology, parse_lldp_text,
    render_dot, render_html, render_mermaid, render_text,
)


SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_configs" / "lldp_neighbors.txt"


# ----------------------------------------------------------------- #
# Graph primitives
# ----------------------------------------------------------------- #
class TestGraph:
    def test_add_node(self):
        topo = Topology()
        topo.add_node(Node(name="A"))
        assert "A" in topo.nodes

    def test_add_node_merges_fields(self):
        topo = Topology()
        topo.add_node(Node(name="A", vendor="Cisco"))
        topo.add_node(Node(name="A", ip="10.0.0.1"))
        n = topo.nodes["A"]
        assert n.vendor == "Cisco"
        assert n.ip == "10.0.0.1"

    def test_add_edge_creates_endpoints(self):
        topo = Topology()
        topo.add_edge(Edge(local_device="A", local_port="Gi0/1",
                           remote_device="B", remote_port="Gi0/2"))
        assert "A" in topo.nodes and "B" in topo.nodes

    def test_add_edge_dedupes_symmetric(self):
        topo = Topology()
        ok1 = topo.add_edge(Edge(local_device="A", local_port="Gi0/1",
                                 remote_device="B", remote_port="Gi0/2"))
        ok2 = topo.add_edge(Edge(local_device="B", local_port="Gi0/2",
                                 remote_device="A", remote_port="Gi0/1"))
        assert ok1 is True
        assert ok2 is False
        assert len(topo.edges) == 1

    def test_neighbors_of(self):
        topo = Topology()
        topo.add_edge(Edge(local_device="A", local_port="1",
                           remote_device="B", remote_port="2"))
        topo.add_edge(Edge(local_device="A", local_port="3",
                           remote_device="C", remote_port="4"))
        assert topo.neighbors_of("A") == ["B", "C"]
        assert topo.neighbors_of("B") == ["A"]


# ----------------------------------------------------------------- #
# LLDP parser
# ----------------------------------------------------------------- #
@pytest.fixture(scope="module")
def parsed_topo():
    text = SAMPLE.read_text(encoding="utf-8")
    return parse_lldp_text(text, local_device="EDGE-01")


class TestParser:
    def test_neighbors_extracted(self, parsed_topo):
        names = set(parsed_topo.nodes.keys())
        assert "EDGE-01" in names
        assert "DC-CORE-01" in names
        assert "SPINE-01" in names
        assert "CAMPUS-CORE-01" in names
        assert "MR42-OFFICE-01" in names

    def test_links_extracted(self, parsed_topo):
        # 4 LLDP records → 4 edges
        assert len(parsed_topo.edges) == 4
        for e in parsed_topo.edges:
            assert e.local_device == "EDGE-01"
            assert e.local_port.startswith("GigabitEthernet")
            assert e.remote_device

    def test_vendor_classification(self, parsed_topo):
        # DC-CORE-01 has "Cisco IOS Software, IOS-XE" -> Cisco / ios-xe
        assert parsed_topo.nodes["DC-CORE-01"].vendor == "Cisco"
        # SPINE-01 has "Arista Networks EOS" -> Arista / eos
        assert parsed_topo.nodes["SPINE-01"].vendor == "Arista"
        # CAMPUS-CORE-01 has "ArubaOS-CX" -> Aruba / aos-cx
        assert parsed_topo.nodes["CAMPUS-CORE-01"].vendor == "Aruba"
        # MR42 has "Meraki" -> Cisco Meraki
        assert "Meraki" in parsed_topo.nodes["MR42-OFFICE-01"].vendor

    def test_ip_extracted(self, parsed_topo):
        assert parsed_topo.nodes["DC-CORE-01"].ip == "10.99.0.10"
        assert parsed_topo.nodes["SPINE-01"].ip == "10.99.0.30"
        assert parsed_topo.nodes["CAMPUS-CORE-01"].ip == "10.99.0.20"

    def test_role_classification(self, parsed_topo):
        # DC-CORE-01 has B,R capabilities -> router
        assert parsed_topo.nodes["DC-CORE-01"].role == "router"
        # MR42 has W -> wireless
        assert parsed_topo.nodes["MR42-OFFICE-01"].role == "wireless"

    def test_empty_input(self):
        topo = parse_lldp_text("", local_device="X")
        # Just the local device
        assert len(topo.nodes) == 1
        assert len(topo.edges) == 0


# ----------------------------------------------------------------- #
# Renderers
# ----------------------------------------------------------------- #
class TestRenderers:
    def test_text_renderer(self, parsed_topo):
        out = render_text(parsed_topo)
        assert "EDGE-01" in out
        assert "DC-CORE-01" in out
        assert "5 nodes, 4 edges" in out or "5 nodes" in out

    def test_mermaid_renderer(self, parsed_topo):
        out = render_mermaid(parsed_topo)
        assert "graph LR" in out
        assert "DC_CORE_01" in out  # ids are sanitized
        assert "EDGE_01 ---" in out

    def test_dot_renderer(self, parsed_topo):
        out = render_dot(parsed_topo)
        assert "digraph SafeCadence" in out
        assert "rankdir=LR" in out
        # Vendor color shows up in node fillcolor
        assert "fillcolor=" in out

    def test_html_renderer(self, parsed_topo):
        out = render_html(parsed_topo, title="UnitTest Topology")
        assert "<!doctype html>" in out
        # Pure inline SVG — no CDN dependencies
        assert "https://" not in out or "safecadence.com" in out  # only safecadence.com link allowed
        assert "<svg" in out or "createElementNS" in out          # SVG-based rendering
        assert "UnitTest Topology" in out
        # Node data is serialized into the JS
        assert "DC-CORE-01" in out

    def test_html_renderer_has_no_external_scripts(self, parsed_topo):
        """No external JS — must be 100% offline-capable."""
        out = render_html(parsed_topo)
        import re
        external_scripts = re.findall(r'<script[^>]+src=["\']https?://', out)
        assert not external_scripts, f"Found CDN script tags: {external_scripts}"

    def test_json_serialization(self, parsed_topo):
        d = parsed_topo.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["nodes"]) == 5
        assert len(d["edges"]) == 4
