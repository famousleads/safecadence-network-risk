"""Topology graph primitives — Node, Edge, Topology."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


@dataclass(frozen=True)
class Node:
    """One device in the graph."""
    name: str
    ip: str = ""
    vendor: str = ""
    platform: str = ""        # raw "system description" from LLDP
    role: str = ""            # access | distribution | core | edge | router | firewall | host
    capabilities: tuple[str, ...] = ()   # ("Bridge",), ("Router", "Bridge"), …

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["capabilities"] = list(self.capabilities)
        return d


@dataclass(frozen=True)
class Edge:
    """One link between two devices, expressed as a directed pair (the
    discovering device → the neighbor)."""
    local_device: str
    local_port: str
    remote_device: str
    remote_port: str
    protocol: str = "lldp"    # lldp | cdp
    vlan: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_key(self) -> tuple[str, str, str, str]:
        """A symmetric key so A→B (Gi0/1↔Gi0/2) == B→A (Gi0/2↔Gi0/1)."""
        a = (self.local_device, self.local_port)
        b = (self.remote_device, self.remote_port)
        if a <= b:
            return (*a, *b)
        return (*b, *a)


@dataclass
class Topology:
    """Collection of nodes + edges; deduplicates symmetric edges.

    `node_details` is an optional dict keyed by node name → arbitrary detail
    payload (running config, scan results, CVEs, EOL info, etc.). The HTML
    renderer reads this and shows it in the double-click modal.
    """
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    node_details: dict[str, dict] = field(default_factory=dict)

    def attach_details(self, node_name: str, details: dict) -> None:
        """Attach an arbitrary payload to a node (shown in HTML double-click modal)."""
        self.node_details[node_name] = details

    def attach_scan_result(self, scan_result_dict: dict) -> bool:
        """Match a ScanResult dict to a node by hostname or IP. Returns True on match."""
        hostname = scan_result_dict.get("parsed_summary", {}).get("hostname", "") \
            or scan_result_dict.get("asset", {}).get("hostname", "")
        ip = scan_result_dict.get("asset", {}).get("ip", "")
        for name, n in self.nodes.items():
            if (hostname and (name == hostname or n.name == hostname)) or \
               (ip and n.ip == ip):
                self.attach_details(name, scan_result_dict)
                return True
        return False

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.name)
        if existing is None:
            self.nodes[node.name] = node
            return node
        # Merge: prefer non-empty fields
        merged = Node(
            name=existing.name,
            ip=existing.ip or node.ip,
            vendor=existing.vendor or node.vendor,
            platform=existing.platform or node.platform,
            role=existing.role or node.role,
            capabilities=existing.capabilities or node.capabilities,
        )
        self.nodes[node.name] = merged
        return merged

    def add_edge(self, edge: Edge) -> bool:
        """Add an edge. Returns True if newly added, False if duplicate."""
        key = edge.canonical_key()
        for existing in self.edges:
            if existing.canonical_key() == key:
                return False
        self.edges.append(edge)
        # Make sure both endpoints exist
        if edge.local_device and edge.local_device not in self.nodes:
            self.nodes[edge.local_device] = Node(name=edge.local_device)
        if edge.remote_device and edge.remote_device not in self.nodes:
            self.nodes[edge.remote_device] = Node(name=edge.remote_device)
        return True

    def add_edges(self, edges: Iterable[Edge]) -> int:
        """Add many edges, return how many were newly added."""
        return sum(1 for e in edges if self.add_edge(e))

    def neighbors_of(self, device: str) -> list[str]:
        """Return all device names directly connected to `device`."""
        out: set[str] = set()
        for e in self.edges:
            if e.local_device == device:
                out.add(e.remote_device)
            elif e.remote_device == device:
                out.add(e.local_device)
        return sorted(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
