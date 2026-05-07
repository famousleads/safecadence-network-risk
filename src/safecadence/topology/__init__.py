"""
Topology mapping engine.

Build an L2/L3 graph of "what's plugged into what" by parsing LLDP / CDP
neighbor output. Supports text input (paste from `show lldp neighbors
detail`) or live SSH collection.

Public API:

    from safecadence.topology import (
        Topology, Node, Edge, parse_lldp_text, render_mermaid,
    )
    topo = parse_lldp_text(open("lldp.txt").read(), local_device="CORE-01")
    print(render_mermaid(topo))
"""

from safecadence.topology.collector import collect_via_ssh, parse_lldp_text
from safecadence.topology.graph import Edge, Node, Topology
from safecadence.topology.renderers import (
    render_dot, render_html, render_mermaid, render_text,
)

__all__ = [
    "Topology", "Node", "Edge",
    "parse_lldp_text", "collect_via_ssh",
    "render_dot", "render_mermaid", "render_html", "render_text",
]
