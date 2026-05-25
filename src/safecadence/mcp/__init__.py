"""
SafeCadence MCP (Model Context Protocol) server.

Lets AI clients (Claude Desktop, Cursor, Claude Code, Block, any
MCP-capable system) query SafeCadence directly via the Anthropic
Model Context Protocol.

The server speaks JSON-RPC 2.0 over stdio per the MCP spec
(https://modelcontextprotocol.io/specification). Each tool call is:
  * RBAC-aware — uses the operator's session capability set
  * Audit-logged — every tool invocation writes to the v11.3
    hash-chained audit log
  * Explainable — responses cite source objects (asset IDs, finding
    IDs, control IDs) so the AI client can reference them

Tools exposed:
  * query_topology     — asset inventory + relationships
  * retrieve_findings  — findings filtered by host / severity / framework
  * query_compliance   — control posture for a given framework
  * fetch_evidence     — evidence files for a specific control attestation
  * inspect_identities — identity posture across the 5 identity systems
  * generate_report    — trigger a report generation for a given scope
  * evaluate_posture   — aggregate Safe Score breakdown

Run as a subprocess from an MCP client config:

    {
      "mcpServers": {
        "safecadence": {
          "command": "safecadence",
          "args": ["mcp-server"]
        }
      }
    }

v12.0 (in progress) — first-class addition to the platform.
"""
from __future__ import annotations

__version__ = "1.0.0"

from .server import MCPServer, serve_stdio
from .tools import TOOL_REGISTRY

__all__ = ["MCPServer", "serve_stdio", "TOOL_REGISTRY"]
