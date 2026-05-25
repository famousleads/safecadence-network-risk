"""
SafeCadence MCP Server — JSON-RPC 2.0 over stdio.

Implements the minimum subset of the Anthropic Model Context Protocol
needed to expose SafeCadence as a tool source:

  * initialize       — handshake; advertises server name + version
  * tools/list       — returns the 7 SafeCadence tools
  * tools/call       — invokes a tool with arguments
  * notifications/initialized — client notification, no response
  * shutdown         — graceful exit

Stdio framing: each message is a single JSON line (LSP-style framing
is also tolerated for clients that prefer it).

Audit log + RBAC integration:
  * Every `tools/call` writes a row to the v11.3 hash-chained audit
    log via ``safecadence.audit.log.log_event_chained``.
  * The active org id + caller identity come from the
    SC_MCP_ORG_ID and SC_MCP_USER env vars when set, defaulting to
    "local" / "mcp-stdio" otherwise.

Never raises out of the main loop — all errors are converted to
JSON-RPC error responses so the client gets a clean failure rather
than a hung pipe.
"""
from __future__ import annotations

import json
import sys
import os
import traceback
from typing import Any

from . import __version__ as MCP_SERVER_VERSION
from .tools import TOOL_REGISTRY, MCPToolError, get_tool, list_tools


# Server identity advertised to MCP clients
SERVER_NAME = "safecadence"
PROTOCOL_VERSION = "2024-11-05"   # MCP spec version we implement


class MCPServer:
    """Single-connection MCP server. Reads JSON-RPC messages line-by-line
    from a readable stream, writes responses to a writable stream.

    Stateless across calls except for the `initialized` flag — once
    the client has sent `initialize` we accept tool calls.
    """

    def __init__(self, stdin=None, stdout=None, stderr=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self.initialized = False
        self.shutdown_requested = False
        # Pull org/user context from env so MCP clients can pass
        # capability context. Default to "local" / "mcp-stdio" for
        # the common single-user case.
        self.org_id = os.environ.get("SC_MCP_ORG_ID", "local")
        self.user = os.environ.get("SC_MCP_USER", "mcp-stdio")

    # ----------------------------------------------------------------
    # Wire format
    # ----------------------------------------------------------------

    def _write_message(self, message: dict) -> None:
        """Write a single JSON-RPC message to stdout, newline-terminated."""
        try:
            line = json.dumps(message, separators=(",", ":"))
            self.stdout.write(line + "\n")
            self.stdout.flush()
        except Exception as e:                              # pragma: no cover
            # If stdout is broken we can't recover; log and exit
            try:
                self.stderr.write(f"MCP write error: {e}\n")
                self.stderr.flush()
            except Exception:
                pass

    def _read_message(self) -> dict | None:
        """Read one JSON-RPC message from stdin. Returns None on EOF."""
        line = self.stdin.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            return self._read_message()
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            self._write_message({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {e}",
                },
            })
            return {}  # keep loop alive

    # ----------------------------------------------------------------
    # Protocol handlers
    # ----------------------------------------------------------------

    def _audit(self, method: str, params: dict, result: Any, error: Any) -> None:
        """Write one row to the hash-chained audit log per tool call.
        Best-effort — audit failures must not crash the MCP server.
        """
        try:
            from safecadence.audit.log import log_event_chained
            log_event_chained(
                org_id=self.org_id,
                actor=self.user,
                action=f"mcp.{method}",
                target=str(params)[:200] if params else "",
                result="ok" if not error else "error",
                detail={"error": str(error)} if error else None,
            )
        except Exception:
            # Audit logging is best-effort. Don't fail the tool call.
            pass

    def _handle_initialize(self, request: dict) -> dict:
        """MCP initialize handshake."""
        self.initialized = True
        params = request.get("params") or {}
        client_info = (params.get("clientInfo") or {})
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": MCP_SERVER_VERSION,
                },
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "instructions": (
                    "SafeCadence MCP server. Use tools/list to see "
                    f"available tools (7 today). Client: "
                    f"{client_info.get('name', 'unknown')}. "
                    f"Org: {self.org_id}. User: {self.user}."
                ),
            },
        }

    def _handle_tools_list(self, request: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"tools": list_tools()},
        }

    def _handle_tools_call(self, request: dict) -> dict:
        params = request.get("params") or {}
        tool_name = params.get("name") or ""
        arguments = params.get("arguments") or {}

        try:
            fn = get_tool(tool_name)
        except MCPToolError as e:
            self._audit("tools/call", params, None, e.message)
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": e.code, "message": e.message},
            }

        try:
            result = fn(arguments)
            self._audit("tools/call", params, result, None)
            # MCP returns tool results as a list of content blocks.
            # We wrap the dict as a single text/json block.
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2,
                                               default=str),
                        }
                    ],
                    "isError": False,
                },
            }
        except MCPToolError as e:
            self._audit("tools/call", params, None, e.message)
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": e.code, "message": e.message},
            }
        except Exception as e:                              # pragma: no cover
            tb = traceback.format_exc()
            self._audit("tools/call", params, None, str(e))
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Tool execution failed: {e}\n{tb[:500]}",
                        }
                    ],
                    "isError": True,
                },
            }

    def _handle_shutdown(self, request: dict) -> dict:
        self.shutdown_requested = True
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": None,
        }

    # ----------------------------------------------------------------
    # Main dispatch
    # ----------------------------------------------------------------

    def handle(self, request: dict) -> dict | None:
        """Dispatch one parsed JSON-RPC message. Returns the response
        dict, or None for notifications (which expect no response).
        """
        method = request.get("method") or ""
        is_notification = "id" not in request

        # Notifications: don't respond
        if method == "notifications/initialized":
            return None
        if method == "notifications/cancelled":
            return None

        if method == "initialize":
            return self._handle_initialize(request)
        if method == "tools/list":
            if not self.initialized:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32002,
                        "message": "Server not initialized — send 'initialize' first.",
                    },
                }
            return self._handle_tools_list(request)
        if method == "tools/call":
            if not self.initialized:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32002,
                        "message": "Server not initialized — send 'initialize' first.",
                    },
                }
            return self._handle_tools_call(request)
        if method == "shutdown":
            return self._handle_shutdown(request)

        # Unknown method
        if is_notification:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }

    def run(self) -> None:
        """Run the server loop. Exits when stdin closes or shutdown is
        requested.
        """
        while not self.shutdown_requested:
            msg = self._read_message()
            if msg is None:
                # EOF — client closed the pipe
                break
            if not msg:
                # Parse error already responded to; loop again
                continue
            response = self.handle(msg)
            if response is not None:
                self._write_message(response)


# Convenience entry point: `python -m safecadence.mcp` or the CLI
# command `safecadence mcp-server` both call this.
def serve_stdio() -> int:
    """Start the MCP server on stdin/stdout. Returns exit code."""
    server = MCPServer()
    try:
        server.run()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:                                  # pragma: no cover
        try:
            sys.stderr.write(f"MCP server fatal error: {e}\n")
            sys.stderr.flush()
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(serve_stdio())
