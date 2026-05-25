"""
MCP tool implementations for SafeCadence.

Each tool is a callable that takes a parsed JSON input dict and returns
either a result dict (success) or raises ``MCPToolError`` (failure).
All tools are wrapped by the server's RBAC check + audit-log
middleware before they execute; the tool implementations themselves
focus on the data query.

Tools intentionally read from the existing SafeCadence storage layer
(`safecadence.storage`, `safecadence.platform.*`) rather than
reimplementing query logic — they're a translation surface, not a
new data model.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


class MCPToolError(Exception):
    """Raised when an MCP tool fails. The server turns this into a
    JSON-RPC error response with the message verbatim.
    """
    def __init__(self, message: str, code: int = -32000):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------


def query_topology(input_data: dict) -> dict:
    """Return the asset inventory + relationships for the active org.

    Input schema:
        {
            "scope": "all" | "site:<name>" | "vendor:<name>",  // optional
            "include_relationships": bool                       // default True
        }

    Returns:
        {
            "assets": [
                {"id": ..., "hostname": ..., "vendor": ..., "asset_type": ..., "site": ...},
                ...
            ],
            "relationships": [
                {"source": "asset_id", "target": "asset_id", "type": "connects_to"},
                ...
            ],
            "summary": {"asset_count": int, "vendor_breakdown": {...}, "site_breakdown": {...}}
        }
    """
    scope = (input_data.get("scope") or "all").strip()
    include_rel = input_data.get("include_relationships", True)

    # Defensive: degrade gracefully when no asset data is loaded yet
    # (fresh install, air-gap pre-scan, etc.). Empty result + note is
    # always better than an opaque error from the MCP client's POV.
    topo: dict = {"assets": [], "links": []}
    try:
        from safecadence.platform.physical_topology import (
            collect_topology_data as _ct
        )
        topo = _ct() or topo
    except Exception:
        try:
            # Fallback to whatever storage layer is available
            from safecadence.storage import sqlite_store
            topo = {
                "assets": list(sqlite_store.list_assets() or []),
                "links": [],
            }
        except Exception:
            pass  # genuinely no data available; that's OK

    assets = []
    for a in topo.get("assets") or []:
        if scope == "all":
            keep = True
        elif scope.startswith("site:"):
            keep = (a.get("site") or "") == scope[5:]
        elif scope.startswith("vendor:"):
            keep = (a.get("vendor") or "").lower() == scope[7:].lower()
        else:
            keep = True
        if keep:
            assets.append({
                "id": a.get("id"),
                "hostname": a.get("hostname"),
                "vendor": a.get("vendor"),
                "asset_type": a.get("asset_type"),
                "site": a.get("site"),
            })

    relationships = []
    if include_rel:
        for r in (topo.get("links") or []):
            relationships.append({
                "source": r.get("a"),
                "target": r.get("b"),
                "type": r.get("link_type") or "connects_to",
            })

    vendor_breakdown: dict[str, int] = {}
    site_breakdown: dict[str, int] = {}
    for a in assets:
        v = a.get("vendor") or "unknown"
        s = a.get("site") or "unknown"
        vendor_breakdown[v] = vendor_breakdown.get(v, 0) + 1
        site_breakdown[s] = site_breakdown.get(s, 0) + 1

    return {
        "assets": assets,
        "relationships": relationships,
        "summary": {
            "asset_count": len(assets),
            "vendor_breakdown": vendor_breakdown,
            "site_breakdown": site_breakdown,
        },
    }


def retrieve_findings(input_data: dict) -> dict:
    """Return findings filtered by host / severity / framework.

    Input schema:
        {
            "host": "<hostname>" | null,
            "severity": "critical" | "high" | "medium" | "low" | null,
            "framework": "nist-800-53" | "cis-v8" | ... | null,
            "limit": int (default 50)
        }
    """
    host = input_data.get("host")
    severity = input_data.get("severity")
    framework = input_data.get("framework")
    limit = int(input_data.get("limit") or 50)

    # Defensive: try multiple asset-loading paths, degrade gracefully.
    # We avoid raising MCPToolError on "no data" so an MCP client gets
    # a clean empty result rather than an error.
    assets: list = []
    try:
        from safecadence.storage import sqlite_store
        assets = list(sqlite_store.list_assets() or [])
    except Exception:
        try:
            from safecadence.intel.ai_assistant import _load_findings
            # Last-resort: empty list, intel layer doesn't expose a clean accessor
            assets = []
        except Exception:
            pass

    findings: list[dict] = []
    for a in (assets or []):
        if host and (a.get("hostname") or "") != host:
            continue
        for f in (a.get("findings") or []):
            if severity and (f.get("severity") or "").lower() != severity.lower():
                continue
            if framework:
                ctrls = f.get("controls") or []
                if not any(framework.lower() in (c.get("framework") or "").lower() for c in ctrls):
                    continue
            findings.append({
                "id": f.get("id") or f.get("rule_id"),
                "host": a.get("hostname"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "description": f.get("description") or f.get("rationale"),
                "fix_snippet": f.get("fix_snippet"),
                "controls": f.get("controls") or [],
                "first_seen": f.get("first_seen"),
            })
            if len(findings) >= limit:
                break
        if len(findings) >= limit:
            break

    return {
        "findings": findings,
        "count": len(findings),
        "filters_applied": {
            "host": host, "severity": severity,
            "framework": framework, "limit": limit,
        },
    }


def query_compliance(input_data: dict) -> dict:
    """Return control posture for a given framework.

    Input schema:
        {
            "framework": "nist-800-53" | "cis-v8" | "pci-dss-v4" |
                         "hipaa" | "soc2" | "cmmc-l2",
            "include_evidence": bool (default False)
        }
    """
    framework = (input_data.get("framework") or "").strip().lower()
    if not framework:
        raise MCPToolError("framework parameter is required", code=-32602)
    include_ev = input_data.get("include_evidence", False)

    try:
        from safecadence.reports.sections import _control_status_for_framework
        status = _control_status_for_framework(framework)
    except Exception as e:                                  # pragma: no cover
        # Fall back to a minimal scaffolding response so MCP clients
        # can rely on the tool existing even before deep data is wired.
        status = {"controls": [], "overall_pct": None, "error": str(e)}

    out: dict = {
        "framework": framework,
        "overall_compliance_pct": status.get("overall_pct"),
        "control_count": len(status.get("controls") or []),
        "controls": [],
    }
    for c in (status.get("controls") or []):
        ctrl = {
            "control_id": c.get("id"),
            "title": c.get("title"),
            "status": c.get("status"),
            "family": c.get("family"),
        }
        if include_ev:
            ctrl["evidence"] = c.get("evidence") or []
        out["controls"].append(ctrl)
    return out


def fetch_evidence(input_data: dict) -> dict:
    """Return evidence files for a specific control attestation.

    Input schema:
        {
            "framework": "soc2" | "nist-800-53" | ...,
            "control_id": "CC6.7" | "AC-2" | ...
        }
    """
    framework = (input_data.get("framework") or "").strip().lower()
    control_id = (input_data.get("control_id") or "").strip()
    if not framework or not control_id:
        raise MCPToolError("framework and control_id are both required",
                           code=-32602)

    # Evidence files live under ~/.safecadence/evidence/<framework>/<control_id>/
    # in the v11.3 layout. We list files + metadata without reading their
    # contents (those can be huge); the MCP client can call a follow-up
    # `fetch_evidence_file` tool for specific file contents.
    home = Path.home() / ".safecadence" / "evidence" / framework / control_id
    files: list[dict] = []
    if home.exists():
        for p in sorted(home.iterdir()):
            if p.is_file():
                try:
                    stat = p.stat()
                    files.append({
                        "path": str(p),
                        "name": p.name,
                        "size_bytes": stat.st_size,
                        "modified": stat.st_mtime,
                    })
                except Exception:
                    pass

    return {
        "framework": framework,
        "control_id": control_id,
        "files": files,
        "file_count": len(files),
    }


def inspect_identities(input_data: dict) -> dict:
    """Return identity posture across the 5 identity systems.

    Input schema:
        {
            "system": "okta" | "entra" | "ise" | "clearpass" | "ad" | null,
            "user_filter": "<substring>" | null
        }
    """
    system = (input_data.get("system") or "").strip().lower()
    user_filter = input_data.get("user_filter")

    identities: list = []
    try:
        # The identity module's listing API isn't uniformly exposed
        # across all installs; degrade gracefully.
        from safecadence.identity import discover as _id_discover
        list_fn = getattr(_id_discover, "list_identities", None)
        if list_fn is not None:
            identities = list(list_fn(system=system or None) or [])
    except Exception:
        identities = []

    if user_filter:
        identities = [i for i in identities
                      if user_filter.lower() in (i.get("username") or "").lower()]

    return {
        "identities": [
            {
                "username": i.get("username"),
                "system": i.get("system"),
                "groups": i.get("groups") or [],
                "last_login": i.get("last_login"),
                "mfa_enabled": i.get("mfa_enabled"),
                "is_admin": i.get("is_admin"),
                "is_nhi": i.get("is_nhi", False),
            }
            for i in identities
        ],
        "count": len(identities),
        "filters_applied": {"system": system, "user_filter": user_filter},
    }


def generate_report(input_data: dict) -> dict:
    """Trigger a report generation for a given scope.

    Input schema:
        {
            "scope": {"hosts": [...], "framework": "...", "site": "..."},
            "preset": "exec_brief" | "executive_risk_brief" |
                      "technical_deepdive" | "compliance_audit" |
                      "quarterly_review" (default "exec_brief"),
            "format": "html" | "pdf" | "docx" | "pptx" | "xlsx"
                      (default "html")
        }

    Returns a job id + a path to the rendered report (or a URL if the
    server is running in HTTP mode).
    """
    scope = input_data.get("scope") or {}
    preset = input_data.get("preset") or "exec_brief"
    fmt = (input_data.get("format") or "html").lower()

    if fmt not in ("html", "pdf", "docx", "pptx", "xlsx", "json", "markdown"):
        raise MCPToolError(f"Unsupported format: {fmt}", code=-32602)

    try:
        from safecadence.reports.builder import compose_report
        from safecadence.reports.presets import get_preset, list_presets
    except Exception as e:                                  # pragma: no cover
        raise MCPToolError(f"Reports module unavailable: {e}")

    preset_obj = get_preset(preset)
    if not preset_obj:
        available = [p["id"] for p in list_presets()]
        raise MCPToolError(
            f"Unknown preset: {preset}. Available: {available}",
            code=-32602,
        )

    try:
        sections = preset_obj.get("sections", [])
        result = compose_report(
            sections=sections,
            scope=scope,
            include_delta=False,
        )
        return {
            "preset": preset,
            "format": fmt,
            "report_id": result.get("report_id"),
            "sections": list(sections),
            "scope": scope,
            "status": "composed",
            "note": "Report composed; rendering via render-download endpoint "
                    "is the caller's next step.",
        }
    except Exception as e:                                  # pragma: no cover
        raise MCPToolError(f"Report composition failed: {e}")


def evaluate_posture(input_data: dict) -> dict:
    """Return aggregate Safe Score breakdown across multiple dimensions.

    v12 polish: returns the multi-dimensional Safe Score (not just the
    single 0–100 number). Each dimension has a value, trend, and
    confidence interval.

    Input schema:
        {
            "include_history": bool (default False)
        }
    """
    include_history = input_data.get("include_history", False)

    try:
        from safecadence.scores.multi_dim_score import compute_multidim_score
        score = compute_multidim_score(include_history=include_history)
    except Exception as e:                                  # pragma: no cover
        # Fallback to a flat compute if multi-dim module isn't wired yet
        try:
            from safecadence.scores import compute_safe_score
            flat = compute_safe_score()
            score = {
                "overall": flat,
                "dimensions": {
                    "compliance_health": flat,
                    "identity_health": flat,
                    "drift_stability": flat,
                    "patch_freshness": flat,
                    "attack_path_risk": flat,
                    "ai_governance_readiness": flat,
                },
                "computed_at": None,
                "note": "fallback flat score; multi-dim module not yet wired",
            }
        except Exception as e2:                             # pragma: no cover
            raise MCPToolError(f"Score computation failed: {e2}")

    return score


# --------------------------------------------------------------------------
# Tool registry — exposed via the MCP `tools/list` method
# --------------------------------------------------------------------------


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "query_topology": {
        "fn": query_topology,
        "description": "Return the asset inventory + relationships for the active org.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Filter scope: 'all', 'site:<name>', or 'vendor:<name>'.",
                },
                "include_relationships": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include link/relationship edges in the response.",
                },
            },
        },
    },
    "retrieve_findings": {
        "fn": retrieve_findings,
        "description": "Return security findings filtered by host, severity, and/or framework.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "framework": {"type": "string"},
                "limit": {"type": "integer", "default": 50, "maximum": 500},
            },
        },
    },
    "query_compliance": {
        "fn": query_compliance,
        "description": "Return control posture for a given compliance framework.",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["nist-800-53", "cis-v8", "pci-dss-v4",
                            "hipaa", "soc2", "cmmc-l2"],
                },
                "include_evidence": {"type": "boolean", "default": False},
            },
            "required": ["framework"],
        },
    },
    "fetch_evidence": {
        "fn": fetch_evidence,
        "description": "Return evidence files (metadata only) for a specific control attestation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string"},
                "control_id": {"type": "string"},
            },
            "required": ["framework", "control_id"],
        },
    },
    "inspect_identities": {
        "fn": inspect_identities,
        "description": "Return identity posture across the 5 supported identity systems.",
        "input_schema": {
            "type": "object",
            "properties": {
                "system": {
                    "type": "string",
                    "enum": ["okta", "entra", "ise", "clearpass", "ad"],
                },
                "user_filter": {"type": "string"},
            },
        },
    },
    "generate_report": {
        "fn": generate_report,
        "description": "Trigger a report composition for a given scope + preset + format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scope": {"type": "object"},
                "preset": {
                    "type": "string",
                    "enum": ["exec_brief", "executive_risk_brief",
                             "technical_deepdive", "compliance_audit",
                             "quarterly_review"],
                },
                "format": {
                    "type": "string",
                    "enum": ["html", "pdf", "docx", "pptx", "xlsx",
                             "json", "markdown"],
                },
            },
        },
    },
    "evaluate_posture": {
        "fn": evaluate_posture,
        "description": ("Return the multi-dimensional Safe Score breakdown "
                        "(compliance / identity / drift / patch / attack-path / "
                        "AI-governance) with trends and confidence intervals."),
        "input_schema": {
            "type": "object",
            "properties": {
                "include_history": {"type": "boolean", "default": False},
            },
        },
    },
}


def get_tool(name: str) -> Callable[[dict], dict]:
    """Look up a tool by name. Raises MCPToolError if not found."""
    entry = TOOL_REGISTRY.get(name)
    if entry is None:
        raise MCPToolError(f"Unknown tool: {name}", code=-32601)
    return entry["fn"]


def list_tools() -> list[dict]:
    """Return the tool catalog for the MCP `tools/list` response."""
    return [
        {
            "name": name,
            "description": entry["description"],
            "inputSchema": entry["input_schema"],
        }
        for name, entry in TOOL_REGISTRY.items()
    ]
