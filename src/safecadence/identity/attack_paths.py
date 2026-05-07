"""
v7.6 — Identity attack-path edges.

Adds identity-flavored edges to the existing attack-path graph so the
reach-weighted scoring catches "Alice → BuildBot SA → AdminRole → Crown
Jewel DB" chains, not just network hops.

Edge kinds:

  member_of            human → group
  can_impersonate      principal → principal (e.g. SA can be assumed by user)
  can_assume_role      principal → role (AWS/Azure)
  has_credential_to    principal → asset (key/cert grants direct access)

The function `compute_identity_paths(assets)` returns a list of
IdentityPath records, sorted by reach-weighted risk descending. Each
path includes the chain of edges so the UI can render the steps.

Pure-Python; depends only on the existing UnifiedAsset schema. Designed
to be called from the v6.2.1 attack_paths module via a glue function so
the existing top-risks output gets identity context for free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class IdentityEdge:
    src: str                    # principal id (user / NHI / group)
    dst: str                    # principal id or asset id
    kind: str                   # member_of | can_impersonate
                                # | can_assume_role | has_credential_to
    weight: float = 1.0         # higher = more privileged


@dataclass
class IdentityPath:
    chain: list[IdentityEdge] = field(default_factory=list)
    terminal_asset: str = ""    # the resource at the end of the chain
    risk_score: float = 0.0     # 0..100 — reach-weighted
    reasons: list[str] = field(default_factory=list)

    def chain_summary(self) -> str:
        if not self.chain:
            return ""
        nodes = [self.chain[0].src] + [e.dst for e in self.chain]
        return " → ".join(nodes)


# ---------------------------------------------------------------- public

def compute_identity_paths(assets: Iterable[dict]) -> list[IdentityPath]:
    """Walk the asset graph for identity attack paths.

    Inputs are JSON-serialized UnifiedAsset dicts (whatever the platform
    store hands back). We tolerate missing fields and only emit paths
    for principals that actually have privileged endpoints.
    """
    edges = _extract_edges(list(assets))
    if not edges:
        return []

    # Build adjacency
    adj: dict[str, list[IdentityEdge]] = {}
    for e in edges:
        adj.setdefault(e.src, []).append(e)

    paths: list[IdentityPath] = []

    # Seed BFS from every human principal that has at least one edge.
    # We bound depth at 5 hops to keep cost predictable on large graphs.
    for human in _humans(edges):
        for path in _bfs(human, adj, max_depth=5):
            risk = _score_path(path)
            if risk <= 0:
                continue
            terminal = path[-1].dst
            paths.append(IdentityPath(
                chain=path,
                terminal_asset=terminal,
                risk_score=risk,
                reasons=_reasons_for(path),
            ))

    paths.sort(key=lambda p: p.risk_score, reverse=True)
    return paths


# ---------------------------------------------------------------- internals

def _extract_edges(assets: list[dict]) -> list[IdentityEdge]:
    out: list[IdentityEdge] = []
    for a in assets:
        ident = (a.get("identity") or {}) if isinstance(a, dict) else {}
        ib = (a.get("identity_block") or {}) if isinstance(a, dict) else {}
        nhi = (a.get("nhi") or {}) if isinstance(a, dict) else {}
        asset_id = ident.get("asset_id", "")

        # member_of: human → group
        for human, groups in (ib.get("group_memberships") or {}).items():
            for g in groups or []:
                out.append(IdentityEdge(src=human, dst=g, kind="member_of",
                                         weight=1.0))

        # can_impersonate: principal → principal (NHI's owner can impersonate it)
        if nhi.get("nhi_id") and nhi.get("owner_principal"):
            out.append(IdentityEdge(
                src=nhi["owner_principal"], dst=nhi["nhi_id"],
                kind="can_impersonate",
                weight=2.0 if nhi.get("subtype") == "service_account" else 1.5,
            ))

        # can_assume_role: NHI → role for AWS IAM (treat scopes as roles)
        if nhi.get("subtype") == "iam_role" and nhi.get("nhi_id"):
            for scope in nhi.get("effective_scopes", []) or []:
                out.append(IdentityEdge(
                    src=nhi["nhi_id"], dst=f"role:{scope}",
                    kind="can_assume_role", weight=2.5,
                ))

        # has_credential_to: explicit can_impersonate field on NHI
        for target in (nhi.get("can_impersonate") or []):
            out.append(IdentityEdge(
                src=nhi.get("nhi_id", ""), dst=target,
                kind="can_impersonate", weight=2.0,
            ))

        # Final: principal → asset edges via group authz on the asset
        for grp in (ib.get("authorized_groups") or []):
            if asset_id:
                out.append(IdentityEdge(
                    src=grp, dst=asset_id, kind="has_credential_to",
                    weight=3.0 if ident.get("criticality") == "crown-jewel"
                            else 2.0,
                ))

    return out


def _humans(edges: list[IdentityEdge]) -> set[str]:
    """A node is treated as 'human' if it has an outbound member_of."""
    humans: set[str] = set()
    for e in edges:
        if e.kind == "member_of":
            humans.add(e.src)
    return humans


def _bfs(start: str, adj: dict[str, list[IdentityEdge]], *,
         max_depth: int) -> list[list[IdentityEdge]]:
    """Yield-style BFS — returns every path from `start` that ends at
    a `has_credential_to` edge (i.e. terminates at an asset)."""
    out: list[list[IdentityEdge]] = []
    queue: list[tuple[str, list[IdentityEdge], set[str]]] = [
        (start, [], {start})
    ]
    while queue:
        node, path, seen = queue.pop(0)
        if len(path) >= max_depth:
            continue
        for edge in adj.get(node, []):
            if edge.dst in seen:
                continue
            new_path = path + [edge]
            if edge.kind == "has_credential_to":
                out.append(new_path)
                # Don't continue past asset terminals
                continue
            queue.append((edge.dst, new_path, seen | {edge.dst}))
    return out


def _score_path(path: list[IdentityEdge]) -> float:
    if not path:
        return 0.0
    weight = 1.0
    for e in path:
        weight *= e.weight
    # Length penalty — longer paths are slightly less concerning per-edge,
    # but high-weight terminal edges still dominate (crown-jewel = 3.0).
    return min(100.0, 10.0 * weight / (len(path) ** 0.5))


def _reasons_for(path: list[IdentityEdge]) -> list[str]:
    reasons = []
    if any(e.kind == "can_impersonate" for e in path):
        reasons.append("path includes principal impersonation")
    if any(e.weight >= 3.0 for e in path):
        reasons.append("terminal asset is crown-jewel")
    if len(path) >= 3:
        reasons.append("multi-hop chain — harder to spot manually")
    return reasons
