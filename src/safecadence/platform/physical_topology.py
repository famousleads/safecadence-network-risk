"""
v9.9 / v9.10 — Physical L2 topology + Meraki-style enrichment.

After v9.4 added LLDP/CDP/MAC-table harvest, every router we've harvested
has its neighbor data persisted at asset.raw_collection.snmp_harvest.
This module reads that data across the whole fleet and produces a
Cytoscape-format graph of:

  - switch-to-switch links     (LLDP/CDP, both directions corroborated)
  - host-to-port edges         (from bridge MAC table)
  - "ghost" nodes              (neighbors we saw but never adopted)

v9.10 adds Meraki-style enrichment to every node:

  - device_icon:  unicode pictogram chosen from asset_type + role tags
  - health_color: green/yellow/red derived from health.grade
  - parent:       site name (Cytoscape compound nodes group by site)

Output shape (Cytoscape):
  {
    elements: {nodes: [...], edges: [...]},
    stats: {router_count, neighbor_count, mac_count, ghost_count},
    layers: {physical: bool}     # caller adds more layers later
  }
"""

from __future__ import annotations

from typing import Iterable


# v9.10 — Meraki-style icon picker. Maps asset_type + role-tag hints to a
# unicode pictogram. Drawn at a large font on the node.
def _device_icon(asset: dict) -> str:
    ident = asset.get("identity") or {}
    atype = (ident.get("asset_type") or "").lower()
    vendor = (ident.get("vendor") or "").lower()
    tags = [t.lower() for t in (ident.get("tags") or [])]
    role = ""
    for t in tags:
        if t.startswith("role:"):
            role = t[5:]; break

    # Network gear sub-types
    if atype == "network":
        if "wireless" in role or "ap" in role.split("-"):
            return "📡"      # access point
        if "firewall" in role or vendor in ("palo-alto", "fortinet", "checkpoint"):
            return "🛡"      # firewall
        if "router" in role or "edge" in role:
            return "🔀"      # router
        if "switch" in role:
            return "⊟"       # switch
        return "🔀"          # default network → router glyph
    if atype == "server":
        return "🖥"
    if atype == "identity":
        return "👤"
    if atype == "cloud":
        if "aws" in vendor: return "☁"
        if "azure" in vendor: return "☁"
        if "gcp" in vendor: return "☁"
        return "☁"
    if atype == "storage":
        return "💾"
    if atype == "backup":
        return "🗄"
    if atype == "iot":
        return "📷"
    if atype == "mobile":
        return "📱"
    return "❓"


def _health_color(asset: dict) -> str:
    """Meraki-style status ring: green = ok, yellow = warning, red = crit."""
    health = asset.get("health") or {}
    grade = (health.get("grade") or "").upper()
    risk = (asset.get("compliance_signals") or {}).get("risk_score_0_100", 0)
    if grade in ("A", "B"):
        return "#10b981"   # green
    if grade == "C":
        return "#f59e0b"   # yellow
    if grade in ("D", "F"):
        return "#ef4444"   # red
    if risk:
        if risk >= 70: return "#ef4444"
        if risk >= 40: return "#f59e0b"
        return "#10b981"
    return "#9ca3af"       # gray = unknown


# -----------------------------------------------------------------------
# helpers


def _norm_mac(s: str) -> str:
    """'00:11:22:33:44:55' → '001122334455' (lowercase, no separators)."""
    if not s:
        return ""
    return "".join(c for c in s.lower() if c in "0123456789abcdef")


def _norm_host(s: str) -> str:
    """'PC-01.acme.local' → 'pc-01' (lowercase, short form)."""
    if not s:
        return ""
    return s.strip().rstrip(".").lower().split(".")[0]


def _build_lookup(assets: Iterable[dict]) -> dict[str, dict]:
    """Build lookup: { 'mac:001122', 'host:pc-01', 'ip:10.0.0.5' } → asset."""
    lookup: dict[str, dict] = {}
    for a in assets:
        ident = a.get("identity") or {}
        aid = ident.get("asset_id")
        if not aid:
            continue
        # MAC variants
        for k in ("mac_address", "mac"):
            mac = _norm_mac(ident.get(k) or "")
            if mac:
                lookup[f"mac:{mac}"] = a
        # Hostname variants
        for k in ("hostname", "name"):
            h = _norm_host(ident.get(k) or "")
            if h:
                lookup[f"host:{h}"] = a
        aid_h = _norm_host(aid)
        if aid_h:
            lookup[f"host:{aid_h}"] = a
        # IP variants — mgmt_ip + interfaces
        for k in ("mgmt_ip", "ip"):
            ip = (ident.get(k) or "").strip()
            if ip:
                lookup[f"ip:{ip}"] = a
        cf = ident.get("custom_fields") or {}
        if cf.get("mgmt_ip"):
            lookup[f"ip:{cf['mgmt_ip']}"] = a
        for iface in (a.get("interfaces") or []):
            ip = (iface.get("ip_address") or iface.get("ip") or "").strip()
            if ip:
                lookup[f"ip:{ip}"] = a
    return lookup


def _match_neighbor(neighbor: dict, lookup: dict[str, dict]) -> dict | None:
    """Try to match an LLDP/CDP neighbor to an existing asset."""
    mac = _norm_mac(neighbor.get("chassis_id") or "")
    if mac and (a := lookup.get(f"mac:{mac}")):
        return a
    h = _norm_host(neighbor.get("hostname") or "")
    if h and (a := lookup.get(f"host:{h}")):
        return a
    ip = (neighbor.get("ip_address") or "").strip()
    if ip and (a := lookup.get(f"ip:{ip}")):
        return a
    return None


# -----------------------------------------------------------------------
# main builder


def build_physical_graph(assets: list[dict]) -> dict:
    """Reconstruct physical L2 topology from persisted SNMP harvests.

    Returns a Cytoscape elements dict with:
      nodes[]:  {id, label, asset_type, vendor, ghost, criticality, ...}
      edges[]:  {source, target, layers:["physical"], protocol, local_port,
                 remote_port, ...}
    """
    lookup = _build_lookup(assets)
    nodes: dict[str, dict] = {}     # asset_id → node dict
    edges: list[dict] = []
    ghost_seq = 0
    router_ids: set[str] = set()
    neighbor_count = 0
    mac_count = 0

    def _node_for_asset(a: dict, *, ghost: bool = False) -> str:
        ident = a.get("identity") or {}
        aid = ident.get("asset_id") or ""
        if aid not in nodes:
            site = ident.get("site", "")
            nodes[aid] = {
                "data": {
                    "id": aid,
                    "label": ident.get("hostname") or aid,
                    "asset_type": ident.get("asset_type", ""),
                    "vendor": ident.get("vendor", ""),
                    "criticality": ident.get("criticality", ""),
                    "site": site,
                    "env": ident.get("environment", ""),
                    "mgmt_ip": ident.get("mgmt_ip", "") or
                                (ident.get("custom_fields") or {}).get("mgmt_ip", ""),
                    "ghost": ghost,
                    "icon": _device_icon(a),
                    "health_color": _health_color(a),
                    "parent": f"site:{site}" if site else "",
                    "layers": ["physical"],
                }
            }
        return aid

    def _ghost_node(label: str, *, kind: str, hint: str = "") -> str:
        nonlocal ghost_seq
        ghost_seq += 1
        gid = f"ghost-{ghost_seq}-{label[:20]}".replace(" ", "_")
        nodes[gid] = {
            "data": {
                "id": gid, "label": label or kind,
                "asset_type": kind, "vendor": "", "criticality": "",
                "site": "", "env": "", "mgmt_ip": "", "ghost": True,
                "icon": "❓", "health_color": "#9ca3af", "parent": "",
                "hint": hint, "layers": ["physical"],
            }
        }
        return gid

    # --- iterate every asset that has persisted harvest data ----
    for a in assets:
        raw = a.get("raw_collection")
        # Some legacy/imported assets store raw_collection as a string
        # (the running-config text). Be defensive — only dicts can have
        # an snmp_harvest sub-key.
        if not isinstance(raw, dict):
            continue
        h = raw.get("snmp_harvest")
        if not h or not isinstance(h, dict):
            continue
        src_id = _node_for_asset(a)
        router_ids.add(src_id)

        # 1. LLDP / CDP neighbors → switch-to-switch edges
        for n in (h.get("neighbors") or []):
            neighbor_count += 1
            target = _match_neighbor(n, lookup)
            if target is not None:
                tgt_id = _node_for_asset(target)
            else:
                # Unmatched: create a ghost node
                label = n.get("hostname") or n.get("ip_address") \
                        or n.get("chassis_id") or "unknown"
                hint = (n.get("sys_description") or n.get("platform") or "")[:80]
                tgt_id = _ghost_node(label, kind="network", hint=hint)
            # avoid self-loops (router seeing its own management IP, rare)
            if tgt_id == src_id:
                continue
            edges.append({"data": {
                "source": src_id, "target": tgt_id,
                "layers": ["physical"],
                "protocol": n.get("source_protocol", "lldp"),
                "local_port": n.get("port_id", "") or "",
                "remote_port": n.get("port_description", "") or "",
                "edge_kind": "neighbor",
            }})

        # 2. MAC table → host-to-port edges (only when host is a known asset
        #    or has at least a non-trivial hostname). Skip pure-ghost macs to
        #    avoid clutter; the bridge table can have hundreds of entries.
        for m in (h.get("macs") or []):
            mac_count += 1
            mac = _norm_mac(m.get("mac") or "")
            if not mac:
                continue
            target = lookup.get(f"mac:{mac}")
            if target is None:
                continue           # don't add ghost MACs to the graph
            tgt_id = _node_for_asset(target)
            if tgt_id == src_id:
                continue
            edges.append({"data": {
                "source": src_id, "target": tgt_id,
                "layers": ["physical-l2"],
                "protocol": "mac-table",
                "local_port": str(m.get("port", "")),
                "edge_kind": "mac",
            }})

    return {
        "elements": {"nodes": list(nodes.values()), "edges": edges},
        "stats": {
            "router_count": len(router_ids),
            "neighbor_count": neighbor_count,
            "mac_count": mac_count,
            "ghost_count": sum(1 for n in nodes.values()
                                if n["data"]["ghost"]),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "layers": {"physical": True},
    }


# -----------------------------------------------------------------------
# unified graph (physical + logical + identity + cloud)


def build_unified_graph(assets: list[dict],
                        *,
                        include_physical: bool = True,
                        include_logical: bool = True,
                        include_identity: bool = True,
                        include_cloud: bool = True,
                        ) -> dict:
    """Merge physical + logical + identity + cloud edges into one graph.

    Each edge carries a ``layers: [...]`` tag listing which logical layers
    it belongs to. The UI uses this to toggle visibility client-side
    without re-fetching.
    """
    # Start with physical (gives us the seed node set + L2 edges).
    if include_physical:
        graph = build_physical_graph(assets)
    else:
        graph = {"elements": {"nodes": [], "edges": []},
                 "stats": {}, "layers": {}}

    # Build node lookup so we can add nodes that aren't already present.
    by_id: dict[str, dict] = {n["data"]["id"]: n
                               for n in graph["elements"]["nodes"]}

    def _ensure_node(a: dict) -> str:
        ident = a.get("identity") or {}
        aid = ident.get("asset_id")
        if not aid:
            return ""
        if aid not in by_id:
            site = ident.get("site", "")
            n = {"data": {
                "id": aid,
                "label": ident.get("hostname") or aid,
                "asset_type": ident.get("asset_type", ""),
                "vendor": ident.get("vendor", ""),
                "criticality": ident.get("criticality", ""),
                "site": site,
                "env": ident.get("environment", ""),
                "mgmt_ip": ident.get("mgmt_ip", "") or
                            (ident.get("custom_fields") or {}).get("mgmt_ip", ""),
                "ghost": False,
                "icon": _device_icon(a),
                "health_color": _health_color(a),
                "parent": f"site:{site}" if site else "",
                "layers": [],
            }}
            by_id[aid] = n
            graph["elements"]["nodes"].append(n)
        return aid

    edges = graph["elements"]["edges"]

    # ---- LOGICAL: edges between assets sharing subnet / VLAN ----
    if include_logical:
        from collections import defaultdict
        by_subnet: dict[str, list[str]] = defaultdict(list)
        by_site_env: dict[tuple[str, str], list[str]] = defaultdict(list)
        for a in assets:
            aid = _ensure_node(a)
            if not aid:
                continue
            ident = a.get("identity") or {}
            site = ident.get("site") or ""
            env = ident.get("environment") or ""
            if site or env:
                by_site_env[(site, env)].append(aid)
            for iface in (a.get("interfaces") or []):
                subnet = iface.get("subnet") or iface.get("network") or ""
                if subnet:
                    by_subnet[subnet].append(aid)
        # Don't draw a complete graph in each subnet — that's quadratic.
        # Connect each member to the FIRST member as a hub-and-spoke
        # representation (good enough for visual grouping).
        for subnet, members in by_subnet.items():
            if len(members) < 2:
                continue
            hub = members[0]
            for m in members[1:]:
                if hub == m: continue
                edges.append({"data": {
                    "source": hub, "target": m,
                    "layers": ["logical-subnet"],
                    "subnet": subnet,
                    "edge_kind": "subnet",
                }})
        # Same for site+env cohort
        for (site, env), members in by_site_env.items():
            if len(members) < 2:
                continue
            hub = members[0]
            for m in members[1:]:
                if hub == m: continue
                edges.append({"data": {
                    "source": hub, "target": m,
                    "layers": ["logical-site"],
                    "site": site, "env": env,
                    "edge_kind": "site-env",
                }})

    # ---- IDENTITY: attack-path edges (uses existing engine) ----
    if include_identity:
        try:
            from safecadence.platform.attack_paths import (
                top_k_paths_to_crown_jewels,
            )
            paths = top_k_paths_to_crown_jewels(assets, k=20, max_hops=4)
            for p in paths:
                # `p` is a path object; extract chain of asset_ids
                chain = (p.get("chain") if isinstance(p, dict)
                         else getattr(p, "chain", None)) or []
                for i in range(len(chain) - 1):
                    src = chain[i]; tgt = chain[i+1]
                    if src in by_id and tgt in by_id:
                        edges.append({"data": {
                            "source": src, "target": tgt,
                            "layers": ["identity-attack-path"],
                            "edge_kind": "attack-path",
                            "risk_score": (p.get("risk_score") if isinstance(p, dict)
                                          else getattr(p, "risk_score", 0)) or 0,
                        }})
        except Exception:                            # pragma: no cover
            pass

    # ---- CLOUD: same cloud account / VPC ----
    if include_cloud:
        from collections import defaultdict
        by_account: dict[str, list[str]] = defaultdict(list)
        for a in assets:
            ident = a.get("identity") or {}
            if ident.get("asset_type") != "cloud":
                continue
            aid = _ensure_node(a)
            if not aid:
                continue
            cf = ident.get("custom_fields") or {}
            acct = (cf.get("aws_account_id") or cf.get("subscription_id")
                    or cf.get("project_id") or ident.get("vendor", ""))
            if acct:
                by_account[acct].append(aid)
        for acct, members in by_account.items():
            if len(members) < 2: continue
            hub = members[0]
            for m in members[1:]:
                if hub == m: continue
                edges.append({"data": {
                    "source": hub, "target": m,
                    "layers": ["cloud"],
                    "account": acct, "edge_kind": "cloud-account",
                }})

    # v9.10 — add Cytoscape compound nodes for each site so the canvas
    # groups devices Meraki-style ("by network"). Each child node already
    # has its `parent` set; we just need to materialize the parent nodes.
    sites_seen: set[str] = set()
    for n in graph["elements"]["nodes"]:
        p = n.get("data", {}).get("parent")
        if p and p not in sites_seen and p not in by_id:
            sites_seen.add(p)
            graph["elements"]["nodes"].append({
                "data": {
                    "id": p,
                    "label": "📍 " + p[len("site:"):] if p.startswith("site:") else p,
                    "is_site_group": True,
                    # Compound parents have no own asset_type/icon
                    "asset_type": "site", "ghost": False,
                    "layers": [],
                }
            })

    # Track which layers have any data so the UI can dim empty toggles
    layers_present: set[str] = set()
    for e in edges:
        for L in e.get("data", {}).get("layers", []):
            layers_present.add(L)
    for n in graph["elements"]["nodes"]:
        for L in n.get("data", {}).get("layers", []):
            layers_present.add(L)

    graph["layers"] = {L: True for L in sorted(layers_present)}
    graph["stats"]["node_count"] = len(graph["elements"]["nodes"])
    graph["stats"]["edge_count"] = len(edges)
    return graph


# =====================================================================
#  v9.13 — Geographic / multi-site map
# =====================================================================
#
# Aggregates the fleet into site cards (one per identity.site, plus one
# per cloud region) and infers inter-site WAN links from:
#   1. routing_protocols.bgp_neighbor / ospf_neighbor IPs that resolve
#      to assets in a different site;
#   2. asset.identity.tags containing 'wan:<peer-site>' or
#      'dx-to:<cloud-region>';
#   3. fallback: any cloud asset implies a WAN link from its on-prem
#      site to its cloud region.

# Approximate geographic anchors for common AWS / Azure / GCP regions
# and well-known site naming patterns. Used as initial positions in
# Cytoscape's preset layout so the map "looks right" before the user
# drags anything around. (lat, lon) → (x, y) in a simple equirectangular
# projection that fits a 1200×600 canvas.
_GEO_HINTS = {
    # AWS regions
    "us-east-1":      (38.0,  -78.0),    # N Virginia
    "us-east-2":      (39.9,  -82.9),    # Ohio
    "us-west-1":      (37.7, -122.4),    # N California
    "us-west-2":      (45.5, -122.7),    # Oregon
    "ca-central-1":   (45.5,  -73.6),    # Montreal
    "eu-west-1":      (53.3,   -6.2),    # Ireland
    "eu-west-2":      (51.5,   -0.1),    # London
    "eu-central-1":   (50.1,    8.7),    # Frankfurt
    "ap-northeast-1": (35.7,  139.7),    # Tokyo
    "ap-southeast-1": ( 1.4,  103.8),    # Singapore
    "ap-southeast-2": (-33.9, 151.2),    # Sydney
    # Azure regions
    "eastus":   (37.6, -77.5),
    "eastus2":  (36.7, -78.4),
    "westus":   (37.8, -122.4),
    "westus2":  (47.6, -122.3),
    "westeurope": (52.4, 4.9),
    # GCP regions (subset)
    "us-central1": (41.3, -93.6),  # Iowa
    "us-east4":    (39.0, -77.5),  # Virginia
    "europe-west1": (50.4, 3.8),    # Belgium
    # Heuristic fallbacks for site names operators commonly use
    "dc1":           (38.9, -77.0),   # Washington DC default
    "dc-east-1":     (38.9, -77.0),
    "branch-nyc":    (40.7, -74.0),
    "branch-lax":    (34.0, -118.2),
    "branch-sfo":    (37.7, -122.4),
    "branch-chi":    (41.9,  -87.6),
    "branch-mia":    (25.8,  -80.2),
    "branch-sea":    (47.6, -122.3),
    "hq":            (37.4, -122.1),  # bay area default
}


def _geo_to_xy(lat: float, lon: float) -> tuple[int, int]:
    """Equirectangular projection onto a 1200×600 canvas
    (lat range roughly -50..70, lon -130..150)."""
    x = int((lon + 130) * 4.5)        # -130..150 → 0..1260
    y = int((70 - lat) * 5)           # 70..-50 → 0..600
    return (max(40, min(1200, x)), max(40, min(580, y)))


def _site_position(site: str, idx: int, total: int) -> dict:
    """Pick a (x,y) for a site card. Use geographic hints when known;
    otherwise fall back to a row-major grid."""
    hint = _GEO_HINTS.get((site or "").lower())
    if hint:
        x, y = _geo_to_xy(*hint)
        return {"x": x, "y": y}
    # Grid fallback
    cols = max(1, int((total or 1) ** 0.5) + 1)
    row = idx // cols
    col = idx % cols
    return {"x": 120 + col * 220, "y": 100 + row * 180}


def build_site_graph(assets: list[dict]) -> dict:
    """Roll the fleet up to one node per site/cloud region.

    Each site node carries:
      label, asset_count, by_type (dict), health_summary (counts), is_cloud
    Edges:
      WAN links between sites, labeled with kind (mpls/sd-wan/dx/inferred)
    """
    from collections import defaultdict

    sites: dict[str, dict] = {}    # site_id → rollup info
    cross_links: dict[tuple[str, str], dict] = {}

    def _site_for(a: dict) -> str:
        ident = a.get("identity") or {}
        atype = (ident.get("asset_type") or "").lower()
        if atype == "cloud":
            # Cloud assets live in their own cloud region "site"
            cf = ident.get("custom_fields") or {}
            return (ident.get("site") or cf.get("region")
                    or cf.get("subscription_id") or "cloud").lower()
        return (ident.get("site") or "unknown").lower()

    for a in assets:
        ident = a.get("identity") or {}
        site = _site_for(a)
        s = sites.setdefault(site, {
            "site_id": site,
            "label": ident.get("site") or site,
            "is_cloud": (ident.get("asset_type") == "cloud"),
            "asset_count": 0,
            "by_type": defaultdict(int),
            "by_vendor": defaultdict(int),
            "health": {"green": 0, "yellow": 0, "red": 0, "unknown": 0},
            "crown_jewels": 0,
            "asset_ids": [],
        })
        s["asset_count"] += 1
        s["asset_ids"].append(ident.get("asset_id"))
        s["by_type"][ident.get("asset_type") or "unknown"] += 1
        if ident.get("vendor"):
            s["by_vendor"][ident["vendor"]] += 1
        # Health bucket from health.grade
        health = a.get("health") or {}
        grade = (health.get("grade") or "").upper()
        if grade in ("A", "B"):  s["health"]["green"] += 1
        elif grade == "C":       s["health"]["yellow"] += 1
        elif grade in ("D", "F"): s["health"]["red"] += 1
        else:                     s["health"]["unknown"] += 1
        if ident.get("criticality") == "crown-jewel":
            s["crown_jewels"] += 1

        # WAN-link inference from tags
        for tag in (ident.get("tags") or []):
            tag_lc = (tag or "").lower()
            if tag_lc.startswith("wan:"):
                peer = tag_lc[4:].strip()
                if peer and peer != site:
                    key = tuple(sorted([site, peer]))
                    cross_links.setdefault(key, {"kind": "wan", "tag": tag})
            elif tag_lc.startswith("dx-to:") or tag_lc.startswith("expressroute:"):
                peer = tag_lc.split(":", 1)[1].strip()
                if peer and peer != site:
                    key = tuple(sorted([site, peer]))
                    cross_links.setdefault(key, {"kind": "direct-connect",
                                                  "tag": tag})

    # Heuristic: every cloud site gets an inferred uplink to the largest
    # on-prem site (common reality for hybrid orgs).
    cloud_sites = [s for s in sites.values() if s["is_cloud"]]
    onprem = [s for s in sites.values() if not s["is_cloud"]]
    if cloud_sites and onprem:
        largest = max(onprem, key=lambda x: x["asset_count"])
        for c in cloud_sites:
            key = tuple(sorted([c["site_id"], largest["site_id"]]))
            cross_links.setdefault(key, {"kind": "inferred-cloud-uplink",
                                          "tag": ""})

    # Build Cytoscape elements
    site_list = list(sites.values())
    nodes = []
    for i, s in enumerate(site_list):
        pos = _site_position(s["site_id"], i, len(site_list))
        # Pick a primary icon for the site card
        is_cloud = s["is_cloud"]
        primary_icon = "☁" if is_cloud else "🏢"
        # Build a compact summary string for the card
        type_summary = ", ".join(f"{n} {t}"
                                  for t, n in sorted(dict(s["by_type"]).items(),
                                                      key=lambda kv: -kv[1])[:3])
        nodes.append({
            "data": {
                "id": "site:" + s["site_id"],
                "site_id": s["site_id"],
                "label": s["label"],
                "is_site_card": True,
                "is_cloud": is_cloud,
                "icon": primary_icon,
                "asset_count": s["asset_count"],
                "type_summary": type_summary,
                "green": s["health"]["green"],
                "yellow": s["health"]["yellow"],
                "red": s["health"]["red"],
                "crown_jewels": s["crown_jewels"],
                "asset_ids": s["asset_ids"],
            },
            "position": pos,
        })

    edges = []
    for (a, b), info in cross_links.items():
        edges.append({
            "data": {
                "id": f"wan:{a}--{b}",
                "source": "site:" + a,
                "target": "site:" + b,
                "kind": info["kind"],
                "label": info["kind"].replace("-", " "),
                "tag": info.get("tag", ""),
            }
        })

    return {
        "elements": {"nodes": nodes, "edges": edges},
        "stats": {
            "site_count": len(sites),
            "wan_link_count": len(cross_links),
            "cloud_count": sum(1 for s in sites.values() if s["is_cloud"]),
            "asset_count": sum(s["asset_count"] for s in sites.values()),
        },
    }


# =====================================================================
#  v9.14 — Christmas-tree network hierarchy
# =====================================================================
#
# Top-down Visio-style topology:
#   Tier 0  🌐 Internet   (synthetic anchor)
#   Tier 1  🛡 Firewalls
#   Tier 2  🔀 Edge routers
#   Tier 3  ⊟ Core / spine switches
#   Tier 4  ⊟ Distribution switches
#   Tier 5  ⊟ Access switches  /  📡 wireless APs
#   Tier 6  🖥 Servers  📷 IoT  💾 Storage
#  Side col 👤 Identity systems (AD/Entra/ISE/Okta) — peers, not in hierarchy
#  Side col ☁ Cloud regions   — peer to edge tier with a labeled WAN link

# Role classification rules. Each rule looks at hostname / tags / vendor /
# capabilities and assigns a tier. Order matters — first match wins.
_TIER_RULES = [
    # (tier_number, tier_name, predicate_fn)
    (1, "firewall",
     lambda ident, tags, ven: any("firewall" in t for t in tags)
       or "firewall" in (ident.get("hostname", "") or "").lower()
       or ven in ("palo-alto", "fortinet", "checkpoint", "sonicwall")
       or "fw" in (ident.get("hostname", "") or "").lower().split("-")),
    (2, "edge",
     lambda ident, tags, ven: any("edge" in t or "wan" in t or "perim" in t
                                    for t in tags)
       or "edge" in (ident.get("hostname", "") or "").lower()
       or "wan" in (ident.get("hostname", "") or "").lower().split("-")),
    (3, "core",
     lambda ident, tags, ven: any("core" in t or "spine" in t for t in tags)
       or "core" in (ident.get("hostname", "") or "").lower()
       or "spine" in (ident.get("hostname", "") or "").lower()),
    (4, "distribution",
     lambda ident, tags, ven: any("dist" in t or "agg" in t for t in tags)
       or "dist" in (ident.get("hostname", "") or "").lower()
       or "agg" in (ident.get("hostname", "") or "").lower()),
    (5, "access",
     lambda ident, tags, ven: any("access" in t or "leaf" in t or "wireless" in t
                                    or "ap" == t.split(":")[-1]
                                    for t in tags)
       or "acc" in (ident.get("hostname", "") or "").lower().split("-")
       or "leaf" in (ident.get("hostname", "") or "").lower()),
]


def _classify_tier(asset: dict) -> int:
    """Return tier number for one asset. Defaults to 5 (access) for any
    network gear that doesn't match a more specific rule, 6 for endpoints."""
    ident = asset.get("identity") or {}
    atype = (ident.get("asset_type") or "").lower()
    if atype != "network":
        return 6           # endpoint
    tags = [str(t).lower() for t in (ident.get("tags") or [])]
    vendor = (ident.get("vendor") or "").lower()
    for tier, _name, pred in _TIER_RULES:
        try:
            if pred(ident, tags, vendor):
                return tier
        except Exception:
            continue
    return 5               # default network gear → access


_TIER_LAYOUT = {
    # tier → (label, y-coordinate, color)
    0: ("🌐 Internet",    50,  "#0ea5e9"),
    1: ("🛡 Firewalls",  150, "#ef4444"),
    2: ("🔀 Edge",       250, "#7c5cff"),
    3: ("⊟ Core",         350, "#3b82f6"),
    4: ("⊟ Distribution", 450, "#3b82f6"),
    5: ("⊟ Access",       550, "#10b981"),
    6: ("🖥 Endpoints",   680, "#64748b"),
}


def build_xmas_tree(assets: list[dict]) -> dict:
    """Top-down hierarchical layout. Adds an Internet anchor + side rails
    for identity providers and cloud regions."""
    # Bucket every asset into a tier
    tiers: dict[int, list[dict]] = {0: [], 1: [], 2: [], 3: [],
                                     4: [], 5: [], 6: []}
    identity_assets: list[dict] = []
    cloud_assets: list[dict] = []
    for a in assets:
        ident = a.get("identity") or {}
        atype = (ident.get("asset_type") or "").lower()
        if atype == "identity":
            identity_assets.append(a)
            continue
        if atype == "cloud":
            cloud_assets.append(a)
            continue
        tier = _classify_tier(a)
        tiers[tier].append(a)

    nodes: list[dict] = []
    edges: list[dict] = []

    # Tier 0 — synthetic Internet anchor
    nodes.append({
        "data": {"id": "_internet", "label": "Internet",
                 "icon": "🌐", "tier": 0, "is_anchor": True,
                 "asset_type": "internet"},
        "position": {"x": 600, "y": _TIER_LAYOUT[0][1]},
    })

    # Tier 1..6 — devices across each tier, evenly spaced horizontally
    canvas_width = 1400
    for t in (1, 2, 3, 4, 5, 6):
        bucket = tiers[t]
        if not bucket:
            continue
        spacing = canvas_width // (len(bucket) + 1)
        for i, a in enumerate(bucket):
            ident = a.get("identity") or {}
            aid = ident.get("asset_id") or "unknown"
            x = (i + 1) * spacing
            y = _TIER_LAYOUT[t][1]
            nodes.append({
                "data": {
                    "id": aid,
                    "label": ident.get("hostname") or aid,
                    "icon": _device_icon(a),
                    "asset_type": ident.get("asset_type", ""),
                    "vendor": ident.get("vendor", ""),
                    "criticality": ident.get("criticality", ""),
                    "site": ident.get("site", ""),
                    "env": ident.get("environment", ""),
                    "mgmt_ip": ident.get("mgmt_ip", "") or
                                (ident.get("custom_fields") or {}).get("mgmt_ip", ""),
                    "health_color": _health_color(a),
                    "tier": t,
                    "tier_label": _TIER_LAYOUT[t][0],
                },
                "position": {"x": x, "y": y},
            })

    # Hub-and-spoke fallback edges between consecutive tiers (when no
    # LLDP harvest exists). Every tier-N device connects to every
    # tier-(N-1) device — Cytoscape draws clean vertical/diagonal lines.
    def _ids_in_tier(t: int) -> list[str]:
        return [(a.get("identity") or {}).get("asset_id")
                for a in tiers.get(t, [])
                if (a.get("identity") or {}).get("asset_id")]

    # Internet → firewalls. If no firewalls, → edges. If no edges, → core.
    above_ids = ["_internet"]
    for t in (1, 2, 3, 4, 5, 6):
        ids = _ids_in_tier(t)
        if not ids:
            continue
        for src in above_ids:
            for tgt in ids:
                edges.append({
                    "data": {
                        "id": f"hier:{src}--{tgt}",
                        "source": src, "target": tgt,
                        "edge_kind": "hierarchy",
                    }
                })
        above_ids = ids

    # Side rail: identity providers — placed to the right of the canvas
    for i, a in enumerate(identity_assets):
        ident = a.get("identity") or {}
        aid = ident.get("asset_id") or f"id-{i}"
        nodes.append({
            "data": {
                "id": aid,
                "label": ident.get("hostname") or aid,
                "icon": "👤",
                "asset_type": "identity",
                "vendor": ident.get("vendor", ""),
                "tier": -1,
                "tier_label": "👤 Identity providers",
                "criticality": ident.get("criticality", ""),
                "health_color": _health_color(a),
                "site": ident.get("site", ""),
                "is_side": True,
            },
            "position": {"x": canvas_width + 80, "y": 250 + i * 90},
        })

    # Side rail: cloud regions — placed to the left
    seen_clouds: set[str] = set()
    cloud_idx = 0
    for a in cloud_assets:
        ident = a.get("identity") or {}
        cf = ident.get("custom_fields") or {}
        region = (ident.get("site") or cf.get("region") or "cloud").lower()
        if region in seen_clouds:
            continue
        seen_clouds.add(region)
        nodes.append({
            "data": {
                "id": f"cloud:{region}",
                "label": region,
                "icon": "☁",
                "asset_type": "cloud",
                "vendor": ident.get("vendor", ""),
                "tier": -2,
                "tier_label": "☁ Cloud regions",
                "criticality": "",
                "health_color": "#f97316",
                "site": region,
                "is_side": True,
            },
            "position": {"x": -120, "y": 250 + cloud_idx * 90},
        })
        cloud_idx += 1

    # Connect identity providers to firewalls / edge (whichever exists);
    # connect cloud regions to edge.
    edge_ids = _ids_in_tier(2) or _ids_in_tier(1) or _ids_in_tier(3)
    for a in identity_assets:
        aid = (a.get("identity") or {}).get("asset_id")
        if not aid: continue
        for tgt in edge_ids:
            edges.append({"data": {
                "id": f"id:{aid}--{tgt}",
                "source": aid, "target": tgt,
                "edge_kind": "identity",
            }})
    for region in seen_clouds:
        for tgt in edge_ids:
            edges.append({"data": {
                "id": f"cloud:{region}--{tgt}",
                "source": f"cloud:{region}", "target": tgt,
                "edge_kind": "wan",
            }})

    # Build tier band annotations so the UI can draw faint horizontal
    # band labels.
    bands = []
    for t, (label, y, color) in _TIER_LAYOUT.items():
        if t == 0 or tiers.get(t) or (t in (1, 2) and identity_assets):
            bands.append({"tier": t, "label": label, "y": y, "color": color})

    return {
        "elements": {"nodes": nodes, "edges": edges},
        "stats": {
            "tier_counts": {_TIER_LAYOUT[t][0]: len(tiers[t])
                             for t in (1, 2, 3, 4, 5, 6)},
            "identity_count": len(identity_assets),
            "cloud_region_count": len(seen_clouds),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "bands": bands,
    }
