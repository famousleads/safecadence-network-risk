"""
Attack-path graph engine — BloodHound-for-infrastructure.

Given a starting asset (or "internet"), walks the cross-domain correlation
graph to enumerate every reachable resource and the chain of hops that
gets the attacker there. This is the single feature CSPM products
(Wiz, Tenable Cyber Exposure, Orca) charge $25k-$100k+/year to provide.

Edges between asset types — built from data we already collect:

  internet           ──reaches──→  cloud      (public_exposure=True)
  internet           ──reaches──→  network    (mgmt port open to 0.0.0.0/0)
  network            ──governs──→  server     (any host reachable through that network)
  server             ──hosts────→  hypervisor (VM hypervisor on a server)
  hypervisor         ──runs─────→  vm/server  (vms list / datastore relations)
  hypervisor         ──mounts───→  storage    (datastore name matches a volume)
  storage            ──holds────→  backup     (backup destination references the array)
  cloud account      ──contains─→  cloud assets (same account_id)
  any compromised → backup       (anything in the same env as the backup mover)

Blast-radius output is a topologically-sorted list of {asset, hop_count,
path, why}; each entry says exactly which edge let the attacker reach it.

Pure Python. Cross-platform.
"""

from __future__ import annotations

from collections import deque
from typing import Any


def _ident(a: dict) -> dict:
    return a.get("identity") or {}


def _by_id(assets: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for a in assets:
        aid = _ident(a).get("asset_id")
        if aid: out[aid] = a
    return out


def _by_type(assets: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for a in assets:
        t = _ident(a).get("asset_type") or "unknown"
        out.setdefault(t, []).append(a)
    return out


def _datastore_names(asset: dict) -> set[str]:
    return {(d.get("name") or "").lower()
            for d in ((asset.get("virtualization") or {}).get("datastores") or [])
            if d.get("name")}


def _volume_names(asset: dict) -> set[str]:
    s = asset.get("storage") or {}
    out: set[str] = set()
    for v in (s.get("volumes") or []):
        if v.get("name"): out.add(v["name"].lower())
    for lun in (s.get("luns") or []):
        if lun.get("name"): out.add(lun["name"].lower())
    return out


def _vm_names(asset: dict) -> set[str]:
    return {(vm.get("name") or "").lower()
            for vm in ((asset.get("virtualization") or {}).get("vms") or [])
            if vm.get("name")}


def _cloud_account(asset: dict) -> str:
    """Pull the cloud account/subscription/project ID for grouping."""
    cloud = asset.get("cloud") or {}
    return (cloud.get("account_id") or cloud.get("subscription_id")
            or cloud.get("project_id") or "")


def _iam_principals(asset: dict) -> set[str]:
    """Identities (users / SPNs / roles) authorized on this asset."""
    out: set[str] = set()
    ib = asset.get("identity_block") or {}
    for u in ib.get("authorized_users") or []:
        if u: out.add(str(u).lower())
    for g in ib.get("authorized_groups") or []:
        if g: out.add(str(g).lower())
    cloud = asset.get("cloud") or {}
    if cloud.get("iam_role"):
        out.add(str(cloud.get("iam_role")).lower())
    return out


def _ssh_key_fingerprints(asset: dict) -> set[str]:
    """SSH key fingerprints / authorized_keys hashes used by this asset."""
    out: set[str] = set()
    sec = asset.get("security") or {}
    for k in sec.get("ssh_authorized_keys") or []:
        if k: out.add(str(k).lower())
    for k in sec.get("ssh_host_keys") or []:
        if k: out.add(str(k).lower())
    return out


def _ad_domain(asset: dict) -> str:
    ib = asset.get("identity_block") or {}
    return (ib.get("domain") or ib.get("ad_domain") or "").lower()


# --------------------------------------------------------------------------
# Edge enumeration — heuristic, but grounded in data we actually collect.
# --------------------------------------------------------------------------

def _edges(asset: dict, all_assets: list[dict]) -> list[tuple[dict, str]]:
    """Return [(neighbor, why)] reachable from `asset`."""
    by_type = _by_type(all_assets)
    aid = _ident(asset).get("asset_id")
    atype = _ident(asset).get("asset_type")
    env = (_ident(asset).get("environment") or "").lower()
    out: list[tuple[dict, str]] = []

    if atype == "hypervisor":
        # → datastore-backed storage arrays
        my_ds = _datastore_names(asset)
        for sa in by_type.get("storage", []):
            if my_ds & _volume_names(sa):
                out.append((sa, "datastore_backed_by_volume"))
        # → backup that lists this hypervisor by id/hostname
        host = _ident(asset).get("hostname", "") or aid or ""
        for ba in by_type.get("backup", []):
            if host and host.lower() in str(ba).lower():
                out.append((ba, "backup_protects_hypervisor"))

    if atype == "server":
        # → backup that protects this server's hostname
        host = _ident(asset).get("hostname", "") or ""
        for ba in by_type.get("backup", []):
            if host and host.lower() in str(ba).lower():
                out.append((ba, "backup_protects_server"))

    if atype == "storage":
        # → hypervisors mounting a volume from this array
        my_vols = _volume_names(asset)
        for hv in by_type.get("hypervisor", []):
            if my_vols & _datastore_names(hv):
                out.append((hv, "hypervisor_mounts_storage"))

    if atype == "backup":
        # → every server / hypervisor that appears in raw_collection
        raw = str(asset.get("raw_collection") or "").lower()
        for srv in by_type.get("server", []) + by_type.get("hypervisor", []):
            host = (_ident(srv).get("hostname") or "").lower()
            if host and host in raw:
                out.append((srv, "appears_in_backup_inventory"))

    if atype == "network":
        # Network gear "governs" everything in the same site (best-effort)
        my_site = _ident(asset).get("site") or _ident(asset).get("datacenter")
        if my_site:
            for other in all_assets:
                if _ident(other).get("asset_id") == aid: continue
                if (_ident(other).get("site") == my_site or
                        _ident(other).get("datacenter") == my_site):
                    out.append((other, "same_site_via_network"))

    if atype == "cloud":
        # Same account_id → same cloud blast radius
        my_acct = _cloud_account(asset)
        if my_acct:
            for other in by_type.get("cloud", []):
                if _ident(other).get("asset_id") == aid: continue
                if _cloud_account(other) == my_acct:
                    out.append((other, "same_cloud_account"))
        # IAM cross-account assume-role: trust policy mentions another account
        cloud = asset.get("cloud") or {}
        trusted = cloud.get("trusted_accounts") or cloud.get("trust_relationships") or []
        if trusted:
            trusted_set = {str(t).strip() for t in trusted if t}
            for other in by_type.get("cloud", []):
                if _ident(other).get("asset_id") == aid: continue
                if _cloud_account(other) in trusted_set:
                    out.append((other, "iam_cross_account_trust"))
        # IAM principal → other assets that grant the same principal access
        my_principals = _iam_principals(asset)
        if my_principals:
            for other in all_assets:
                if _ident(other).get("asset_id") == aid: continue
                if _ident(other).get("asset_type") not in ("cloud", "server", "compute"):
                    continue
                if my_principals & _iam_principals(other):
                    out.append((other, "shared_iam_principal"))

    if atype == "identity":
        # An identity-store asset is reachable to every asset that authorizes
        # any of its members. In practice this is the "credential dump" path:
        # compromise AD/Okta → pivot to every device/account that trusts it.
        my_users = _iam_principals(asset)
        my_domain = _ad_domain(asset)
        if my_users:
            for other in all_assets:
                if _ident(other).get("asset_id") == aid: continue
                their_users = _iam_principals(other)
                if my_users & their_users:
                    out.append((other, "identity_grants_access"))
        if my_domain:
            for other in all_assets:
                if _ident(other).get("asset_id") == aid: continue
                if _ad_domain(other) == my_domain:
                    out.append((other, "ad_domain_member"))

    if atype in ("server", "compute"):
        # SSH key reuse — a key compromised on one host opens every host that
        # trusts it via ~/.ssh/authorized_keys (real-world ransomware spread).
        my_keys = _ssh_key_fingerprints(asset)
        if my_keys:
            for other in by_type.get("server", []) + by_type.get("compute", []):
                if _ident(other).get("asset_id") == aid: continue
                if my_keys & _ssh_key_fingerprints(other):
                    out.append((other, "ssh_key_reuse"))
        # Server in a cloud account → every other asset in that account
        my_acct = _cloud_account(asset)
        if my_acct:
            for other in by_type.get("cloud", []):
                if _cloud_account(other) == my_acct:
                    out.append((other, "server_in_cloud_account"))

    if atype == "network":
        # Real ACL → server reachability. If we have an explicit allowed_cidr
        # list, fan out to every server whose mgmt_ip falls inside it.
        net = asset.get("network") or {}
        allowed = net.get("allowed_destinations") or net.get("permit_cidrs") or []
        if allowed:
            try:
                import ipaddress as _ip
                cidrs = []
                for c in allowed:
                    try:
                        cidrs.append(_ip.ip_network(str(c), strict=False))
                    except ValueError:
                        continue
                if cidrs:
                    for other in by_type.get("server", []) + by_type.get("compute", []):
                        ip = ((other.get("network") or {}).get("mgmt_ip")
                              or (other.get("identity") or {}).get("ip"))
                        if not ip: continue
                        try:
                            ip_obj = _ip.ip_address(str(ip))
                        except ValueError:
                            continue
                        if any(ip_obj in c for c in cidrs):
                            out.append((other, "network_acl_permits"))
            except Exception:
                pass

    # Same-environment backup is reachable from anything compromised
    if env and atype != "backup":
        for ba in by_type.get("backup", []):
            if (_ident(ba).get("environment") or "").lower() == env:
                out.append((ba, "lateral_to_same_env_backup"))

    # Dedupe by neighbor asset_id, preserving the first 'why'
    seen: set[str] = set()
    deduped: list[tuple[dict, str]] = []
    for n, why in out:
        nid = _ident(n).get("asset_id")
        if not nid or nid == aid or nid in seen: continue
        seen.add(nid); deduped.append((n, why))
    return deduped


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def blast_radius(start_asset_id: str, all_assets: list[dict],
                 *, max_hops: int = 8) -> dict[str, Any]:
    """BFS from `start_asset_id`. Returns the blast-radius envelope."""
    by_id = _by_id(all_assets)
    if start_asset_id == "internet":
        # Treat every public-exposure cloud asset and every network asset
        # with mgmt access as direct reachable-from-internet seeds.
        seeds: list[tuple[dict, str]] = []
        for a in all_assets:
            cloud = a.get("cloud") or {}
            net = a.get("network") or {}
            if cloud.get("public_exposure") or cloud.get("public_ip"):
                seeds.append((a, "internet_via_public_exposure"))
                continue
            if net.get("public_ip") or net.get("internet_facing"):
                seeds.append((a, "internet_via_public_network"))
                continue
            zone = (net.get("zone") or "").lower()
            if zone in ("dmz", "edge", "internet"):
                seeds.append((a, "internet_via_edge_zone"))
                continue
            # Any asset config that exposes mgmt to 0.0.0.0/0
            rc = a.get("raw_collection") or {}
            cfg = ""
            if isinstance(rc, dict):
                for v in rc.values():
                    if isinstance(v, str): cfg += v + "\n"
            elif isinstance(rc, str):
                cfg = rc
            if "0.0.0.0/0" in cfg or "permit any any" in cfg.lower():
                seeds.append((a, "internet_via_open_mgmt"))
        # Dedupe by asset_id
        seen_seed: set[str] = set()
        deduped_seeds: list[tuple[dict, str]] = []
        for s, why in seeds:
            sid = _ident(s).get("asset_id")
            if sid and sid not in seen_seed:
                seen_seed.add(sid)
                deduped_seeds.append((s, why))
        seeds = deduped_seeds
        if not seeds:
            return {"start": "internet", "reached": 0, "paths": [],
                    "summary": "no internet-reachable assets discovered"}
        start_node = {"identity": {"asset_id": "internet", "asset_type": "internet"}}
        start = "internet"
        # Synthetic edges from the "internet" node
        synthetic_first_hop = seeds
    else:
        if start_asset_id not in by_id:
            return {"start": start_asset_id, "reached": 0,
                    "paths": [], "error": "asset not found"}
        start_node = by_id[start_asset_id]
        start = start_asset_id
        synthetic_first_hop = None

    visited = {start: 0}                     # asset_id → hop count
    paths: dict[str, list[dict]] = {start: []}
    why_in: dict[str, str] = {}              # asset_id → why we got here
    q: deque = deque([start_node])

    while q:
        cur = q.popleft()
        cur_id = _ident(cur).get("asset_id")
        cur_hops = visited[cur_id]
        if cur_hops >= max_hops:
            continue
        if synthetic_first_hop is not None and cur_id == "internet":
            edges = synthetic_first_hop
            synthetic_first_hop = None
        else:
            edges = _edges(cur, all_assets)
        for neighbor, why in edges:
            nid = _ident(neighbor).get("asset_id")
            if nid in visited:
                continue
            visited[nid] = cur_hops + 1
            paths[nid] = paths[cur_id] + [{"to": nid, "via": why,
                                           "from": cur_id}]
            why_in[nid] = why
            q.append(neighbor)

    reached = []
    for aid, hops in sorted(visited.items(), key=lambda kv: kv[1]):
        if aid == start: continue
        a = by_id.get(aid, {})
        ident = _ident(a)
        sec = a.get("security") or {}
        reached.append({
            "asset_id": aid,
            "hops": hops,
            "vendor": ident.get("vendor"),
            "asset_type": ident.get("asset_type"),
            "environment": ident.get("environment"),
            "criticality": ident.get("criticality"),
            "kev_cves": sec.get("kev_cves", 0),
            "critical_cves": sec.get("critical_cves", 0),
            "via": why_in.get(aid, ""),
            "path": paths.get(aid, []),
        })

    # Brutally honest impact summary
    crown_jewels = sum(1 for r in reached
                       if (r.get("criticality") or "").lower() == "crown-jewel")
    backup_reach = sum(1 for r in reached if r.get("asset_type") == "backup")
    storage_reach = sum(1 for r in reached if r.get("asset_type") == "storage")
    cloud_reach = sum(1 for r in reached if r.get("asset_type") == "cloud")
    summary = (
        f"Compromise of {start} grants reach to {len(reached)} additional assets "
        f"({crown_jewels} crown-jewels · {backup_reach} backup targets · "
        f"{storage_reach} storage arrays · {cloud_reach} cloud assets) "
        f"within {max(visited.values(), default=0)} hops."
    )

    return {
        "start": start,
        "reached": len(reached),
        "max_hops_walked": max(visited.values(), default=0),
        "by_hop": {hops: sum(1 for r in reached if r["hops"] == hops)
                   for hops in sorted({r["hops"] for r in reached})},
        "by_type": {t: sum(1 for r in reached if r["asset_type"] == t)
                    for t in sorted({r["asset_type"] for r in reached if r["asset_type"]})},
        "crown_jewels_reached": crown_jewels,
        "summary": summary,
        "paths": reached,
    }


def attack_paths_to(target_asset_id: str, all_assets: list[dict],
                    *, max_hops: int = 6) -> list[dict]:
    """For every asset, compute whether it can reach `target` and how."""
    out: list[dict] = []
    target_set = {target_asset_id}
    by_id = _by_id(all_assets)
    if target_asset_id not in by_id:
        return out
    for a in all_assets:
        sid = _ident(a).get("asset_id")
        if not sid or sid == target_asset_id:
            continue
        br = blast_radius(sid, all_assets, max_hops=max_hops)
        for r in br.get("paths") or []:
            if r["asset_id"] in target_set:
                out.append({
                    "starting_asset": sid,
                    "vendor": _ident(a).get("vendor"),
                    "asset_type": _ident(a).get("asset_type"),
                    "hops": r["hops"],
                    "path": r["path"],
                })
                break
    out.sort(key=lambda r: r["hops"])
    return out


def top_k_paths_to_crown_jewels(all_assets: list[dict], *, k: int = 10,
                                max_hops: int = 6) -> list[dict]:
    """Find the K shortest internet→crown-jewel paths, ranked by (hops asc,
    blast-impact desc).

    This is the BloodHound-for-infrastructure killer view: "if I'm an
    attacker on the internet right now, here are the K shortest routes to
    your most valuable assets."
    """
    crown_ids = [
        _ident(a).get("asset_id") for a in all_assets
        if (_ident(a).get("criticality") or "").lower() == "crown-jewel"
        and _ident(a).get("asset_id")
    ]
    if not crown_ids:
        return []
    br = blast_radius("internet", all_assets, max_hops=max_hops)
    by_id = _by_id(all_assets)
    candidate_paths: list[dict] = []
    for r in br.get("paths") or []:
        if r["asset_id"] not in crown_ids:
            continue
        target = by_id.get(r["asset_id"], {})
        sec = target.get("security") or {}
        candidate_paths.append({
            "target_asset_id": r["asset_id"],
            "target_vendor": (_ident(target).get("vendor")),
            "target_asset_type": _ident(target).get("asset_type"),
            "hops": r["hops"],
            "kev_cves_at_target": sec.get("kev_cves", 0),
            "critical_cves_at_target": sec.get("critical_cves", 0),
            "path": r["path"],
            "summary": (
                f"Internet → {r['asset_id']} in {r['hops']} hops via "
                + " → ".join(p["via"] for p in r["path"])
            ),
        })
    # Rank: shortest path first, then most KEVs at the target
    candidate_paths.sort(key=lambda p: (p["hops"],
                                        -p["kev_cves_at_target"],
                                        -p["critical_cves_at_target"]))
    return candidate_paths[:k]
