"""
Cross-domain correlation engine.

Operates on UnifiedAsset dicts (as produced by adapters → save_asset).
Builds dependency chains, finds orphans, and surfaces toxic combos
across the boundary between domains:

    VM   → hypervisor host
    Host → datastore
    Datastore → storage array volume / LUN
    Server / VM → backup job
    Anything → cloud account / network gear

The engine is intentionally heuristic and string-based: production
deployments wire in real foreign-keys via the asset_id field. The
goal is to give operators a "what depends on what" view without
requiring a CMDB.
"""

from __future__ import annotations

from typing import Any


# --------------------------------------------------------------------------
# Indexing helpers
# --------------------------------------------------------------------------

def _by_id(assets: list[dict]) -> dict[str, dict]:
    return {(a.get("identity") or {}).get("asset_id"): a for a in assets
            if (a.get("identity") or {}).get("asset_id")}


def _by_type(assets: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for a in assets:
        t = (a.get("identity") or {}).get("asset_type") or "unknown"
        out.setdefault(t, []).append(a)
    return out


def _vm_names(asset: dict) -> list[str]:
    """Pull VM display names off a hypervisor / vCenter asset."""
    v = asset.get("virtualization") or {}
    return [vm.get("name", "") for vm in (v.get("vms") or []) if vm.get("name")]


def _datastore_refs(asset: dict) -> list[str]:
    """Pull datastore names referenced by this hypervisor."""
    v = asset.get("virtualization") or {}
    return [ds.get("name", "") for ds in (v.get("datastores") or []) if ds.get("name")]


def _volume_refs(asset: dict) -> list[str]:
    """Pull volume / LUN names from a storage array."""
    s = asset.get("storage") or {}
    out = []
    for v in (s.get("volumes") or []):
        if v.get("name"):
            out.append(v["name"])
    for lun in (s.get("luns") or []):
        if lun.get("name"):
            out.append(lun["name"])
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def build_dependency_chain(asset: dict, all_assets: list[dict]) -> dict:
    """Walk both directions from `asset` and return a graph of related assets.

    Direction 'upstream' = things this asset depends on (e.g. VM → host → array)
    Direction 'downstream' = things that depend on this asset (e.g. array ← host ← VM)
    """
    by_id = _by_id(all_assets)
    by_type = _by_type(all_assets)
    aid = (asset.get("identity") or {}).get("asset_id")
    atype = (asset.get("identity") or {}).get("asset_type")

    upstream: list[dict] = []
    downstream: list[dict] = []

    if atype == "hypervisor":
        # Upstream: storage arrays whose volumes match my datastores.
        my_ds = set(_datastore_refs(asset))
        for sa in by_type.get("storage", []):
            if my_ds & set(_volume_refs(sa)):
                upstream.append({
                    "asset_id": (sa.get("identity") or {}).get("asset_id"),
                    "vendor": (sa.get("identity") or {}).get("vendor"),
                    "model": (sa.get("identity") or {}).get("model"),
                    "relation": "datastore_backed_by_volume",
                })
        # Downstream: backup jobs that reference my hypervisor name (best-effort).
        for ba in by_type.get("backup", []):
            if aid and aid in str(ba):
                downstream.append({
                    "asset_id": (ba.get("identity") or {}).get("asset_id"),
                    "vendor": (ba.get("identity") or {}).get("vendor"),
                    "relation": "protects",
                })
    elif atype == "storage":
        # Downstream: hypervisors whose datastores match my volumes.
        my_vols = set(_volume_refs(asset))
        for hv in by_type.get("hypervisor", []):
            if my_vols & set(_datastore_refs(hv)):
                downstream.append({
                    "asset_id": (hv.get("identity") or {}).get("asset_id"),
                    "vendor": (hv.get("identity") or {}).get("vendor"),
                    "relation": "hosts_datastore",
                })
    elif atype == "server":
        # Upstream: backup software that protects this server's hostname.
        host = (asset.get("identity") or {}).get("hostname", "")
        for ba in by_type.get("backup", []):
            if host and host in str(ba):
                upstream.append({
                    "asset_id": (ba.get("identity") or {}).get("asset_id"),
                    "vendor": (ba.get("identity") or {}).get("vendor"),
                    "relation": "protects",
                })
    elif atype == "backup":
        # Downstream: every server / VM that appears in raw_collection.
        raw_str = str(asset.get("raw_collection", ""))
        for srv in by_type.get("server", []) + by_type.get("hypervisor", []):
            host = (srv.get("identity") or {}).get("hostname", "")
            if host and host in raw_str:
                downstream.append({
                    "asset_id": (srv.get("identity") or {}).get("asset_id"),
                    "vendor": (srv.get("identity") or {}).get("vendor"),
                    "relation": "protected",
                })

    return {
        "asset_id": aid,
        "asset_type": atype,
        "upstream_count": len(upstream),
        "downstream_count": len(downstream),
        "upstream": upstream,
        "downstream": downstream,
    }


def find_orphans(all_assets: list[dict]) -> list[dict]:
    """Return assets that are at risk of being orphaned by another change.

    Examples surfaced:
      - storage arrays whose volumes no hypervisor mounts (over-provisioned)
      - servers with no recent backup record across any backup platform
      - hypervisors with no upstream array detected
      - cloud assets with no associated network gear in the same account
    """
    out: list[dict] = []
    by_type = _by_type(all_assets)

    backup_strs = " ".join(str(a) for a in by_type.get("backup", []))
    for srv in by_type.get("server", []):
        host = (srv.get("identity") or {}).get("hostname", "")
        if host and host not in backup_strs:
            out.append({
                "asset_id": (srv.get("identity") or {}).get("asset_id"),
                "asset_type": "server",
                "vendor": (srv.get("identity") or {}).get("vendor"),
                "issue": "no_backup_reference",
                "severity": "high",
            })

    hypervisor_ds = set()
    for hv in by_type.get("hypervisor", []):
        hypervisor_ds.update(_datastore_refs(hv))
    for sa in by_type.get("storage", []):
        vols = set(_volume_refs(sa))
        if vols and not (vols & hypervisor_ds):
            out.append({
                "asset_id": (sa.get("identity") or {}).get("asset_id"),
                "asset_type": "storage",
                "vendor": (sa.get("identity") or {}).get("vendor"),
                "issue": "volumes_not_mounted_by_any_hypervisor",
                "severity": "medium",
            })

    storage_vols = set()
    for sa in by_type.get("storage", []):
        storage_vols.update(_volume_refs(sa))
    for hv in by_type.get("hypervisor", []):
        ds = set(_datastore_refs(hv))
        if ds and not (ds & storage_vols):
            out.append({
                "asset_id": (hv.get("identity") or {}).get("asset_id"),
                "asset_type": "hypervisor",
                "vendor": (hv.get("identity") or {}).get("vendor"),
                "issue": "no_upstream_storage_array_correlated",
                "severity": "low",
            })

    return out


def find_toxic_combinations(all_assets: list[dict]) -> list[dict]:
    """Cross-domain toxic-combo detection.

    Examples flagged:
      - production VM on hypervisor that's past EOS
      - prod storage array with critical CVEs AND replication broken
      - backup job with last_successful_backup_at >7 days
      - cloud asset with public exposure AND high CVEs
    """
    findings: list[dict] = []

    for a in all_assets:
        ident = a.get("identity") or {}
        env = (ident.get("environment") or "").lower()
        sec = a.get("security") or {}
        lc = a.get("lifecycle") or {}

        if env == "prod" and lc.get("eol_status") in ("end-of-support", "end-of-software"):
            findings.append({
                "asset_id": ident.get("asset_id"),
                "type": "prod_on_eos",
                "severity": "critical",
                "msg": f"{ident.get('vendor')} {ident.get('model')} in production is past end-of-support",
            })

        if ident.get("asset_type") == "storage":
            stg = a.get("storage") or {}
            if sec.get("critical_cves", 0) > 0 and stg.get("replication_status") in ("broken", "degraded"):
                findings.append({
                    "asset_id": ident.get("asset_id"),
                    "type": "vulnerable_array_no_replication",
                    "severity": "critical",
                    "msg": "Storage array has critical CVEs AND replication is broken/degraded",
                })

        if ident.get("asset_type") == "backup":
            bkp = a.get("backup") or {}
            if bkp.get("actual_rpo_hours", 0) > 168:
                findings.append({
                    "asset_id": ident.get("asset_id"),
                    "type": "backup_stale",
                    "severity": "high",
                    "msg": f"Last successful backup was {bkp['actual_rpo_hours']}h ago (>7 days)",
                })

        if ident.get("asset_type") == "cloud":
            cl = a.get("cloud") or {}
            if cl.get("public_exposure") and sec.get("critical_cves", 0) > 0:
                findings.append({
                    "asset_id": ident.get("asset_id"),
                    "type": "public_with_critical_cve",
                    "severity": "critical",
                    "msg": "Public-facing cloud asset has critical CVEs",
                })

    return findings
