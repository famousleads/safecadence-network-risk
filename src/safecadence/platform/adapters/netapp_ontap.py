"""
NetApp ONTAP adapter — REST API based.

Discovers ONTAP storage clusters: aggregates, volumes, LUNs, SVMs,
snapshots, and replication state.

Required credentials:
  - username
  - password

Tested against: ONTAP 9.7+. Older versions support REST but with caveats.
Documentation: https://docs.netapp.com/us-en/ontap-restapi/
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Storage, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("netapp_ontap")
class NetAppONTAPAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="netapp_ontap",
        description="NetApp ONTAP storage clusters via REST API",
        vendor="netapp",
        asset_types=["storage"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        supports_discovery=False,
        rate_limit_calls_per_minute=60,
        documentation_url="https://docs.netapp.com/us-en/ontap-restapi/",
    )

    def __init__(self, target: str, credentials: dict[str, str], **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base_url = target if target.startswith("http") else f"https://{target}"
        self.username = credentials.get("username", "")
        self.password = credentials.get("password", "")

    def _api_get(self, path: str) -> dict:
        url = self.base_url.rstrip("/") + path
        r = self.cm.http_get(url, auth=(self.username, self.password),
                             headers={"Accept": "application/json"})
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        r = self._api_get("/api/cluster")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        return {"ok": True, "detail": f"ONTAP cluster {r.get('name','?')} v{r.get('version', {}).get('full', '?')}"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "cluster": self._api_get("/api/cluster"),
            "nodes": self._api_get("/api/cluster/nodes"),
            "aggregates": self._api_get("/api/storage/aggregates"),
            "volumes": self._api_get("/api/storage/volumes"),
            "luns": self._api_get("/api/storage/luns"),
            "svms": self._api_get("/api/svm/svms"),
            "snapmirror": self._api_get("/api/snapmirror/relationships"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        cluster = raw.get("cluster", {}) or {}
        version = (cluster.get("version") or {}).get("full", "")

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="NetApp",
            product_family="ONTAP",
            model=cluster.get("name", ""),
            asset_type="storage",
            hostname=cluster.get("name", ""),
        )

        # Aggregate storage capacity
        aggrs = (raw.get("aggregates", {}) or {}).get("records", [])
        total_tb = sum((a.get("space", {}).get("block_storage", {}).get("size", 0) or 0) for a in aggrs) / (1024**4)

        volumes = (raw.get("volumes", {}) or {}).get("records", [])
        used_tb = sum((v.get("space", {}).get("used", 0) or 0) for v in volumes) / (1024**4)

        # Replication
        sm = (raw.get("snapmirror", {}) or {}).get("records", [])
        repl_status = "ok"
        if any(r.get("state") not in ("snapmirrored", "in_sync", "uninitialized") for r in sm):
            repl_status = "degraded"

        storage = Storage(
            total_capacity_tb=round(total_tb, 2),
            used_capacity_tb=round(used_tb, 2),
            free_capacity_tb=round(total_tb - used_tb, 2),
            pools=[{
                "name": a.get("name"),
                "total_gb": (a.get("space", {}).get("block_storage", {}).get("size", 0) or 0) / (1024**3),
                "raid_level": (a.get("block_storage", {}).get("primary", {}).get("raid_type", "")),
            } for a in aggrs[:20]],
            volumes=[{
                "name": v.get("name"),
                "size_gb": (v.get("space", {}).get("size", 0) or 0) / (1024**3),
                "protocol": v.get("nas", {}).get("path") and "nfs" or "san",
            } for v in volumes[:50]],
            replication_status=repl_status,
        )

        asset = UnifiedAsset(
            identity=identity, storage=storage, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
