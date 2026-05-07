"""
Pure Storage FlashArray adapter — REST API.

Pure FlashArray exposes a REST API on https://<array>/api/2.x/.
Auth via API token.

Required credentials: api_token

Reference: https://support.purestorage.com/FlashArray/PurityFA/REST_API
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, Storage, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("pure_storage")
class PureStorageAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="pure_storage",
        description="Pure Storage FlashArray via REST API",
        vendor="purestorage",
        asset_types=["storage"],
        connection_types=[ConnectionType.REST],
        required_credentials=["api_token"],
        documentation_url="https://support.purestorage.com/FlashArray/PurityFA/REST_API",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base = f"https://{target}" if not target.startswith("http") else target
        self.api_token = credentials.get("api_token", "")
        self._session_token: str | None = None

    def _login(self) -> str | None:
        if self._session_token:
            return self._session_token
        url = f"{self.base}/api/2.20/login"
        r = self.cm.http_post(url, headers={"api-token": self.api_token})
        if r.get("ok"):
            self._session_token = r.get("headers", {}).get("x-auth-token")
        return self._session_token

    def _get(self, path: str) -> dict:
        token = self._login()
        if not token:
            return {"_error": "Pure Storage login failed"}
        url = f"{self.base}/api/2.20{path}"
        r = self.cm.http_get(url, headers={"x-auth-token": token})
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        r = self._get("/arrays")
        if "_error" in r:
            return {"ok": False, "error": r["_error"]}
        items = r.get("items", []) or []
        if items:
            arr = items[0]
            return {"ok": True, "detail": f"Pure FlashArray {arr.get('name','?')} Purity {arr.get('version','?')}"}
        return {"ok": True, "detail": "Connected (no array data)"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "arrays": self._get("/arrays"),
            "controllers": self._get("/controllers"),
            "hardware": self._get("/hardware"),
            "volumes": self._get("/volumes"),
            "snapshots": self._get("/volume-snapshots?limit=100"),
            "hosts": self._get("/hosts"),
            "alerts": self._get("/alerts?filter=state='open'"),
            "drives": self._get("/drives"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        arr = (raw.get("arrays", {}).get("items", []) or [{}])[0]

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Pure Storage",
            product_family="FlashArray",
            model=arr.get("controller_id", ""),
            asset_type="storage",
            hostname=arr.get("name", ""),
        )

        # Hardware
        hardware_items = raw.get("hardware", {}).get("items", []) or []
        power_supplies = []
        fans = []
        for item in hardware_items:
            name = item.get("name", "")
            status = (item.get("status") or "").lower()
            if "psu" in name.lower() or "power" in name.lower():
                power_supplies.append({"slot": name, "status": status})
            elif "fan" in name.lower():
                fans.append({"slot": name, "status": status})

        controllers = raw.get("controllers", {}).get("items", []) or []
        first_ctrl = controllers[0] if controllers else {}
        hardware = Hardware(
            chassis_pid=first_ctrl.get("model", ""),
            firmware_version=first_ctrl.get("version", ""),
            power_supplies=power_supplies,
            fans=fans,
        )

        # Storage capacity
        space = arr.get("space", {}) or {}
        total_bytes = space.get("capacity", 0) or 0
        used_bytes = (space.get("total_physical", 0) or 0)

        volumes = raw.get("volumes", {}).get("items", []) or []
        storage = Storage(
            total_capacity_tb=round(total_bytes / (1024**4), 2),
            used_capacity_tb=round(used_bytes / (1024**4), 2),
            free_capacity_tb=round((total_bytes - used_bytes) / (1024**4), 2),
            volumes=[{
                "name": v.get("name", ""),
                "size_gb": (v.get("provisioned", 0) or 0) / (1024**3),
                "protocol": "san",
            } for v in volumes[:50]],
            dedupe_ratio=space.get("data_reduction", 0) or 0,
        )

        # Security checks
        security = Security()
        alerts = raw.get("alerts", {}).get("items", []) or []
        for a in alerts[:10]:
            if a.get("severity") in ("critical", "warning"):
                security.findings.append(f"Open alert: {a.get('summary', '?')} ({a.get('severity')})")

        asset = UnifiedAsset(
            identity=identity, hardware=hardware, storage=storage,
            security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
