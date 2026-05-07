"""
Veeam Backup & Replication adapter — REST API.

Veeam exposes a REST API on port 9419 (Veeam Backup Enterprise Manager
or Veeam Backup Server REST API as of v11+).

Required credentials: username, password.

Reference: https://helpcenter.veeam.com/docs/backup/vbr_rest/overview.html
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Backup, Security,
)
from safecadence.platform.health_scoring import score_asset_health


@register_adapter("veeam_backup")
class VeeamBackupAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="veeam_backup",
        description="Veeam Backup & Replication via REST API (v11+)",
        vendor="veeam",
        asset_types=["backup"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://helpcenter.veeam.com/docs/backup/vbr_rest/overview.html",
    )

    def __init__(self, target: str, credentials: dict, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        port = credentials.get("port", 9419)
        self.base = f"https://{target}:{port}" if not target.startswith("http") else target
        self.username = credentials.get("username", "")
        self.password = credentials.get("password", "")
        self._token: str | None = None

    def _login(self) -> str | None:
        if self._token:
            return self._token
        url = f"{self.base}/api/oauth2/token"
        data = {"grant_type": "password", "username": self.username, "password": self.password}
        try:
            with self.cm.http() as c:
                r = c.post(url, data=data, headers={"x-api-version": "1.1-rev1"})
                if r.status_code < 400:
                    self._token = r.json().get("access_token")
        except Exception:
            pass
        return self._token

    def _get(self, path: str) -> dict:
        token = self._login()
        if not token:
            return {"_error": "Veeam REST login failed"}
        url = f"{self.base}/api/v1{path}"
        r = self.cm.http_get(url, headers={
            "Authorization": f"Bearer {token}",
            "x-api-version": "1.1-rev1",
        })
        return r.get("json") or {"_error": r.get("error", "?")}

    def test_connection(self) -> dict:
        token = self._login()
        if not token:
            return {"ok": False, "error": "Veeam REST authentication failed"}
        return {"ok": True, "detail": "Veeam REST API session established"}

    def collect(self, asset_id: str) -> dict[str, Any]:
        return {
            "server_info": self._get("/serverInfo"),
            "jobs": self._get("/jobs"),
            "backup_objects": self._get("/backupObjects"),
            "sessions": self._get("/sessions?limit=50&filter=state==Failed"),
            "repositories": self._get("/backupInfrastructure/repositories"),
            "managed_servers": self._get("/backupInfrastructure/managedServers"),
        }

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        info = raw.get("server_info", {}) or {}
        jobs = (raw.get("jobs", {}) or {}).get("data", []) or []
        sessions = (raw.get("sessions", {}) or {}).get("data", []) or []

        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Veeam",
            product_family="Backup & Replication",
            asset_type="backup",
            hostname=info.get("name", ""),
        )

        # Aggregate backup state
        total_jobs = len(jobs)
        failed_24h = sum(1 for s in sessions if s.get("state") == "Failed")
        successful_jobs = sum(1 for j in jobs if j.get("isHighPriority") is not None)

        backup = Backup(
            platform="veeam",
            last_backup_status="failed" if failed_24h > 0 else "success" if total_jobs > 0 else "never",
            failed_jobs_24h=failed_24h,
            retention_days=30,  # default; per-job in real config
        )

        security = Security()
        if failed_24h > 0:
            security.findings.append(f"{failed_24h} backup job(s) failed in last 50 sessions")
            security.recommended_actions.append("Investigate failed Veeam jobs immediately")
        if not jobs:
            security.findings.append("No backup jobs configured")

        asset = UnifiedAsset(
            identity=identity, backup=backup, security=security, raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset
