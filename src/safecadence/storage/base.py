"""Storage interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseStore(ABC):
    """All storage backends implement this contract."""

    @abstractmethod
    def save(self, scan_dict: dict, *, tenant_id: str = "default") -> int: ...

    @abstractmethod
    def list(self, *, limit: int = 50, source: str | None = None,
             tenant_id: str | None = None) -> list[dict]: ...

    @abstractmethod
    def get(self, scan_id: int, *, tenant_id: str | None = None) -> dict | None: ...

    @abstractmethod
    def latest_per_host(self, *, tenant_id: str | None = None) -> list[dict]: ...

    @abstractmethod
    def close(self) -> None: ...

    # ---- defaults ---------------------------------------------- #
    def stats(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        rows = self.latest_per_host(tenant_id=tenant_id)
        n = len(rows)
        return {
            "device_count": n,
            "avg_health": int(sum(r.get("health_score", 0) for r in rows) / n) if n else 0,
            "avg_risk":   int(sum(r.get("risk_score", 0)   for r in rows) / n) if n else 0,
            "critical_devices": sum(1 for r in rows if r.get("risk_band") == "critical"),
        }
