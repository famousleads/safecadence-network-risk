"""
Adapter framework — base class every vendor adapter inherits from.

Adapter lifecycle:
  1. instantiate    : Adapter(target=..., credentials=...)
  2. validate       : adapter.test_connection() returns ok/error
  3. discover       : adapter.discover() returns list of asset stubs
  4. collect        : adapter.collect(asset_id) returns raw data
  5. normalize      : adapter.normalize(raw_data) returns UnifiedAsset
  6. all_in_one     : adapter.collect_all() does discover→collect→normalize for every asset

Adapters declare their capabilities so the platform knows how to invoke them
(e.g., does this adapter support real-time refresh? batch? incremental?).

Registration is module-level — adapters call register_adapter() at import.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterator

from safecadence.platform.schema import UnifiedAsset


class ConnectionType(str, Enum):
    SSH = "ssh"
    REST = "rest"
    SOAP = "soap"
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"
    REDFISH = "redfish"
    IPMI = "ipmi"
    VENDOR_SDK = "vendor_sdk"
    AGENT = "agent"


@dataclass
class AdapterCapabilities:
    """What the adapter can do — declared at adapter class level."""
    name: str = ""
    description: str = ""
    vendor: str = ""
    asset_types: list[str] = field(default_factory=list)        # network | server | storage | hypervisor | cloud | backup
    connection_types: list[ConnectionType] = field(default_factory=list)
    required_credentials: list[str] = field(default_factory=list)  # ['username', 'password'] or ['api_key']
    supports_discovery: bool = False
    supports_collection: bool = True
    supports_realtime: bool = False
    supports_telemetry_streaming: bool = False
    rate_limit_calls_per_minute: int = 60
    requires_python_extras: list[str] = field(default_factory=list)  # ['vmware', 'aws', ...]
    documentation_url: str = ""
    # ---- v7.5: write-back capability declaration ---- #
    # Adapters opt in to mutations explicitly. CLI / UI hides the "apply"
    # action for adapters that haven't declared they support writes.
    supports_write: bool = False
    write_capabilities: list[str] = field(default_factory=list)
    # Suggested values: 'authz_rule', 'group_membership', 'mfa_enforce',
    # 'session_revoke', 'ca_policy', 'app_assignment',
    # 'service_account_rotate', 'group_rule'.


class BaseAdapter(ABC):
    """Every vendor adapter subclasses this."""

    capabilities: AdapterCapabilities = AdapterCapabilities()

    def __init__(self, target: str, credentials: dict[str, str], *,
                 verify_ssl: bool = True, timeout: int = 30):
        """
        target: hostname/IP/URL/account-id (whatever uniquely addresses this instance)
        credentials: dict with the required auth fields
        verify_ssl: for REST/Redfish/SOAP — set False for self-signed test gear
        timeout: network call timeout
        """
        self.target = target
        self.credentials = credentials
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._connection: Any = None

    # ---- Required hook points each adapter implements ----

    @abstractmethod
    def test_connection(self) -> dict:
        """
        Return {'ok': bool, 'error': str|None, 'detail': str}.
        Should be cheap — just a single auth check.
        """
        ...

    def discover(self) -> list[dict]:
        """
        Return list of {'asset_id': str, 'identity_hint': dict}.
        Default: returns single self-asset for adapters that target one device.
        Override for adapters that enumerate multiple assets (vCenter, AWS, vault).
        """
        return [{"asset_id": self.target, "identity_hint": {}}]

    @abstractmethod
    def collect(self, asset_id: str) -> dict[str, Any]:
        """
        Pull raw vendor data for the asset. Returns vendor-specific dict.
        Adapter may make many API/SSH/SNMP calls — bundle into one dict.
        Will be passed to normalize() next.
        """
        ...

    @abstractmethod
    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        """
        Transform raw vendor data into a UnifiedAsset. This is where
        vendor-specific names get mapped to the universal schema.
        """
        ...

    # ---- Convenience: full pipeline ----

    def collect_all(self) -> Iterator[UnifiedAsset]:
        """Discover → collect → normalize → yield each UnifiedAsset."""
        assets = self.discover()
        for stub in assets:
            asset_id = stub["asset_id"]
            try:
                raw = self.collect(asset_id)
                asset = self.normalize(asset_id, raw)
                yield asset
            except Exception as e:
                # Yield a minimal asset with the error in security.findings
                # so the platform sees the failure rather than silently dropping
                from safecadence.platform.schema import (
                    UnifiedAsset, AssetIdentity, Security
                )
                fallback = UnifiedAsset(
                    identity=AssetIdentity(asset_id=asset_id, vendor=self.capabilities.vendor),
                    security=Security(findings=[f"Collection failed: {e}"]),
                )
                yield fallback


# ---- Registry --------------------------------------------------------

_REGISTRY: dict[str, type[BaseAdapter]] = {}


def register_adapter(name: str):
    """Decorator: @register_adapter('dell_idrac')"""
    def deco(cls: type[BaseAdapter]) -> type[BaseAdapter]:
        if not name:
            raise ValueError("adapter name required")
        if not issubclass(cls, BaseAdapter):
            raise TypeError(f"{cls} must subclass BaseAdapter")
        _REGISTRY[name] = cls
        if not cls.capabilities.name:
            cls.capabilities.name = name
        return cls
    return deco


def get_adapter(name: str) -> type[BaseAdapter]:
    if name not in _REGISTRY:
        raise KeyError(f"unknown adapter: {name}. Registered: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def list_adapters() -> list[dict]:
    """List all registered adapters with their capabilities."""
    out = []
    for name, cls in sorted(_REGISTRY.items()):
        c = cls.capabilities
        out.append({
            "name": name,
            "vendor": c.vendor,
            "description": c.description,
            "asset_types": c.asset_types,
            "connection_types": [ct.value for ct in c.connection_types],
            "required_credentials": c.required_credentials,
            "supports_discovery": c.supports_discovery,
            "documentation_url": c.documentation_url,
        })
    return out
