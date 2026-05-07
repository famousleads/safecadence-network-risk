"""SafeCadence core — common asset schema, adapter contract, registry, store."""

from safecadence.core.schema import (
    Asset,
    Interface,
    Neighbor,
    ParsedConfig,
    Finding,
    ScanResult,
    Severity,
)
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import AdapterRegistry, register_adapter, get_adapter

__all__ = [
    "Asset", "Interface", "Neighbor", "ParsedConfig", "Finding", "ScanResult", "Severity",
    "BaseAdapter", "AdapterRegistry", "register_adapter", "get_adapter",
]
