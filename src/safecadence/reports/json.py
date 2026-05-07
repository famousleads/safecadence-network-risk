"""JSON report renderer."""

from __future__ import annotations

import json

from safecadence.core.schema import ScanResult


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    """Render a ScanResult as deterministic JSON."""
    return json.dumps(result.to_dict(), indent=indent, sort_keys=True, default=str)
