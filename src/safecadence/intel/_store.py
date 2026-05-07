"""
v7.9 — Tiny JSON store shared by intel modules.

Each module's data lives in a single JSON file under
$SC_INTEL_HOME / <module>.json (default: ~/.safecadence/intel/).
Atomic writes via tmp + os.replace so concurrent daemon + UI reads
never see a half-written file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def store_path(module: str) -> Path:
    base = os.environ.get("SC_INTEL_HOME",
                            str(Path.home() / ".safecadence" / "intel"))
    p = Path(base) / f"{module}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def read(module: str, default: Any = None) -> Any:
    p = store_path(module)
    if not p.exists():
        return default if default is not None else {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default if default is not None else {}


def write(module: str, data: Any) -> None:
    p = store_path(module)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, default=str),
                    encoding="utf-8")
    os.replace(tmp, p)
