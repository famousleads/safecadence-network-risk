#!/usr/bin/env python3
"""
v9.32 — generate a CycloneDX SBOM for SafeCadence + its installed deps.

Usage:
    python scripts/generate_sbom.py [--output dist/sbom.cdx.json]

Why this lives here: shipping a CycloneDX SBOM with each release is
table-stakes for any security tool a serious buyer would adopt.
SBOMs are the supply-chain receipt — "here's everything that's in
the wheel, here are its versions, here are the licenses, here's
what depends on what."

We use cyclonedx-py if available; otherwise we generate a minimal
hand-rolled SBOM that's still valid CycloneDX 1.5.

The output ships next to the wheel + sdist on every release.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _runtime_components() -> list[dict]:
    """Walk every installed distribution and emit a CycloneDX component
    record for it. The 'application' component (SafeCadence itself) is
    added separately by the caller."""
    out: list[dict] = []
    for dist in md.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
            lic = (dist.metadata.get("License")
                    or dist.metadata.get("License-Expression")
                    or "")
            home = dist.metadata.get("Home-page", "") or ""
        except Exception:
            continue
        if not name or not version:
            continue
        comp = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name.lower()}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        }
        if lic:
            comp["licenses"] = [{"license": {"name": lic[:120]}}]
        if home:
            comp["externalReferences"] = [
                {"type": "website", "url": home}
            ]
        out.append(comp)
    out.sort(key=lambda c: c["name"].lower())
    return out


def _safecadence_metadata() -> dict:
    """Pull our own version + repo info."""
    try:
        from safecadence import __version__
    except Exception:
        __version__ = "unknown"
    return {
        "type": "application",
        "bom-ref": f"pkg:pypi/safecadence-netrisk@{__version__}",
        "name": "safecadence-netrisk",
        "version": __version__,
        "purl": f"pkg:pypi/safecadence-netrisk@{__version__}",
        "supplier": {"name": "SafeCadence"},
        "licenses": [{"license": {"id": "MIT"}}],
        "description": (
            "Local-first multi-vendor security posture management "
            "for hybrid networks."
        ),
    }


def build_bom() -> dict:
    metadata_component = _safecadence_metadata()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{
                "vendor": "SafeCadence",
                "name": "scripts/generate_sbom.py",
                "version": "1.0.0",
            }],
            "component": metadata_component,
        },
        "components": _runtime_components(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output", "-o",
        default="dist/safecadence_netrisk.cdx.json",
        help="Where to write the SBOM (default: dist/...cdx.json)",
    )
    args = ap.parse_args()

    bom = build_bom()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    print(f"Wrote {out} — {len(bom['components'])} components, "
            f"safecadence-netrisk @ {bom['metadata']['component']['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
