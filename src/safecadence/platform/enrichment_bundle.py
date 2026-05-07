"""
v6.1 — Air-gapped enrichment bundle.

Two commands:
  - safecadence enrichment package <out.tar.gz>
        Builds a sneakernet bundle containing the latest CVE / KEV / EOL /
        EPSS data so an air-gapped SafeCadence install can stay current.

  - safecadence enrichment import <bundle.tar.gz>
        Loads a previously-built bundle into the local cache so subsequent
        scans use the fresh data.

Cross-platform: pure Python tarfile + json. Works on Windows / macOS /
Linux. No shell pipelines, no subprocess.

Bundle layout:
    enrichment-2026-05-04.tar.gz
    ├── bundle.json          metadata + version + checksum manifest
    ├── cves/                  one file per vendor
    │   ├── cisco_ios.yaml
    │   ├── arista_eos.yaml
    │   └── ...
    ├── eol/                   end-of-life data per vendor
    │   ├── cisco_ios.yaml
    │   └── ...
    ├── epss_scores.json       latest EPSS scores
    └── kev/
        └── known_exploited.json   CISA KEV catalog snapshot
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_BUNDLE_VERSION = 1


def _data_dir() -> Path:
    """Bundled enrichment data inside the wheel."""
    return Path(__file__).resolve().parent.parent / "data"


def _user_cache_dir() -> Path:
    """Per-user enrichment cache (writable)."""
    p = Path.home() / ".safecadence"
    p.mkdir(parents=True, exist_ok=True)
    return p


# --------------------------------------------------------------------------
# Package
# --------------------------------------------------------------------------

def package(out_path: str | Path, *, include_epss: bool = True) -> dict[str, Any]:
    """Bundle the current CVE / EOL / EPSS / KEV data into a single tarball.

    Returns {ok, path, files_packed, sha256, bytes}.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data_dir = _data_dir()
    user_dir = _user_cache_dir()
    files_packed: list[dict] = []

    # Build manifest as we go
    manifest = {
        "schema_version": _BUNDLE_VERSION,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "files": [],
    }

    sha = hashlib.sha256()

    with tarfile.open(out_path, "w:gz") as tar:
        # 1. CVE per-vendor YAML
        cve_dir = data_dir / "cves"
        if cve_dir.exists():
            for f in sorted(cve_dir.glob("*.yaml")):
                content = f.read_bytes()
                tar_info = tarfile.TarInfo(f"cves/{f.name}")
                tar_info.size = len(content); tar_info.mode = 0o644
                tar.addfile(tar_info, io.BytesIO(content))
                files_packed.append({"path": f"cves/{f.name}", "bytes": len(content)})
                sha.update(content)
        # 2. EOL per-vendor YAML
        eol_dir = data_dir / "eol"
        if eol_dir.exists():
            for f in sorted(eol_dir.glob("*.yaml")):
                content = f.read_bytes()
                tar_info = tarfile.TarInfo(f"eol/{f.name}")
                tar_info.size = len(content); tar_info.mode = 0o644
                tar.addfile(tar_info, io.BytesIO(content))
                files_packed.append({"path": f"eol/{f.name}", "bytes": len(content)})
                sha.update(content)
        # 3. EPSS scores (from user cache if present, else bundled)
        if include_epss:
            epss_user = user_dir / "epss_scores.json"
            epss_bundled = data_dir / "epss_scores.json"
            for src, label in [(epss_user, "epss_scores.json"),
                                (epss_bundled, "epss_scores.json")]:
                if src.exists():
                    content = src.read_bytes()
                    tar_info = tarfile.TarInfo(label)
                    tar_info.size = len(content); tar_info.mode = 0o644
                    tar.addfile(tar_info, io.BytesIO(content))
                    files_packed.append({"path": label, "bytes": len(content)})
                    sha.update(content)
                    break
        # 4. KEV catalog (from user cache if present)
        kev_user = user_dir / "known_exploited.json"
        if kev_user.exists():
            content = kev_user.read_bytes()
            tar_info = tarfile.TarInfo("kev/known_exploited.json")
            tar_info.size = len(content); tar_info.mode = 0o644
            tar.addfile(tar_info, io.BytesIO(content))
            files_packed.append({"path": "kev/known_exploited.json",
                                  "bytes": len(content)})
            sha.update(content)

        # 5. Manifest LAST (with the running checksum)
        manifest["files"] = files_packed
        manifest["sha256"] = sha.hexdigest()
        m_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        m_info = tarfile.TarInfo("bundle.json")
        m_info.size = len(m_bytes); m_info.mode = 0o644
        tar.addfile(m_info, io.BytesIO(m_bytes))

    size = out_path.stat().st_size
    return {"ok": True, "path": str(out_path), "files_packed": len(files_packed),
            "sha256": manifest["sha256"], "bytes": size}


# --------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------

def import_bundle(bundle_path: str | Path) -> dict[str, Any]:
    """Load a bundle into the local cache. Returns {ok, files_imported, manifest}."""
    bundle_path = Path(bundle_path)
    if not bundle_path.exists():
        return {"ok": False, "error": f"bundle not found: {bundle_path}"}

    user_dir = _user_cache_dir()
    cves_dir = user_dir / "cves"; cves_dir.mkdir(parents=True, exist_ok=True)
    eol_dir = user_dir / "eol";    eol_dir.mkdir(parents=True, exist_ok=True)

    files_imported: list[str] = []
    manifest: dict | None = None

    with tarfile.open(bundle_path, "r:gz") as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            f = tar.extractfile(m)
            if not f: continue
            data = f.read()
            if m.name == "bundle.json":
                try: manifest = json.loads(data.decode("utf-8"))
                except Exception: manifest = None
                continue
            # Map known prefixes into the user cache
            if m.name.startswith("cves/"):
                target = cves_dir / Path(m.name).name
            elif m.name.startswith("eol/"):
                target = eol_dir / Path(m.name).name
            elif m.name == "epss_scores.json":
                target = user_dir / "epss_scores.json"
            elif m.name.startswith("kev/"):
                target = user_dir / Path(m.name).name
            else:
                continue
            target.write_bytes(data)
            files_imported.append(str(target))

    return {"ok": True,
            "files_imported": len(files_imported),
            "manifest": manifest,
            "cache_dir": str(user_dir)}
