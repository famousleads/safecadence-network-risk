"""
Bulk-scan helpers — designed for hundreds of devices.

Walks a directory of config files, runs the audit in a thread pool, and
writes per-device JSON + Markdown to an output dir. Optionally records to
the local SQLite history.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from safecadence.core.registry import AdapterRegistry
from safecadence.core.schema import Asset, ScanResult
from safecadence.core.store import HistoryStore
from safecadence.engines.config_audit import ConfigAuditEngine
from safecadence.engines.health import compute_health, health_band
from safecadence.engines.risk import compute_risk, risk_band, summarize
from safecadence.enrichment import eol_status, find_cves
from safecadence.reports.json import to_json
from safecadence.reports.markdown import to_markdown


@dataclass
class BulkResult:
    source: str
    hostname: str
    vendor: str
    health: int
    risk: int
    findings: int
    cves: int
    eol_status: str
    duration_ms: int
    error: str = ""


def _scan_one(path: Path, *, vendor_override: str | None = None,
              criticality: str = "medium") -> tuple[ScanResult | None, BulkResult]:
    started = time.perf_counter()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        if vendor_override:
            adapter = AdapterRegistry.get(vendor_override)
        else:
            adapter = AdapterRegistry.detect(text, filename=str(path))
        if adapter is None:
            return None, BulkResult(
                source=str(path), hostname="", vendor="?", health=0, risk=0,
                findings=0, cves=0, eol_status="", duration_ms=0,
                error="vendor not detected; pass --vendor",
            )
        parsed = adapter.parse_config(text)
        findings = ConfigAuditEngine(vendor=adapter.slug).run(parsed)
        health = compute_health(parsed, findings)
        risk = compute_risk(findings, business_criticality=criticality)
        cves_matched = find_cves(vendor=adapter.slug, os=parsed.os, version=parsed.version)
        eol_rec = eol_status(vendor=adapter.slug, os=parsed.os, version=parsed.version)
        eol_dict = None
        if eol_rec is not None:
            eol_dict = eol_rec.to_dict()
            eol_dict["status_today"] = eol_rec.status_today()

        asset = Asset(
            asset_id=parsed.hostname or path.stem,
            hostname=parsed.hostname, vendor=adapter.slug,
            model=parsed.model, os=parsed.os, version=parsed.version,
            device_type=parsed.device_type,
            business_criticality=criticality,
            interfaces=parsed.interfaces, neighbors=parsed.neighbors,
            health_score=health, risk_score=risk,
            health_band=health_band(health), risk_band=risk_band(risk),
            findings=findings,
        )
        result = ScanResult(
            source=str(path), vendor=adapter.slug,
            duration_ms=int((time.perf_counter() - started) * 1000),
            parsed=parsed, asset=asset, findings=findings,
            health_score=health, risk_score=risk,
            health_band=health_band(health), risk_band=risk_band(risk),
            summary=summarize(findings),
            cves=[c.to_dict() for c in cves_matched], eol=eol_dict,
        )
        return result, BulkResult(
            source=str(path), hostname=parsed.hostname or path.stem,
            vendor=adapter.slug, health=health, risk=risk,
            findings=len(findings), cves=len(cves_matched),
            eol_status=eol_dict["status_today"] if eol_dict else "unknown",
            duration_ms=result.duration_ms,
        )
    except Exception as exc:
        return None, BulkResult(
            source=str(path), hostname="", vendor="?", health=0, risk=0,
            findings=0, cves=0, eol_status="", duration_ms=0,
            error=str(exc)[:160],
        )


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        if f.suffix.lower() in (".txt", ".cfg", ".conf", ".config"):
            out.append(f)
        elif "running-config" in f.name.lower() or "show-run" in f.name.lower():
            out.append(f)
    return out


def bulk_scan(
    root: Path | str,
    *,
    workers: int = 8,
    out_dir: Path | str | None = None,
    vendor: str | None = None,
    criticality: str = "medium",
    save_history: bool = False,
    progress_cb=None,
) -> list[BulkResult]:
    """
    Run audits across every config under `root` in a thread pool.
    Writes per-device JSON + Markdown to `out_dir` (created if missing).
    """
    files = _candidate_files(Path(root))
    out_path = Path(out_dir) if out_dir else None
    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)

    store = HistoryStore() if save_history else None

    summaries: list[BulkResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_one, f, vendor_override=vendor, criticality=criticality): f
            for f in files
        }
        for i, fut in enumerate(concurrent.futures.as_completed(futures)):
            result, summary = fut.result()
            summaries.append(summary)
            if result is not None and out_path is not None:
                stem = (result.parsed.hostname or Path(summary.source).stem).replace("/", "_")
                (out_path / f"{stem}.json").write_text(to_json(result), encoding="utf-8")
                (out_path / f"{stem}.md").write_text(to_markdown(result), encoding="utf-8")
            if result is not None and store is not None:
                store.save(result)
            if progress_cb is not None:
                progress_cb(i + 1, len(files), summary)

    if store is not None:
        store.close()
    summaries.sort(key=lambda r: -r.risk)
    return summaries
