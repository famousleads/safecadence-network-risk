"""
v9.19 — Discovery scheduling.

Persisted "discovery job" records: each says "run source X with these
params every Y hours". The daemon will eventually fire them; for now
the UI exposes a "Run now" button that hits the underlying source
endpoint.

Schema:
  job_id, name, source ('lan-scan'|'snmp'|'ad'|'entra'|'dhcp'|'aws'|...),
  params (dict — varies by source), interval_hours (int),
  last_run_at (iso, optional), next_run_at (iso, optional),
  enabled (bool), created_at, last_status ('ok'|'error'|'pending'|''),
  last_error (str), tenant.

File-backed under SC_DATA_DIR/discovery_jobs/<job_id>.json.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


SUPPORTED_SOURCES = ("lan-scan", "snmp", "ad", "entra",
                     "dhcp", "aws", "azure", "gcp")


# v9.36 — Required keys per source. Fail fast at create time instead of
# letting the operator save a job that will only error on the first fire.
REQUIRED_PARAMS: dict[str, tuple[str, ...]] = {
    "lan-scan": ("cidr",),
    "snmp": ("host",),
    "ad": ("server", "base_dn"),
    "entra": ("tenant_id", "client_id", "client_secret"),
    "dhcp": (),                             # default lease_file works
    "aws": (),                              # default profile/region work
    "azure": ("subscription",),
    "gcp": ("project",),
}


# v9.36 — Human-readable hint per source. Surfaced by the
# /api/platform/discovery-jobs/sources endpoint so the UI can render
# "what each source needs" inline next to the dropdown.
SOURCE_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "lan-scan": {"label": "LAN scan",
                  "needs": "cidr (e.g. 10.0.0.0/24)"},
    "snmp":     {"label": "SNMP harvest",
                  "needs": "host (router IP); optional community, version"},
    "ad":       {"label": "Active Directory",
                  "needs": "server, base_dn; optional bind_dn, password"},
    "entra":    {"label": "Microsoft Entra ID",
                  "needs": "tenant_id, client_id, client_secret"},
    "dhcp":     {"label": "DHCP lease file",
                  "needs": "optional lease_file (defaults to /var/lib/dhcp/dhcpd.leases)"},
    "aws":      {"label": "AWS",
                  "needs": "optional profile, region"},
    "azure":    {"label": "Azure",
                  "needs": "subscription"},
    "gcp":      {"label": "Google Cloud",
                  "needs": "project"},
}


def validate_params(source: str, params: dict | None) -> tuple[bool, str]:
    """Check that every key required for `source` is present and non-empty.

    Returns (ok, error). Used by create_job (raises ValueError on bad)
    and surfaced to operators so they don't save a job that will only
    fail at fire time.
    """
    if source not in SUPPORTED_SOURCES:
        return False, f"source must be one of {SUPPORTED_SOURCES}"
    needed = REQUIRED_PARAMS.get(source, ())
    p = params or {}
    missing = [k for k in needed if not str(p.get(k) or "").strip()]
    if missing:
        return False, (f"{source} requires: {', '.join(missing)}")
    return True, ""


@dataclass
class DiscoveryJob:
    job_id: str
    name: str
    source: str
    params: dict = field(default_factory=dict)
    interval_hours: int = 24
    enabled: bool = True
    last_run_at: str = ""
    next_run_at: str = ""
    last_status: str = ""    # "" | "pending" | "ok" | "error"
    last_error: str = ""
    created_at: str = ""
    tenant: str = "local"


# ----------------------------------------------------------------- store


def _store_dir() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "discovery_jobs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _path_for(job_id: str) -> Path:
    if not re.match(r"^[a-zA-Z0-9._\-]+$", job_id or ""):
        raise ValueError(f"invalid job_id: {job_id}")
    return _store_dir() / f"{job_id}.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_jobs() -> list[DiscoveryJob]:
    out = []
    for f in _store_dir().glob("*.json"):
        try:
            d = json.loads(f.read_text())
            out.append(DiscoveryJob(**d))
        except Exception:
            continue
    out.sort(key=lambda j: j.created_at)
    return out


def get_job(job_id: str) -> DiscoveryJob | None:
    try:
        f = _path_for(job_id)
    except ValueError:
        return None
    if not f.exists():
        return None
    try:
        return DiscoveryJob(**json.loads(f.read_text()))
    except Exception:
        return None


def save_job(job: DiscoveryJob) -> DiscoveryJob:
    if not job.created_at:
        job.created_at = _now_iso()
    if job.enabled and not job.next_run_at:
        job.next_run_at = (datetime.now(timezone.utc) +
                           timedelta(hours=max(1, job.interval_hours))).isoformat()
    f = _path_for(job.job_id)
    f.write_text(json.dumps(asdict(job), indent=2))
    return job


def delete_job(job_id: str) -> bool:
    try:
        f = _path_for(job_id)
    except ValueError:
        return False
    if not f.exists():
        return False
    f.unlink()
    return True


def create_job(*, name: str, source: str, params: dict | None = None,
               interval_hours: int = 24, tenant: str = "local") -> DiscoveryJob:
    if source not in SUPPORTED_SOURCES:
        raise ValueError(
            f"source must be one of {SUPPORTED_SOURCES}, got {source!r}")
    if interval_hours < 1:
        raise ValueError("interval_hours must be ≥ 1")
    # v9.36 — fail fast on missing required params instead of waiting for
    # the first fire to surface "lan-scan requires params.cidr".
    ok, err = validate_params(source, params)
    if not ok:
        raise ValueError(err)
    j = DiscoveryJob(
        job_id=str(uuid.uuid4())[:12],
        name=name.strip() or f"{source}-job",
        source=source,
        params=params or {},
        interval_hours=interval_hours,
        tenant=tenant,
    )
    return save_job(j)


def mark_run(job_id: str, *, ok: bool, error: str = "") -> DiscoveryJob | None:
    j = get_job(job_id)
    if not j:
        return None
    j.last_run_at = _now_iso()
    j.next_run_at = (datetime.now(timezone.utc) +
                     timedelta(hours=max(1, j.interval_hours))).isoformat()
    j.last_status = "ok" if ok else "error"
    j.last_error = error if not ok else ""
    save_job(j)
    return j


# --------------------------------------------------------------- runner
#
# v9.36 — Single source-of-truth dispatcher used by BOTH the daemon's
# scheduled cycle (`daemon._run_due_discovery_jobs`) and the HTTP
# `/api/platform/discovery-jobs/{id}/run-now` endpoint. Before v9.36 the
# HTTP path stamped `mark_run(ok=True)` without firing anything, which
# made Run Now a fake-success — exactly the kind of "looks real but
# isn't" gap the v9.33/v9.35 audits caught. This function is now the
# only place that knows how to dispatch a job.
#
# Each branch returns (ok, error_message). Imports happen lazily so the
# module loads cleanly without optional discovery dependencies installed.


def fire_job(job: DiscoveryJob) -> tuple[bool, str]:
    """Dispatch a discovery job to its source-specific runner.

    Returns (ok, error_message). On error, the caller is responsible
    for calling mark_run(job_id, ok=False, error=...).
    """
    src = (job.source or "").lower()
    p = job.params or {}

    # Re-validate at fire time. A job might have been saved before
    # v9.36's create-time check landed; we don't want to attempt a fire
    # with missing params.
    ok, err = validate_params(src, p)
    if not ok:
        return False, err

    try:
        if src == "lan-scan":
            from safecadence.discovery.lan_scan import deep_scan
            from safecadence.platform.bridge import adopt_discovered
            mode = p.get("mode", "lan_deep")
            result = deep_scan(p["cidr"], mode=mode, workers=64, timeout=1.0)
            adopt_discovered({"hosts": [
                {"ip": h.ip, "hostname": h.hostname or h.ip,
                 "mac": h.mac or "", "vendor_guess": h.vendor_guess or "",
                 "os_guess": h.os_guess or "",
                 "device_type_guess": h.device_type_guess or "unknown"}
                for h in (result.hosts or [])
            ]})
            return True, ""

        if src == "snmp":
            from safecadence.discovery.snmp_harvest import harvest_from_router
            r = harvest_from_router(p["host"],
                                     p.get("community", "public"),
                                     version=p.get("version", "2c"))
            return (not r.error), r.error or ""

        if src == "ad":
            from safecadence.discovery.ad_harvest import harvest_ad
            r = harvest_ad(server=p["server"],
                           bind_dn=p.get("bind_dn", ""),
                           password=p.get("password", ""),
                           base_dn=p["base_dn"])
            return (not r.error), r.error or ""

        if src == "entra":
            from safecadence.discovery.entra_harvest import harvest_entra
            r = harvest_entra(p["tenant_id"], p["client_id"],
                              p["client_secret"])
            return (not r.error), r.error or ""

        if src == "dhcp":
            from safecadence.discovery.dhcp_harvest import harvest_isc
            r = harvest_isc(lease_file=p.get(
                "lease_file", "/var/lib/dhcp/dhcpd.leases"))
            return (not r.error), r.error or ""

        if src in ("aws", "azure", "gcp"):
            from safecadence.discovery.cloud_harvest import (
                harvest_aws, harvest_azure, harvest_gcp,
            )
            fn = {"aws": harvest_aws, "azure": harvest_azure,
                  "gcp": harvest_gcp}[src]
            r = fn(**{k: v for k, v in p.items()
                      if k in ("profile", "region", "subscription", "project")})
            return (not r.error), r.error or ""

        return False, f"unknown source: {src}"
    except Exception as e:                      # pragma: no cover
        return False, f"{type(e).__name__}: {e}"
