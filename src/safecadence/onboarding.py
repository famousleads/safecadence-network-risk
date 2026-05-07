"""Unified onboarding — get assets into the platform store.

Four ingestion paths, one validation pipeline, one commit step.

  1. CSV import   (parse_csv → validate → preview → commit)
  2. Discovery    (scan a CIDR → propose → adopt)
  3. Cloud connect (adapter.discover() → propose → adopt)
  4. Manual one-off (POST /api/platform/asset)

The CSV format is the most-used real path (most enterprises have a
CMDB extract). The columns mirror the v7.0 asset model so an operator
can produce the file from ServiceNow / Snipe-IT / Lansweeper without
column gymnastics:

    asset_id, hostname, asset_type, vendor, model, criticality,
    site, environment, owner, team, country, city, campus, building,
    floor, rack, support_contract, ip, public_ip, vlan, subnet,
    zone, cloud_account, cloud_region, tags

Required: ``asset_id``, ``asset_type``, ``vendor``.
Everything else is optional and rolls into the right block of the
UnifiedAsset shape.

This module is pure-Python, no I/O until commit. Cross-platform.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------
# Schema definition + template
# --------------------------------------------------------------------------

REQUIRED_COLS = ["asset_id", "asset_type", "vendor"]

OPTIONAL_COLS = [
    "hostname", "model", "criticality", "site", "environment",
    "owner", "team",
    "country", "city", "campus", "building", "floor", "rack",
    "support_contract",
    "ip", "public_ip", "vlan", "subnet", "zone",
    "cloud_account", "cloud_region",
    "os_type", "os_version",
    "tags",   # comma-separated
]

ALL_COLS = REQUIRED_COLS + OPTIONAL_COLS


_VALID_ASSET_TYPES = {
    "network", "server", "storage", "hypervisor",
    "cloud", "backup", "identity",
}


def template_csv() -> str:
    """Generate a downloadable CSV template with header + one example row."""
    example = {
        "asset_id":         "edge-rtr-01.acme.local",
        "hostname":         "edge-rtr-01.acme.local",
        "asset_type":       "network",
        "vendor":           "cisco",
        "model":            "ASR-1001-X",
        "criticality":      "high",
        "site":             "dc-east-1",
        "environment":      "prod",
        "owner":            "netops",
        "team":             "Network Operations",
        "country":          "US",
        "city":             "Ashburn",
        "campus":           "DC1",
        "building":         "B1",
        "floor":            "2",
        "rack":             "R12",
        "support_contract": "SmartNet-2026",
        "ip":               "10.0.0.1",
        "public_ip":        "203.0.113.42",
        "vlan":             "100",
        "subnet":           "10.0.0.0/24",
        "zone":             "edge",
        "cloud_account":    "",
        "cloud_region":     "",
        "os_type":          "ios-xe",
        "os_version":       "16.9.4",
        "tags":             "core,internet-facing",
    }
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ALL_COLS)
    w.writeheader()
    w.writerow(example)
    return buf.getvalue()


# --------------------------------------------------------------------------
# Parser + validator
# --------------------------------------------------------------------------

@dataclass
class RowResult:
    row_number: int
    raw: dict[str, str]
    asset: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PreviewResult:
    headers: list[str]
    rows: list[RowResult]
    valid_count: int = 0
    error_count: int = 0
    summary: str = ""


def _build_asset(row: dict[str, str]) -> tuple[dict, list[str], list[str]]:
    """Project a CSV row into a UnifiedAsset-shaped dict.
    Returns (asset, errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    aid = (row.get("asset_id") or "").strip()
    atype = (row.get("asset_type") or "").strip().lower()
    vendor = (row.get("vendor") or "").strip().lower()

    if not aid:
        errors.append("asset_id is required")
    elif "/" in aid or ".." in aid or "\x00" in aid:
        errors.append("asset_id contains illegal characters (/ .. NUL)")
    if not atype:
        errors.append("asset_type is required")
    elif atype not in _VALID_ASSET_TYPES:
        errors.append(f"asset_type must be one of {sorted(_VALID_ASSET_TYPES)}")
    if not vendor:
        errors.append("vendor is required")

    if errors:
        return {}, errors, warnings

    identity = {
        "asset_id":         aid,
        "asset_type":       atype,
        "vendor":           vendor,
        "hostname":         row.get("hostname") or aid,
        "model":            row.get("model") or "",
        "criticality":      (row.get("criticality") or "medium").lower(),
        "site":             row.get("site") or "",
        "environment":      (row.get("environment") or "prod").lower(),
        "owner":            row.get("owner") or "",
        "team":             row.get("team") or "",
        "country":          row.get("country") or "",
        "city":             row.get("city") or "",
        "campus":           row.get("campus") or "",
        "building":         row.get("building") or "",
        "floor":            row.get("floor") or "",
        "rack":             row.get("rack") or "",
        "support_contract": row.get("support_contract") or "",
    }

    asset: dict[str, Any] = {"identity": identity}

    # OS block
    if row.get("os_type") or row.get("os_version"):
        asset["os"] = {
            "os_type":    row.get("os_type") or "",
            "version":    row.get("os_version") or "",
        }

    # Network block
    network: dict[str, Any] = {}
    if row.get("ip"):         network["mgmt_ip"] = row["ip"]
    if row.get("public_ip"):  network["public_ip"] = row["public_ip"]
    if row.get("vlan"):       network["vlan"] = row["vlan"]
    if row.get("subnet"):     network["subnet"] = row["subnet"]
    if row.get("zone"):       network["zone"] = row["zone"].lower()
    if network:
        asset["network"] = network
        if network.get("public_ip") or network.get("zone") in ("dmz", "edge"):
            network["internet_facing"] = True

    # Cloud block
    if row.get("cloud_account") or row.get("cloud_region"):
        asset["cloud"] = {
            "account_id": row.get("cloud_account") or "",
            "region":     row.get("cloud_region") or "",
        }

    # Tags — comma- or pipe-separated
    raw_tags = (row.get("tags") or "").strip()
    if raw_tags:
        sep = "|" if "|" in raw_tags else ","
        asset["tags"] = [t.strip() for t in raw_tags.split(sep) if t.strip()]
    else:
        asset["tags"] = []

    # Sensible warnings
    if identity["criticality"] == "crown-jewel" and not identity["owner"]:
        warnings.append(
            "crown-jewel asset without an owner — drift alerts will go to the "
            "default queue, not a person"
        )
    if atype == "network" and not network:
        warnings.append("network asset has no IP / subnet / zone — limited "
                         "policy coverage until populated")
    return asset, errors, warnings


def parse_csv(text: str) -> PreviewResult:
    """Parse a CSV body and validate every row. Returns PreviewResult
    so the UI can surface errors row-by-row before commit."""
    rdr = csv.DictReader(io.StringIO(text))
    headers = list(rdr.fieldnames or [])
    missing = [c for c in REQUIRED_COLS if c not in headers]
    rows: list[RowResult] = []
    if missing:
        return PreviewResult(
            headers=headers, rows=[],
            error_count=1,
            summary=f"CSV is missing required columns: {missing}. "
                    f"Use /api/platform/import/csv-template to download "
                    f"the canonical schema."
        )
    valid = errs = 0
    for i, raw in enumerate(rdr, start=2):  # header is row 1
        asset, errors, warnings = _build_asset(raw)
        rr = RowResult(row_number=i, raw=raw,
                        asset=asset if not errors else None,
                        errors=errors, warnings=warnings)
        rows.append(rr)
        if errors:
            errs += 1
        else:
            valid += 1
    return PreviewResult(
        headers=headers, rows=rows, valid_count=valid, error_count=errs,
        summary=(f"Parsed {len(rows)} rows: {valid} valid, {errs} with errors. "
                  f"Run /csv-commit after fixing errors."),
    )


# --------------------------------------------------------------------------
# Commit
# --------------------------------------------------------------------------

def commit_preview(preview: PreviewResult, *, overwrite: bool = False
                    ) -> dict[str, Any]:
    """Write every valid row to the platform store. Idempotent: existing
    asset_ids are skipped unless overwrite=True. Returns the audit list."""
    from safecadence.server.platform_api import save_asset, get_asset
    written = 0
    skipped = 0
    overwritten = 0
    failed = 0
    failed_rows: list[dict] = []
    for r in preview.rows:
        if r.errors or not r.asset:
            failed += 1
            continue
        aid = r.asset["identity"]["asset_id"]
        existing = get_asset(aid)
        if existing and not overwrite:
            skipped += 1
            continue
        try:
            save_asset(r.asset)
            if existing:
                overwritten += 1
            else:
                written += 1
        except Exception as e:
            failed += 1
            failed_rows.append({"row": r.row_number, "asset_id": aid,
                                  "error": f"{type(e).__name__}: {e}"})
    return {
        "written":     written,
        "overwritten": overwritten,
        "skipped":     skipped,
        "failed":      failed,
        "failed_rows": failed_rows,
        "summary":     (f"Committed {written} new assets, "
                         f"overwrote {overwritten}, skipped {skipped} "
                         f"(use overwrite=true to replace), failed {failed}."),
    }


# --------------------------------------------------------------------------
# Bulk credentials CSV — separate concern, separate columns
# --------------------------------------------------------------------------

CREDENTIAL_COLS = ["asset_id", "username", "password", "key_filename",
                    "port", "timeout", "method"]
REQUIRED_CRED_COLS = ["asset_id", "username"]


def parse_credentials_csv(text: str) -> dict:
    """Parse the bulk-credentials CSV. Validates, doesn't commit."""
    rdr = csv.DictReader(io.StringIO(text))
    headers = list(rdr.fieldnames or [])
    missing = [c for c in REQUIRED_CRED_COLS if c not in headers]
    out: list[dict] = []
    valid = errs = 0
    if missing:
        return {"headers": headers, "rows": [], "valid_count": 0,
                "error_count": 1,
                "summary": f"missing required columns: {missing}"}
    for i, raw in enumerate(rdr, start=2):
        rec_errs: list[str] = []
        aid = (raw.get("asset_id") or "").strip()
        if not aid:
            rec_errs.append("asset_id required")
        if not raw.get("username"):
            rec_errs.append("username required")
        if not raw.get("password") and not raw.get("key_filename"):
            rec_errs.append("either password or key_filename required")
        rec = {
            "row_number": i, "asset_id": aid,
            "errors": rec_errs,
            "credential": {
                "username":     raw.get("username") or "",
                "password":     raw.get("password") or "",
                "key_filename": raw.get("key_filename") or "",
                "port":         int(raw.get("port") or 22),
                "timeout":      int(raw.get("timeout") or 15),
                "method":       (raw.get("method") or "ssh").lower(),
            } if not rec_errs else None,
        }
        out.append(rec)
        if rec_errs:
            errs += 1
        else:
            valid += 1
    return {"headers": headers, "rows": out,
            "valid_count": valid, "error_count": errs,
            "summary": f"{valid} valid, {errs} errors"}


def commit_credentials_preview(preview: dict, *,
                                  overwrite: bool = False) -> dict:
    try:
        from safecadence.vault import set_credential
    except Exception:
        return {"sent": False,
                "reason": ("vault module not available; "
                            "install [vault] extras to use bulk import")}
    written = skipped = failed = 0
    for r in preview.get("rows") or []:
        if r["errors"] or not r["credential"]:
            failed += 1
            continue
        try:
            set_credential(r["asset_id"], r["credential"],
                            overwrite=overwrite)
            written += 1
        except FileExistsError:
            skipped += 1
        except Exception:
            failed += 1
    return {"written": written, "skipped": skipped, "failed": failed,
            "summary": (f"Vaulted {written} credentials, "
                         f"skipped {skipped} existing, failed {failed}.")}
