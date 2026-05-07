"""v7.3 — Onboarding (CSV / scan / credentials), storage adapter
routing, Phase 2 Next.js scaffold."""

from __future__ import annotations

import json
from pathlib import Path


# --------------------------------------------------------------------------
# CSV importer — template, parser, validator, commit
# --------------------------------------------------------------------------

def test_csv_template_has_required_columns():
    from safecadence.onboarding import template_csv, REQUIRED_COLS, ALL_COLS
    text = template_csv()
    header = text.splitlines()[0].split(",")
    for c in REQUIRED_COLS:
        assert c in header, f"template missing required column: {c}"
    # Every advertised column should appear so operators can fill it in.
    for c in ALL_COLS:
        assert c in header


def test_csv_parser_rejects_missing_required_columns():
    from safecadence.onboarding import parse_csv
    p = parse_csv("hostname,asset_type\nfoo,network\n")
    assert p.error_count >= 1
    assert "missing required" in p.summary.lower()


def test_csv_parser_validates_per_row():
    from safecadence.onboarding import parse_csv
    body = (
        "asset_id,asset_type,vendor,criticality\n"
        "rtr-1,network,cisco,high\n"
        ",server,linux,medium\n"                    # missing asset_id
        "../etc/passwd,server,linux,medium\n"       # bad asset_id
        "good-1,not-a-real-type,linux,medium\n"     # bad asset_type
    )
    p = parse_csv(body)
    assert p.valid_count == 1
    assert p.error_count == 3
    assert p.rows[0].errors == []
    assert any("required" in e for e in p.rows[1].errors)
    assert any("illegal" in e for e in p.rows[2].errors)
    assert any("asset_type" in e for e in p.rows[3].errors)


def test_csv_parser_builds_full_asset_shape():
    from safecadence.onboarding import parse_csv
    body = (
        "asset_id,asset_type,vendor,owner,team,country,city,campus,"
        "building,floor,rack,support_contract,ip,public_ip,vlan,subnet,"
        "zone,os_type,os_version,tags\n"
        "edge-1,network,cisco,netops,Network,US,Ashburn,DC1,B1,2,R12,"
        "SmartNet,10.0.0.1,203.0.113.1,100,10.0.0.0/24,edge,ios-xe,"
        "16.9.4,core|internet-facing\n"
    )
    p = parse_csv(body)
    assert p.valid_count == 1
    a = p.rows[0].asset
    assert a is not None
    ident = a["identity"]
    for k in ("owner", "team", "country", "city", "campus",
              "building", "floor", "rack", "support_contract"):
        assert ident[k]
    assert a["network"]["mgmt_ip"] == "10.0.0.1"
    assert a["network"]["public_ip"] == "203.0.113.1"
    assert a["network"]["zone"] == "edge"
    assert a["network"]["internet_facing"] is True
    assert a["os"]["os_type"] == "ios-xe"
    assert a["tags"] == ["core", "internet-facing"]


def test_csv_commit_writes_to_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from safecadence.onboarding import parse_csv, commit_preview
    body = ("asset_id,asset_type,vendor\n"
            "csv-rtr-1,network,cisco\n"
            "csv-rtr-2,network,arista\n")
    preview = parse_csv(body)
    assert preview.valid_count == 2
    out = commit_preview(preview)
    assert out["written"] == 2
    # Re-commit without overwrite → both skipped
    out2 = commit_preview(preview)
    assert out2["written"] == 0
    assert out2["skipped"] == 2


# --------------------------------------------------------------------------
# Bulk credentials CSV
# --------------------------------------------------------------------------

def test_credentials_csv_parser():
    from safecadence.onboarding import parse_credentials_csv
    body = ("asset_id,username,password,port\n"
            "rtr-1,admin,secret,22\n"
            ",admin,secret,22\n"             # missing asset_id
            "rtr-2,admin,,22\n")             # missing password AND key
    p = parse_credentials_csv(body)
    assert p["valid_count"] == 1
    assert p["error_count"] == 2


# --------------------------------------------------------------------------
# Storage adapter routing
# --------------------------------------------------------------------------

def test_platform_api_uses_files_when_database_url_unset(tmp_path, monkeypatch):
    """Default path: file-backed JSON store."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from safecadence.server.platform_api import save_asset, get_asset
    asset = {"identity": {"asset_id": "test-routing-1",
                            "asset_type": "network",
                            "vendor": "cisco"}}
    save_asset(asset)
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    assert get_asset("test-routing-1") is not None


# --------------------------------------------------------------------------
# Onboarding endpoints registered
# --------------------------------------------------------------------------

def test_onboarding_endpoints_registered():
    src = (Path(__file__).resolve().parents[2]
           / "src" / "safecadence" / "server" / "platform_api.py").read_text()
    for path in ("/api/platform/import/csv-template",
                  "/api/platform/import/csv-preview",
                  "/api/platform/import/csv-commit",
                  "/api/platform/import/credentials-preview",
                  "/api/platform/import/credentials-commit"):
        assert path in src, f"endpoint not registered: {path}"


# --------------------------------------------------------------------------
# Phase 2 Next.js scaffold
# --------------------------------------------------------------------------

def test_phase2_views_exist():
    repo = Path(__file__).resolve().parents[2]
    web = repo / "webui"
    for must in ("app/drift/page.tsx",
                  "app/approvals/page.tsx",
                  "app/topology/page.tsx"):
        assert (web / must).exists(), f"missing webui/{must}"


def test_topology_view_loads_cytoscape_from_cdn():
    repo = Path(__file__).resolve().parents[2]
    src = (repo / "webui" / "app" / "topology" / "page.tsx").read_text()
    assert "cytoscape" in src.lower()
    assert "cdn.jsdelivr.net" in src


# --------------------------------------------------------------------------
# CLI onboard subcommand registered
# --------------------------------------------------------------------------

def test_cli_onboard_registered():
    from safecadence.cli import cli
    assert "onboard" in cli.commands
    sub = list(cli.commands["onboard"].commands.keys())
    for must in ("csv-template", "csv-import", "scan", "credentials"):
        assert must in sub, f"missing safecadence onboard {must}"
