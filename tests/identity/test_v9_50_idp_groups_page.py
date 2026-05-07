"""v9.50 — /idp-groups page + /api/idp-groups endpoint + CLI."""
from __future__ import annotations

from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return app


def test_idp_groups_page_renders(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/idp-groups")
    assert r.status_code == 200
    assert "IdP groups" in r.text
    assert "igLoad" in r.text


def test_api_idp_groups_empty(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/idp-groups")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["groups"] == []


def test_api_idp_groups_returns_seeded(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    from safecadence.identity.groups import upsert_group, GroupRecord
    upsert_group(GroupRecord(system="okta", id="g1",
                                name="eng-leads",
                                members=["alice", "bob"]))
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/idp-groups")
    body = r.json()
    assert body["count"] == 1
    assert body["groups"][0]["name"] == "eng-leads"
    assert body["groups"][0]["members"] == ["alice", "bob"]
    assert body["groups"][0]["stale"] is False


def test_cli_groups_list(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity.groups import upsert_group, GroupRecord
    upsert_group(GroupRecord(system="ad", id="cn-secops",
                                name="secops", members=["carol"]))
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["groups", "list"])
    assert r.exit_code == 0
    assert "secops" in r.output
    assert "carol" not in r.output  # list view shows count, not members


def test_cli_groups_show(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity.groups import upsert_group, GroupRecord
    upsert_group(GroupRecord(system="okta", id="g1",
                                name="eng-leads",
                                members=["alice"]))
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["groups", "show", "eng-leads"])
    assert r.exit_code == 0
    assert "alice" in r.output
    assert "okta" in r.output


def test_cli_groups_show_unknown_aborts(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["groups", "show", "nope"])
    assert r.exit_code != 0
    assert "no such group" in r.output
