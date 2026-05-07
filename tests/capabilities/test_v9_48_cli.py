"""v9.48 — CLI parity for capability grants."""
from __future__ import annotations

from click.testing import CliRunner


def test_cli_caps_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.cli import cli
    runner = CliRunner()

    r = runner.invoke(cli, ["capabilities", "grant", "alice",
                              "execute.real",
                              "--actor", "test",
                              "--reason", "trial"])
    assert r.exit_code == 0, r.output
    assert "granted execute.real" in r.output

    r = runner.invoke(cli, ["capabilities", "list"])
    assert r.exit_code == 0
    assert "alice" in r.output
    assert "execute.real" in r.output

    r = runner.invoke(cli, ["capabilities", "show", "alice"])
    assert r.exit_code == 0
    assert "execute.real" in r.output

    r = runner.invoke(cli, ["capabilities", "revoke", "alice",
                              "execute.real",
                              "--actor", "test"])
    assert r.exit_code == 0
    assert "revoked" in r.output

    r = runner.invoke(cli, ["capabilities", "clear-deny", "alice",
                              "execute.real",
                              "--actor", "test"])
    assert r.exit_code == 0
    assert "cleared deny" in r.output


def test_cli_caps_unknown_capability_aborts(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["capabilities", "grant", "alice",
                              "totally.made.up",
                              "--actor", "test"])
    assert r.exit_code != 0
    assert "unknown capability" in r.output.lower()
