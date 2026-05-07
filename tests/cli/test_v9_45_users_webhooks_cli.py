"""v9.45 — CLI parity for users / webhooks / notify-prefs.

Verifies the new `safecadence users`, `safecadence webhooks`, and
`safecadence notify-prefs` command groups round-trip through the same
storage layer the HTTP endpoints use. Pure click-runner tests, no
network.
"""
from __future__ import annotations

from click.testing import CliRunner


# ---------------------------------------------------------------- users

def test_users_add_list_delete(monkeypatch, tmp_path):
    from safecadence.cli import cli
    users_file = tmp_path / "users.yaml"
    runner = CliRunner()

    r = runner.invoke(cli, ["users", "add", "alice",
                              "--email", "alice@x.com",
                              "--role", "admin",
                              "--display-name", "Alice C.",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "saved" in r.output

    r = runner.invoke(cli, ["users", "list",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "alice" in r.output
    assert "alice@x.com" in r.output

    r = runner.invoke(cli, ["users", "delete", "alice", "--yes",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "deleted" in r.output

    r = runner.invoke(cli, ["users", "list",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "alice" not in r.output


# ------------------------------------------------------------- webhooks

def test_webhooks_add_list_delete(monkeypatch, tmp_path):
    from safecadence.cli import cli
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    runner = CliRunner()

    r = runner.invoke(cli, ["webhooks", "add", "team-slack",
                              "--url", "https://hooks.slack.com/services/T/B/X",
                              "--provider", "slack",
                              "--category", "finding_critical",
                              "--min-severity", "high",
                              "--enabled"])
    assert r.exit_code == 0, r.output
    assert "saved" in r.output

    r = runner.invoke(cli, ["webhooks", "list"])
    assert r.exit_code == 0, r.output
    assert "team-slack" in r.output
    assert "slack" in r.output

    r = runner.invoke(cli, ["webhooks", "delete", "team-slack", "--yes"])
    assert r.exit_code == 0, r.output
    assert "deleted" in r.output


def test_webhooks_add_rejects_bad_url(monkeypatch, tmp_path):
    from safecadence.cli import cli
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    runner = CliRunner()
    r = runner.invoke(cli, ["webhooks", "add", "bad",
                              "--url", "ftp://example.com/x",
                              "--enabled"])
    assert r.exit_code != 0, r.output
    assert "http" in r.output.lower()


# --------------------------------------------------------- notify-prefs

def test_notify_prefs_set_and_get(monkeypatch, tmp_path):
    from safecadence.cli import cli
    users_file = tmp_path / "users.yaml"
    runner = CliRunner()

    runner.invoke(cli, ["users", "add", "bob",
                          "--email", "bob@x.com",
                          "--role", "approver",
                          "--users-file", str(users_file)])

    r = runner.invoke(cli, ["notify-prefs", "set", "bob",
                              "finding_critical",
                              "--channel", "email",
                              "--channel", "slack",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "set" in r.output

    r = runner.invoke(cli, ["notify-prefs", "get", "bob",
                              "--users-file", str(users_file)])
    assert r.exit_code == 0, r.output
    assert "finding_critical" in r.output
    assert "email" in r.output


def test_notify_prefs_unknown_user(tmp_path):
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["notify-prefs", "get", "nobody",
                              "--users-file", str(tmp_path / "u.yaml")])
    assert r.exit_code != 0
    assert "no such user" in r.output
