"""End-to-end CLI smoke tests for `safecadence policy ...` subcommands.

Uses click's CliRunner — invokes commands as if from a real shell, asserts on
stdout, exit code, and side-effects in the (test-isolated) policy store.
"""

from __future__ import annotations

import json
import re
import sys

import pytest
from click.testing import CliRunner


@pytest.fixture
def cli():
    """Lazy-import the CLI group so isolated_home is honored."""
    from safecadence.cli_policy import policy_cli
    return policy_cli


def test_templates_lists_all_10(cli):
    res = CliRunner().invoke(cli, ["templates"])
    assert res.exit_code == 0, res.output
    # 10 expected template ids
    for tid in ("tmpl_network_hardening", "tmpl_firewall_baseline",
                 "tmpl_router_switch_baseline", "tmpl_server_hardening",
                 "tmpl_cloud_security", "tmpl_logging_monitoring",
                 "tmpl_identity_access_control", "tmpl_encryption",
                 "tmpl_backup_security", "tmpl_zero_trust"):
        assert tid in res.output, f"missing template {tid} in output"


def test_controls_lists_22_known_controls(cli):
    res = CliRunner().invoke(cli, ["controls"])
    assert res.exit_code == 0, res.output
    must_have = ["disable_telnet", "enforce_ssh_v2", "require_aaa",
                 "enforce_snmpv3", "enable_syslog", "enable_ntp",
                 "block_insecure_crypto", "restrict_management_access",
                 "enforce_patch_level", "enforce_encryption_at_rest",
                 "enforce_encryption_in_transit", "restrict_default_creds",
                 "enforce_password_policy", "enforce_mfa",
                 "enforce_least_privilege", "block_public_exposure",
                 "enforce_cloud_iam", "enforce_logging",
                 "enforce_backup_retention", "enforce_immutability",
                 "enforce_air_gap", "replication_enabled"]
    for cid in must_have:
        assert cid in res.output, f"missing control {cid} in output"


def test_interpret_offline_extracts_controls_and_params(cli):
    text = ("Disable Telnet, enforce SSHv2, require AAA/TACACS, enable NTP, "
            "enforce SNMPv3, send logs to 10.10.10.50, "
            "restrict mgmt to 10.10.10.0/24, password length 16")
    res = CliRunner().invoke(cli, ["interpret", text])
    assert res.exit_code == 0, res.output
    # Must mention these controls
    for cid in ("disable_telnet", "enforce_ssh_v2", "require_aaa",
                "enforce_snmpv3", "enable_ntp"):
        assert cid in res.output, f"interpret didn't extract {cid}"
    # Must extract the syslog target IP
    assert "10.10.10.50" in res.output
    # Source label
    assert "source: nl" in res.output


def test_interpret_save_round_trip(cli):
    runner = CliRunner()
    # Save
    r1 = runner.invoke(cli, ["interpret", "disable telnet, enforce sshv2",
                              "--name", "RoundTripTest", "--save"])
    assert r1.exit_code == 0, r1.output
    m = re.search(r"policy_id:\s+(pol_\w+)", r1.output)
    assert m, f"no policy_id in output:\n{r1.output}"
    pid = m.group(1)
    # List should now contain our policy
    r2 = runner.invoke(cli, ["list"])
    assert pid in r2.output, f"saved policy {pid} not in list:\n{r2.output}"
    assert "RoundTripTest" in r2.output
    # Delete cleans up
    r3 = runner.invoke(cli, ["delete", pid])
    assert r3.exit_code == 0, r3.output
    assert "deleted" in r3.output.lower()


def test_create_evaluate_export_pipeline(cli, cisco_router_messy):
    """Full pipeline: create from template → save → evaluate → export."""
    runner = CliRunner()

    # 1. Create from network-hardening template
    r1 = runner.invoke(cli, ["create", "-t", "tmpl_network_hardening",
                              "--name", "EndToEndPipeline"])
    assert r1.exit_code == 0, r1.output
    m = re.search(r"created\s+([^\s:]+)", r1.output)
    pid = m.group(1) if m else None
    assert pid, f"could not parse policy id: {r1.output}"

    # 2. Seed the platform asset store with one messy router so evaluate has data
    from pathlib import Path
    asset_dir = Path.home() / ".safecadence" / "platform_assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / "r2.json").write_text(json.dumps(cisco_router_messy),
                                       encoding="utf-8")

    # 3. Evaluate
    r2 = runner.invoke(cli, ["evaluate", pid])
    assert r2.exit_code == 0, r2.output
    assert "fail=" in r2.output

    # 4. Export as ansible
    r3 = runner.invoke(cli, ["export", pid, "--format", "ansible"])
    assert r3.exit_code == 0, r3.output
    assert "cisco.ios.ios_config" in r3.output, "ansible exporter didn't pick the right module"

    # 5. Cleanup
    runner.invoke(cli, ["delete", pid])


def test_simulate_returns_summary_json(cli):
    runner = CliRunner()
    r1 = runner.invoke(cli, ["create", "-t", "tmpl_zero_trust", "--name", "SimTest"])
    pid = re.search(r"created\s+([^\s:]+)", r1.output).group(1)
    r2 = runner.invoke(cli, ["simulate", pid])
    assert r2.exit_code == 0, r2.output
    parsed = json.loads(r2.output)
    assert "summary" in parsed
    assert "would_fail" in parsed
    runner.invoke(cli, ["delete", pid])


def test_audit_records_create_and_delete(cli):
    runner = CliRunner()
    r1 = runner.invoke(cli, ["create", "-t", "tmpl_firewall_baseline", "--name", "AuditTest"])
    pid = re.search(r"created\s+([^\s:]+)", r1.output).group(1)
    runner.invoke(cli, ["delete", pid])
    r3 = runner.invoke(cli, ["audit", "--limit", "20"])
    assert r3.exit_code == 0, r3.output
    assert "policy_saved" in r3.output
    assert "policy_deleted" in r3.output


def test_help_for_every_subcommand(cli):
    """Smoke: every registered subcommand at least responds to --help."""
    runner = CliRunner()
    res_root = runner.invoke(cli, ["--help"])
    assert res_root.exit_code == 0
    # Every subcommand we expect to ship in v5.x
    subs = ["templates", "controls", "list", "create", "interpret",
            "delete", "evaluate", "simulate", "export", "compliance",
            "drift", "shadow", "git-sync", "test", "audit"]
    for s in subs:
        r = runner.invoke(cli, [s, "--help"])
        assert r.exit_code == 0, f"`policy {s} --help` exited {r.exit_code}: {r.output}"
