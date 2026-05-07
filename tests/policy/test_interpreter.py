"""AI interpreter (offline path) tests."""

from __future__ import annotations

from safecadence.policy.interpreter import interpret_offline


def test_interprets_basic_network_intent():
    p = interpret_offline("Disable Telnet, enforce SSHv2, require AAA, enable NTP, "
                          "enforce SNMPv3, send logs to 10.10.10.50, restrict "
                          "management to 10.10.10.0/24, no SSL3 or RC4")
    cids = {c.control_id for c in p.controls}
    must_have = {"disable_telnet", "enforce_ssh_v2", "require_aaa", "enable_ntp",
                 "enforce_snmpv3", "block_insecure_crypto"}
    assert must_have.issubset(cids), f"missing: {must_have - cids}"


def test_interpreter_extracts_syslog_target_param():
    p = interpret_offline("send logs to 10.0.0.5")
    syslog = next((c for c in p.controls if c.control_id == "enable_syslog"), None)
    assert syslog is not None
    assert syslog.parameters.get("syslog_target") == "10.0.0.5"


def test_interpreter_extracts_cidr():
    p = interpret_offline("restrict mgmt access to 192.168.0.0/16 and enable ssh")
    rma = next((c for c in p.controls if c.control_id == "restrict_management_access"), None)
    if rma:
        assert "192.168.0.0/16" in (rma.parameters.get("allowed_cidrs") or [])


def test_interpreter_extracts_password_minlen():
    p = interpret_offline("enforce password policy min 16 characters")
    pp = next((c for c in p.controls if c.control_id == "enforce_password_policy"), None)
    assert pp is not None
    assert pp.parameters.get("min_length") == 16
