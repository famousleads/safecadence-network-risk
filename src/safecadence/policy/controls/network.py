"""Network-device controls: SSH, AAA, SNMP, syslog, NTP, mgmt access, crypto."""

from __future__ import annotations

import re
from typing import Any

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _config_text(asset: dict) -> str:
    """Pull the running-config / system text from collected raw data."""
    raw = asset.get("raw_collection") or {}
    if isinstance(raw, dict):
        # Pick whichever raw field looks like config text.
        for k in ("show_running-config", "running-config", "config",
                  "show_system", "show_version", "display_version"):
            v = raw.get(k)
            if isinstance(v, str) and v:
                return v
        # Concatenate all string fields as a fallback.
        return "\n".join(v for v in raw.values() if isinstance(v, str))
    return str(raw)


def _has_line(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None


# --------------------------------------------------------------------------
# disable_telnet
# --------------------------------------------------------------------------

def _check_disable_telnet(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    # Common indicators of telnet enabled across vendors
    bad = [r"^\s*transport input telnet", r"^\s*transport input all",
           r"telnet-server enable", r"set system services telnet"]
    if any(_has_line(cfg, p) for p in bad):
        return EvaluationResult.FAIL, "telnet appears enabled in collected config"
    # Look for explicit "no telnet" or transport ssh-only
    good = [r"^\s*transport input ssh\s*$", r"no telnet-server",
            r"delete system services telnet"]
    if any(_has_line(cfg, p) for p in good):
        return EvaluationResult.PASS, "telnet explicitly disabled"
    return EvaluationResult.PASS, "no telnet enabling found (assumed disabled)"


register_control(ControlSpec(
    id="disable_telnet",
    description="Telnet must not be enabled on management or VTY lines",
    applies_to=["network"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-17", "cis:net-1.1.4", "pci:2.3"],
    check_fn=_check_disable_telnet,
))


# --------------------------------------------------------------------------
# enforce_ssh_v2
# --------------------------------------------------------------------------

def _check_enforce_ssh_v2(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    if _has_line(cfg, r"^\s*ip ssh version 2") or _has_line(cfg, r"set system services ssh protocol-version v2"):
        return EvaluationResult.PASS, "ssh v2 explicitly enforced"
    if _has_line(cfg, r"^\s*ip ssh version 1"):
        return EvaluationResult.FAIL, "ssh v1 explicitly enabled"
    return EvaluationResult.PASS, "no ssh v1 found"


register_control(ControlSpec(
    id="enforce_ssh_v2",
    description="SSH must be restricted to protocol version 2",
    applies_to=["network", "server"],
    severity=Severity.HIGH,
    frameworks=["nist:SC-8", "cis:5.2.1", "pci:2.3"],
    check_fn=_check_enforce_ssh_v2,
))


# --------------------------------------------------------------------------
# require_aaa
# --------------------------------------------------------------------------

def _check_require_aaa(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    if (_has_line(cfg, r"^\s*aaa new-model") or
        _has_line(cfg, r"^\s*tacacs-server host") or
        _has_line(cfg, r"set system tacplus-server")):
        return EvaluationResult.PASS, "aaa/tacacs configured"
    return EvaluationResult.FAIL, "no aaa/tacacs configuration detected"


register_control(ControlSpec(
    id="require_aaa",
    description="AAA must be enabled (TACACS+ or RADIUS) for management access",
    applies_to=["network"],
    severity=Severity.HIGH,
    frameworks=["nist:IA-2", "cis:1.5", "pci:8.1"],
    check_fn=_check_require_aaa,
))


# --------------------------------------------------------------------------
# enforce_snmpv3
# --------------------------------------------------------------------------

def _check_enforce_snmpv3(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    if _has_line(cfg, r"^\s*snmp-server community .+ (RO|RW)") and not _has_line(cfg, r"snmp-server group .+ v3"):
        return EvaluationResult.FAIL, "SNMPv1/v2c community present without SNMPv3 group"
    if _has_line(cfg, r"snmp-server group .+ v3") or _has_line(cfg, r"set snmp v3"):
        return EvaluationResult.PASS, "snmpv3 configured"
    return EvaluationResult.PASS, "no snmpv1/v2c communities found"


register_control(ControlSpec(
    id="enforce_snmpv3",
    description="Only SNMPv3 may be used; SNMPv1/v2c communities are forbidden",
    applies_to=["network"],
    severity=Severity.MEDIUM,
    frameworks=["nist:SC-8", "cis:net-2.4"],
    check_fn=_check_enforce_snmpv3,
))


# --------------------------------------------------------------------------
# enable_syslog
# --------------------------------------------------------------------------

def _check_enable_syslog(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    target = params.get("syslog_target")
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    has_log = (_has_line(cfg, r"^\s*logging host") or _has_line(cfg, r"^\s*logging \d+\.\d+\.\d+\.\d+")
               or _has_line(cfg, r"set system syslog host"))
    if not has_log:
        return EvaluationResult.FAIL, "no syslog destination configured"
    if target and target not in cfg:
        return EvaluationResult.FAIL, f"syslog target {target} not present"
    return EvaluationResult.PASS, "syslog configured"


register_control(ControlSpec(
    id="enable_syslog",
    description="Logs must be sent to a central syslog destination",
    applies_to=["network", "server"],
    severity=Severity.MEDIUM,
    frameworks=["nist:AU-3", "cis:8.2", "pci:10.5"],
    check_fn=_check_enable_syslog,
))


# --------------------------------------------------------------------------
# enable_ntp
# --------------------------------------------------------------------------

def _check_enable_ntp(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    if (_has_line(cfg, r"^\s*ntp server") or _has_line(cfg, r"set system ntp server")
            or _has_line(cfg, r"timedatectl set-ntp")):
        return EvaluationResult.PASS, "ntp server(s) configured"
    return EvaluationResult.FAIL, "no NTP server configured"


register_control(ControlSpec(
    id="enable_ntp",
    description="NTP must be enabled with at least one trusted source",
    applies_to=["network", "server"],
    severity=Severity.LOW,
    frameworks=["nist:AU-8", "cis:2.2.2", "pci:10.4"],
    check_fn=_check_enable_ntp,
))


# --------------------------------------------------------------------------
# block_insecure_crypto
# --------------------------------------------------------------------------

def _check_block_insecure_crypto(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    bad = [r"sslv3", r"tlsv1\.0", r"tls 1\.0", r"des\b", r"rc4", r"md5\b(?!.*hmac)"]
    found = [p for p in bad if re.search(p, cfg, re.IGNORECASE)]
    if found:
        return EvaluationResult.FAIL, f"insecure crypto present: {', '.join(found)}"
    return EvaluationResult.PASS, "no insecure crypto detected"


register_control(ControlSpec(
    id="block_insecure_crypto",
    description="Disable SSLv3, TLS 1.0, DES, RC4, MD5",
    applies_to=["network", "server"],
    severity=Severity.HIGH,
    frameworks=["nist:SC-13", "cis:5.2.4", "pci:4.1"],
    check_fn=_check_block_insecure_crypto,
))


# --------------------------------------------------------------------------
# restrict_management_access
# --------------------------------------------------------------------------

def _check_restrict_management_access(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    cfg = _config_text(asset)
    allowed = params.get("allowed_cidrs") or []
    if not cfg:
        return EvaluationResult.UNKNOWN, "no config text collected"
    # Look for an ACL or firewall filter restricting VTY/SSH access
    if (_has_line(cfg, r"^\s*access-class \d+ in") or _has_line(cfg, r"set system services ssh client-alive")
            or _has_line(cfg, r"AllowUsers ")):
        return EvaluationResult.PASS, "management access restricted via ACL/filter"
    if allowed:
        return EvaluationResult.FAIL, f"no ACL restricting management to {allowed}"
    return EvaluationResult.FAIL, "no management-access restriction detected"


register_control(ControlSpec(
    id="restrict_management_access",
    description="Management plane (SSH/HTTPS) must be restricted to specific source CIDRs",
    applies_to=["network", "server"],
    severity=Severity.HIGH,
    frameworks=["nist:AC-3", "cis:net-3.1", "pci:1.3"],
    check_fn=_check_restrict_management_access,
))
