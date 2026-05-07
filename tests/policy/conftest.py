"""Shared fixtures + test helpers — cross-platform via pathlib + tmp_path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Re-root ~ to a tmp dir so policy/audit/store don't touch the real ~/.safecadence."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    # Path.home() reads HOME on POSIX, USERPROFILE on Windows.
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    yield fake_home


@pytest.fixture
def cisco_router_clean():
    return {
        "identity": {"asset_id": "r1", "vendor": "cisco", "asset_type": "network",
                     "environment": "prod"},
        "os": {"os_type": "ios-xe", "os_version": "17.6"},
        "raw_collection": {
            "show_running-config": (
                "hostname r1\n"
                "ip ssh version 2\n"
                "aaa new-model\n"
                "tacacs-server host 10.10.10.5\n"
                "logging host 10.10.10.50\n"
                "ntp server pool.ntp.org\n"
                "snmp-server group SC-RO v3 priv read v1default\n"
                "line vty 0 4\n"
                " transport input ssh\n"
                " access-class 10 in\n"
            )
        }
    }


@pytest.fixture
def cisco_router_messy():
    return {
        "identity": {"asset_id": "r2", "vendor": "cisco", "asset_type": "network",
                     "environment": "prod"},
        "os": {"os_type": "ios-xe", "os_version": "17.6"},
        "raw_collection": {
            "show_running-config": (
                "hostname r2\n"
                "snmp-server community public RO\n"
                "snmp-server community private RW\n"
                "line vty 0 4\n"
                " transport input telnet ssh\n"
                "no logging host\n"
            )
        }
    }


@pytest.fixture
def linux_server():
    return {
        "identity": {"asset_id": "linux1", "vendor": "ubuntu", "asset_type": "server",
                     "environment": "prod"},
        "os": {"os_type": "linux"},
        "security": {"weak_protocols": ["telnet"], "missing_patches": ["CVE-2025-9999"],
                     "critical_cves": 1, "mfa_enabled": False},
        "raw_collection": {"show_version": "Ubuntu 22.04"},
    }


@pytest.fixture
def cloud_asset_public():
    return {
        "identity": {"asset_id": "ec2-1", "vendor": "aws", "asset_type": "cloud"},
        "cloud": {"provider": "aws", "public_exposure": True, "public_ip": "1.2.3.4",
                  "iam_role": "", "instance_id": "i-abc"},
        "security": {"critical_cves": 1, "kev_cves": 1, "findings": ["wildcard iam:*"]},
        "raw_collection": {"meta": "no cloudtrail marker"},
    }
