"""Tests for the Cisco IOS parser."""

from pathlib import Path

import pytest

from safecadence.adapters.cisco_ios import parser as ios_parser


SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_configs" / "cisco_ios_running.txt"


@pytest.fixture(scope="module")
def parsed():
    text = SAMPLE.read_text(encoding="utf-8")
    return ios_parser.parse(text)


def test_hostname(parsed):
    assert parsed.hostname == "BRANCH-EDGE-01"


def test_version(parsed):
    assert parsed.version.startswith("15")


def test_interfaces_count(parsed):
    # 4 interfaces in the sample
    assert len(parsed.interfaces) == 4


def test_interface_shutdown_detected(parsed):
    by_name = {i.name: i for i in parsed.interfaces}
    assert by_name["GigabitEthernet0/3"].admin_up is False
    assert by_name["GigabitEthernet0/0"].admin_up is True


def test_ip_extracted(parsed):
    by_name = {i.name: i for i in parsed.interfaces}
    assert by_name["GigabitEthernet0/0"].ip == "203.0.113.10"
    assert by_name["GigabitEthernet0/1"].ip == "10.10.10.1"


def test_vlan_extracted(parsed):
    by_name = {i.name: i for i in parsed.interfaces}
    assert by_name["GigabitEthernet0/2"].vlan == 1


def test_os_detection():
    assert ios_parser.detect_os("Cisco IOS Software, Foo") == "ios"
    assert ios_parser.detect_os("Cisco IOS XE Software") == "ios-xe"
    assert ios_parser.detect_os("Cisco Nexus NX-OS Software") == "nxos"
    assert ios_parser.detect_os("Cisco Adaptive Security Appliance, ASA Version 9.8") == "asa"
