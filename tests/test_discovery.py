"""Discovery engine — unit tests that don't touch the network."""

import socket
import threading

import pytest

from safecadence.discovery import discover_subnet, sweep_host
from safecadence.discovery.identify import grab_banners, guess_combined, guess_from_banners
from safecadence.discovery.oui import is_network_gear, vendor_for


# ---------------------------------------------------------------- #
# OUI lookup
# ---------------------------------------------------------------- #
class TestOUI:
    def test_cisco_oui(self):
        assert vendor_for("00:00:0C:11:22:33") == "Cisco"

    def test_aruba_oui(self):
        assert vendor_for("60:D2:48:aa:bb:cc") == "Aruba"

    def test_normalization(self):
        # Different separators
        assert vendor_for("00-00-0C-11-22-33") == "Cisco"
        assert vendor_for("00000c112233") == "Cisco"

    def test_unknown_oui(self):
        assert vendor_for("FF:FF:FF:00:00:00") == ""

    def test_empty_input(self):
        assert vendor_for("") == ""
        assert vendor_for(None) == ""

    def test_is_network_gear(self):
        assert is_network_gear("Cisco")
        assert is_network_gear("Aruba")
        assert is_network_gear("Arista")
        assert is_network_gear("Fortinet")
        assert not is_network_gear("Apple")
        assert not is_network_gear("VMware")
        assert not is_network_gear("")


# ---------------------------------------------------------------- #
# Banner heuristics
# ---------------------------------------------------------------- #
class TestIdentify:
    def test_cisco_ios_xe_from_banner(self):
        banners = {22: "SSH-2.0-Cisco-1.25"}
        # Generic cisco banner is matched as "Cisco IOS Software" only when
        # full string is present; SSH banner alone is generic.
        v, os, dt = guess_from_banners({22: "Cisco IOS Software"})
        assert v == "Cisco"
        assert os == "ios"

    def test_arista_eos(self):
        v, os, dt = guess_from_banners({22: "SSH-2.0-Arista Networks EOS"})
        assert v == "Arista"
        assert os == "eos"
        assert dt == "switch"

    def test_fortigate(self):
        v, os, dt = guess_from_banners({443: "Server: FortiGate"})
        assert v == "Fortinet"
        assert dt == "firewall"

    def test_juniper(self):
        v, os, dt = guess_from_banners({22: "SSH-2.0-OpenSSH_7.5 Juniper JUNOS 20.4"})
        assert v == "Juniper"

    def test_combined_falls_back_to_oui(self):
        # No banner match, but OUI says Cisco
        v, os, dt = guess_combined({}, "Cisco")
        assert v == "Cisco"
        assert dt == "network"

    def test_combined_returns_empty_when_nothing_found(self):
        v, os, dt = guess_combined({}, "")
        assert v == ""
        assert os == ""


# ---------------------------------------------------------------- #
# Sweep against a localhost mock TCP server
# ---------------------------------------------------------------- #
class _MockTCPServer:
    def __init__(self, port: int, banner: bytes = b""):
        self.port = port
        self.banner = banner
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(8)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            try:
                if self.banner:
                    conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


@pytest.fixture(scope="module")
def mock_ssh_server():
    # Pick an ephemeral free port so re-runs don't collide
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = _MockTCPServer(port, b"Server: Arista Networks EOS  4.28.3M\r\n")
    server.start()
    yield port
    server.stop()


def test_sweep_finds_local_listener(mock_ssh_server):
    h = sweep_host("127.0.0.1", ports=(mock_ssh_server,), timeout=0.5,
                   reverse_dns=False)
    assert h is not None, "sweep should detect localhost listener"
    assert h.ip == "127.0.0.1"
    assert mock_ssh_server in h.open_ports
    # Port 18080 isn't in the default _BANNER_PORTS allowlist, so we expect
    # no banner grab to happen — but the sweep itself should still detect it.
    # The key behavior under test is "liveness detection works".


def test_sweep_returns_none_for_unreachable():
    # Pick a port nothing should listen on
    h = sweep_host("127.0.0.1", ports=(54311,), timeout=0.2, reverse_dns=False)
    assert h is None


def test_discover_subnet_handles_single_host_cidr():
    # /32 has 0 .hosts() according to ipaddress: scanned should be 0
    # (Python's ipaddress.ip_network('127.0.0.1/32').hosts() yields the host)
    import ipaddress
    n = ipaddress.ip_network("127.0.0.1/32", strict=False)
    expected = len(list(n.hosts()))
    result = discover_subnet("127.0.0.1/32", workers=4, timeout=0.2,
                             grab_banner=False, reverse_dns=False,
                             ports=(54311,))
    assert result.hosts_scanned == expected


def test_discover_subnet_with_listener(mock_ssh_server):
    # /30 hosts() = .1, .2 ⇒ scanned == 2, only .1 has the mock listener
    result = discover_subnet("127.0.0.0/30", workers=4, timeout=0.3,
                             ports=(mock_ssh_server,),
                             grab_banner=False, reverse_dns=False)
    assert result.hosts_scanned == 2
    assert result.hosts_responding >= 1
    assert any(h.ip == "127.0.0.1" for h in result.hosts)


def test_discover_returns_proper_dataclass():
    """The result should always be a DiscoveryResult with valid timing fields."""
    result = discover_subnet("127.0.0.0/30", workers=2, timeout=0.2,
                             ports=(54312,), grab_banner=False, reverse_dns=False)
    assert result.subnet == "127.0.0.0/30"
    assert result.duration_ms >= 0
    assert result.hosts_scanned == 2
    assert isinstance(result.hosts, list)
    assert "subnet" in result.to_dict()
    assert "hosts" in result.to_dict()
