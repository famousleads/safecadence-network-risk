"""Local-only Python launcher guard; not a replacement for OS egress isolation."""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
from dataclasses import dataclass


class EgressDenied(PermissionError):
    """A network or subprocess operation exceeds the local-only boundary."""


@dataclass(frozen=True)
class LocalPolicy:
    internal_targets: tuple = ()

    def __post_init__(self):
        for host, port in self.internal_targets:
            address = ipaddress.ip_address(host)
            internal = any(address in ipaddress.ip_network(block) for block in (
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"
            ) if address.version == ipaddress.ip_network(block).version)
            if not internal or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError("Internal targets require an RFC1918/ULA IP and exact port")

    def permits(self, host, port) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except (ValueError, TypeError):
            return False
        if address.is_loopback:
            return True
        return (str(address), port) in self.internal_targets


def install_guard(policy=None):
    """Irreversible per-process guard. Call before importing network-capable code.

    Numeric destinations only: no public DNS, proxy discovery or implicit LAN
    authorization. Subprocesses are denied because Python hooks cannot govern
    a child/native engine's sockets. TCP listeners and Unix sockets remain usable.
    """
    policy = policy or LocalPolicy()

    def audit(event, args):
        if event == "socket.__new__":
            family, kind = args[1:3]
            if family not in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
                raise EgressDenied("Socket family denied by local-only policy")
            if family != socket.AF_UNIX and kind & 0xF != socket.SOCK_STREAM:
                raise EgressDenied("UDP/raw sockets denied by local-only policy")
        elif event == "socket.bind":
            sock, address = args
            if sock.family != socket.AF_UNIX:
                try:
                    local = ipaddress.ip_address(address[0]).is_loopback
                except ValueError:
                    local = False
                if not local:
                    raise EgressDenied("Local launcher listeners must bind to loopback")
        elif event == "socket.connect":
            sock, address = args
            if sock.family == socket.AF_UNIX:
                return
            if not isinstance(address, tuple) or not policy.permits(*address[:2]):
                raise EgressDenied("Destination denied by local-only policy")
        elif event == "socket.getaddrinfo":
            host, port = args[:2]
            if host is None:  # listener setup, not a resolver request
                return
            if not policy.permits(host, port):
                raise EgressDenied("DNS/destination denied by local-only policy")
        elif event in ("socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo"):
            raise EgressDenied("Name-service calls denied by local-only policy")
        elif event in ("socket.sendto", "socket.sendmsg"):
            raise EgressDenied("Datagram transmission denied by local-only policy")
        elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
            raise EgressDenied("Subprocesses require separately isolated, reviewed workers")

    sys.addaudithook(audit)
    return policy


def main():
    # Never offer an environment variable that disables the guard.
    try:
        import json
        targets = json.loads(os.environ.get("SC_LOCAL_INTERNAL_TARGETS", "[]"))
        if not isinstance(targets, list):
            raise ValueError("Expected a list")
        policy = LocalPolicy(tuple((item["ip"], item["port"]) for item in targets))
    except (ValueError, TypeError, KeyError):
        sys.stderr.write("Invalid SC_LOCAL_INTERNAL_TARGETS; refusing startup.\n")
        return 2
    install_guard(policy)
    from safecadence.cli import cli
    cli()
    return 0


if __name__ == "__main__":
    sys.exit(main())
