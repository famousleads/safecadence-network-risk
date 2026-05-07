"""
Network discovery engine.

Find every device on a subnet, identify vendor + likely OS, and prepare
the asset inventory for the audit pipeline. All TCP-based — no raw
sockets, no root required.

Public API:

    from safecadence.discovery import discover_subnet, DiscoveredHost

    hosts = discover_subnet("10.10.10.0/24", workers=64)
    for h in hosts:
        print(h.ip, h.vendor_guess, h.open_ports)
"""

from safecadence.discovery.asset import DiscoveredHost, DiscoveryResult
from safecadence.discovery.sweep import discover_subnet, sweep_host

__all__ = ["DiscoveredHost", "DiscoveryResult", "discover_subnet", "sweep_host"]
