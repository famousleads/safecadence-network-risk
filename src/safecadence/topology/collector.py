"""
LLDP / CDP collector + parser.

Two ways to feed the topology engine:

  1. parse_lldp_text(text, local_device="...")
       Paste the output of `show lldp neighbors detail` (or CDP equivalent)
       and we extract neighbor records. No SSH dependency.

  2. collect_via_ssh(host, username, password=..., key_path=...)
       Live SSH (paramiko, optional extra). Runs the right command per
       vendor and feeds the output into parse_lldp_text.
"""

from __future__ import annotations

import re
from typing import Iterable

from safecadence.topology.graph import Edge, Node, Topology


# ----------------------------------------------------------------------- #
# LLDP "neighbors detail" parser — handles Cisco IOS / IOS-XE / NX-OS,    #
# Aruba CX, Arista EOS. Vendor differences are subtle in this output.     #
# ----------------------------------------------------------------------- #
_RECORD_BOUNDARY = re.compile(
    r"-{4,}\s*\n",       # Cisco IOS / NXOS use a row of '-' between records
)
_FIELD_PATTERNS = {
    # Order matters — first one that matches wins.
    "local_port":      re.compile(r"(?im)^\s*Local\s+(?:Intf|Port\s+id|Port)\s*:\s*([^\s\n]+)\s*$"),
    "remote_device":   re.compile(r"(?im)^\s*(?:System\s+Name|SysName|Device\s+ID)\s*:\s*([^\s\n]+)\s*$"),
    "remote_port":     re.compile(r"(?im)^\s*Port\s+(?:id|ID|Description|Desc)\s*:\s*([^\n]+?)\s*$"),
    # Platform pulls the full multi-line "System Description" block (DOTALL until a blank line or next field)
    "platform":        re.compile(r"(?ims)^\s*System\s+Description\s*:\s*\n?(.+?)(?=^\s*(?:Time\s+remaining|System\s+Capabilities|Enabled\s+Capabilities|Management\s+Addresses?|Auto\s+Negotiation|-{4,}|$))"),
    "capabilities":    re.compile(r"(?im)^\s*Enabled\s+Capabilities\s*:\s*([\w,\- ]+?)\s*$"),
    # IP can be on the same line as 'Mgmt Address' OR indented under 'Management Addresses:'
    "remote_ip":       re.compile(r"(?im)^\s*(?:Mgmt\s+Address(?:es)?|Management\s+Address(?:es)?\s*:\s*\n\s*IP|IP\s+address|IP)\s*:\s*(\d+\.\d+\.\d+\.\d+)"),
}
_VENDOR_FROM_PLATFORM = (
    (re.compile(r"(?i)cisco\s+ios\s+xe"),         "Cisco",   "ios-xe"),
    (re.compile(r"(?i)cisco\s+nexus|nx-os"),      "Cisco",   "nxos"),
    (re.compile(r"(?i)cisco\s+adaptive"),         "Cisco",   "asa"),
    (re.compile(r"(?i)cisco\s+ios"),              "Cisco",   "ios"),
    (re.compile(r"(?i)arubaos[-_ ]?cx"),          "Aruba",   "aos-cx"),
    (re.compile(r"(?i)arubaos"),                  "Aruba",   "arubaos"),
    (re.compile(r"(?i)arista|eos"),               "Arista",  "eos"),
    (re.compile(r"(?i)juniper|junos"),            "Juniper", "junos"),
    (re.compile(r"(?i)fortigate|fortios"),        "Fortinet","fortios"),
    (re.compile(r"(?i)pan-os|palo alto"),         "Palo Alto Networks","panos"),
    (re.compile(r"(?i)mikrotik|routeros"),        "MikroTik","routeros"),
    (re.compile(r"(?i)meraki"),                   "Cisco Meraki", "meraki"),
)


def _vendor_from_platform(platform: str) -> tuple[str, str]:
    if not platform:
        return "", ""
    for pattern, vendor, os_short in _VENDOR_FROM_PLATFORM:
        if pattern.search(platform):
            return vendor, os_short
    return "", ""


def _split_records(text: str) -> list[str]:
    """Split LLDP detail output into per-neighbor blocks."""
    if not text:
        return []
    # Cisco IOS uses a row of dashes between records.
    chunks = _RECORD_BOUNDARY.split(text)
    if len(chunks) > 1:
        return [c for c in chunks if c.strip()]
    # Aruba CX / Arista often use a blank line between records or a
    # "Local Port :" header. Try splitting on "Local Port" or "Port id" markers.
    chunks = re.split(r"\n(?=\s*Local Port\s*:|^Local Intf\s*:)", text, flags=re.MULTILINE)
    return [c for c in chunks if c.strip()]


def parse_lldp_text(text: str, *, local_device: str = "LOCAL") -> Topology:
    """Parse 'show lldp neighbors detail' output into a Topology."""
    topo = Topology()
    topo.add_node(Node(name=local_device))

    for block in _split_records(text or ""):
        fields: dict[str, str] = {}
        for key, pattern in _FIELD_PATTERNS.items():
            m = pattern.search(block)
            if m:
                fields[key] = m.group(1).strip()

        remote = fields.get("remote_device", "")
        # "system name" can be a FQDN or quoted; clean it up
        if remote:
            remote = remote.strip('"').split(".")[0]
        if not remote:
            continue

        platform = fields.get("platform", "")
        vendor, os_short = _vendor_from_platform(platform)
        caps = tuple(c.strip() for c in fields.get("capabilities", "").split(",") if c.strip())

        # Heuristic role from LLDP single-letter codes (or full words)
        role = ""
        caps_set = {c.upper() for c in caps}
        # LLDP single-letter codes: R=Router, B=Bridge(switch), W=WLAN AP, T=Telephone
        if "W" in caps_set or any("WLAN" in c.upper() or "AP" in c.upper() for c in caps):
            role = "wireless"
        elif "R" in caps_set or "router" in [c.lower() for c in caps]:
            role = "router"
        elif "B" in caps_set or "bridge" in [c.lower() for c in caps]:
            role = "switch"
        # Override: if vendor + platform suggest firewall, set firewall
        if "asa" in (platform or "").lower() or "fortigate" in (platform or "").lower() or "pan-os" in (platform or "").lower():
            role = "firewall"

        topo.add_node(Node(
            name=remote,
            ip=fields.get("remote_ip", ""),
            vendor=vendor,
            platform=platform[:120],
            role=role,
            capabilities=caps,
        ))

        topo.add_edge(Edge(
            local_device=local_device,
            local_port=fields.get("local_port", ""),
            remote_device=remote,
            remote_port=fields.get("remote_port", ""),
            protocol="lldp",
        ))

    return topo


# ----------------------------------------------------------------------- #
# Optional: live SSH collection (requires `pip install ...[ssh]`)         #
# ----------------------------------------------------------------------- #
_LLDP_COMMANDS = {
    "ios":     "show lldp neighbors detail",
    "ios-xe":  "show lldp neighbors detail",
    "nxos":    "show lldp neighbors detail",
    "asa":     "show lldp neighbors detail",
    "aos-cx":  "show lldp neighbor-info detail",
    "eos":     "show lldp neighbors detail",
}


def _import_paramiko():
    try:
        import paramiko  # type: ignore
        return paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Live SSH topology collection requires paramiko. "
            "Install with: pip install 'safecadence-network-risk[ssh]'"
        ) from exc


def collect_via_ssh(
    host: str, username: str,
    *,
    password: str = "",
    key_path: str = "",
    port: int = 22,
    timeout: int = 15,
    os_family: str = "ios",
    local_device: str = "",
) -> Topology:
    """
    SSH into `host`, run the right LLDP command for `os_family`, and
    return the parsed Topology.
    """
    paramiko = _import_paramiko()
    cmd = _LLDP_COMMANDS.get(os_family, _LLDP_COMMANDS["ios"])
    if not local_device:
        local_device = host

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            client.connect(host, port=port, username=username, key_filename=key_path,
                           timeout=timeout, allow_agent=False, look_for_keys=False)
        else:
            client.connect(host, port=port, username=username, password=password,
                           timeout=timeout, allow_agent=False, look_for_keys=False)
        # Many vendors paginate; disable with terminal width 0 / "term len 0".
        chan = client.invoke_shell()
        chan.settimeout(timeout)
        chan.send("terminal length 0\n")
        chan.send("no page\n")           # Aruba CX
        import time as _t
        _t.sleep(0.3)
        chan.recv(65535)                  # drain prompt
        chan.send(cmd + "\n")
        _t.sleep(2.0)
        out = b""
        while chan.recv_ready():
            out += chan.recv(65535)
            _t.sleep(0.2)
        text = out.decode("utf-8", errors="replace")
    finally:
        client.close()

    return parse_lldp_text(text, local_device=local_device)


def merge(topologies: Iterable[Topology]) -> Topology:
    """Merge multiple per-device walks into one combined topology."""
    out = Topology()
    for t in topologies:
        for n in t.nodes.values():
            out.add_node(n)
        out.add_edges(t.edges)
    return out
