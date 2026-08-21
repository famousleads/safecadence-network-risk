"""
Inbound listeners — syslog UDP + SNMPv2c trap receiver.

OFF by default. Enabled with ``SC_EVENTS_LISTENERS=1`` (both) or
individually via ``SC_SYSLOG_PORT`` / ``SC_TRAP_PORT``. Defaults use
unprivileged ports (5514 / 5162) so no root is required; agencies
forward from their devices or relay from :514/:162.

Stdlib only. The BER decoder below is the read-side sibling of the
hand-rolled encoder in ``discovery/snmp_probe.py`` — minimal, defensive,
and only as deep as an SNMPv2c trap PDU needs.

Security posture:
  * bind address defaults to 127.0.0.1 (``SC_EVENTS_BIND`` to widen)
  * optional community allowlist ``SC_TRAP_COMMUNITIES`` (comma-sep);
    unmatched communities are recorded as auth-failure events, not
    processed as telemetry
  * datagrams are size-capped; parse failures never kill the thread
"""

from __future__ import annotations

import os
import socket
import threading
from typing import Any

from safecadence.events.schema import Event, normalize_syslog, normalize_trap
from safecadence.events.store import append_event

_MAX_DGRAM = 16384
_threads: list[threading.Thread] = []
_stops: list[threading.Event] = []


# ---------------------------------------------------------------- BER decode

def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    """Return (length, next_index) for a BER length at buf[i]."""
    if i >= len(buf):
        raise ValueError("truncated length")
    b = buf[i]
    if b < 0x80:
        return b, i + 1
    n = b & 0x7F
    if n == 0 or n > 4 or i + 1 + n > len(buf):
        raise ValueError("bad long-form length")
    return int.from_bytes(buf[i + 1:i + 1 + n], "big"), i + 1 + n


def _read_tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index)."""
    if i >= len(buf):
        raise ValueError("truncated tag")
    tag = buf[i]
    length, j = _read_len(buf, i + 1)
    if j + length > len(buf):
        raise ValueError("value overruns buffer")
    return tag, buf[j:j + length], j + length


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def _decode_value(tag: int, value: bytes) -> Any:
    if tag == 0x02:                                   # INTEGER
        return int.from_bytes(value, "big", signed=True) if value else 0
    if tag == 0x04:                                   # OCTET STRING
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if tag == 0x06:                                   # OID
        return _decode_oid(value)
    if tag == 0x40:                                   # IpAddress
        return ".".join(str(b) for b in value) if len(value) == 4 else value.hex()
    if tag in (0x41, 0x42, 0x43, 0x46):               # Counter/Gauge/TimeTicks/Counter64
        return int.from_bytes(value, "big") if value else 0
    if tag == 0x05:                                   # NULL
        return None
    return value.hex()


def decode_trap(datagram: bytes) -> dict:
    """Decode an SNMPv2c trap datagram.

    Returns {version, community, trap_oid, varbinds:[(oid, value)...]}.
    Raises ValueError on anything that isn't a well-formed v2c trap.
    """
    tag, msg, _ = _read_tlv(datagram, 0)
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    i = 0
    tag, ver_b, i = _read_tlv(msg, i)
    if tag != 0x02:
        raise ValueError("missing version")
    version = int.from_bytes(ver_b, "big") if ver_b else 0
    tag, comm_b, i = _read_tlv(msg, i)
    if tag != 0x04:
        raise ValueError("missing community")
    community = comm_b.decode("utf-8", "replace")
    tag, pdu, _ = _read_tlv(msg, i)
    if tag != 0xA7:                                   # SNMPv2-Trap-PDU
        raise ValueError(f"not a v2c trap PDU (tag=0x{tag:02x})")

    j = 0
    _, _reqid, j = _read_tlv(pdu, j)                  # request-id
    _, _estat, j = _read_tlv(pdu, j)                  # error-status
    _, _eidx, j = _read_tlv(pdu, j)                   # error-index
    tag, vbl, _ = _read_tlv(pdu, j)                   # varbind list
    if tag != 0x30:
        raise ValueError("missing varbind list")

    varbinds: list[tuple[str, Any]] = []
    k = 0
    while k < len(vbl):
        tag, vb, k = _read_tlv(vbl, k)
        if tag != 0x30:
            break
        m = 0
        tag_o, oid_b, m = _read_tlv(vb, m)
        if tag_o != 0x06:
            continue
        tag_v, val_b, _ = _read_tlv(vb, m)
        varbinds.append((_decode_oid(oid_b), _decode_value(tag_v, val_b)))

    # v2c convention: varbind[0]=sysUpTime, varbind[1]=snmpTrapOID.0
    trap_oid = ""
    for oid, value in varbinds:
        if oid == "1.3.6.1.6.3.1.1.4.1.0":
            trap_oid = str(value)
            break
    return {"version": version, "community": community,
             "trap_oid": trap_oid, "varbinds": varbinds}


# ---------------------------------------------------------------- listeners

def _bind_addr() -> str:
    return os.environ.get("SC_EVENTS_BIND", "127.0.0.1")


def _allowed_communities() -> set[str]:
    raw = os.environ.get("SC_TRAP_COMMUNITIES", "")
    return {c.strip() for c in raw.split(",") if c.strip()}


def handle_syslog_datagram(data: bytes, source_ip: str) -> dict:
    """Parse + store one syslog datagram (exposed for tests)."""
    line = data[:_MAX_DGRAM].decode("utf-8", "replace")
    return append_event(normalize_syslog(line, source_ip=source_ip))


def handle_trap_datagram(data: bytes, source_ip: str) -> dict:
    """Decode + store one trap datagram (exposed for tests)."""
    try:
        t = decode_trap(data[:_MAX_DGRAM])
    except ValueError as exc:
        return append_event(Event(
            source="snmp_trap", source_ip=source_ip,
            event_type="trap.malformed", severity="low",
            description=f"Undecodable trap datagram: {exc}",
            raw={"error": str(exc), "size": len(data)}))
    allowed = _allowed_communities()
    if allowed and t["community"] not in allowed:
        return append_event(Event(
            source="snmp_trap", source_ip=source_ip,
            event_type="trap.community_rejected", severity="medium",
            description=("Trap with unlisted community rejected "
                          "(community allowlist active)"),
            raw={"trap_oid": t["trap_oid"]}))
    return append_event(normalize_trap(
        t["trap_oid"], t["varbinds"], source_ip=source_ip))


def _bound_socket(port: int) -> socket.socket:
    """Create + bind the UDP socket in the CALLER's thread so that by
    the time start_listeners() returns, the port is guaranteed open
    (no lost datagrams between start and the thread's first recv)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind((_bind_addr(), port))
    return sock


def _udp_loop(sock: socket.socket, handler, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(_MAX_DGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                handler(data, addr[0])
            except Exception:                          # noqa: BLE001
                continue                                # never kill the loop
    finally:
        sock.close()


def start_listeners() -> dict:
    """Start whichever listeners are enabled. Idempotent per process.
    Returns {syslog_port, trap_port} for whatever actually started."""
    started: dict[str, int] = {}
    if _threads:
        return {"already_running": True}
    both = os.environ.get("SC_EVENTS_LISTENERS", "") == "1"

    syslog_port = int(os.environ.get("SC_SYSLOG_PORT", "5514") or 0) \
        if (both or os.environ.get("SC_SYSLOG_PORT")) else 0
    trap_port = int(os.environ.get("SC_TRAP_PORT", "5162") or 0) \
        if (both or os.environ.get("SC_TRAP_PORT")) else 0

    # Audit fix — all-or-nothing startup. Bind EVERY socket first, then
    # start threads. Previously, a failed trap bind after a successful
    # syslog start left the process half-started, and the idempotency
    # guard (`_threads` non-empty) made every retry a no-op.
    plans = []
    if syslog_port:
        plans.append(("syslog_port", syslog_port, handle_syslog_datagram, "sc-syslog"))
    if trap_port:
        plans.append(("trap_port", trap_port, handle_trap_datagram, "sc-traps"))
    socks = []
    try:
        for _, port, _, _ in plans:
            socks.append(_bound_socket(port))  # bound before we return
    except OSError:
        for s in socks:                        # roll back partial binds
            try:
                s.close()
            except OSError:
                pass
        raise
    for (key, port, handler, name), sock in zip(plans, socks):
        stop = threading.Event()
        t = threading.Thread(target=_udp_loop, args=(sock, handler, stop),
                              name=name, daemon=True)
        t.start()
        _threads.append(t)
        _stops.append(stop)
        started[key] = port
    return started


def stop_listeners() -> None:
    for s in _stops:
        s.set()
    for t in _threads:
        t.join(timeout=2.0)
    _threads.clear()
    _stops.clear()
