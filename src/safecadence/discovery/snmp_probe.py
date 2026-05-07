"""
SNMP v2c sysDescr probe — pure stdlib, no pysnmp dependency.

Most enterprise network gear (Cisco, Aruba, Arista, Juniper, HP, Fortinet,
Palo Alto, etc.) responds to SNMP v2c GETs with their full sysDescr.0 string.
That string typically contains:
  - vendor
  - product line / model
  - OS name + version + train

Example sysDescr from a Cisco IOS switch:
  "Cisco IOS Software, C3560 Software (C3560-IPSERVICESK9-M),
   Version 12.2(55)SE9, RELEASE SOFTWARE (fc1)"

That single string lets us populate vendor, os_guess, os_version, model,
device_type — all from one UDP packet.

We try a small list of commonly-default community strings. If none of them
work, we fall back to TCP-banner identification.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional


# OID 1.3.6.1.2.1.1.1.0 = sysDescr.0
_SYS_DESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)
_SYS_NAME_OID = (1, 3, 6, 1, 2, 1, 1, 5, 0)

# Community strings to try, in order. Most-likely-to-work first.
DEFAULT_COMMUNITIES = ("public", "private", "community", "snmpread", "monitoring")


# ---------------------------------------------------------------- BER helpers
def _ber_encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber_encode_integer(n: int) -> bytes:
    body = n.to_bytes(((n.bit_length() // 8) + 1), "big", signed=False) if n >= 0 else b""
    if not body:
        body = b"\x00"
    # Pad if high bit set so it's not interpreted as negative
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + _ber_encode_length(len(body)) + body


def _ber_encode_octet_string(s: bytes) -> bytes:
    return b"\x04" + _ber_encode_length(len(s)) + s


def _ber_encode_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID must have at least 2 components")
    body = bytes([oid[0] * 40 + oid[1]])
    for n in oid[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            # Multi-byte base-128
            buf = []
            while n > 0:
                buf.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(buf) - 1):
                buf[i] |= 0x80
            body += bytes(buf)
    return b"\x06" + _ber_encode_length(len(body)) + body


def _ber_encode_null() -> bytes:
    return b"\x05\x00"


def _ber_encode_sequence(*parts: bytes, tag: int = 0x30) -> bytes:
    body = b"".join(parts)
    return bytes([tag]) + _ber_encode_length(len(body)) + body


# ---------------------------------------------------------------- Build SNMPv2c GET
def _build_get_request(community: str, oid: tuple[int, ...], request_id: int = 1) -> bytes:
    """
    Build a complete SNMPv2c GET request packet for the given OID.

    Structure:
      SEQUENCE
        INTEGER version (1 = v2c)
        OCTET STRING community
        Get-Request PDU [tag 0xa0]
          INTEGER request-id
          INTEGER error-status (0)
          INTEGER error-index  (0)
          SEQUENCE varbinds
            SEQUENCE
              OID
              NULL
    """
    varbind = _ber_encode_sequence(_ber_encode_oid(oid), _ber_encode_null())
    varbinds = _ber_encode_sequence(varbind)
    pdu = _ber_encode_sequence(
        _ber_encode_integer(request_id),
        _ber_encode_integer(0),  # error-status
        _ber_encode_integer(0),  # error-index
        varbinds,
        tag=0xA0,  # Get-Request
    )
    msg = _ber_encode_sequence(
        _ber_encode_integer(1),  # version v2c
        _ber_encode_octet_string(community.encode("utf-8")),
        pdu,
    )
    return msg


# ---------------------------------------------------------------- Parse SNMP response
def _parse_length(data: bytes, idx: int) -> tuple[int, int]:
    """Return (length, new_idx)."""
    b = data[idx]
    idx += 1
    if b < 0x80:
        return b, idx
    n = b & 0x7F
    length = int.from_bytes(data[idx:idx + n], "big")
    return length, idx + n


def _extract_octet_string(data: bytes) -> Optional[str]:
    """
    Walk the SNMP response BER and return the LAST octet string found
    (the value of sysDescr in our reply structure).
    """
    found_strings: list[str] = []
    i = 0
    while i < len(data):
        tag = data[i]
        i += 1
        try:
            length, i = _parse_length(data, i)
        except Exception:
            return None
        if tag == 0x04:  # OCTET STRING
            try:
                found_strings.append(data[i:i + length].decode("utf-8", errors="replace"))
            except Exception:
                pass
            i += length
        elif tag in (0x30, 0xA0, 0xA1, 0xA2):  # SEQUENCE / PDU
            # descend
            continue
        else:
            i += length
    if not found_strings:
        return None
    # The last octet string is the value (after community + OID stuff)
    # but the longest one is usually sysDescr. Pick the longest non-community.
    found_strings.sort(key=len, reverse=True)
    return found_strings[0]


# ---------------------------------------------------------------- Public API
def snmp_get_sysdescr(
    ip: str,
    *,
    timeout: float = 1.5,
    communities: tuple[str, ...] = DEFAULT_COMMUNITIES,
    port: int = 161,
) -> dict:
    """
    Try each community string until one returns a sysDescr.0 string.

    Returns dict:
      {
        "ok":         bool — True if any community succeeded
        "community":  str  — which community worked (None if failed)
        "sys_descr":  str  — the full sysDescr.0 value
        "sys_name":   str  — the sysName.0 value (hostname per device's view)
      }

    Network packets sent: at most len(communities)*2 UDP packets.
    Round-trip: typically <1s per community on the LAN.
    """
    out = {"ok": False, "community": "", "sys_descr": "", "sys_name": ""}

    for community in communities:
        # First: sysDescr.0
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(_build_get_request(community, _SYS_DESCR_OID), (ip, port))
            data, _ = sock.recvfrom(4096)
            sd = _extract_octet_string(data)
            if not sd or sd == community:
                continue
            out["ok"] = True
            out["community"] = community
            out["sys_descr"] = sd

            # Second: sysName.0 (best-effort)
            sock.sendto(_build_get_request(community, _SYS_NAME_OID, request_id=2), (ip, port))
            data2, _ = sock.recvfrom(4096)
            sn = _extract_octet_string(data2)
            if sn and sn != community:
                out["sys_name"] = sn
            return out
        except (socket.timeout, OSError):
            continue
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    return out


def parse_sysdescr(s: str) -> dict:
    """
    Heuristic vendor/model/OS extraction from a sysDescr.0 string.
    Best-effort — returns {} if nothing recognizable.
    """
    if not s:
        return {}
    sl = s.lower()
    out = {}
    # Cisco
    if "cisco" in sl:
        out["vendor"] = "Cisco"
        if "ios xe" in sl or "ios-xe" in sl:
            out["os"] = "ios-xe"
        elif "nx-os" in sl or "nxos" in sl:
            out["os"] = "nxos"
        elif "asa" in sl and "version" in sl:
            out["os"] = "asa"
        elif "ios software" in sl or "internetwork operating" in sl:
            out["os"] = "ios"
        # Try to extract version like "Version 12.2(55)SE9"
        import re
        m = re.search(r"version[:\s]+([0-9.()a-zA-Z-]{3,30})", s, re.IGNORECASE)
        if m:
            out["version"] = m.group(1)
    elif "arista" in sl:
        out["vendor"] = "Arista"; out["os"] = "eos"
    elif "aruba" in sl or "arubaos" in sl:
        out["vendor"] = "Aruba"; out["os"] = "aos-cx" if "aos-cx" in sl else "aos"
    elif "juniper" in sl or "junos" in sl:
        out["vendor"] = "Juniper"; out["os"] = "junos"
    elif "fortinet" in sl or "fortios" in sl or "fortigate" in sl:
        out["vendor"] = "Fortinet"; out["os"] = "fortios"
    elif "palo alto" in sl or "pan-os" in sl:
        out["vendor"] = "Palo Alto"; out["os"] = "pan-os"
    elif "mikrotik" in sl or "routeros" in sl:
        out["vendor"] = "MikroTik"; out["os"] = "routeros"
    elif "ubnt" in sl or "ubiquiti" in sl or "edgeos" in sl:
        out["vendor"] = "Ubiquiti"
    elif "linux" in sl:
        out["vendor"] = out.get("vendor", ""); out["os"] = "linux"
    elif "windows" in sl:
        out["os"] = "windows"
    elif "freebsd" in sl:
        out["os"] = "freebsd"
    elif "vmware" in sl or "esxi" in sl:
        out["vendor"] = "VMware"; out["os"] = "esxi"
    elif "synology" in sl:
        out["vendor"] = "Synology"; out["os"] = "dsm"
    elif "qnap" in sl:
        out["vendor"] = "QNAP"; out["os"] = "qts"

    return out
