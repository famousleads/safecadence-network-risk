"""
MAC OUI -> vendor lookup.

Uses a small bundled lookup table covering the network-equipment vendors
SafeCadence cares about. For exhaustive coverage, ship the full IEEE OUI
database in v0.2.
"""

from __future__ import annotations

# OUI prefix (first 6 hex chars, no separators) -> vendor name
# Hand-picked — covers the most common Cisco / Aruba / Juniper / Arista / HP /
# Fortinet / Palo Alto / MikroTik / Ubiquiti / Meraki / Mist devices.
_OUI: dict[str, str] = {
    # Cisco — partial list; Cisco has hundreds
    "00000C": "Cisco", "0001C7": "Cisco", "0002B9": "Cisco", "0002BA": "Cisco",
    "0003E3": "Cisco", "00059A": "Cisco", "0005DC": "Cisco", "0007B3": "Cisco",
    "0009B6": "Cisco", "000A41": "Cisco", "000B45": "Cisco", "000B46": "Cisco",
    "000C30": "Cisco", "000D28": "Cisco", "000ECF": "Cisco", "000F23": "Cisco",
    "0011BB": "Cisco", "001179": "Cisco", "0013C3": "Cisco", "00146A": "Cisco",
    "0015F9": "Cisco", "001721": "Cisco", "0019AA": "Cisco", "001A6D": "Cisco",
    "001B53": "Cisco", "001C58": "Cisco", "001E13": "Cisco", "001F26": "Cisco",
    "0022BD": "Cisco", "0024C4": "Cisco", "002608": "Cisco", "002651": "Cisco",
    "0025B4": "Cisco", "002A6A": "Cisco", "0040E0": "Cisco", "00504B": "Cisco",
    "005056": "Cisco", "006052": "Cisco", "00643B": "Cisco", "0083C0": "Cisco",
    "00904C": "Cisco", "00BCE6": "Cisco", "00CCFC": "Cisco", "00D006": "Cisco",
    "00E08F": "Cisco", "00FE5C": "Cisco", "0469F8": "Cisco", "08D40C": "Cisco",
    "0CD996": "Cisco", "1062EB": "Cisco", "10B7F6": "Cisco", "1869CE": "Cisco",
    "20BBC0": "Cisco", "2C543D": "Cisco", "2CD02D": "Cisco", "302303": "Cisco",
    "3C0E23": "Cisco", "44E08E": "Cisco", "4C0082": "Cisco", "4C710C": "Cisco",
    "5067AE": "Cisco", "542F89": "Cisco", "58971E": "Cisco", "5C5015": "Cisco",
    "60735C": "Cisco", "64F69D": "Cisco", "688F84": "Cisco", "70CA9B": "Cisco",
    "78DA6E": "Cisco", "7C95F3": "Cisco", "8478AC": "Cisco", "84B5170": "Cisco",
    "9077B0": "Cisco", "94D469": "Cisco", "98E7F4": "Cisco", "B414892": "Cisco",
    "B4A4E3": "Cisco", "BC1665": "Cisco", "C067AF": "Cisco", "D4A02A": "Cisco",
    "E0AC0B": "Cisco", "E886A1": "Cisco", "F02FA7": "Cisco", "FCFB8B": "Cisco",
    # Cisco Meraki
    "0018BA": "Cisco Meraki", "00187D": "Cisco Meraki", "001D70": "Cisco Meraki",
    "0CF42C": "Cisco Meraki", "ACBB0F": "Cisco Meraki", "C476C8": "Cisco Meraki",
    "DC2C6E": "Cisco Meraki", "E0CB1D": "Cisco Meraki", "E8A21D": "Cisco Meraki",
    "F8F8E7": "Cisco Meraki",
    # HPE / Aruba (and pre-acquisition Aruba Networks)
    "001083": "HP", "0010E7": "HP", "0011A5": "HP", "00116B": "HP",
    "001A4B": "HP", "001CC4": "HP", "001E0B": "HP", "001F29": "HP",
    "002264": "HP", "0023AE": "HP", "00237D": "HP", "002481": "HP",
    "0024A8": "HP", "0025B3": "HP", "0026F1": "HP", "002AAF": "HP",
    "00306E": "HP", "003064": "HP", "00807E": "HP", "00B0D0": "HP",
    "001A1E": "Aruba", "0024F7": "Aruba", "002604": "Aruba", "00295A": "Aruba",
    "60D248": "Aruba", "6CF37F": "Aruba", "70CD60": "Aruba", "84D47E": "Aruba",
    "9C1C12": "Aruba", "ACA31E": "Aruba", "B47AF1": "Aruba", "F08260": "Aruba",
    # Juniper
    "001083": "Juniper", "001E5A": "Juniper", "00216A": "Juniper", "002283": "Juniper",
    "002405": "Juniper", "0026C1": "Juniper", "002D9B": "Juniper", "00904C": "Juniper",
    "08A47A": "Juniper", "0C8625": "Juniper", "204E71": "Juniper", "281878": "Juniper",
    "30B64F": "Juniper", "44F458": "Juniper", "4C7A40": "Juniper", "5C5EAB": "Juniper",
    "78FE3D": "Juniper", "84B59C": "Juniper", "EC1300": "Juniper", "EC3EF7": "Juniper",
    "F0F00A": "Juniper", "F4A739": "Juniper",
    # Arista
    "00112233": "Arista",  # placeholder
    "001C73": "Arista", "744D28": "Arista", "98F2B3": "Arista", "C8159F": "Arista",
    "FCBD67": "Arista", "F4525E": "Arista", "00BB60": "Arista", "281C9F": "Arista",
    # Fortinet
    "001E96": "Fortinet", "0009F0": "Fortinet", "043F1B": "Fortinet", "08CCA7": "Fortinet",
    "9050BA": "Fortinet", "70451B": "Fortinet", "AC1E04": "Fortinet", "C40838": "Fortinet",
    "F0CABA": "Fortinet", "FC95EA": "Fortinet",
    # Palo Alto
    "001B17": "Palo Alto Networks", "B4E2C0": "Palo Alto Networks",
    "BCF1F2": "Palo Alto Networks", "BCC74D": "Palo Alto Networks",
    # Ubiquiti
    "002722": "Ubiquiti", "0418D6": "Ubiquiti", "044BED": "Ubiquiti", "245A4C": "Ubiquiti",
    "44D9E7": "Ubiquiti", "687251": "Ubiquiti", "74AC5F": "Ubiquiti", "78457A": "Ubiquiti",
    "788A20": "Ubiquiti", "802AA8": "Ubiquiti", "942A6F": "Ubiquiti", "AC8BA9": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "E063DA": "Ubiquiti", "F09FC2": "Ubiquiti",
    "FC0A81": "Ubiquiti", "FCECDA": "Ubiquiti",
    # MikroTik
    "000C42": "MikroTik", "08555D": "MikroTik", "18FD74": "MikroTik", "2CC81B": "MikroTik",
    "4C5E0C": "MikroTik", "6469BC": "MikroTik", "6C3B6B": "MikroTik", "B869F4": "MikroTik",
    "CC2DE0": "MikroTik", "D4CA6D": "MikroTik", "E48D8C": "MikroTik",
    # Mist (Juniper)
    "5C5B35": "Mist (Juniper)", "F0E8F4": "Mist (Juniper)",
    # Common server / hypervisor
    "000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
    "525400": "QEMU/KVM", "080027": "VirtualBox",
    "F01FAF": "Dell", "001E4F": "Dell", "002219": "Dell", "00219B": "Dell",
    "0014C2": "HP Server", "001E0B": "HP Server", "002481": "HP Server",
    # Apple, Intel etc — useful for distinguishing client vs network gear
    "001451": "Apple", "001CB3": "Apple", "001D4F": "Apple", "002241": "Apple",
    "0023DF": "Apple", "002500": "Apple", "0026B0": "Apple", "0026BB": "Apple",
    "F40F24": "Apple", "F8E94E": "Apple",
    "001517": "Intel", "001CC0": "Intel", "001E64": "Intel", "001F3B": "Intel",
    "002164": "Intel", "0021CC": "Intel", "00266C": "Intel",
}


def _normalize(mac: str) -> str:
    """Strip separators and uppercase. '00:11:22:33:44:55' -> '00112233445500'."""
    return "".join(c for c in (mac or "") if c.isalnum()).upper()


def vendor_for(mac: str) -> str:
    """Return the vendor name for a MAC, or '' if unknown."""
    norm = _normalize(mac)
    if len(norm) < 6:
        return ""
    return _OUI.get(norm[:6], "")


def is_network_gear(vendor: str) -> bool:
    """True if the vendor is one of our supported network-equipment vendors."""
    if not vendor:
        return False
    v = vendor.lower()
    return any(k in v for k in (
        "cisco", "aruba", "hp", "juniper", "mist",
        "arista", "fortinet", "palo alto", "ubiquiti", "mikrotik",
    ))
