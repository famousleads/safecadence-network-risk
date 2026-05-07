"""
v9.5 — Active Directory / LDAP read connector.

Search a Windows AD or any LDAP directory for computer objects and return
them as DiscoveredHost-shaped dicts. AD is the single biggest source of
endpoints in any enterprise — every domain-joined Windows / Mac / Linux
host shows up here with OS, last-seen, OU, and SPNs.

Implementation: uses ldap3 if installed (we already depend on it for v7.6
write-back). Falls back to a clear "pip install ldap3" message. Has a
search_fn test seam so unit tests don't need a real DC.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# computer-object attributes we care about (AD schema)
_COMPUTER_ATTRS = [
    "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "lastLogonTimestamp", "whenCreated",
    "whenChanged", "distinguishedName", "servicePrincipalName",
    "userAccountControl", "objectSid",
]


@dataclass
class ADComputer:
    """One computer object as harvested from AD."""
    name: str
    dns_hostname: str = ""
    os: str = ""
    os_version: str = ""
    last_logon: str = ""
    distinguished_name: str = ""
    ou: str = ""
    enabled: bool = True
    spns: list[str] = field(default_factory=list)


@dataclass
class ADHarvestResult:
    server: str
    base_dn: str
    started_at: str
    finished_at: str
    computers: list[ADComputer] = field(default_factory=list)
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.computers)


# ----------------------------------------------------------- ldap3 wrapper

SearchFn = Callable[..., list[dict]]


def _default_search(server: str, base_dn: str, *,
                    bind_dn: str, password: str,
                    ldap_filter: str = "(objectClass=computer)",
                    use_ssl: bool = True,
                    timeout: int = 30) -> list[dict]:
    """Default search: ldap3 LDAP search, returns one dict per entry."""
    try:
        import ldap3                                       # type: ignore
    except ImportError:
        raise RuntimeError(
            "ldap3 not installed. Run `pip install ldap3` "
            "or use a SafeCadence install with the 'identity' extra."
        )
    proto = "ldaps" if use_ssl else "ldap"
    s = ldap3.Server(f"{proto}://{server}", get_info=ldap3.NONE,
                     connect_timeout=timeout)
    conn = ldap3.Connection(s, user=bind_dn, password=password,
                            auto_bind=True, raise_exceptions=True)
    try:
        conn.search(search_base=base_dn,
                    search_filter=ldap_filter,
                    attributes=_COMPUTER_ATTRS,
                    paged_size=1000)
        out: list[dict] = []
        for entry in conn.entries:
            d: dict = {}
            for attr in _COMPUTER_ATTRS:
                v = entry[attr].value if attr in entry else None
                if v is None:
                    continue
                d[attr] = v
            d["distinguishedName"] = entry.entry_dn
            out.append(d)
        return out
    finally:
        try: conn.unbind()
        except Exception: pass


# --------------------------------------------------------------- parsers

def _ou_from_dn(dn: str) -> str:
    """CN=PC1,OU=Workstations,OU=Corp,DC=acme,DC=com → 'Workstations/Corp'."""
    parts = []
    for chunk in dn.split(","):
        chunk = chunk.strip()
        if chunk.upper().startswith("OU="):
            parts.append(chunk[3:])
    return "/".join(reversed(parts))


def _enabled_from_uac(uac: int | str) -> bool:
    """userAccountControl bit 0x2 = ACCOUNTDISABLE."""
    try:
        return not (int(uac) & 0x2)
    except (ValueError, TypeError):
        return True


def _parse_entries(entries: list[dict]) -> list[ADComputer]:
    out: list[ADComputer] = []
    for d in entries:
        name = str(d.get("name") or "").strip()
        if not name:
            continue
        spns = d.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        last = d.get("lastLogonTimestamp") or d.get("whenChanged") or ""
        if hasattr(last, "isoformat"):
            last = last.isoformat()
        out.append(ADComputer(
            name=name,
            dns_hostname=str(d.get("dNSHostName") or ""),
            os=str(d.get("operatingSystem") or ""),
            os_version=str(d.get("operatingSystemVersion") or ""),
            last_logon=str(last)[:32],
            distinguished_name=str(d.get("distinguishedName") or ""),
            ou=_ou_from_dn(str(d.get("distinguishedName") or "")),
            enabled=_enabled_from_uac(d.get("userAccountControl", 0)),
            spns=list(spns),
        ))
    return out


# -------------------------------------------------------------- harvester

def harvest_ad(server: str, *,
               bind_dn: str = "",
               password: str = "",
               base_dn: str = "",
               ldap_filter: str = "(objectClass=computer)",
               use_ssl: bool = True,
               search_fn: Optional[SearchFn] = None,
               ) -> ADHarvestResult:
    """Search an AD/LDAP server for computer objects.

    Args:
        server:    DC hostname or IP (e.g. dc01.acme.local)
        bind_dn:   bind user (e.g. CN=svc_safecadence,OU=Service,DC=acme,DC=com)
        password:  bind password
        base_dn:   search base (e.g. DC=acme,DC=com)
        ldap_filter: LDAP filter; defaults to all computer objects
        use_ssl:   LDAPS (default true)
        search_fn: test seam (returns list-of-dict entries)
    """
    started = datetime.now(timezone.utc).isoformat()
    res = ADHarvestResult(server=server, base_dn=base_dn,
                          started_at=started, finished_at="")
    search = search_fn or _default_search
    if not server:
        res.error = "server required"
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    try:
        entries = search(server, base_dn,
                          bind_dn=bind_dn, password=password,
                          ldap_filter=ldap_filter, use_ssl=use_ssl)
    except Exception as e:
        res.error = str(e)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.computers = _parse_entries(entries)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# --------------------------------------------------- → DiscoveredHost-shape

def computers_as_discovered_hosts(result: ADHarvestResult) -> list[dict]:
    """Convert AD computers to bridge.discovered_to_asset() input shape."""
    out: list[dict] = []
    for c in result.computers:
        os_lower = c.os.lower()
        os_guess = ""
        if "windows" in os_lower:
            os_guess = "windows"
        elif "linux" in os_lower:
            os_guess = "linux"
        elif "mac" in os_lower or "darwin" in os_lower:
            os_guess = "macos"
        # Type heuristic: server OS → server, otherwise endpoint (server type
        # in our schema also covers workstations).
        dev_type = "server"
        if "workstation" in os_lower or "10" in c.os or "11" in c.os:
            if "server" not in os_lower:
                dev_type = "server"  # endpoint == server in our schema
        out.append({
            "ip": "",                              # AD doesn't expose IP directly
            "hostname": c.dns_hostname or c.name,
            "mac": "",
            "vendor_guess": "microsoft" if os_guess == "windows" else "",
            "os_guess": os_guess,
            "device_type_guess": dev_type,
            "snmp_sysdescr": c.os + " " + c.os_version,
            "open_ports": [],
            "banners": {
                "_via": f"ad on {result.server}",
                "_ou": c.ou,
                "_dn": c.distinguished_name,
                "_last_logon": c.last_logon,
                "_enabled": "yes" if c.enabled else "no",
            },
        })
    return out
