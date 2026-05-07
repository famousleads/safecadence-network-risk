"""
v9.5 — Microsoft Entra ID (Azure AD) read connector.

Pulls /devices and optionally /users from Microsoft Graph using a
client-credentials flow (tenant_id + client_id + client_secret). For
hybrid orgs Entra has a different worldview from on-prem AD — it sees
Intune-enrolled phones, BYOD laptops, and managed Macs that an LDAP
search to a DC will miss entirely.

Implementation: HTTPS POST to https://login.microsoftonline.com/{tenant}
/oauth2/v2.0/token, then GET https://graph.microsoft.com/v1.0/devices.
Uses urllib.request to avoid taking a dep on requests. Has an http_fn
test seam.

Endpoint shape from Graph /devices:
  {id, displayName, deviceId, operatingSystem, operatingSystemVersion,
   accountEnabled, deviceOwnership, isCompliant, isManaged,
   approximateLastSignInDateTime, registrationDateTime, ...}
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass
class EntraDevice:
    id: str
    display_name: str = ""
    device_id: str = ""
    os: str = ""
    os_version: str = ""
    enabled: bool = True
    ownership: str = ""        # "company" or "personal"
    compliant: bool = False
    managed: bool = False
    last_signin: str = ""
    registration_date: str = ""


@dataclass
class EntraHarvestResult:
    tenant_id: str
    started_at: str
    finished_at: str
    devices: list[EntraDevice] = field(default_factory=list)
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.devices)


# ----------------------------------------------------- token + graph fetch

HttpFn = Callable[[str, dict, dict, Optional[bytes]], dict]


def _default_http(method: str, url: str, headers: dict,
                  body: Optional[bytes] = None) -> dict:
    """Minimal HTTP wrapper. Returns parsed JSON dict on 2xx, else raises."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HTTP {e.code} from {url}: {msg}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error to {url}: {e.reason}")


def _get_token(tenant_id: str, client_id: str, client_secret: str,
               http_fn: HttpFn) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    out = http_fn("POST", url,
                  {"Content-Type": "application/x-www-form-urlencoded"},
                  body)
    tok = out.get("access_token", "")
    if not tok:
        raise RuntimeError(f"no access_token in token response: {out}")
    return tok


def _list_devices(token: str, http_fn: HttpFn) -> list[dict]:
    """Page through /devices until done. Graph caps at 100/page by default."""
    url = "https://graph.microsoft.com/v1.0/devices?$top=100"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    all_devices: list[dict] = []
    while url:
        page = http_fn("GET", url, headers, None)
        all_devices.extend(page.get("value", []))
        url = page.get("@odata.nextLink", "")
    return all_devices


# ---------------------------------------------------------------- parser

def _parse_devices(raw: list[dict]) -> list[EntraDevice]:
    out: list[EntraDevice] = []
    for d in raw:
        out.append(EntraDevice(
            id=str(d.get("id") or ""),
            display_name=str(d.get("displayName") or ""),
            device_id=str(d.get("deviceId") or ""),
            os=str(d.get("operatingSystem") or ""),
            os_version=str(d.get("operatingSystemVersion") or ""),
            enabled=bool(d.get("accountEnabled", True)),
            ownership=str(d.get("deviceOwnership") or ""),
            compliant=bool(d.get("isCompliant", False)),
            managed=bool(d.get("isManaged", False)),
            last_signin=str(d.get("approximateLastSignInDateTime") or ""),
            registration_date=str(d.get("registrationDateTime") or ""),
        ))
    return out


# -------------------------------------------------------------- harvester

def harvest_entra(tenant_id: str, client_id: str, client_secret: str, *,
                  http_fn: Optional[HttpFn] = None,
                  ) -> EntraHarvestResult:
    """Pull /devices from Microsoft Graph using client-credentials.

    Required Graph perms: ``Device.Read.All`` (admin consent).
    """
    started = datetime.now(timezone.utc).isoformat()
    res = EntraHarvestResult(tenant_id=tenant_id, started_at=started,
                             finished_at="")
    if not (tenant_id and client_id and client_secret):
        res.error = "tenant_id, client_id, and client_secret are all required"
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    fn = http_fn or _default_http
    try:
        token = _get_token(tenant_id, client_id, client_secret, fn)
        raw = _list_devices(token, fn)
    except Exception as e:
        res.error = str(e)
        res.finished_at = datetime.now(timezone.utc).isoformat()
        return res
    res.devices = _parse_devices(raw)
    res.finished_at = datetime.now(timezone.utc).isoformat()
    return res


# --------------------------------------------------- → DiscoveredHost-shape

def devices_as_discovered_hosts(result: EntraHarvestResult) -> list[dict]:
    """Convert Entra devices to bridge.discovered_to_asset() input shape."""
    out: list[dict] = []
    for d in result.devices:
        os_lower = d.os.lower()
        if "windows" in os_lower:
            os_guess = "windows"; vendor = "microsoft"
        elif "ios" in os_lower or "ipad" in os_lower:
            os_guess = "ios"; vendor = "apple"
        elif "mac" in os_lower:
            os_guess = "macos"; vendor = "apple"
        elif "android" in os_lower:
            os_guess = "android"; vendor = "google"
        elif "linux" in os_lower:
            os_guess = "linux"; vendor = ""
        else:
            os_guess = ""; vendor = ""
        dev_type = "mobile" if os_guess in ("ios", "android") else "server"
        out.append({
            "ip": "",
            "hostname": d.display_name,
            "mac": "",
            "vendor_guess": vendor,
            "os_guess": os_guess,
            "device_type_guess": dev_type,
            "snmp_sysdescr": f"{d.os} {d.os_version}".strip(),
            "open_ports": [],
            "banners": {
                "_via": f"entra tenant {result.tenant_id[:8]}…",
                "_ownership": d.ownership,
                "_compliant": "yes" if d.compliant else "no",
                "_managed": "yes" if d.managed else "no",
                "_last_signin": d.last_signin,
                "_enabled": "yes" if d.enabled else "no",
            },
        })
    return out
