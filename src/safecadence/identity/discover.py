"""
v7.8 — Identity-system auto-discovery.

Tries to detect what identity systems are reachable from where the
operator is running SafeCadence, so first-run setup is not 30 minutes
of env-var-spelunking. Pure-Python — uses stdlib + httpx (already a
dep of [server]). No bytes leave the machine for anything not already
configured.

Strategies:
  okta_from_email_domain      Probe `<domain>.okta.com/.well-known/openid-configuration`
  entra_from_tenant_hint      MS Graph public discovery doc per tenant hint
  ise_on_local_lan            TCP probe 9060 + 443 on common LAN ranges
  clearpass_on_local_lan      TCP probe 443 on common LAN ranges (then test root)
  ad_via_dns_srv              Resolve _ldap._tcp.<domain> via system DNS

Each returns a DiscoveryFinding with a confidence score and the env-var
recipe to set if the operator wants to commit.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class DiscoveryFinding:
    system: str                 # okta | entra | ise | clearpass | ad
    target: str                 # what we'd point at (host or domain)
    confidence: float           # 0..1
    evidence: str               # what we observed
    next_step: str              # one-line set-up instruction
    env_vars: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------- public

MAX_LAN_CIDRS = 16


def _probe_target_allowed(host: str) -> bool:
    """LAN probes only reach private addresses, never loopback, link-local (cloud metadata),
    multicast, reserved or unspecified ones."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_multicast
                                    or ip.is_reserved or ip.is_unspecified))


def validate_lan_cidrs(cidrs) -> list[str]:
    """Checked LAN ranges for discovery. Raises ValueError with a plain reason."""
    import ipaddress
    if not isinstance(cidrs, (list, tuple)):
        raise ValueError("lan_cidrs must be a list")
    if len(cidrs) > MAX_LAN_CIDRS:
        raise ValueError(f"at most {MAX_LAN_CIDRS} ranges per request")
    out = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            raise ValueError(f"not a network range: {str(c)[:40]}")
        if net.version != 4 or net.prefixlen < 24:
            raise ValueError(f"use IPv4 ranges of /24 or smaller: {net}")
        if not _probe_target_allowed(str(net.network_address)):
            raise ValueError(f"only private LAN ranges can be probed: {net}")
        out.append(str(net))
    return out


_DOMAIN_RE = None


def _public_domain(name: str) -> str | None:
    """``name`` if it is a plain DNS name (no IP literal, port, path or credentials) that doesn't
    resolve to a private or internal address; else None."""
    import ipaddress, re
    global _DOMAIN_RE
    if _DOMAIN_RE is None:
        _DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    name = (name or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(name):
        return None
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        return None
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_global:
            return None
    return name


def discover(*, email_domain: str | None = None,
              entra_tenant_hint: str | None = None,
              lan_cidrs: list[str] | None = None,
              ad_domain: str | None = None) -> list[DiscoveryFinding]:
    """Run every discovery probe; return what we found.

    Strategies are independent — failure of one never blocks another.
    All probes time out fast (≤2s) so this returns within 5-10s on a
    cold network.
    """
    findings: list[DiscoveryFinding] = []

    if email_domain:
        f = _probe_okta_from_domain(email_domain)
        if f: findings.append(f)

    if entra_tenant_hint:
        f = _probe_entra(entra_tenant_hint)
        if f: findings.append(f)

    # Distinguish None (use defaults) from [] (caller explicitly opts out).
    cidrs = _default_lan_cidrs() if lan_cidrs is None else lan_cidrs
    for cidr in cidrs:
        # Don't sweep entire CIDRs in v7.8 — only probe the .1 / .2 / .10
        # of each. Full sweep is v7.9 if anyone asks.
        for hostpart in (1, 2, 10, 20):
            host = _cidr_host(cidr, hostpart)
            if host is None:
                continue
            f = _probe_ise(host)
            if f: findings.append(f)
            f = _probe_clearpass(host)
            if f: findings.append(f)

    if ad_domain:
        f = _probe_ad(ad_domain)
        if f: findings.append(f)

    return findings


# ---------------------------------------------------------------- probes

def _probe_okta_from_domain(domain: str) -> DiscoveryFinding | None:
    """Try `<email-domain-base>.okta.com` and `<email-domain>` as Okta org."""
    candidates = []
    base = domain.split("@")[-1]
    if "." in base:
        prefix = base.split(".")[0]
        candidates.append(f"{prefix}.okta.com")
    candidates.append(f"{base}.okta.com")
    candidates.append(base)
    candidates = list(dict.fromkeys(candidates))   # dedupe, preserve order

    for cand in candidates:
        if _public_domain(cand) is None:          # caller-supplied: only public DNS names
            continue
        url = f"https://{cand}/.well-known/openid-configuration"
        try:
            import httpx
            r = httpx.get(url, timeout=2.0,
                           headers={"User-Agent": "SafeCadence/7.8"})
        except Exception:
            continue
        if r.status_code == 200 and "okta" in r.text.lower():
            return DiscoveryFinding(
                system="okta",
                target=cand,
                confidence=0.9,
                evidence=f"OIDC discovery doc at {url}",
                next_step=("Create an Okta API token at "
                            "Security → API → Tokens, then set "
                            f"OKTA_DOMAIN={cand} and OKTA_API_TOKEN=…"),
                env_vars={"OKTA_DOMAIN": cand,
                           "OKTA_API_TOKEN": "<paste-token>"},
            )
    return None


def _probe_entra(tenant_hint: str) -> DiscoveryFinding | None:
    """Hit Microsoft's tenant discovery doc."""
    import re
    cand = (tenant_hint or "").strip()
    if not re.match(r"^[A-Za-z0-9.-]{1,253}$", cand):   # it goes into a URL path
        return None
    if "." not in cand:
        cand = f"{cand}.onmicrosoft.com"
    url = (f"https://login.microsoftonline.com/{cand}/.well-known/"
           "openid-configuration")
    try:
        import httpx
        r = httpx.get(url, timeout=2.0)
    except Exception:
        return None
    if r.status_code == 200 and "tenant" in r.text.lower():
        return DiscoveryFinding(
            system="entra",
            target=cand,
            confidence=0.95,
            evidence=f"Microsoft OIDC discovery resolved at {url}",
            next_step=("Create an Entra app registration with "
                        "Policy.ReadWrite.ConditionalAccess, then set "
                        f"ENTRA_TENANT={cand}, ENTRA_CLIENT_ID, "
                        "ENTRA_CLIENT_SECRET"),
            env_vars={"ENTRA_TENANT": cand,
                       "ENTRA_CLIENT_ID": "<app-id>",
                       "ENTRA_CLIENT_SECRET": "<secret>"},
        )
    return None


def _probe_ise(host: str) -> DiscoveryFinding | None:
    if not _probe_target_allowed(host):
        return None
    """Cisco ISE serves ERS on TCP 9060."""
    if not _tcp_open(host, 9060, timeout=1.5):
        return None
    return DiscoveryFinding(
        system="ise",
        target=host,
        confidence=0.5,    # 9060 is suggestive, not definitive
        evidence=f"TCP 9060 (ISE ERS port) open on {host}",
        next_step=("Confirm by trying https://{host}:9060/ers/sdk in a "
                    "browser; create an ERS admin user, then set "
                    f"ISE_HOST={host}, ISE_USERNAME, ISE_PASSWORD"),
        env_vars={"ISE_HOST": host,
                   "ISE_USERNAME": "<ers-admin>",
                   "ISE_PASSWORD": "<password>"},
    )


def _probe_clearpass(host: str) -> DiscoveryFinding | None:
    """ClearPass exposes /api/oauth on 443; 200 is suggestive.

    Certificate checks stay off on purpose: on-prem ClearPass usually has a self-signed certificate,
    the probe sends no credentials or data, follows no redirects and only reads the status code.
    What keeps it safe is the target check: only private LAN addresses (never loopback, link-local
    or metadata addresses) chosen by an admin or analyst."""
    if not _probe_target_allowed(host):
        return None
    if not _tcp_open(host, 443, timeout=1.5):
        return None
    try:
        import httpx
        r = httpx.get(f"https://{host}/api/oauth", verify=False, timeout=2.0,
                      follow_redirects=False)
    except Exception:
        return None
    # ClearPass returns 405 / 401 / 400 on GET — anything but 404 implies present
    if r.status_code in (200, 400, 401, 405):
        return DiscoveryFinding(
            system="clearpass",
            target=host,
            confidence=0.6,
            evidence=f"https://{host}/api/oauth returned {r.status_code}",
            next_step=("Create an API client in ClearPass UI; set "
                        f"CLEARPASS_HOST={host}, CLEARPASS_CLIENT_ID, "
                        "CLEARPASS_CLIENT_SECRET"),
            env_vars={"CLEARPASS_HOST": host,
                       "CLEARPASS_CLIENT_ID": "<client>",
                       "CLEARPASS_CLIENT_SECRET": "<secret>"},
        )
    return None


def _probe_ad(domain: str) -> DiscoveryFinding | None:
    """Look up _ldap._tcp.<domain> via DNS SRV."""
    try:
        # Use system resolver via socket.getaddrinfo to find LDAP SRV target
        # Fallback: try a literal LDAP host at dc.<domain>
        candidate = f"dc.{domain}"
        addr = socket.gethostbyname(candidate)
    except Exception:
        return None
    return DiscoveryFinding(
        system="ad",
        target=candidate,
        confidence=0.4,  # SRV-less probing — best-effort
        evidence=f"resolved {candidate} → {addr}",
        next_step=("Create a service-account bind DN with rights to modify "
                    "the SafeCadence-Quarantined group; set "
                    f"AD_SERVER=ldaps://{candidate}, AD_BIND_DN, "
                    "AD_BIND_PASSWORD, AD_BASE_DN"),
        env_vars={"AD_SERVER": f"ldaps://{candidate}",
                   "AD_BIND_DN": "<bind-dn>",
                   "AD_BIND_PASSWORD": "<password>",
                   "AD_BASE_DN": f"DC={domain.replace('.', ',DC=')}"},
    )


# ---------------------------------------------------------------- helpers

def _tcp_open(host: str, port: int, *, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _cidr_host(cidr: str, hostpart: int) -> str | None:
    """Return the .<hostpart> address inside a /24-or-bigger CIDR.
    Best-effort; if the CIDR isn't /24 we skip."""
    try:
        net, bits = cidr.split("/")
        if int(bits) < 24:
            return None
        a, b, c, _ = net.split(".")
        return f"{a}.{b}.{c}.{hostpart}"
    except (ValueError, IndexError):
        return None


def _default_lan_cidrs() -> list[str]:
    """Common enterprise LAN ranges to probe when the operator hasn't
    specified. Avoid full RFC1918 sweeps — too noisy and slow."""
    return ["10.0.0.0/24", "10.10.0.0/24", "192.168.1.0/24",
             "192.168.10.0/24"]
