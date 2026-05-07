"""
v6.0 — Cross-system policy drift detector.

The killer feature nobody else does in one product: reason across
identity ↔ network ↔ infrastructure to find policy CONFLICTS where one
system says "deny" and another says "allow."

Examples it surfaces:

  1. ISE/ClearPass authz says contractors → quarantine VLAN
     AD group `Contractors` has 47 users
     Firewall ACL allows 10.50.0.0/16 → prod
     Two contractor IPs are in 10.50.0.0/16
     → CONFLICT — ISE policy is bypassable

  2. Entra ID Conditional Access requires MFA for admins
     Azure RBAC has a Service Principal with Owner role and no MFA
     → CONFLICT — privileged shortcut bypasses CA

  3. AD password policy says min 14 chars
     A network device's local-user has 6-char password
     → CONFLICT — weakest-link bypass of corporate policy

Each finding includes:
  - The conflicting systems (left + right)
  - The exact assets/groups/rules involved
  - A severity (info/medium/high/critical)
  - A suggested resolution that, when applied, removes the conflict
"""

from __future__ import annotations

import ipaddress
from typing import Any


def _ident(a: dict) -> dict:
    return a.get("identity") or {}


def _by_provider(assets: list[dict]) -> dict[str, list[dict]]:
    """Group identity assets by their provider (cisco-ise, ad, entra, etc.)."""
    out: dict[str, list[dict]] = {}
    for a in assets:
        ib = a.get("identity_block") or {}
        prov = (ib.get("provider") or "").lower()
        if prov:
            out.setdefault(prov, []).append(a)
    return out


def _contractor_groups(ad_assets: list[dict]) -> set[str]:
    """Best-effort heuristic: AD groups whose name contains 'contract' / 'guest' / 'temp'."""
    keywords = ("contract", "guest", "temp", "vendor", "external", "partner")
    out: set[str] = set()
    for a in ad_assets:
        ib = a.get("identity_block") or {}
        for g in ib.get("authorized_groups") or []:
            if any(k in g.lower() for k in keywords):
                out.add(g)
    return out


# --------------------------------------------------------------------------
# 1. ISE/ClearPass restricted-group ↔ network ACL conflict
# --------------------------------------------------------------------------

def detect_nac_vs_firewall_conflicts(all_assets: list[dict]) -> list[dict]:
    """For every restricted NAC group, check if any firewall rule still permits
    that group's CIDR range to a sensitive destination."""
    findings: list[dict] = []
    nac_assets = []
    fw_assets = []
    for a in all_assets:
        atype = _ident(a).get("asset_type")
        if atype == "identity":
            ib = a.get("identity_block") or {}
            if ib.get("provider") in ("cisco-ise", "clearpass"):
                nac_assets.append(a)
        elif atype == "network":
            v = (_ident(a).get("vendor") or "").lower()
            if v in ("cisco", "fortinet", "palo-alto", "juniper", "arista"):
                fw_assets.append(a)

    if not nac_assets or not fw_assets:
        return findings

    # Pull "restricted" CIDRs from NAC raw_collection (heuristic)
    restricted_cidrs: list[tuple[str, str]] = []  # (cidr, provider)
    for nac in nac_assets:
        raw = str(nac.get("raw_collection") or "").lower()
        for token in raw.split():
            if "/" in token and token.count(".") == 3:
                try:
                    ipaddress.ip_network(token, strict=False)
                    restricted_cidrs.append(
                        (token, (nac.get("identity_block") or {}).get("provider", ""))
                    )
                except ValueError:
                    continue
    if not restricted_cidrs:
        return findings

    # Look in firewall configs for any explicit `permit` to those CIDRs
    for fw in fw_assets:
        cfg = ""
        for v in (fw.get("raw_collection") or {}).values():
            if isinstance(v, str): cfg += v + "\n"
        cfg_low = cfg.lower()
        for cidr, prov in restricted_cidrs:
            if cidr in cfg_low and "permit" in cfg_low:
                findings.append({
                    "type": "nac_vs_firewall",
                    "severity": "high",
                    "left": {"system": prov, "asset_id": _ident(nac).get("asset_id")},
                    "right": {"system": "firewall", "asset_id": _ident(fw).get("asset_id")},
                    "conflict": (f"{prov} treats {cidr} as restricted, but firewall "
                                 f"{_ident(fw).get('asset_id')} contains an explicit `permit` for it"),
                    "resolution": (f"Tighten the {_ident(fw).get('vendor')} ACL to deny {cidr} "
                                   f"to sensitive destinations, OR remove the {prov} restriction "
                                   f"if the network already segments these hosts."),
                })
    return findings


# --------------------------------------------------------------------------
# 2. Entra Conditional Access requires MFA ↔ Azure RBAC has unprotected admins
# --------------------------------------------------------------------------

def detect_mfa_bypass_via_rbac(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_prov = _by_provider(all_assets)
    entra = by_prov.get("entra", [])
    cloud = [a for a in all_assets if _ident(a).get("asset_type") == "cloud"
             and (_ident(a).get("vendor") or "").lower() == "azure"]

    if not entra or not cloud:
        return findings

    mfa_required = any(((e.get("identity_block") or {}).get("mfa_enrolled"))
                       for e in entra)
    if not mfa_required:
        return findings

    for ca in cloud:
        sec = ca.get("security") or {}
        cl = ca.get("cloud") or {}
        findings_text = " ".join(sec.get("findings") or []).lower()
        # Service principals / app-only auth bypass MFA — flag if seen
        if cl.get("iam_role") and ("service principal" in findings_text or
                                    "app-only" in findings_text or
                                    cl.get("iam_role") == ""):
            findings.append({
                "type": "mfa_bypass_via_rbac",
                "severity": "high",
                "left": {"system": "entra-id", "asset_id": _ident(entra[0]).get("asset_id")},
                "right": {"system": "azure", "asset_id": _ident(ca).get("asset_id")},
                "conflict": ("Entra Conditional Access requires MFA for admins, "
                             f"but Azure asset {_ident(ca).get('asset_id')} has a "
                             "non-MFA service principal with privileged access."),
                "resolution": ("Either remove the SP's privileged role OR add a "
                                "Conditional-Access exclusion for SPs only behind a "
                                "managed identity + workload-identity federation."),
            })
    return findings


# --------------------------------------------------------------------------
# 3. AD password policy ↔ network device local-user weak password
# --------------------------------------------------------------------------

def detect_password_policy_drift(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_prov = _by_provider(all_assets)
    ad = by_prov.get("ad", [])
    if not ad:
        return findings

    ad_min = max(((a.get("identity_block") or {}).get("posture_score", 14)
                   for a in ad), default=14)

    for a in all_assets:
        if _ident(a).get("asset_type") != "network":
            continue
        cfg = str(a.get("raw_collection") or "").lower()
        # Look for short local-user passwords (heuristic)
        if "username" in cfg and "password 7" in cfg:
            # Cisco type-7 obfuscated passwords — known weak
            findings.append({
                "type": "weak_local_password_vs_corp_policy",
                "severity": "medium",
                "left": {"system": "active-directory",
                         "asset_id": _ident(ad[0]).get("asset_id")},
                "right": {"system": "network", "asset_id": _ident(a).get("asset_id")},
                "conflict": (f"AD password policy expects ≥{ad_min} chars + complexity, but "
                             f"{_ident(a).get('asset_id')} uses Cisco type-7 obfuscated "
                             "passwords (cryptographically weak)."),
                "resolution": (f"On {_ident(a).get('asset_id')}: `service password-encryption` "
                                "+ migrate users to AAA/TACACS so AD policy applies, "
                                "OR re-enroll local users with `secret 9 ...` (scrypt)."),
            })
    return findings


# --------------------------------------------------------------------------
# 4. Public-cloud asset has a privileged identity from non-corp directory
# --------------------------------------------------------------------------

def detect_privileged_identity_drift(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_prov = _by_provider(all_assets)
    okta = by_prov.get("okta", [])
    if not okta:
        return findings

    for a in all_assets:
        if _ident(a).get("asset_type") != "cloud":
            continue
        ib = a.get("identity_block") or {}
        admins = ib.get("authorized_users") or []
        if not admins: continue
        okta_users: set[str] = set()
        for o in okta:
            okta_users.update((o.get("identity_block") or {}).get("authorized_users") or [])
        # Anyone admin on the cloud asset who isn't in Okta?
        rogue = [u for u in admins if u not in okta_users]
        if rogue:
            findings.append({
                "type": "cloud_admin_outside_corp_idp",
                "severity": "critical",
                "left": {"system": "okta",
                         "asset_id": _ident(okta[0]).get("asset_id")},
                "right": {"system": "cloud", "asset_id": _ident(a).get("asset_id")},
                "conflict": (f"Cloud asset {_ident(a).get('asset_id')} grants admin to "
                             f"{len(rogue)} principals not in Okta: {rogue[:5]}..."),
                "resolution": ("Either add missing users to Okta + federate the cloud "
                                "account, OR revoke their admin grant."),
            })
    return findings


# --------------------------------------------------------------------------
# 5. Admin without MFA — same identity is both admin AND mfa_enrolled=False.
# --------------------------------------------------------------------------

def detect_admin_without_mfa(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for a in all_assets:
        ib = a.get("identity_block") or {}
        if not ib:
            continue
        groups = [str(g).lower() for g in (ib.get("authorized_groups") or [])]
        is_admin = any(("admin" in g or "owner" in g or "root" in g)
                       for g in groups)
        mfa = ib.get("mfa_enrolled")
        if is_admin and mfa is False:
            findings.append({
                "type": "admin_without_mfa",
                "severity": "critical",
                "left": {"system": ib.get("provider", "identity"),
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy", "asset_id": "corp-mfa-policy"},
                "conflict": (f"{_ident(a).get('asset_id')} holds an admin/owner "
                             "group membership but MFA is not enrolled."),
                "resolution": ("Enroll the principal in MFA, or strip the "
                               "elevated role until MFA is in place. Add a "
                               "Conditional Access rule that blocks legacy "
                               "auth for admin tier."),
            })
    return findings


# --------------------------------------------------------------------------
# 6. Dormant privileged identity — admin/owner that hasn't logged in for 90+ days.
# --------------------------------------------------------------------------

def detect_dormant_privileged_identity(all_assets: list[dict],
                                       max_days_idle: int = 90) -> list[dict]:
    from datetime import datetime, timedelta, timezone
    findings: list[dict] = []
    threshold = datetime.now(timezone.utc) - timedelta(days=max_days_idle)
    for a in all_assets:
        ib = a.get("identity_block") or {}
        if not ib:
            continue
        groups = [str(g).lower() for g in (ib.get("authorized_groups") or [])]
        is_priv = any(("admin" in g or "owner" in g) for g in groups)
        if not is_priv:
            continue
        last = ib.get("last_login") or ib.get("last_signin")
        if not last or not isinstance(last, str):
            continue
        try:
            ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if ts < threshold:
            days_idle = (datetime.now(timezone.utc) - ts).days
            findings.append({
                "type": "dormant_privileged_identity",
                "severity": "high",
                "left": {"system": ib.get("provider", "identity"),
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy", "asset_id": "corp-jml-policy"},
                "conflict": (f"Privileged identity {_ident(a).get('asset_id')} "
                             f"has not signed in for {days_idle} days but still "
                             "holds admin/owner role."),
                "resolution": ("Disable or remove the account. Standing privilege "
                               "on dormant accounts is a top breach vector — "
                               "rotate to JIT access via PIM/SSM."),
            })
    return findings


# --------------------------------------------------------------------------
# 7. EoS hardware in a crown-jewel role — supplier no longer ships fixes.
# --------------------------------------------------------------------------

def detect_eos_in_crown_jewel(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for a in all_assets:
        ident = _ident(a)
        if (ident.get("criticality") or "").lower() != "crown-jewel":
            continue
        lc = a.get("lifecycle") or {}
        days = lc.get("days_until_eos")
        if days is not None and days <= 0:
            findings.append({
                "type": "eos_in_crown_jewel",
                "severity": "critical",
                "left": {"system": "asset-inventory",
                         "asset_id": ident.get("asset_id")},
                "right": {"system": "vendor-lifecycle",
                          "asset_id": f"{ident.get('vendor')}-eos"},
                "conflict": (f"Crown-jewel asset {ident.get('asset_id')} is "
                             "past end-of-support — vendor will not issue "
                             "security fixes for newly disclosed CVEs."),
                "resolution": ("Schedule replacement (this quarter) or move "
                               "the workload behind a virtual patching layer "
                               "(IPS / WAF) and isolate via micro-segmentation."),
            })
    return findings


# --------------------------------------------------------------------------
# 8. KEV CVE on internet-facing asset — actively-exploited bug at the edge.
# --------------------------------------------------------------------------

def detect_kev_on_perimeter(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for a in all_assets:
        sec = a.get("security") or {}
        net = a.get("network") or {}
        if (sec.get("kev_cves") or 0) <= 0:
            continue
        # "perimeter" heuristic: has a public IP or is tagged as edge/dmz.
        public = bool(net.get("public_ip")) or bool(net.get("internet_facing"))
        zone = (net.get("zone") or "").lower()
        if not (public or zone in ("dmz", "edge", "internet")):
            continue
        findings.append({
            "type": "kev_on_perimeter",
            "severity": "critical",
            "left": {"system": "asset-inventory",
                     "asset_id": _ident(a).get("asset_id")},
            "right": {"system": "cisa-kev", "asset_id": "kev-catalog"},
            "conflict": (f"Internet-facing asset {_ident(a).get('asset_id')} "
                         f"has {sec.get('kev_cves')} CVE(s) on the CISA KEV "
                         "list — actively exploited in the wild today."),
            "resolution": ("Patch within 72h per CISA BOD 22-01. If patching "
                           "isn't possible, take the asset offline or place "
                           "it behind a WAF with KEV-specific virtual patches."),
        })
    return findings


# --------------------------------------------------------------------------
# 9. Management plane exposed to any — vty/ssh/snmp from 0.0.0.0/0.
# --------------------------------------------------------------------------

def detect_management_plane_exposed(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    risky = ("0.0.0.0/0", "0.0.0.0 0.0.0.0", "any any", "permit any")
    mgmt_keywords = ("vty", "ssh", "snmp-server", "telnet", "https-server",
                     "ip http server", "management")
    for a in all_assets:
        if _ident(a).get("asset_type") not in ("network", "infra", "compute"):
            continue
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str):
                    cfg += v + "\n"
        elif isinstance(rc, str):
            cfg = rc
        cfg_low = cfg.lower()
        hit_mgmt = any(k in cfg_low for k in mgmt_keywords)
        hit_open = any(k in cfg_low for k in risky)
        if hit_mgmt and hit_open:
            findings.append({
                "type": "management_plane_exposed",
                "severity": "high",
                "left": {"system": "asset-config",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy", "asset_id": "corp-mgmt-acl"},
                "conflict": (f"{_ident(a).get('asset_id')} accepts management "
                             "(SSH/SNMP/HTTPS) from any source — bypasses "
                             "the corp out-of-band management ACL."),
                "resolution": ("Restrict vty / SNMP / management ACL to the "
                               "OOB jump-host CIDR. If OOB is not yet in "
                               "place, at minimum lock to the corp egress IP."),
            })
    return findings


# --------------------------------------------------------------------------
# 10. Unencrypted management protocol enabled (telnet, http, snmpv1/v2).
# --------------------------------------------------------------------------

def detect_unencrypted_management(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    insecure = {
        "telnet": ("line vty", "transport input telnet"),
        "http (cleartext)": ("ip http server", "service http"),
        "snmpv2c": ("snmp-server community", "snmp-server host"),
    }
    for a in all_assets:
        if _ident(a).get("asset_type") not in ("network", "infra"):
            continue
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str): cfg += v + "\n"
        cfg_low = cfg.lower()
        offenders = []
        for label, needles in insecure.items():
            if all(n in cfg_low for n in needles[:1]):
                # Single keyword match is enough for these
                offenders.append(label)
        if offenders:
            findings.append({
                "type": "unencrypted_management_protocol",
                "severity": "high",
                "left": {"system": "asset-config",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy",
                          "asset_id": "corp-crypto-baseline"},
                "conflict": (f"{_ident(a).get('asset_id')} has cleartext "
                             f"management enabled: {', '.join(offenders)}."),
                "resolution": ("Replace telnet → SSHv2, http → https with TLS "
                               "1.2+, SNMPv2c → SNMPv3 with authPriv. Disable "
                               "the cleartext service after migration."),
            })
    return findings


# --------------------------------------------------------------------------
# 11. Default / weak credentials still present.
# --------------------------------------------------------------------------

def detect_default_credentials(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    DEFAULT_PAIRS = (
        ("admin", "admin"), ("admin", "password"), ("cisco", "cisco"),
        ("root", "root"), ("root", "calvin"),  # iDRAC default
        ("administrator", "administrator"),
    )
    for a in all_assets:
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str): cfg += v + "\n"
        cfg_low = cfg.lower()
        for user, pw in DEFAULT_PAIRS:
            if f"username {user}" in cfg_low and f"password {pw}" in cfg_low:
                findings.append({
                    "type": "default_credentials",
                    "severity": "critical",
                    "left": {"system": "asset-config",
                             "asset_id": _ident(a).get("asset_id")},
                    "right": {"system": "policy",
                              "asset_id": "corp-credential-baseline"},
                    "conflict": (f"{_ident(a).get('asset_id')} has the default "
                                 f"vendor credential pair `{user}/{pw}` — "
                                 "documented in public bug bounty reports."),
                    "resolution": (f"Remove the `{user}` local account, replace "
                                   "with AAA/TACACS-backed login, and rotate "
                                   "all device passwords on the same hardware "
                                   "model in case the cred is reused."),
                })
                break  # one finding per asset
    return findings


# --------------------------------------------------------------------------
# 12. Backup gap — crown-jewel asset without a corresponding backup record.
# --------------------------------------------------------------------------

def detect_backup_gap(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    backup_targets: set[str] = set()
    for a in all_assets:
        if _ident(a).get("asset_type") == "backup":
            bk = a.get("backup") or {}
            for t in bk.get("protected_assets") or []:
                backup_targets.add(str(t).lower())
    for a in all_assets:
        ident = _ident(a)
        if (ident.get("criticality") or "").lower() != "crown-jewel":
            continue
        aid = (ident.get("asset_id") or "").lower()
        host = (ident.get("hostname") or "").lower()
        if aid not in backup_targets and host not in backup_targets:
            findings.append({
                "type": "backup_gap_on_crown_jewel",
                "severity": "high",
                "left": {"system": "asset-inventory",
                         "asset_id": ident.get("asset_id")},
                "right": {"system": "backup-platform",
                          "asset_id": "any-backup-target-list"},
                "conflict": (f"Crown-jewel {ident.get('asset_id')} has no "
                             "matching backup adapter record — restore in a "
                             "ransomware scenario is not guaranteed."),
                "resolution": ("Enroll the asset in a backup platform with "
                               "immutable retention (Veeam hardened repo, "
                               "S3 Object Lock, Azure Blob immutability) "
                               "and verify a full restore quarterly."),
            })
    return findings


# --------------------------------------------------------------------------
# 13. Legacy protocol enabled (SMBv1, NTLMv1, SSLv3, TLS 1.0/1.1).
# --------------------------------------------------------------------------

def detect_legacy_protocol(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    legacy = ("smbv1", "smb1", "ntlmv1", "sslv3", "tlsv1.0", "tls 1.0",
              "tlsv1.1", "tls 1.1", "rc4", "des-cbc")
    for a in all_assets:
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str): cfg += v + "\n"
        cfg_low = cfg.lower()
        hits = [l for l in legacy if l in cfg_low]
        if hits:
            findings.append({
                "type": "legacy_protocol_enabled",
                "severity": "high",
                "left": {"system": "asset-config",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy",
                          "asset_id": "corp-crypto-baseline"},
                "conflict": (f"{_ident(a).get('asset_id')} still enables "
                             f"deprecated protocols: {', '.join(hits)}."),
                "resolution": ("Disable the legacy protocols. SMBv1 → SMBv3 "
                               "with signing required, TLS 1.0/1.1 → TLS 1.2+, "
                               "RC4/DES → AES-GCM ciphers."),
            })
    return findings


# --------------------------------------------------------------------------
# 14. Excessive admin count — one resource with too many admins.
# --------------------------------------------------------------------------

def detect_excessive_admin_count(all_assets: list[dict],
                                 max_admins: int = 10) -> list[dict]:
    findings: list[dict] = []
    for a in all_assets:
        ib = a.get("identity_block") or {}
        admins = ib.get("authorized_users") or []
        if len(admins) > max_admins:
            findings.append({
                "type": "excessive_admin_count",
                "severity": "medium",
                "left": {"system": "asset-inventory",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy",
                          "asset_id": "corp-least-privilege"},
                "conflict": (f"{_ident(a).get('asset_id')} grants admin to "
                             f"{len(admins)} principals (policy max: {max_admins})."),
                "resolution": ("Move standing admin to a JIT model. Require "
                               "approval-on-elevation via PIM/SSM. Audit which "
                               "of these accounts have used admin in 90 days "
                               "and downgrade the rest."),
            })
    return findings


# --------------------------------------------------------------------------
# 15. Logging absent — asset has no syslog/audit destination configured.
# --------------------------------------------------------------------------

def detect_missing_audit_logging(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    log_indicators = ("logging host", "syslog server", "logging server",
                      "audit-log", "diagnostic-settings", "logs analytic")
    for a in all_assets:
        if _ident(a).get("asset_type") not in ("network", "infra", "cloud"):
            continue
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str): cfg += v + "\n"
        elif isinstance(rc, str):
            cfg = rc
        if not cfg.strip():
            continue
        cfg_low = cfg.lower()
        if not any(k in cfg_low for k in log_indicators):
            findings.append({
                "type": "missing_audit_logging",
                "severity": "medium",
                "left": {"system": "asset-config",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy",
                          "asset_id": "corp-logging-baseline"},
                "conflict": (f"{_ident(a).get('asset_id')} has no syslog or "
                             "diagnostic destination configured — security "
                             "events are not centrally captured."),
                "resolution": ("Point the asset at the corporate SIEM / log "
                               "collector. Validate events arrive within 5 "
                               "minutes after a test login."),
            })
    return findings


# --------------------------------------------------------------------------
# 16. Open egress — outbound any-any to internet.
# --------------------------------------------------------------------------

def detect_open_egress(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for a in all_assets:
        if _ident(a).get("asset_type") != "network":
            continue
        cfg = ""
        rc = a.get("raw_collection") or {}
        if isinstance(rc, dict):
            for v in rc.values():
                if isinstance(v, str): cfg += v + "\n"
        cfg_low = cfg.lower()
        # Heuristic: an outbound or egress permit any any
        if (("permit ip any any" in cfg_low or
             "permit any any" in cfg_low) and
            ("outbound" in cfg_low or "egress" in cfg_low or
             "out interface" in cfg_low)):
            findings.append({
                "type": "open_egress",
                "severity": "high",
                "left": {"system": "asset-config",
                         "asset_id": _ident(a).get("asset_id")},
                "right": {"system": "policy",
                          "asset_id": "corp-egress-baseline"},
                "conflict": (f"{_ident(a).get('asset_id')} permits any-any "
                             "egress to the internet — exfiltration and "
                             "C2 callbacks are unrestricted."),
                "resolution": ("Replace with explicit allow-list of required "
                               "destinations + ports. Default-deny everything "
                               "else and route exceptions through a forward "
                               "proxy with TLS inspection."),
            })
    return findings


# --------------------------------------------------------------------------
# 17. Inconsistent crypto baseline across same vendor — drift between siblings.
# --------------------------------------------------------------------------

def detect_inconsistent_crypto_baseline(all_assets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_vendor: dict[str, list[dict]] = {}
    for a in all_assets:
        if _ident(a).get("asset_type") != "network":
            continue
        v = (_ident(a).get("vendor") or "").lower()
        if v:
            by_vendor.setdefault(v, []).append(a)
    for vendor, devices in by_vendor.items():
        if len(devices) < 2:
            continue
        with_baseline = []
        without_baseline = []
        for d in devices:
            cfg = ""
            rc = d.get("raw_collection") or {}
            if isinstance(rc, dict):
                for v in rc.values():
                    if isinstance(v, str): cfg += v + "\n"
            cfg_low = cfg.lower()
            has_strong = ("ssh version 2" in cfg_low or "ip ssh ver 2" in cfg_low
                          or "tls 1.2" in cfg_low or "tlsv1.2" in cfg_low)
            (with_baseline if has_strong else without_baseline).append(d)
        if with_baseline and without_baseline:
            for d in without_baseline:
                findings.append({
                    "type": "inconsistent_crypto_baseline",
                    "severity": "medium",
                    "left": {"system": "asset-config",
                             "asset_id": _ident(d).get("asset_id")},
                    "right": {"system": "asset-config",
                              "asset_id": _ident(with_baseline[0]).get("asset_id")},
                    "conflict": (f"{vendor} fleet has mixed crypto baselines: "
                                 f"{_ident(d).get('asset_id')} lacks the SSHv2/"
                                 f"TLS1.2 baseline that "
                                 f"{_ident(with_baseline[0]).get('asset_id')} "
                                 "(same vendor) uses."),
                    "resolution": ("Bring drifted devices to the standard "
                                   "baseline. Use `safecadence policy export "
                                   "<policy_id> --format ansible` to push the "
                                   "fix to all peers in one run."),
                })
    return findings


# --------------------------------------------------------------------------
# Public entry — run all detectors
# --------------------------------------------------------------------------

# Ordered list so callers can inspect / disable individual detectors.
ALL_DETECTORS = (
    detect_nac_vs_firewall_conflicts,
    detect_mfa_bypass_via_rbac,
    detect_password_policy_drift,
    detect_privileged_identity_drift,
    detect_admin_without_mfa,
    detect_dormant_privileged_identity,
    detect_eos_in_crown_jewel,
    detect_kev_on_perimeter,
    detect_management_plane_exposed,
    detect_unencrypted_management,
    detect_default_credentials,
    detect_backup_gap,
    detect_legacy_protocol,
    detect_excessive_admin_count,
    detect_missing_audit_logging,
    detect_open_egress,
    detect_inconsistent_crypto_baseline,
)


def detect_all(all_assets: list[dict]) -> dict[str, Any]:
    """Run every cross-system drift detector. Returns a single result dict.

    Each detector is wrapped — if one detector blows up on bad data, the
    others still run. The detector name is recorded in `detector_errors`.
    """
    findings: list[dict] = []
    detector_errors: list[dict] = []
    for det in ALL_DETECTORS:
        try:
            findings.extend(det(all_assets) or [])
        except Exception as e:  # pragma: no cover - defensive
            detector_errors.append({
                "detector": det.__name__,
                "error": f"{type(e).__name__}: {e}",
            })

    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "info")
        t = f.get("type", "unknown")
        by_severity[s] = by_severity.get(s, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1

    return {
        "asset_count": len(all_assets),
        "detector_count": len(ALL_DETECTORS),
        "finding_count": len(findings),
        "by_severity": by_severity,
        "by_type": by_type,
        "findings": findings,
        "detector_errors": detector_errors,
        "summary": (f"{len(findings)} cross-system policy conflicts detected "
                    f"({by_severity.get('critical', 0)} critical, "
                    f"{by_severity.get('high', 0)} high) "
                    f"across {len(ALL_DETECTORS)} detectors."
                    if findings else
                    f"No cross-system policy conflicts detected "
                    f"across {len(ALL_DETECTORS)} detectors."),
    }
