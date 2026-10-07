"""Reviewed backlog identities, not an automatic engine installer."""
from __future__ import annotations

_PROJECTS = (
    ("wazuh", "Wazuh", "endpoint", "NR-INT-01"),
    ("crowdsec", "CrowdSec", "protection", "NR-INT-02"),
    ("cybersecurity-skills", "Anthropic-Cybersecurity-Skills", "guidance", "NR-SKILLS-01"),
    ("personal-security-checklist", "Personal Security Checklist", "guidance", "NR-INT-03"),
    ("spiderfoot", "SpiderFoot", "exposure", "NR-INT-04"),
    ("sniffnet", "Sniffnet", "network", "NR-INT-05"),
    ("safeline", "SafeLine", "protection", "NR-INT-06"),
    ("sherlock", "Sherlock", "exposure", "NR-INT-07"),
    ("maigret", "Maigret", "exposure", "NR-INT-08"),
    ("strix", "Strix", "application-testing", "NR-INT-09"),
    ("shannon", "Shannon", "application-testing", "NR-INT-10"),
    ("hexstrike", "HexStrike AI", "application-testing", "NR-INT-11"),
    ("imhex", "ImHex", "specialist", "NR-INT-12"),
    ("x64dbg", "x64dbg", "specialist", "NR-INT-13"),
    ("h4cker", "h4cker", "guidance", "NR-INT-14"),
    ("ghosttrack", "GhostTrack", "exposure", "NR-INT-15"),
    ("vuls", "Vuls", "endpoint", "NR-INT-16"),
    ("httpx", "ProjectDiscovery httpx", "network", "NR-INT-17"),
    ("opencti", "OpenCTI", "intelligence", "NR-INT-18"),
    ("bunkerweb", "BunkerWeb", "protection", "NR-INT-19"),
    ("zeek", "Zeek", "network", "NR-INT-20"),
    ("suricata", "Suricata", "network", "NR-INT-21"),
    ("arkime", "Arkime", "network", "NR-INT-22"),
    ("malcolm", "Malcolm", "network", "NR-INT-23"),
    ("osquery", "osquery", "endpoint", "NR-INT-24"),
    ("fleet", "Fleet", "endpoint", "NR-INT-25"),
    ("falco", "Falco", "workload", "NR-INT-26"),
    ("opa", "Open Policy Agent", "policy", "NR-INT-27"),
    ("authentik", "authentik", "identity", "NR-INT-28"),
    ("frigate", "Frigate", "safety", "NR-INT-29"),
    ("home-assistant", "Home Assistant", "safety", "NR-INT-30"),
    ("thingsboard", "ThingsBoard", "safety", "NR-INT-31"),
)
IMPORT_SOURCES = frozenset({"wazuh", "crowdsec", "zeek", "suricata"})


def catalog():
    return [dict(
        key=key, name=name, category=category, backlog_id=backlog,
        status="file-import" if key in IMPORT_SOURCES else
               "deferred" if key == "ghosttrack" else "planned",
        live_connector=False, engine_installed=False, license_cleared=False,
        local_polling_available=key in {"wazuh", "crowdsec", "frigate", "home-assistant", "thingsboard"},
        passive_log_forwarder_available=key in {"zeek", "suricata"},
        external_egress=False, actions="read-only",
        public_safety_status="scoped-file-import" if key in {"frigate", "home-assistant", "thingsboard"}
                             else "scoped-csv-review" if key in {"sherlock", "maigret"}
                             else "planned" if category == "safety" else "not-assessed",
    ) for key, name, category, backlog in _PROJECTS]
