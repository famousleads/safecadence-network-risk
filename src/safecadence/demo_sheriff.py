"""
Sheriff demo tenant (DESAT) — a synthetic public-safety agency with the
five demo scenarios wired end-to-end.

    safecadence demo --sheriff

Seeds "Cypress County Sheriff's Office" (fictional): HQ, two district
stations, jail, evidence facility, and dispatch center — cameras, VMS,
body-cam docks, ALPR, UAS, evidence storage + backup, CAD/dispatch,
radio, identity — every asset carrying the ``public_safety`` block
(category, mission, evidence roles, GPS) so the map, evidence-health,
and incident surfaces light up immediately.

Scenario matrix (each traceable in the UI):
  S1  district-1 switch degraded → camera outage    → linkDown trap + OPEN critical incident
  S2  evidence storage 91% + replication degraded   → INVESTIGATING high incident
  S3  KEV CVE on the VMS server                     → OPEN critical incident (blast radius demo)
  S4  CAD/dispatch TLS certificate expiring         → ACKNOWLEDGED medium incident
  S5  identity provider outage (yesterday)          → RESOLVED incident (lifecycle demo)

Fictional agency, fictional coordinates, no real-world data.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AGENCY = "Cypress County Sheriff's Office"

# Site → (lat, lon) — fictional west-Florida-ish spread so the map has
# real geometry to show.
_SITES = {
    "hq":                (27.9781, -82.4512),
    "district-1":        (28.0403, -82.5121),
    "district-2":        (27.9021, -82.3705),
    "jail":              (27.9622, -82.4890),
    "evidence-facility": (27.9855, -82.4300),
    "dispatch-center":   (27.9700, -82.4601),
}


def _ts(days_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _health(overall: int = 95, band: str = "safe", **kw) -> dict:
    return {"hardware_health": kw.get("hardware", overall),
             "security_health": kw.get("security", overall),
             "lifecycle_health": kw.get("lifecycle", overall),
             "operational_health": kw.get("operational", overall),
             "overall_score": overall,
             "grade": "A" if overall >= 90 else "B" if overall >= 80
                        else "C" if overall >= 70 else "D" if overall >= 60 else "F",
             "risk_band": band}


def _asset(asset_id: str, *, asset_type: str, vendor: str, site: str,
            ps_category: str = "", mission: str = "", roles: list[str] | None = None,
            cji: str = "unknown", criticality: str = "medium",
            hostname: str = "", ip: str = "", model: str = "",
            jitter: tuple[float, float] = (0.0, 0.0),
            health: dict | None = None, **blocks: Any) -> dict:
    lat, lon = _SITES[site]
    out: dict[str, Any] = {
        "identity": {
            "asset_id": asset_id,
            "hostname": hostname or asset_id,
            "vendor": vendor, "model": model,
            "asset_type": asset_type,
            "site": site, "environment": "prod",
            "owner": "it@cypresssheriff.example",
            "team": "Agency IT",
            "criticality": criticality,
            "tags": [f"site:{site}", "demo:sheriff"],
            "discovered_at": _ts(90), "last_collected_at": _ts(0),
            "discovery_source": "manual",
        },
        "public_safety": {
            "ps_category": ps_category,
            "mission_function": mission,
            "evidence_roles": list(roles or []),
            "agency": AGENCY,
            "department": site.replace("-", " ").title(),
            "latitude": round(lat + jitter[0], 6),
            "longitude": round(lon + jitter[1], 6),
            "geo_source": "manual",
            "cji_classification": cji,
        },
        "health": health or _health(),
    }
    out.update(blocks)
    if ip:
        out["raw_collection"] = {"discover": {"ip": ip}}
    return out


# --------------------------------------------------------------------------
# Fleet
# --------------------------------------------------------------------------

def build_sheriff_fleet() -> list[dict]:
    a: list[dict] = []

    # ---- network fabric --------------------------------------------------
    a.append(_asset("sh-fw-hq-01", asset_type="network", vendor="palo-alto",
                     site="hq", criticality="crown-jewel", ip="10.80.0.1",
                     model="PA-1410", mission="communications",
                     health=_health(92)))
    a.append(_asset("sh-sw-hq-core", asset_type="network", vendor="cisco",
                     site="hq", criticality="high", ip="10.80.0.2",
                     model="C9300-48P", health=_health(95)))
    # S1 — the degraded switch behind the district-1 cameras.
    a.append(_asset("sh-sw-d1-01", asset_type="network", vendor="cisco",
                     site="district-1", criticality="high", ip="10.81.0.2",
                     model="C9200-24P",
                     health=_health(38, band="critical", operational=15),
                     security={"findings": ["device unreachable — port flapping"],
                                "weak_protocols": []}))
    a.append(_asset("sh-sw-d2-01", asset_type="network", vendor="cisco",
                     site="district-2", criticality="medium", ip="10.82.0.2",
                     model="C9200-24P", health=_health(96)))
    a.append(_asset("sh-sw-jail-01", asset_type="network", vendor="cisco",
                     site="jail", criticality="crown-jewel", ip="10.83.0.2",
                     model="C9300-24P", health=_health(93)))
    a.append(_asset("sh-sw-evid-01", asset_type="network", vendor="cisco",
                     site="evidence-facility", criticality="crown-jewel",
                     ip="10.84.0.2", model="C9300-24P", health=_health(94)))
    a.append(_asset("sh-rtr-dispatch", asset_type="network", vendor="cisco",
                     site="dispatch-center", criticality="crown-jewel",
                     ip="10.85.0.1", model="ISR-4331", health=_health(91)))

    # ---- cameras (capture) ----------------------------------------------
    cam = dict(asset_type="iot", vendor="axis", ps_category="camera",
                mission="surveillance", roles=["capture"], cji="unknown")
    a.append(_asset("sh-cam-hq-lot-a", site="hq", ip="10.80.2.11",
                     jitter=(0.0009, 0.0004), **cam))
    a.append(_asset("sh-cam-hq-lot-b", site="hq", ip="10.80.2.12",
                     jitter=(-0.0007, 0.0011), **cam))
    a.append(_asset("sh-cam-jail-intake", site="jail", ip="10.83.2.11",
                     criticality="high", jitter=(0.0004, -0.0006),
                     **{**cam, "roles": ["capture"], "cji": "cji"}))
    a.append(_asset("sh-cam-evid-bay", site="evidence-facility",
                     ip="10.84.2.11", criticality="high",
                     jitter=(0.0002, 0.0008),
                     **{**cam, "cji": "cji"}))
    # S1 — the two cameras downstream of the dead district-1 switch.
    for i, jit in (("1", (0.0006, -0.0009)), ("2", (-0.0004, 0.0007))):
        a.append(_asset(f"sh-cam-d1-lot-{i}", site="district-1",
                         ip=f"10.81.2.1{i}",
                         health=_health(20, band="critical", operational=0),
                         jitter=jit,
                         security={"findings": ["stream lost — no path to VMS"]},
                         **cam))

    # ---- body-cam infrastructure (capture/transfer) ----------------------
    for site, ip in (("hq", "10.80.3.11"), ("district-2", "10.82.3.11")):
        a.append(_asset(f"sh-bwc-dock-{site}", asset_type="iot",
                         vendor="axon", site=site, criticality="high",
                         ip=ip, ps_category="body_camera_infrastructure",
                         mission="evidence_transfer",
                         roles=["capture", "transfer"], cji="cji",
                         jitter=(0.0003, 0.0003)))

    # ---- ALPR + UAS + sensors -------------------------------------------
    a.append(_asset("sh-alpr-main-st", asset_type="iot", vendor="flock",
                     site="district-1", ps_category="alpr",
                     mission="patrol_support", roles=["capture"], cji="cji",
                     ip="10.81.4.11", jitter=(0.0121, 0.0087)))
    a.append(_asset("sh-alpr-bridge", asset_type="iot", vendor="flock",
                     site="district-2", ps_category="alpr",
                     mission="patrol_support", roles=["capture"], cji="cji",
                     ip="10.82.4.11", jitter=(-0.0094, 0.0112)))
    a.append(_asset("sh-uas-dock-hq", asset_type="iot", vendor="skydio",
                     site="hq", ps_category="uas", mission="surveillance",
                     roles=["capture"], ip="10.80.5.11",
                     jitter=(0.0015, -0.0012)))
    a.append(_asset("sh-gunshot-d2", asset_type="iot", vendor="soundthinking",
                     site="district-2", ps_category="environmental_sensor",
                     mission="surveillance", roles=["capture"],
                     cji="non_cji", ip="10.82.5.11",
                     jitter=(0.0064, -0.0078)))

    # ---- evidence core (store / access / preserve) -----------------------
    # S3 — VMS with a KEV-listed CVE.
    a.append(_asset("sh-vms-01", asset_type="server", vendor="milestone",
                     site="evidence-facility", criticality="crown-jewel",
                     ip="10.84.1.10", ps_category="vms",
                     mission="evidence_storage", roles=["store", "access"],
                     cji="cji",
                     health=_health(41, band="critical", security=15),
                     security={"kev_cves": 1, "critical_cves": 2,
                                "vulnerabilities": [
                                    {"cve_id": "CVE-2026-31337", "severity": "critical",
                                      "kev": True,
                                      "note": "RCE in media gateway — KEV-listed"}],
                                "findings": ["KEV-listed CVE on evidence VMS"]}))
    # S2 — evidence NAS: 91% full, replication degraded.
    a.append(_asset("sh-evid-nas-01", asset_type="storage", vendor="netapp",
                     site="evidence-facility", criticality="crown-jewel",
                     ip="10.84.1.20", ps_category="evidence_platform",
                     mission="evidence_storage",
                     roles=["store", "preserve"], cji="cji",
                     health=_health(62, band="high", operational=55),
                     storage={"total_capacity_tb": 200.0,
                               "used_capacity_tb": 182.0,
                               "free_capacity_tb": 18.0,
                               "replication_status": "degraded",
                               "replication_partners": ["sh-evid-nas-dr"]}))
    a.append(_asset("sh-evid-app-01", asset_type="server", vendor="dell",
                     site="evidence-facility", criticality="crown-jewel",
                     ip="10.84.1.30", ps_category="evidence_platform",
                     mission="evidence_access", roles=["access", "preserve"],
                     cji="cji", health=_health(90)))
    veeam = _asset("sh-veeam-evid", asset_type="backup", vendor="veeam",
                     site="evidence-facility", criticality="high",
                     ip="10.84.1.40", ps_category="evidence_platform",
                     mission="evidence_storage", roles=["preserve"],
                     cji="cji", health=_health(78, band="medium"),
                     backup={"platform": "veeam",
                              "last_backup_status": "success",
                              "last_backup_at": _ts(2),
                              "rpo_target_hours": 24, "actual_rpo_hours": 49,
                              "retention_days": 3650,
                              "immutability_enabled": True,
                              "air_gapped": False})
    # Correlation food: the dependency-chain engine links backup→protected
    # assets by hostname mention in raw_collection (same trick demo.py uses).
    veeam["raw_collection"] = {
        "discover": {"ip": "10.84.1.40"},
        "jobs": [
            {"name": "evid-nas-daily", "protects": "sh-evid-nas-01"},
            {"name": "vms-daily", "protects": "sh-vms-01"},
            {"name": "evid-app-daily", "protects": "sh-evid-app-01"},
            {"name": "cad-daily", "protects": "sh-cad-01"},
        ],
    }
    a.append(veeam)

    # ---- dispatch / CAD / radio / identity -------------------------------
    # S4 — CAD server with an expiring TLS certificate.
    a.append(_asset("sh-cad-01", asset_type="server", vendor="microsoft",
                     site="dispatch-center", criticality="crown-jewel",
                     ip="10.85.1.10", ps_category="cad_rms",
                     mission="dispatch", roles=["access"], cji="cji",
                     health=_health(74, band="medium"),
                     compliance_signals={
                         "weak_config_detected": True,
                         "weak_config_findings":
                             ["TLS certificate expires in 11 days"]}))
    a.append(_asset("sh-radio-core", asset_type="iot", vendor="l3harris",
                     site="dispatch-center", criticality="crown-jewel",
                     ip="10.85.2.10", ps_category="radio_comms",
                     mission="communications", cji="non_cji",
                     jitter=(0.0006, 0.0009), health=_health(93)))
    # S5 — identity provider, outage RESOLVED yesterday.
    a.append(_asset("sh-idp-entra", asset_type="cloud", vendor="microsoft",
                     site="hq", criticality="crown-jewel",
                     ps_category="", mission="communications",
                     health=_health(88, band="low"),
                     identity_block={"provider": "entra",
                                       "tenant_id": "cypress-sheriff",
                                       "user_count": 412,
                                       "privileged_user_count": 9,
                                       "mfa_enrolled": True}))
    return a


# --------------------------------------------------------------------------
# Scenario wiring — events + incidents
# --------------------------------------------------------------------------

def _seed_events() -> int:
    from safecadence.events.schema import Event
    from safecadence.events.store import append_event
    seeded = 0
    rows = [
        Event(source="snmp_trap", source_ip="10.81.0.2",
               event_type="trap.linkDown", severity="high",
               description="SNMP trap linkDown — Gi1/0/12 (camera uplink), "
                            "Gi1/0/13 (camera uplink)",
               asset_id="sh-sw-d1-01", hostname="sh-sw-d1-01",
               site="district-1"),
        Event(source="syslog", source_ip="10.84.1.20",
               event_type="syslog.daemon", severity="high",
               description="SnapMirror lag exceeds threshold — replication "
                            "to sh-evid-nas-dr degraded",
               asset_id="sh-evid-nas-01", hostname="sh-evid-nas-01",
               site="evidence-facility"),
        Event(source="webhook", event_type="vuln.kev_match",
               severity="critical",
               description="CVE-2026-31337 (KEV) matched on Milestone media "
                            "gateway", asset_id="sh-vms-01",
               hostname="sh-vms-01", site="evidence-facility"),
        Event(source="webhook", event_type="cert.expiring", severity="medium",
               description="TLS certificate for cad.cypresssheriff.example "
                            "expires in 11 days",
               asset_id="sh-cad-01", hostname="sh-cad-01",
               site="dispatch-center"),
        Event(source="webhook", event_type="identity.outage", severity="high",
               description="Entra ID sign-ins failing agency-wide "
                            "(resolved — upstream provider incident)",
               asset_id="sh-idp-entra", hostname="sh-idp-entra", site="hq"),
    ]
    for e in rows:
        try:
            append_event(e, link_asset=False)
            seeded += 1
        except Exception:
            continue
    return seeded


def _seed_incidents() -> int:
    from safecadence.incidents.store import (
        add_note, create_incident, list_incidents, transition_incident,
    )
    # Idempotency: the S1 title is the marker — if it exists, the
    # scenario set was already seeded (survives --overwrite re-runs).
    if any("District 1 camera outage" in str(i.get("title", ""))
            for i in list_incidents(limit=500)):
        return 0
    seeded = 0
    try:
        # S1 — open critical: camera outage from switch failure.
        inc = create_incident(
            "District 1 camera outage — switch sh-sw-d1-01 down",
            severity="critical", incident_type="operational",
            site="district-1",
            affected_assets=["sh-sw-d1-01", "sh-cam-d1-lot-1",
                               "sh-cam-d1-lot-2"],
            mission_impact="Evidence capture lost for District 1 parking "
                             "lots; prisoner-transfer documentation degraded.",
            actor="demo")
        add_note(inc.incident_id,
                  "Graph blast radius: 1 switch → 2 cameras → VMS recording "
                  "gap. Field tech dispatched.", actor="demo")
        seeded += 1

        # S2 — investigating high: evidence storage capacity + replication.
        inc = create_incident(
            "Evidence storage at 91% — replication degraded",
            severity="high", incident_type="operational",
            site="evidence-facility",
            affected_assets=["sh-evid-nas-01"],
            mission_impact="Evidence PRESERVE stage at risk: capacity "
                             "runway ~5 weeks at current BWC ingest rate.",
            actor="demo")
        transition_incident(inc.incident_id, "acknowledged", actor="demo")
        transition_incident(inc.incident_id, "investigating", actor="demo",
                             note="Expansion shelf quote requested; "
                                    "SnapMirror lag under review.")
        seeded += 1

        # S3 — open critical: KEV on the VMS.
        inc = create_incident(
            "KEV-listed CVE-2026-31337 on evidence VMS",
            severity="critical", incident_type="security",
            site="evidence-facility", affected_assets=["sh-vms-01"],
            mission_impact="Actively-exploited RCE on the system storing "
                             "all camera evidence (CJI).",
            actor="demo")
        add_note(inc.incident_id,
                  "Patch available (10.3.2). Change window requested — "
                  "tier-3 dry-run prepared.", actor="demo")
        seeded += 1

        # S4 — acknowledged medium: cert expiry on CAD.
        inc = create_incident(
            "CAD TLS certificate expires in 11 days",
            severity="medium", incident_type="lifecycle",
            site="dispatch-center", affected_assets=["sh-cad-01"],
            mission_impact="Dispatch console trust failures if it lapses.",
            actor="demo")
        transition_incident(inc.incident_id, "acknowledged", actor="demo",
                             note="Renewal CSR submitted to CA.")
        seeded += 1

        # S5 — resolved: identity outage (yesterday) — lifecycle demo.
        inc = create_incident(
            "Identity provider outage — agency-wide sign-in failures",
            severity="high", incident_type="operational", site="hq",
            affected_assets=["sh-idp-entra"],
            mission_impact="CAD, VMS, and evidence-platform logins blocked "
                             "for 40 minutes.",
            actor="demo")
        transition_incident(inc.incident_id, "acknowledged", actor="demo")
        transition_incident(inc.incident_id, "investigating", actor="demo")
        transition_incident(inc.incident_id, "resolved", actor="demo",
                             resolution="Upstream provider incident; "
                                          "restored 14:40Z. Break-glass local "
                                          "accounts validated during outage.")
        seeded += 1
    except Exception:
        return seeded
    return seeded


# --------------------------------------------------------------------------
# Loader
# --------------------------------------------------------------------------

def load_sheriff_demo(target_dir: Path | None = None,
                       *, overwrite: bool = False) -> dict:
    """Write the sheriff fleet + scenario events/incidents. Idempotent."""
    from safecadence.server.platform_api import _SAFE_ASSET_ID, _store_dir

    base = Path(target_dir) if target_dir else _store_dir()
    base.mkdir(parents=True, exist_ok=True)

    written = skipped = 0
    for asset in build_sheriff_fleet():
        aid = (asset.get("identity") or {}).get("asset_id", "")
        if not aid or not _SAFE_ASSET_ID.match(aid) or ".." in aid:
            skipped += 1
            continue
        target = base / f"{aid}.json"
        if target.exists() and not overwrite:
            skipped += 1
            continue
        target.write_text(json.dumps(asset, indent=2, default=str),
                            encoding="utf-8")
        written += 1

    events_seeded = _seed_events() if written else 0
    incidents_seeded = _seed_incidents() if written else 0

    # Light up EVERY UI surface with sheriff-flavored data by reusing the
    # main demo's auxiliary seeders (compliance/findings, identity vault,
    # NHIs, execution queue, users/webhooks, capabilities, IdP groups,
    # automation rules). Each block is best-effort — identical policy to
    # load_demo_fleet: one failure never breaks the loader.
    surfaces: dict[str, Any] = {}
    if written:
        asset_ids = [x["identity"]["asset_id"] for x in build_sheriff_fleet()]
        from safecadence import demo as _d
        for name, fn, args in (
            ("compliance", getattr(_d, "_seed_compliance_demo", None), (asset_ids,)),
            ("identity_vault", getattr(_d, "_seed_identity_vault_demo", None), ()),
            ("nhi", getattr(_d, "_seed_nhi_demo", None), ()),
            ("execution", getattr(_d, "_seed_execution_demo", None), (asset_ids,)),
            ("users_webhooks", getattr(_d, "_seed_users_and_webhooks_demo", None), ()),
            ("capabilities", getattr(_d, "_seed_capabilities_demo", None), ()),
            ("idp_groups", getattr(_d, "_seed_idp_groups_demo", None), ()),
            ("automation", getattr(_d, "_seed_automation_demo", None), ()),
        ):
            if fn is None:
                continue
            try:
                surfaces[name] = fn(*args)
            except Exception as exc:          # noqa: BLE001 — best-effort
                surfaces[name] = {"error": str(exc)[:120]}

    return {
        "agency": AGENCY,
        "written": written, "skipped": skipped,
        "events_seeded": events_seeded,
        "incidents_seeded": incidents_seeded,
        "surfaces_seeded": sorted(k for k, v in surfaces.items()
                                     if not (isinstance(v, dict) and v.get("error"))),
        "target_dir": str(base),
        "summary": (
            f"{AGENCY}: {written} public-safety assets across "
            f"{len(_SITES)} sites, {events_seeded} events, "
            f"{incidents_seeded} incidents.\n"
            "Scenarios: S1 camera outage (open) · S2 evidence storage 91% "
            "(investigating) · S3 KEV on VMS (open) · S4 CAD cert expiry "
            "(acknowledged) · S5 identity outage (resolved).\n"
            "See: /map · /evidence-infrastructure · /incidents"),
    }


def clear_sheriff_demo(target_dir: Path | None = None) -> dict:
    """Remove sheriff demo assets (events/incidents age out naturally)."""
    from safecadence.server.platform_api import _store_dir
    base = Path(target_dir) if target_dir else _store_dir()
    removed = 0
    for f in base.glob("sh-*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if "demo:sheriff" in (data.get("identity", {}).get("tags") or []):
                f.unlink()
                removed += 1
        except Exception:
            continue
    return {"removed": removed, "target_dir": str(base)}
