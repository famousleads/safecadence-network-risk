"""
DESAT batch 2 — events ingestion, incidents, GIS, SAML hardening.

Covers:
  events:    syslog RFC3164/5424 parsing, trap BER decode roundtrip,
             dedup window, store/query, webhook auth, listener E2E (UDP)
  incidents: lifecycle transitions (legal + illegal), notes/timeline,
             auto-open from critical events, API surface
  geo:       GeoJSON features from public_safety lat/lon, filters,
             honest count of assets without coordinates
  saml:      real XML-DSig roundtrip (signxml, self-signed cert),
             wrong-cert rejection, expiry, audience mismatch, replay,
             AuthnRequest redirect binding
"""

from __future__ import annotations

import base64
import socket
import time
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence.events.store import reset_for_tests
    reset_for_tests()
    yield


# ============================================================ events: syslog


def test_syslog_rfc3164_parse():
    from safecadence.events.schema import normalize_syslog
    e = normalize_syslog("<34>Aug 17 12:01:02 fw-01 %ASA-2-106001: "
                           "Inbound TCP connection denied",
                           source_ip="10.0.0.5")
    assert e.source == "syslog"
    assert e.severity == "critical"          # PRI 34 % 8 == 2
    assert e.hostname == "fw-01"
    assert "denied" in e.description


def test_syslog_rfc5424_parse():
    from safecadence.events.schema import normalize_syslog
    e = normalize_syslog('<165>1 2026-08-17T12:00:00Z cam-07 vms 123 ID47 '
                           '- camera stream lost', source_ip="10.0.0.9")
    assert e.severity == "low"                # 165 % 8 == 5
    assert e.hostname == "cam-07"
    assert e.occurred_at.startswith("2026-08-17")


def test_syslog_unparseable_still_stored():
    from safecadence.events.schema import normalize_syslog
    e = normalize_syslog("not really syslog at all")
    assert e.event_type == "syslog.unparsed"


# ============================================================ events: traps


def _encode_trap(community=b"public", trap_oid=(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)):
    """Build a syntactically-valid SNMPv2c trap datagram using the
    repo's own BER encoder — encoder and decoder must agree."""
    from safecadence.discovery import snmp_probe as enc

    def seq(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + enc._ber_encode_length(len(body)) + body

    uptime_vb = seq(0x30,
        enc._ber_encode_oid((1, 3, 6, 1, 2, 1, 1, 3, 0))
        + seq(0x43, b"\x01\x02"))
    trapoid_vb = seq(0x30,
        enc._ber_encode_oid((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
        + enc._ber_encode_oid(trap_oid))
    vbl = seq(0x30, uptime_vb + trapoid_vb)
    pdu = seq(0xA7,
               enc._ber_encode_integer(42)
               + enc._ber_encode_integer(0)
               + enc._ber_encode_integer(0)
               + vbl)
    msg = seq(0x30,
               enc._ber_encode_integer(1)          # v2c
               + enc._ber_encode_octet_string(community)
               + pdu)
    return msg


def test_trap_decode_roundtrip():
    from safecadence.events.listeners import decode_trap
    t = decode_trap(_encode_trap())
    assert t["version"] == 1
    assert t["community"] == "public"
    assert t["trap_oid"] == "1.3.6.1.6.3.1.1.5.3"     # linkDown


def test_trap_handler_normalizes_linkdown():
    from safecadence.events.listeners import handle_trap_datagram
    res = handle_trap_datagram(_encode_trap(), "10.0.0.7")
    assert res["stored"] is True
    from safecadence.events.store import query_events
    rec = query_events(limit=1)[0]
    assert rec["event_type"] == "trap.linkDown"
    assert rec["severity"] == "high"


def test_trap_community_allowlist(monkeypatch):
    monkeypatch.setenv("SC_TRAP_COMMUNITIES", "S3cureComm")
    from safecadence.events.listeners import handle_trap_datagram
    handle_trap_datagram(_encode_trap(community=b"public"), "10.0.0.7")
    from safecadence.events.store import query_events
    rec = query_events(limit=1)[0]
    assert rec["event_type"] == "trap.community_rejected"


def test_malformed_trap_recorded_not_raised():
    from safecadence.events.listeners import handle_trap_datagram
    res = handle_trap_datagram(b"\xff\x00garbage", "10.0.0.7")
    assert res["stored"] is True
    from safecadence.events.store import query_events
    assert query_events(limit=1)[0]["event_type"] == "trap.malformed"


# ============================================================ events: store


def test_dedup_within_window():
    from safecadence.events.schema import Event
    from safecadence.events.store import append_event
    e1 = Event(source="syslog", source_ip="1.2.3.4",
                event_type="syslog.daemon", description="link flap")
    e2 = Event(source="syslog", source_ip="1.2.3.4",
                event_type="syslog.daemon", description="link flap")
    r1 = append_event(e1)
    r2 = append_event(e2)
    assert r1["stored"] is True
    assert r2["stored"] is False
    assert r2["deduped_into"] == e1.event_id
    assert r2["repeat_count"] == 1


def test_query_filters_and_counts():
    from safecadence.events.schema import Event
    from safecadence.events.store import append_event, event_counts, query_events
    append_event(Event(source="webhook", event_type="a", severity="critical",
                         description="x"))
    append_event(Event(source="syslog", event_type="b", severity="info",
                         description="y"))
    assert len(query_events(severity="critical")) == 1
    c = event_counts()
    assert c["total"] == 2
    assert c["by_severity"]["critical"] == 1


def test_syslog_listener_end_to_end(monkeypatch):
    """Real UDP datagram → listener thread → store."""
    import random
    port = random.randint(20000, 40000)
    monkeypatch.setenv("SC_SYSLOG_PORT", str(port))
    monkeypatch.delenv("SC_EVENTS_LISTENERS", raising=False)
    from safecadence.events import listeners
    listeners.stop_listeners()
    started = listeners.start_listeners()
    assert started.get("syslog_port") == port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<34>Aug 17 12:01:02 fw-99 test message", ("127.0.0.1", port))
        s.close()
        from safecadence.events.store import query_events
        for _ in range(50):
            if query_events(limit=5):
                break
            time.sleep(0.1)
        recs = query_events(limit=5)
        assert recs and recs[0]["hostname"] == "fw-99"
    finally:
        listeners.stop_listeners()


# ============================================================ incidents


def test_incident_lifecycle_legal_path():
    from safecadence.incidents import create_incident, transition_incident
    inc = create_incident("Camera outage — HQ lot", severity="high",
                            affected_assets=["cam-01"])
    assert inc.status == "open"
    inc = transition_incident(inc.incident_id, "acknowledged", actor="faz")
    inc = transition_incident(inc.incident_id, "investigating")
    inc = transition_incident(inc.incident_id, "resolved",
                                resolution="switch port re-enabled")
    inc = transition_incident(inc.incident_id, "closed")
    assert inc.status == "closed"
    assert inc.closed_at
    kinds = [t["kind"] for t in inc.timeline]
    assert kinds.count("status") == 4


def test_incident_illegal_transition_rejected():
    from safecadence.incidents import create_incident, transition_incident
    inc = create_incident("x", severity="low")
    transition_incident(inc.incident_id, "closed")
    with pytest.raises(ValueError):
        transition_incident(inc.incident_id, "resolved")
    # reopen is legal
    inc = transition_incident(inc.incident_id, "open")
    assert inc.status == "open"


def test_incident_notes_and_event_attach():
    from safecadence.incidents import add_note, attach_events, create_incident
    inc = create_incident("y", severity="medium")
    inc = add_note(inc.incident_id, "vendor ticket opened", actor="faz")
    inc = attach_events(inc.incident_id, ["evt-abc", "evt-abc", "evt-def"])
    assert inc.event_ids == ["evt-abc", "evt-def"]
    assert any(t["kind"] == "note" for t in inc.timeline)


def test_auto_incident_from_critical_event():
    from safecadence.incidents import attach_or_open_for_event, list_incidents
    evt = {"event_id": "evt-1", "severity": "critical", "asset_id": "cam-01",
            "hostname": "cam-01", "event_type": "trap.linkDown",
            "source": "snmp_trap", "site": "hq"}
    inc = attach_or_open_for_event(evt)
    assert inc is not None and inc.severity == "critical"
    # second event on same asset attaches, doesn't duplicate
    inc2 = attach_or_open_for_event({**evt, "event_id": "evt-2"})
    assert inc2.incident_id == inc.incident_id
    assert len(list_incidents()) == 1
    # info events never auto-open
    assert attach_or_open_for_event({**evt, "severity": "info",
                                        "event_id": "evt-3"}) is None


def test_event_append_auto_incident_flag(monkeypatch):
    monkeypatch.setenv("SC_EVENTS_AUTO_INCIDENT", "1")
    from safecadence.events.schema import Event
    from safecadence.events.store import append_event
    e = Event(source="webhook", event_type="w.custom", severity="critical",
               description="storage failure", asset_id="nas-01")
    res = append_event(e, link_asset=False)
    assert res["incident_id"].startswith("inc-")


# ============================================================ geo


def _geo_asset(hostname, lat, lon, band="safe", cat="camera"):
    return {"identity": {"asset_id": hostname, "hostname": hostname,
                           "asset_type": "iot", "site": "hq",
                           "criticality": "high"},
             "public_safety": {"ps_category": cat, "latitude": lat,
                                "longitude": lon},
             "health": {"risk_band": band, "overall_score": 90}}


def test_geojson_features_and_honest_missing_count():
    from safecadence.platform.geo_api import assets_geojson
    assets = [
        _geo_asset("cam-01", 27.9506, -82.4572),
        _geo_asset("cam-02", 27.9981, -82.4300, band="critical"),
        {"identity": {"asset_id": "sw-1"}},          # no coords
    ]
    gj = assets_geojson(assets)
    assert gj["type"] == "FeatureCollection"
    assert len(gj["features"]) == 2
    assert gj["properties"]["assets_without_geo"] == 1
    lon, lat = gj["features"][0]["geometry"]["coordinates"]
    assert (lat, lon) == (27.9506, -82.4572)          # GeoJSON = [lon, lat]


def test_geojson_filters_and_bounds():
    from safecadence.platform.geo_api import assets_geojson
    assets = [_geo_asset("cam-01", 27.9, -82.4, band="critical"),
               _geo_asset("bad", 999.0, 0.0)]          # out of range
    gj = assets_geojson(assets, risk_band="critical")
    assert len(gj["features"]) == 1
    assert gj["features"][0]["properties"]["hostname"] == "cam-01"


# ============================================================ saml


def _selfsigned_cert_and_key():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.test")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return cert_pem, key_pem


def _signed_response(key_pem, cert_pem, *, audience="sc-sp",
                       email="deputy@sheriff.test",
                       not_on_or_after=None, assertion_id=None,
                       omit_conditions=False):
    pytest.importorskip("signxml")
    from lxml import etree
    from signxml import XMLSigner
    nooa = (not_on_or_after or
             datetime.now(timezone.utc) + timedelta(minutes=5))
    aid = assertion_id or f"_a{int(time.time() * 1000)}"
    conditions = "" if omit_conditions else (
        f'    <saml:Conditions NotBefore="2000-01-01T00:00:00Z"\n'
        f'      NotOnOrAfter="{nooa.strftime("%Y-%m-%dT%H:%M:%SZ")}">\n'
        f'      <saml:AudienceRestriction><saml:Audience>{audience}'
        f'</saml:Audience>\n'
        f'      </saml:AudienceRestriction>\n'
        f'    </saml:Conditions>\n')
    xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0">
  <saml:Assertion ID="{aid}" Version="2.0">
    <saml:Issuer>https://idp.test</saml:Issuer>
    <saml:Subject><saml:NameID
      Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      >{email}</saml:NameID></saml:Subject>
{conditions}  </saml:Assertion>
</samlp:Response>"""
    root = etree.fromstring(xml.encode())
    signed = XMLSigner().sign(root, key=key_pem, cert=cert_pem)
    return base64.b64encode(etree.tostring(signed)).decode()


@pytest.fixture()
def saml_env(monkeypatch, tmp_path):
    cert_pem, key_pem = _selfsigned_cert_and_key()
    cert_file = tmp_path / "idp.pem"
    cert_file.write_text(cert_pem)
    monkeypatch.setenv("SC_SAML_IDP_METADATA_URL", "https://idp.test/md")
    monkeypatch.setenv("SC_SAML_SP_ENTITY_ID", "sc-sp")
    monkeypatch.setenv("SC_SAML_IDP_CERT_FILE", str(cert_file))
    monkeypatch.delenv("SC_SAML_IDP_SHARED_SECRET", raising=False)
    from safecadence.auth import saml
    saml._SEEN_ASSERTIONS.clear()
    return cert_pem, key_pem


def test_saml_real_signature_roundtrip(saml_env, monkeypatch):
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    monkeypatch.setattr(
        "safecadence.auth.magic_link.create_session",
        lambda uid, email: "tok-123", raising=False)
    monkeypatch.setattr(
        "safecadence.auth.magic_link._user_id_for",
        lambda email: "u-1", raising=False)
    res = saml.handle_acs_response(_signed_response(key_pem, cert_pem))
    assert res["ok"] is True, res
    assert res["email"] == "deputy@sheriff.test"


def test_saml_wrong_cert_rejected(saml_env):
    _, key_pem = saml_env
    other_cert, other_key = _selfsigned_cert_and_key()
    from safecadence.auth import saml
    res = saml.handle_acs_response(_signed_response(other_key, other_cert))
    assert res["ok"] is False
    assert res["error"] == "signature_invalid"


def test_saml_expired_assertion_rejected(saml_env):
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    res = saml.handle_acs_response(_signed_response(
        key_pem, cert_pem,
        not_on_or_after=datetime.now(timezone.utc) - timedelta(minutes=10)))
    assert res["ok"] is False
    assert res["error"] == "assertion_expired"


def test_saml_audience_mismatch_rejected(saml_env):
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    res = saml.handle_acs_response(
        _signed_response(key_pem, cert_pem, audience="someone-else"))
    assert res["ok"] is False
    assert res["error"] == "audience_mismatch"


def test_saml_replay_rejected(saml_env, monkeypatch):
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    monkeypatch.setattr(
        "safecadence.auth.magic_link.create_session",
        lambda uid, email: "tok-123", raising=False)
    monkeypatch.setattr(
        "safecadence.auth.magic_link._user_id_for",
        lambda email: "u-1", raising=False)
    resp = _signed_response(key_pem, cert_pem, assertion_id="_fixed1")
    assert saml.handle_acs_response(resp)["ok"] is True
    res = saml.handle_acs_response(resp)
    assert res["ok"] is False
    assert res["error"] == "assertion_replayed"


def test_saml_missing_conditions_rejected(saml_env):
    """Audit fix: an assertion with no <Conditions> must fail closed."""
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    resp = _signed_response(key_pem, cert_pem, omit_conditions=True)
    res = saml.handle_acs_response(resp)
    assert res["ok"] is False
    assert res["error"] == "assertion_missing_conditions"


def test_saml_unreadable_cert_fails_closed(saml_env, monkeypatch, tmp_path):
    """Audit fix: a configured-but-unreadable cert must NOT downgrade to
    the HMAC path — it must fail closed."""
    cert_pem, key_pem = saml_env
    from safecadence.auth import saml
    monkeypatch.setenv("SC_SAML_IDP_CERT_FILE", str(tmp_path / "does-not-exist.pem"))
    monkeypatch.setenv("SC_SAML_IDP_SHARED_SECRET", "sekret")  # tempt the downgrade
    res = saml.handle_acs_response(_signed_response(key_pem, cert_pem))
    assert res["ok"] is False
    assert res["error"].startswith("saml_verification_unavailable")


def test_saml_authn_request_redirect(monkeypatch):
    import zlib
    from urllib.parse import parse_qs, urlparse
    monkeypatch.setenv("SC_SAML_IDP_METADATA_URL", "https://idp.test/md")
    monkeypatch.setenv("SC_SAML_SP_ENTITY_ID", "sc-sp")
    monkeypatch.setenv("SC_SAML_IDP_SSO_URL", "https://idp.test/sso")
    from safecadence.auth.saml import build_authn_request
    rid, url = build_authn_request()
    assert url.startswith("https://idp.test/sso?SAMLRequest=")
    q = parse_qs(urlparse(url).query)
    xml = zlib.decompress(
        base64.b64decode(q["SAMLRequest"][0]), -15).decode()
    assert rid in xml
    assert "sc-sp" in xml
