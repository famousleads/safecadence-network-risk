"""
v10.8 tests — approval chains, SOC 2 evidence, change management hooks,
pen-test workflow, SAML SP stub, AWS Security Hub ingestion.

Everything external is mocked. None of these tests hit the network, a
real SAML IdP, AWS, Jira, or ServiceNow.
"""

from __future__ import annotations

import base64
import io
import json
import os
import zipfile
from unittest import mock

import pytest


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "sc_data"))
    # Disable read-only enforcement by default.
    monkeypatch.delenv("SC_READONLY", raising=False)
    # Clear AWS + SAML knobs.
    for var in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION",
        "SC_SAML_IDP_METADATA_URL", "SC_SAML_SP_ENTITY_ID",
        "SC_SAML_IDP_SHARED_SECRET",
        "SC_SERVICENOW_INSTANCE", "JIRA_CLIENT_ID",
    ):
        monkeypatch.delenv(var, raising=False)
    # Auth disabled means RBAC checks pass automatically — handy default.
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    # Hooks: start each test with a clean hook table so the built-in
    # jira/servicenow stubs don't interfere with explicit assertions.
    from safecadence.workflow.change_mgmt import clear_hooks_for_tests
    clear_hooks_for_tests()
    yield


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _create_org(monkeypatch, name="acme"):
    from safecadence.storage.org_store import create_org
    return create_org(name=name, owner_email="alice@acme.com")


# --------------------------------------------------------------------------
# 1. Approval chains
# --------------------------------------------------------------------------


def test_approval_chain_happy_path(monkeypatch):
    from safecadence.auth.rbac import assign_role, UserRole
    from safecadence.workflow import approval_chains as ac

    org = _create_org(monkeypatch)
    assign_role(org.id, "alice@acme.com", UserRole.ADMIN)
    assign_role(org.id, "bob@acme.com", UserRole.EDITOR)

    chain = ac.define_chain(org.id, "standard", ["editor", "admin"])
    assert chain["role_steps"] == ["editor", "admin"]

    approval = ac.start_approval(org.id, "CVE-2025-0001", "standard",
                                  host="rtr1", rationale="x")
    assert approval.status == "pending"
    assert len(approval.steps) == 2

    # Bob signs the editor step.
    monkeypatch.delenv("SC_AUTH_DISABLED", raising=False)
    ac.sign_step(approval.id, "bob@acme.com", "editor", org_id=org.id)

    # Final admin signature applies the acceptance.
    final = ac.sign_step(approval.id, "alice@acme.com", "admin", org_id=org.id)
    assert final.status == "approved"
    assert final.acceptance_id

    # Acceptance was applied.
    from safecadence.reports.risk_acceptance import is_accepted
    assert is_accepted("CVE-2025-0001", host="rtr1") is not None


def test_approval_chain_rejects_wrong_role(monkeypatch):
    from safecadence.auth.rbac import assign_role, UserRole
    from safecadence.workflow import approval_chains as ac

    org = _create_org(monkeypatch)
    assign_role(org.id, "viewer@acme.com", UserRole.VIEWER)
    ac.define_chain(org.id, "chain1", ["admin"])
    approval = ac.start_approval(org.id, "CVE-X", "chain1")

    monkeypatch.delenv("SC_AUTH_DISABLED", raising=False)
    with pytest.raises(ValueError, match="role"):
        ac.sign_step(approval.id, "viewer@acme.com", "viewer", org_id=org.id)


def test_approval_chain_cancel(monkeypatch):
    from safecadence.workflow import approval_chains as ac

    org = _create_org(monkeypatch)
    ac.define_chain(org.id, "ch", ["admin"])
    ap = ac.start_approval(org.id, "CVE-Y", "ch")
    cancelled = ac.cancel_approval(ap.id, "no longer applicable", org_id=org.id)
    assert cancelled.status == "cancelled"
    # Listing only pending should be empty.
    pending = ac.list_approvals(org.id, status="pending")
    assert pending == []


def test_approval_chain_readonly_refuses(monkeypatch):
    from safecadence.workflow import approval_chains as ac
    org = _create_org(monkeypatch)
    ac.define_chain(org.id, "ch", ["admin"])
    monkeypatch.setenv("SC_READONLY", "1")
    with pytest.raises(PermissionError):
        ac.start_approval(org.id, "X", "ch")


# --------------------------------------------------------------------------
# 2. SOC 2 evidence
# --------------------------------------------------------------------------


def test_evidence_attach_and_list(monkeypatch):
    from safecadence.workflow import soc2_evidence as ev
    org = _create_org(monkeypatch)
    item = ev.attach_evidence(
        org.id, "AC-2", "NIST 800-53", "screenshot",
        b"PNG-bytes-here", "access-control.png",
        note="quarterly evidence", user="alice@acme.com",
    )
    assert item.id.startswith("ev_")
    assert os.path.exists(item.file_ref)
    listed = ev.list_evidence(org.id, framework="NIST 800-53")
    assert len(listed) == 1 and listed[0].id == item.id


def test_evidence_export_zip_shape(monkeypatch):
    from safecadence.workflow import soc2_evidence as ev
    org = _create_org(monkeypatch)
    ev.attach_evidence(
        org.id, "CC-6.1", "SOC 2", "log",
        b"log-line-1\nlog-line-2", "access.log", user="ops",
    )
    ev.attach_evidence(
        org.id, "CC-7.2", "SOC 2", "config",
        b"firewall config", "fw.cfg", user="ops",
    )
    blob = ev.export_evidence_pack(org.id, "SOC 2")
    assert isinstance(blob, bytes) and len(blob) > 0
    zf = zipfile.ZipFile(io.BytesIO(blob))
    names = zf.namelist()
    assert "MANIFEST.csv" in names
    manifest = zf.read("MANIFEST.csv").decode("utf-8")
    assert "CC-6.1" in manifest and "CC-7.2" in manifest
    # Two evidence files plus manifest = 3 entries.
    assert len(names) == 3


def test_evidence_invalid_kind_rejected(monkeypatch):
    from safecadence.workflow import soc2_evidence as ev
    org = _create_org(monkeypatch)
    with pytest.raises(ValueError, match="kind"):
        ev.attach_evidence(org.id, "AC-1", "NIST", "video",
                           b"x", "vid.mp4")


# --------------------------------------------------------------------------
# 3. Change management
# --------------------------------------------------------------------------


def test_change_record_and_list(monkeypatch):
    from safecadence.workflow import change_mgmt as cm
    org = _create_org(monkeypatch)
    cm.record_change(org.id, "template_saved",
                     before=None, after={"id": "t1"}, actor="alice")
    cm.record_change(org.id, "risk_accepted",
                     before=None, after={"id": "ra-x"}, actor="bob")
    rows = cm.list_changes(org.id)
    kinds = [r.kind for r in rows]
    assert "template_saved" in kinds and "risk_accepted" in kinds


def test_change_hook_fires(monkeypatch):
    from safecadence.workflow import change_mgmt as cm
    org = _create_org(monkeypatch)
    captured: list = []

    def my_hook(event):
        captured.append((event.kind, event.actor))

    cm.register_hook("test_hook", my_hook)
    cm.record_change(org.id, "risk_accepted",
                     before=None, after={"id": "ra-7"}, actor="alice")
    assert ("risk_accepted", "alice") in captured


def test_jira_hook_calls_create_ticket(monkeypatch):
    from safecadence.workflow import change_mgmt as cm
    from safecadence.workflow.change_mgmt import _jira_hook

    org = _create_org(monkeypatch)
    monkeypatch.setenv("JIRA_CLIENT_ID", "x")
    monkeypatch.setenv("JIRA_CLIENT_SECRET", "y")

    cm.register_hook("jira", _jira_hook)

    from safecadence.integrations import jira
    with mock.patch.object(jira, "create_jira_ticket",
                            return_value={"issue_key": "SAFE-1",
                                          "url": "https://x"}) as m:
        cm.record_change(org.id, "risk_accepted",
                         before=None,
                         after={"id": "ra-9"},
                         actor="alice",
                         asset_id="rtr1")
        m.assert_called_once()


def test_change_readonly_no_op(monkeypatch):
    from safecadence.workflow import change_mgmt as cm
    org = _create_org(monkeypatch)
    monkeypatch.setenv("SC_READONLY", "1")
    out = cm.record_change(org.id, "risk_accepted", actor="x")
    assert out is None


# --------------------------------------------------------------------------
# 4. Pentest
# --------------------------------------------------------------------------


def test_pentest_lifecycle(monkeypatch):
    from safecadence.workflow import pentest as pt
    org = _create_org(monkeypatch)
    p = pt.create_pentest(org.id, "Q2 external", "*.acme.com",
                           planned_start="2026-04-01",
                           planned_end="2026-04-15")
    assert p.status == "planned"
    p = pt.start_pentest(org.id, p.id)
    assert p.status == "running" and p.actual_start

    f = pt.add_finding(org.id, p.id, "Open SSH 22 on edge",
                       "high", evidence="nmap output…")
    assert f.severity == "high"

    p = pt.complete_pentest(org.id, p.id)
    assert p.status == "completed" and p.actual_end

    p = pt.signoff(org.id, p.id, "ceo@acme.com", note="approved")
    assert p.status == "signed_off"
    assert p.signoff_by == "ceo@acme.com"


def test_pentest_gap_to_remediation(monkeypatch):
    from safecadence.workflow import pentest as pt
    org = _create_org(monkeypatch)
    p = pt.create_pentest(org.id, "test", "scope")
    pt.start_pentest(org.id, p.id)
    pt.add_finding(org.id, p.id, "x", "critical")
    rows = pt.gap_to_remediation(org.id, p.id, target_days=30)
    assert rows and rows[0]["days_open"] >= 0


def test_pentest_cannot_signoff_before_complete(monkeypatch):
    from safecadence.workflow import pentest as pt
    org = _create_org(monkeypatch)
    p = pt.create_pentest(org.id, "test", "scope")
    with pytest.raises(ValueError):
        pt.signoff(org.id, p.id, "x@acme.com")


# --------------------------------------------------------------------------
# 5. SAML
# --------------------------------------------------------------------------


def test_saml_metadata_when_not_configured():
    from safecadence.auth import saml
    xml = saml.metadata_xml()
    assert "not configured" in xml.lower() or "<error" in xml.lower()


def test_saml_metadata_well_formed(monkeypatch):
    monkeypatch.setenv("SC_SAML_IDP_METADATA_URL", "https://idp.example/md")
    monkeypatch.setenv("SC_SAML_SP_ENTITY_ID", "urn:safecadence:sp")
    import xml.etree.ElementTree as ET
    from safecadence.auth import saml
    xml = saml.metadata_xml()
    # Well-formed parse — raises ParseError on failure.
    tree = ET.fromstring(xml)
    assert "EntityDescriptor" in tree.tag


def test_saml_acs_rejects_unsigned_response(monkeypatch):
    monkeypatch.setenv("SC_SAML_IDP_METADATA_URL", "https://idp.example/md")
    monkeypatch.setenv("SC_SAML_SP_ENTITY_ID", "urn:safecadence:sp")
    # Deliberately omit the shared secret — verification must fail.
    monkeypatch.delenv("SC_SAML_IDP_SHARED_SECRET", raising=False)
    from safecadence.auth import saml
    assertion = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml:Subject><saml:NameID>alice@acme.com</saml:NameID></saml:Subject>'
        '</saml:Assertion>'
    )
    encoded = base64.b64encode(assertion.encode()).decode()
    result = saml.handle_acs_response(encoded)
    assert result["ok"] is False
    assert "signature" in (result.get("error") or "")


def test_saml_acs_accepts_signed_response(monkeypatch):
    import hashlib
    import hmac as _hmac
    monkeypatch.setenv("SC_SAML_IDP_METADATA_URL", "https://idp.example/md")
    monkeypatch.setenv("SC_SAML_SP_ENTITY_ID", "urn:safecadence:sp")
    monkeypatch.setenv("SC_SAML_IDP_SHARED_SECRET", "shared-secret")

    from safecadence.auth import saml

    # Build the assertion with a *placeholder* ds:Signature, ask the
    # SP for the canonical form (which strips the Signature element),
    # sign that bytestring, then splice the real signature back in.
    inner = (
        '<saml:Subject><saml:NameID>alice@acme.com</saml:NameID></saml:Subject>'
        '<saml:AttributeStatement>'
        '<saml:Attribute Name="groups">'
        '<saml:AttributeValue>analysts</saml:AttributeValue>'
        '</saml:Attribute>'
        '</saml:AttributeStatement>'
    )
    template = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'{inner}'
        '<ds:Signature><ds:SignatureValue>__SIG__</ds:SignatureValue></ds:Signature>'
        '</saml:Assertion>'
    )
    canonical = saml._canonical_assertion(template.encode())
    sig = _hmac.new(b"shared-secret", canonical, hashlib.sha256).digest()
    sig_b64 = base64.b64encode(sig).decode()
    signed = template.replace("__SIG__", sig_b64)
    encoded = base64.b64encode(signed.encode()).decode()

    result = saml.handle_acs_response(encoded)
    assert result["ok"] is True
    assert result["email"] == "alice@acme.com"
    assert "analysts" in result["groups"]


# --------------------------------------------------------------------------
# 6. AWS Security Hub
# --------------------------------------------------------------------------


def _shub_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_REGION", "us-east-1")


def test_security_hub_not_configured_returns_empty():
    from safecadence.integrations import aws_security_hub as sh
    assert sh.is_configured() is False
    assert sh.ingest_findings() == []


def test_security_hub_ingest_normalised(monkeypatch):
    _shub_env(monkeypatch)
    from safecadence.integrations import aws_security_hub as sh

    response_body = json.dumps({
        "Findings": [{
            "Id": "arn:aws:securityhub:us-east-1::product/abc/finding/1",
            "Title": "EC2.1: EBS volume should be encrypted",
            "Description": "An EBS volume is not encrypted at rest.",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "arn:aws:ec2:us-east-1:111:volume/v-1",
                           "Type": "AwsEc2Volume"}],
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "Vulnerabilities": [{"Id": "CVE-2025-1234"}],
            "AwsAccountId": "111111111111",
            "Region": "us-east-1",
            "Remediation": {"Recommendation": {"Text": "Enable encryption."}},
        }]
    }).encode()

    def fake_signed_request(**kwargs):
        return 200, response_body, {}

    monkeypatch.setattr(sh, "_signed_request", fake_signed_request)
    rows = sh.ingest_findings(region="us-east-1", max=10)
    assert len(rows) == 1
    row = rows[0]
    assert row["severity"] == "high"
    assert row["cve"] == "CVE-2025-1234"
    assert row["source"] == "aws-security-hub"
    assert row["asset_id"].startswith("arn:aws:ec2")


def test_security_hub_handles_http_error(monkeypatch):
    _shub_env(monkeypatch)
    from safecadence.integrations import aws_security_hub as sh
    monkeypatch.setattr(sh, "_signed_request",
                        lambda **kw: (403, b'{"message":"denied"}', {}))
    assert sh.ingest_findings(region="us-east-1") == []


# --------------------------------------------------------------------------
# 7. Wiring sanity: change_mgmt sees risk_acceptance + template events
# --------------------------------------------------------------------------


def test_risk_acceptance_emits_change_event(monkeypatch, tmp_path):
    from safecadence.workflow import change_mgmt as cm
    org = _create_org(monkeypatch)
    monkeypatch.setenv("SAFECADENCE_RISK_ACCEPTANCE_PATH",
                       str(tmp_path / "ra.json"))
    from safecadence.reports.risk_acceptance import add_acceptance
    add_acceptance({
        "finding_id": "CVE-X", "host": "h1", "org_id": org.id,
        "accepted_by": "alice", "rationale": "ok",
    })
    rows = cm.list_changes(org.id, kind="risk_accepted")
    assert len(rows) >= 1
