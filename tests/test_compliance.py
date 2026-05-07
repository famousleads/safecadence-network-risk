"""
v9.27 — comprehensive tests for the compliance suite.

Covers (in this order):
  * mappings        — control-to-framework mapping pack + coverage math
  * sla             — finding SLA annotation + breach detection
  * exception_lifecycle — create / list / revoke / expire / promote-to-finding
  * control_history — append + history + summary + prune
  * risk_register   — create / list / score / update / delete
  * baseline_drift  — set / get / clear / compute / promote-to-finding
  * auditor_portal  — issue / verify / scope / expiry / revoke
  * evidence_chain  — append / verify / tamper-detection
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("yaml", reason="PyYAML required for v9.27 packs")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Each test gets a clean SC_DATA_DIR so file-backed state
    doesn't bleed between tests."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    yield


# =========================================================== mappings


def test_mappings_loads_known_control():
    from safecadence.compliance.mappings import load_mappings
    m = load_mappings(force_reload=True)
    assert "enforce_mfa" in m
    assert "enforce_logging" in m
    assert "iso_27001_2022" in m["enforce_mfa"]


def test_mappings_lists_all_six_frameworks():
    from safecadence.compliance.mappings import list_frameworks
    fws = list_frameworks()
    keys = {f["key"] for f in fws}
    for k in ("nist_800_53", "cis_v8", "pci_dss_4", "hipaa",
                "iso_27001_2022", "soc2_tsc"):
        assert k in keys
    # Each framework must have non-zero coverage given our seed pack.
    assert all(f["covered_count"] > 0 for f in fws)


def test_coverage_returns_per_framework_id_rows():
    from safecadence.compliance.mappings import coverage
    c = coverage("nist_800_53")
    assert c["covered_count"] > 0
    # AC-2 should be covered (require_aaa, idp_disable_dormant_accounts, etc.)
    fids = {row["framework_id"] for row in c["covered"]}
    assert "AC-2" in fids


def test_control_detail_carries_metadata():
    from safecadence.compliance.mappings import control_detail
    d = control_detail("enforce_mfa")
    assert d.get("owner_default")
    assert d.get("frequency")
    assert d.get("evidence_type")
    assert d.get("sla_severity_days")


# =========================================================== sla


def test_sla_critical_finding_breaches_quickly():
    from safecadence.compliance.sla import annotate_finding
    old = datetime.now(timezone.utc) - timedelta(days=30)
    f = {"id": "f1", "severity": "critical", "control_id": "enforce_mfa",
          "opened_at": old.isoformat(), "status": "open"}
    a = annotate_finding(f)
    assert a.breached is True
    assert a.breach_age_days > 0


def test_sla_resolved_finding_does_not_breach():
    from safecadence.compliance.sla import annotate_finding
    old = datetime.now(timezone.utc) - timedelta(days=30)
    f = {"id": "f1", "severity": "critical", "control_id": "enforce_mfa",
          "opened_at": old.isoformat(), "status": "resolved"}
    a = annotate_finding(f)
    assert a.breached is False


def test_sla_breach_summary_counts_by_severity():
    from safecadence.compliance.sla import breach_summary
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    findings = [
        {"id": "a", "severity": "critical", "opened_at": old, "status": "open"},
        {"id": "b", "severity": "low", "opened_at": old, "status": "open"},
        {"id": "c", "severity": "high", "opened_at": old, "status": "open"},
    ]
    s = breach_summary(findings)
    assert s["total_findings"] == 3
    assert s["breached"] == 3


def test_sla_synthetic_findings_emit_for_breaches():
    from safecadence.compliance.sla import sla_breaches_as_findings
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    out = sla_breaches_as_findings([
        {"id": "x", "severity": "low", "opened_at": old, "status": "open"},
    ])
    assert len(out) == 1
    assert out[0]["kind"] == "sla_breach"


# =========================================================== exceptions


def test_exception_create_persists_and_lists():
    from safecadence.compliance.exception_lifecycle import (
        create_exception, list_exceptions,
    )
    rec = create_exception(
        control_id="enforce_mfa", asset_id="rtr-1",
        finding_id="f1", justification="legacy box, scheduled retirement Q2",
        accepted_by="ciso@acme.com", valid_for_days=30,
    )
    assert rec.id.startswith("exc-")
    rows = list_exceptions(status="active")
    assert any(r["id"] == rec.id for r in rows)


def test_exception_create_rejects_short_justification():
    from safecadence.compliance.exception_lifecycle import create_exception
    with pytest.raises(ValueError):
        create_exception(control_id="enforce_mfa", asset_id="x",
                          finding_id="f1", justification="too short",
                          accepted_by="x", valid_for_days=30)


def test_exception_revoke():
    from safecadence.compliance.exception_lifecycle import (
        create_exception, revoke_exception, list_exceptions,
    )
    rec = create_exception(
        control_id="enforce_mfa", asset_id="rtr-1",
        finding_id="f1", justification="long enough justification text",
        accepted_by="ciso", valid_for_days=30,
    )
    assert revoke_exception(rec.id, by="ciso") is True
    rows = list_exceptions(status="revoked")
    assert any(r["id"] == rec.id for r in rows)


def test_exception_expiring_promotes_to_finding():
    from safecadence.compliance.exception_lifecycle import (
        create_exception, expiring_exceptions_as_findings,
    )
    create_exception(
        control_id="enforce_mfa", asset_id="rtr-1",
        finding_id="f1", justification="long enough justification text",
        accepted_by="ciso", valid_for_days=7,   # re-review in ~3 days
    )
    out = expiring_exceptions_as_findings(within_days=14)
    assert len(out) == 1
    assert out[0]["kind"] == "exception_expiring"


# =========================================================== control_history


def test_control_history_append_then_history():
    from safecadence.compliance.control_history import record, history
    record("enforce_mfa", "rtr-1", "pass", method="config_inspection")
    record("enforce_mfa", "rtr-1", "fail", method="config_inspection")
    rows = history(control_id="enforce_mfa", days=30)
    assert len(rows) == 2


def test_control_history_summary_for_evidence_pack():
    from safecadence.compliance.control_history import (
        record, summary_for_evidence_pack,
    )
    for _ in range(5):
        record("enforce_mfa", "rtr-1", "pass")
    record("enforce_mfa", "rtr-1", "fail")
    summary = summary_for_evidence_pack(days=30)
    row = next(r for r in summary if r["control_id"] == "enforce_mfa")
    assert row["tests"] == 6
    assert row["pass"] == 5
    assert row["fail"] == 1
    assert 80 < row["effectiveness_pct"] < 90


# =========================================================== risk_register


def test_risk_create_and_score():
    from safecadence.compliance.risk_register import (
        create_risk, get_risk,
    )
    rec = create_risk(
        title="Ransomware via misconfigured RDP",
        description="Public RDP on jump host",
        owner="ciso@acme.com",
        domain="server",
        likelihood=3, impact=5,
        control_ids=["enforce_mfa", "restrict_management_access"],
        mitigation="Force CA, disable public RDP",
    )
    assert rec.id.startswith("risk-")
    detail = get_risk(rec.id)
    assert detail["inherent_score"] == 15
    assert detail["band_inherent"] in ("high", "critical")


def test_risk_validates_levels():
    from safecadence.compliance.risk_register import create_risk
    with pytest.raises(ValueError):
        create_risk(title="x" * 5, description="y", owner="o",
                      domain="server", likelihood=6, impact=3)


def test_risk_residual_drops_with_strong_controls():
    """Pre-populate control_history with passes so the residual score
    drops below the inherent score."""
    from safecadence.compliance.control_history import record
    from safecadence.compliance.risk_register import create_risk, get_risk
    for _ in range(20):
        record("enforce_mfa", "rtr-1", "pass")
    rec = create_risk(
        title="Some risk", description="x", owner="o",
        domain="server", likelihood=4, impact=4,
        control_ids=["enforce_mfa"],
    )
    d = get_risk(rec.id)
    assert d["residual_score"] < d["inherent_score"]


def test_risk_delete():
    from safecadence.compliance.risk_register import (
        create_risk, delete_risk, get_risk,
    )
    rec = create_risk(title="Some risk", description="x", owner="o",
                       domain="server", likelihood=2, impact=2)
    assert delete_risk(rec.id) is True
    assert get_risk(rec.id) is None


# =========================================================== baseline_drift


def test_baseline_set_get_clear():
    from safecadence.compliance.baseline_drift import (
        set_baseline, get_baseline, clear_baseline,
    )
    meta = set_baseline("rtr-1", "aaa new-model\nip ssh version 2\n")
    assert meta["asset_id"] == "rtr-1"
    assert get_baseline("rtr-1").startswith("aaa new-model")
    assert clear_baseline("rtr-1") is True
    assert get_baseline("rtr-1") is None


def test_baseline_drift_flags_added_and_removed():
    from safecadence.compliance.baseline_drift import (
        set_baseline, compute_drift,
    )
    set_baseline("rtr-1",
                  "aaa new-model\n"
                  "ip ssh version 2\n"
                  "no ip http server\n")
    current = ("aaa new-model\n"
                 "ip ssh version 2\n"
                 "ip http server\n"           # removed (no ip http server)
                 "service password-encryption\n")  # added
    rep = compute_drift("rtr-1", current)
    assert rep.has_baseline is True
    assert any("service password-encryption" in line for line in rep.added)
    assert any("no ip http server" in line for line in rep.removed)


def test_baseline_drift_returns_no_baseline_marker_when_unset():
    from safecadence.compliance.baseline_drift import compute_drift
    rep = compute_drift("never-set", "any config")
    assert rep.has_baseline is False


def test_baseline_safe_id_blocks_traversal():
    from safecadence.compliance.baseline_drift import set_baseline
    with pytest.raises(ValueError):
        set_baseline("../../etc/passwd", "x")


# =========================================================== auditor_portal


def test_auditor_issue_and_verify():
    from safecadence.compliance.auditor_portal import issue, verify
    rec, secret = issue(name="Acme CPA Q4", issued_to="auditor@acme.com",
                          valid_for_days=30)
    found = verify(secret, path="/compliance")
    assert found is not None
    assert "secret_hash" not in found  # hash never returned


def test_auditor_secret_does_not_match_others():
    from safecadence.compliance.auditor_portal import issue, verify
    issue(name="A", issued_to="a@x.com", valid_for_days=30)
    assert verify("wrong-secret", path="/compliance") is None


def test_auditor_scope_blocks_unauthorized_path():
    from safecadence.compliance.auditor_portal import issue, verify
    rec, secret = issue(name="X", issued_to="a@x.com",
                          valid_for_days=30,
                          scope=["/compliance"])
    assert verify(secret, path="/compliance") is not None
    assert verify(secret, path="/policies") is None


def test_auditor_revoke_kills_token():
    from safecadence.compliance.auditor_portal import (
        issue, revoke, verify,
    )
    rec, secret = issue(name="X", issued_to="a@x.com", valid_for_days=30)
    assert revoke(rec.id) is True
    assert verify(secret, path="/compliance") is None


# =========================================================== evidence_chain


def test_evidence_chain_append_and_verify_intact():
    from safecadence.compliance.evidence_chain import (
        append, verify_chain, list_chain,
    )
    append(framework="soc2", content=b"hello world",
            generated_by="test")
    append(framework="iso27001", content=b"another pack")
    rep = verify_chain()
    assert rep["ok"] is True
    assert rep["checked"] == 2
    rows = list_chain()
    assert len(rows) == 2


def test_evidence_chain_detects_tampering():
    """Mutate a record in the chain and confirm verify_chain catches it."""
    import json
    from pathlib import Path
    import os
    from safecadence.compliance.evidence_chain import (
        append, verify_chain, _store_path,
    )
    append(framework="soc2", content=b"a")
    append(framework="soc2", content=b"b")
    p = _store_path()
    raw = p.read_text(encoding="utf-8").splitlines()
    # Mutate the first record's content_sha256 — chain should detect.
    obj = json.loads(raw[0])
    obj["content_sha256"] = "0" * 64
    raw[0] = json.dumps(obj, separators=(",", ":"))
    p.write_text("\n".join(raw) + "\n", encoding="utf-8")
    rep = verify_chain()
    assert rep["ok"] is False
    assert rep["broken_at"] is not None


def test_evidence_chain_verify_content_round_trip():
    from safecadence.compliance.evidence_chain import (
        append, verify_content,
    )
    rec = append(framework="pci", content=b"audit-evidence")
    out = verify_content(rec["pack_id"], b"audit-evidence")
    assert out["match"] is True
    bad = verify_content(rec["pack_id"], b"tampered")
    assert bad["match"] is False
