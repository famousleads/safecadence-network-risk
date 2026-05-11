"""Tests for v10.4 Theme B — Compliance depth.

Covers:

* New frameworks (NIS2, FedRAMP, CMMC) appear in ``_COMPLIANCE_LIBRARY``.
* ``_control_family`` handles the new ID schemes.
* Custom frameworks load from a YAML file and round-trip into the merged
  library.
* SLA policy: KEV uplift overrides a low-priority bucket.
* SLA policy: a past due_date is reported as breached.
* Risk acceptance log: add → query → expire → remove.
* Audit trail: log events and recover TTT/TTR via ``summary_for``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# 1. New frameworks registered
# --------------------------------------------------------------------------


def test_new_frameworks_registered():
    from safecadence.reports.sections import _COMPLIANCE_LIBRARY

    for key in ("NIS2", "FedRAMP", "CMMC"):
        assert key in _COMPLIANCE_LIBRARY, f"missing framework: {key}"
        entry = _COMPLIANCE_LIBRARY[key]
        controls = entry.get("controls") or []
        assert len(controls) >= 10, (
            f"{key} has only {len(controls)} controls (need >= 10)"
        )
        # Tuple shape: (id, title, family, purpose)
        for c in controls:
            assert isinstance(c, tuple) and len(c) == 4
            cid, title, family, purpose = c
            assert cid and title and family and purpose
            assert isinstance(family, str)


def test_new_frameworks_have_metadata():
    from safecadence.reports.sections import _COMPLIANCE_LIBRARY

    nis2 = _COMPLIANCE_LIBRARY["NIS2"]
    assert "NIS 2" in nis2["name"]
    assert nis2["category"] == "EU regulatory"
    assert "Risk management" in nis2["families"]

    fedramp = _COMPLIANCE_LIBRARY["FedRAMP"]
    assert "FedRAMP" in fedramp["name"]
    assert fedramp["category"] == "US federal cloud"
    # Standard FedRAMP baselines
    assert {"Low", "Moderate", "High"}.issubset(set(fedramp["families"]))

    cmmc = _COMPLIANCE_LIBRARY["CMMC"]
    assert "CMMC" in cmmc["name"]
    assert cmmc["category"] == "US defense supply chain"
    assert any("Level" in f for f in cmmc["families"])


# --------------------------------------------------------------------------
# 2. _control_family handles the new ID schemes
# --------------------------------------------------------------------------


def test_control_family_handles_new_id_schemes():
    from safecadence.reports.sections import _control_family

    # NIS2 article numbers
    assert _control_family("NIS2-21.2(a)", "NIS2") == "Article 21"
    assert _control_family("NIS2-23", "NIS2") == "Article 23"

    # FedRAMP uses NIST-style IDs
    assert _control_family("AC-2", "FedRAMP") == "AC"
    assert _control_family("SC-7", "FedRAMP") == "SC"

    # CMMC dotted-domain IDs
    assert _control_family("AC.L2-3.1.5", "CMMC") == "AC"
    assert _control_family("SI.L1-3.14.1", "CMMC") == "SI"


# --------------------------------------------------------------------------
# 3. Custom framework support via YAML
# --------------------------------------------------------------------------


def test_validate_framework_catches_missing_fields():
    from safecadence.reports.custom_frameworks import validate_framework

    errs = validate_framework({})
    assert errs  # must report problems
    assert any("id" in e for e in errs)
    assert any("controls" in e for e in errs)


def test_validate_framework_passes_good_definition():
    from safecadence.reports.custom_frameworks import validate_framework

    good = {
        "id": "ACME-INTERNAL",
        "name": "Acme Internal Security Standard",
        "category": "Internal policy",
        "families": ["Identity", "Network"],
        "controls": [
            {
                "id": "ACME-IAM-01",
                "title": "MFA on all admin",
                "family": "Identity",
                "purpose": "Prevent credential theft.",
            },
        ],
    }
    assert validate_framework(good) == []


def test_custom_framework_yaml_round_trip(tmp_path):
    pytest.importorskip("yaml")
    from safecadence.reports.custom_frameworks import load_custom_frameworks

    yaml_text = """
frameworks:
  - id: "ACME-INTERNAL"
    name: "Acme Internal Security Standard"
    category: "Internal policy"
    families: ["Identity", "Network", "Data"]
    controls:
      - id: "ACME-IAM-01"
        title: "MFA on all admin"
        family: "Identity"
        purpose: "Prevent credential theft from leading to account takeover."
      - id: "ACME-NET-01"
        title: "Egress filtering"
        family: "Network"
        purpose: "Block unexpected outbound traffic."
"""
    p = tmp_path / "frameworks.yaml"
    p.write_text(yaml_text)

    loaded = load_custom_frameworks(str(p))
    assert "ACME-INTERNAL" in loaded
    fw = loaded["ACME-INTERNAL"]
    assert fw["name"] == "Acme Internal Security Standard"
    assert fw["category"] == "Internal policy"
    assert len(fw["controls"]) == 2
    # Internal shape: tuple of (id, title, family, purpose)
    cid, title, family, purpose = fw["controls"][0]
    assert cid == "ACME-IAM-01"
    assert title == "MFA on all admin"
    assert family == "Identity"
    assert "credential theft" in purpose


def test_custom_framework_merges_into_resolver(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    from safecadence.reports import sections

    yaml_text = """
frameworks:
  - id: "ACME-INTERNAL"
    name: "Acme Internal Security Standard"
    category: "Internal policy"
    families: ["Identity"]
    controls:
      - id: "ACME-IAM-01"
        title: "MFA"
        family: "Identity"
        purpose: "p"
"""
    p = tmp_path / "custom.yaml"
    p.write_text(yaml_text)

    monkeypatch.setattr(
        sections,
        "_merged_compliance_library",
        lambda: {
            **sections._COMPLIANCE_LIBRARY,
            "ACME-INTERNAL": {
                "name": "Acme Internal Security Standard",
                "category": "Internal policy",
                "families": ["Identity"],
                "controls": [("ACME-IAM-01", "MFA", "Identity", "p")],
                "custom": True,
            },
        },
    )
    names = sections._resolve_compliance_frameworks(
        {"compliance_frameworks": ["ACME-INTERNAL"]}
    )
    assert "ACME-INTERNAL" in names


# --------------------------------------------------------------------------
# 4. SLA policy
# --------------------------------------------------------------------------


def test_sla_compute_due_date_default_buckets():
    from safecadence.reports.sla_policy import compute_due_date

    base = _dt.date(2026, 5, 10)
    assert compute_due_date("P0", base=base) == "2026-05-24"   # +14d
    assert compute_due_date("P1", base=base) == "2026-06-09"   # +30d
    assert compute_due_date("P2", base=base) == "2026-07-09"   # +60d
    assert compute_due_date("P3", base=base) == "2026-08-08"   # +90d


def test_sla_compute_due_date_kev_uplift():
    """P3 finding flagged KEV should land in the P0 SLA (14d), not P3 (90d)."""
    from safecadence.reports.sla_policy import compute_due_date

    base = _dt.date(2026, 5, 10)
    nonkev = compute_due_date("P3", kev=False, base=base)
    kev = compute_due_date("P3", kev=True, base=base)
    assert nonkev == "2026-08-08"
    assert kev == "2026-05-24"  # 14 days, not 90


def test_sla_compute_due_date_kev_uplift_with_explicit_days(tmp_path):
    """When kev_uplift_days > 0 in policy, that fixed value wins."""
    from safecadence.reports.sla_policy import compute_due_date

    policy = {
        "P0": 14, "P1": 30, "P2": 60, "P3": 90,
        "kev_uplift_days": 7,
        "immediate_priority": "P0",
    }
    base = _dt.date(2026, 5, 10)
    assert compute_due_date("P3", kev=True, base=base, policy=policy) == "2026-05-17"


def test_sla_breach_flag():
    """A finding whose due-date is 5 days ago must be breached."""
    from safecadence.reports.sla_policy import is_breached, sla_status

    today = _dt.date(2026, 5, 10)
    past = (today - _dt.timedelta(days=5)).isoformat()
    future = (today + _dt.timedelta(days=20)).isoformat()
    soon = (today + _dt.timedelta(days=3)).isoformat()

    assert is_breached(past, today=today) is True
    assert is_breached(future, today=today) is False

    assert sla_status(past, today=today) == "BREACHED"
    assert sla_status(soon, today=today) == "DUE_SOON"
    assert sla_status(future, today=today) == "ON_TRACK"


def test_sla_load_policy_from_yaml(tmp_path):
    pytest.importorskip("yaml")
    from safecadence.reports.sla_policy import load_sla_policy

    yaml_text = """
P0: 7
P1: 21
P2: 45
P3: 60
kev_uplift_days: 0
immediate_priority: "P0"
"""
    p = tmp_path / "sla.yaml"
    p.write_text(yaml_text)
    pol = load_sla_policy(str(p))
    assert pol["P0"] == 7
    assert pol["P1"] == 21
    assert pol["P2"] == 45
    assert pol["P3"] == 60


# --------------------------------------------------------------------------
# 5. Risk acceptance log
# --------------------------------------------------------------------------


@pytest.fixture
def acceptance_path(tmp_path, monkeypatch):
    p = tmp_path / "risk_acceptance.json"
    monkeypatch.setenv("SAFECADENCE_RISK_ACCEPTANCE_PATH", str(p))
    yield str(p)


def test_risk_acceptance_round_trip(acceptance_path):
    from safecadence.reports.risk_acceptance import (
        add_acceptance, is_accepted, remove_acceptance, list_acceptances,
        active_acceptances,
    )

    today = _dt.date(2026, 5, 10)
    future = (today + _dt.timedelta(days=180)).isoformat() + "T00:00:00Z"
    rec = add_acceptance({
        "finding_id": "CVE-2024-12345",
        "host": "legacy-app-01",
        "accepted_by": "Jane Doe (CISO)",
        "expires_at": future,
        "rationale": "Vendor patch unavailable",
        "compensating_controls": ["WAF rule X", "Network segmentation"],
    })
    assert rec["id"].startswith("ra-")
    assert rec["accepted_at"]
    assert list_acceptances() == [rec]

    hit = is_accepted("CVE-2024-12345", "legacy-app-01", today=today)
    assert hit is not None
    assert hit["accepted_by"] == "Jane Doe (CISO)"

    # Wrong host → no hit
    miss = is_accepted("CVE-2024-12345", "other-host", today=today)
    assert miss is None

    # Expired entry → no hit
    expired_yesterday = (today - _dt.timedelta(days=1)).isoformat() + "T00:00:00Z"
    add_acceptance({
        "finding_id": "CVE-2024-00001",
        "host": "h2",
        "accepted_by": "Acme",
        "expires_at": expired_yesterday,
        "rationale": "old",
    })
    assert is_accepted("CVE-2024-00001", "h2", today=today) is None
    # active_acceptances filters expired out
    actives = active_acceptances(today=today)
    assert len(actives) == 1
    assert actives[0]["finding_id"] == "CVE-2024-12345"

    # Remove works
    assert remove_acceptance(rec["id"]) is True
    assert is_accepted("CVE-2024-12345", "legacy-app-01", today=today) is None
    # Removing again returns False
    assert remove_acceptance(rec["id"]) is False


def test_risk_acceptance_log_section_renders(acceptance_path):
    from safecadence.reports.sections import risk_acceptance_log
    from safecadence.reports.risk_acceptance import add_acceptance

    # Empty path → empty-state HTML, but still a valid section dict
    out = risk_acceptance_log(None, {})
    assert out["title"] == "Risk acceptance log"
    assert "html_fragment" in out

    future = (_dt.date.today() + _dt.timedelta(days=60)).isoformat() + "T00:00:00Z"
    add_acceptance({
        "finding_id": "CVE-2024-99999",
        "host": "host-a",
        "accepted_by": "CISO",
        "expires_at": future,
        "rationale": "Vendor patch pending",
        "compensating_controls": ["WAF rule"],
    })
    out2 = risk_acceptance_log(None, {})
    html = out2["html_fragment"]
    assert "CVE-2024-99999" in html
    assert "host-a" in html
    assert "WAF rule" in html


def test_risk_acceptance_log_registered_default_off():
    from safecadence.reports.sections import SECTION_REGISTRY

    entry = next(
        (s for s in SECTION_REGISTRY if s["key"] == "risk_acceptance_log"),
        None,
    )
    assert entry is not None
    assert entry["default_enabled"] is False
    assert entry["category"] == "Compliance"


# --------------------------------------------------------------------------
# 6. Audit trail
# --------------------------------------------------------------------------


@pytest.fixture
def trail_path(tmp_path, monkeypatch):
    p = tmp_path / "audit_trail.jsonl"
    monkeypatch.setenv("SAFECADENCE_AUDIT_TRAIL_PATH", str(p))
    yield str(p)


def test_audit_trail_log_and_query(trail_path):
    from safecadence.reports.audit_trail import (
        log_event, events_for, summary_for,
    )

    log_event(
        "CVE-2024-12345", "h1", "discovered",
        actor="netrisk-scanner",
        ts="2026-05-01T08:00:00Z",
    )
    log_event(
        "CVE-2024-12345", "h1", "triaged",
        actor="security-eng", note="Confirmed",
        ts="2026-05-02T10:00:00Z",
    )
    log_event(
        "CVE-2024-12345", "h1", "remediated",
        actor="netops", note="Patched",
        ts="2026-05-05T14:00:00Z",
    )

    events = events_for("CVE-2024-12345", "h1")
    assert len(events) == 3
    # Sorted oldest → newest
    assert events[0]["event"] == "discovered"
    assert events[-1]["event"] == "remediated"
    # Timestamps preserved
    assert events[0]["ts"] == "2026-05-01T08:00:00Z"

    summary = summary_for("CVE-2024-12345", "h1")
    assert summary["discovered_at"] == "2026-05-01T08:00:00Z"
    assert summary["triaged_at"] == "2026-05-02T10:00:00Z"
    assert summary["remediated_at"] == "2026-05-05T14:00:00Z"
    assert summary["ttt"] == 1  # 05-01 → 05-02
    assert summary["ttr"] == 4  # 05-01 → 05-05


def test_audit_trail_unknown_finding_returns_empty(trail_path):
    from safecadence.reports.audit_trail import events_for, summary_for

    assert events_for("nope") == []
    s = summary_for("nope")
    assert s["ttt"] is None
    assert s["ttr"] is None


# --------------------------------------------------------------------------
# 7. Integration: control matrix surfaces due-date + sla columns
# --------------------------------------------------------------------------


def test_control_matrix_includes_sla_columns(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.storage.sqlite_store import SqliteStore
    from safecadence.reports.sections import compliance_control_matrix

    store = SqliteStore(tmp_path / "history.db")
    try:
        sample = {
            "started_at": "2026-05-08T10:00:00Z",
            "vendor": "cisco",
            "asset": {"hostname": "rtr-01", "device_type": "network",
                      "criticality": "critical"},
            "risk_score": 90,
            "risk_band": "critical",
            "cves": [{"id": "CVE-2024-1", "cvss": 9.8, "kev": True}],
            "findings": [
                {"rule_id": "x", "title": "bad config",
                 "severity": "critical",
                 "controls": {"NIST 800-53": "AC-3"}},
            ],
        }
        store.save(sample)
        out = compliance_control_matrix(store, {})
        rows = out["data"]["rows"]
        # Every row has the SLA fields, even if pass → due is empty.
        for r in rows:
            assert "due_date" in r
            assert "sla_status" in r
        # At least one failing/partial row has a non-empty due_date
        nonempty = [r for r in rows if r["due_date"]]
        assert nonempty, "expected at least one row with a due_date"
        # HTML fragment exposes the new columns
        assert "Due date" in out["html_fragment"]
        assert "SLA status" in out["html_fragment"]
    finally:
        store.close()
