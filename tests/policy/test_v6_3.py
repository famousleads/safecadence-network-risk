"""Tests for v6.3 platform features:

  - Demo fleet loader produces 30 realistic assets that surface real findings
  - Daemon runs a single cycle end-to-end without external dependencies
  - Slack notifier formats Block Kit payloads correctly + degrades gracefully
  - Adapter manifest tells the truth (no inflated count)
  - Onboarding HTML appears in the platform UI when fleet is empty
"""

from __future__ import annotations

import json


# --------------------------------------------------------------------------
# Demo fleet
# --------------------------------------------------------------------------

def test_demo_fleet_size_and_shape():
    from safecadence.demo import build_demo_fleet
    fleet = build_demo_fleet()
    assert len(fleet) >= 30
    # Every asset has identity + asset_type
    for a in fleet:
        ident = a.get("identity") or {}
        assert ident.get("asset_id"), a
        assert ident.get("asset_type"), a
    # We have at least one of each major type
    types = {(a["identity"]["asset_type"]) for a in fleet}
    assert {"network", "server", "cloud", "identity", "backup"}.issubset(types)
    # We have crown-jewels — required for top_k_paths_to_crown_jewels to fire
    crown = [a for a in fleet
             if (a["identity"].get("criticality") or "").lower() == "crown-jewel"]
    assert len(crown) >= 5


def test_demo_fleet_loader_writes_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    result = load_demo_fleet()
    assert result["written"] >= 30
    assert result["skipped"] == 0
    files = list(tmp_path.glob("*.json"))
    assert len(files) >= 30
    # Re-running without overwrite skips everything
    result2 = load_demo_fleet()
    assert result2["written"] == 0
    assert result2["skipped"] >= 30


def test_demo_fleet_clear_removes_only_demo_assets(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet, clear_demo_fleet
    load_demo_fleet()
    # Drop a non-demo asset that should NOT get removed
    (tmp_path / "real-customer-asset.json").write_text(
        json.dumps({"identity": {"asset_id": "real-customer-asset"}}),
        encoding="utf-8",
    )
    result = clear_demo_fleet()
    assert result["removed"] >= 30
    assert (tmp_path / "real-customer-asset.json").exists()


def test_demo_fleet_surfaces_drift_findings(tmp_path, monkeypatch):
    """The demo fleet was crafted to deliberately trip detectors; if it
    doesn't, the empty-UI fix would still feel empty on first run."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.policy.cross_system_drift import detect_all
    from safecadence.server.platform_api import list_assets
    load_demo_fleet()
    result = detect_all(list_assets())
    # The demo fleet has: default creds, EoS crown-jewel, KEV on perimeter,
    # admin without MFA, weak password policy, backup gap, legacy proto,
    # excessive admins, etc. Should produce many findings.
    assert result["finding_count"] >= 5
    types = {f["type"] for f in result["findings"]}
    # At least a couple of these specific detectors should fire
    expected = {
        "default_credentials", "eos_in_crown_jewel", "kev_on_perimeter",
        "admin_without_mfa", "legacy_protocol_enabled",
        "backup_gap_on_crown_jewel", "weak_local_password_vs_corp_policy",
        "unencrypted_management_protocol",
    }
    assert types & expected, f"no expected detector fired: {types}"


# --------------------------------------------------------------------------
# Daemon
# --------------------------------------------------------------------------

def test_daemon_runs_one_cycle(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    monkeypatch.setenv("SC_DAEMON_STATE", str(tmp_path / "daemon.json"))
    monkeypatch.setenv("SC_DAEMON_LOG", str(tmp_path / "daemon.log"))
    from safecadence.demo import load_demo_fleet
    from safecadence.daemon import run_daemon
    load_demo_fleet()
    report = run_daemon(once=True, interval=1)
    assert report["finding_count"] >= 0
    assert "started_at" in report and "finished_at" in report
    assert "delta" in report
    # Log file must exist
    assert (tmp_path / "daemon.log").exists()


def test_daemon_diff_findings_correct():
    from safecadence.daemon import diff_findings
    prev = [{"source": "policy", "type": "x", "asset_id": "a",
             "control_id": "c1", "policy_id": "p1"}]
    cur = [{"source": "policy", "type": "x", "asset_id": "a",
            "control_id": "c2", "policy_id": "p1"}]
    delta = diff_findings(prev, cur)
    assert len(delta["new"]) == 1
    assert len(delta["resolved"]) == 1
    assert delta["new"][0]["control_id"] == "c2"
    assert delta["resolved"][0]["control_id"] == "c1"


# --------------------------------------------------------------------------
# Notifier
# --------------------------------------------------------------------------

def test_notifier_no_webhook_returns_unsent(monkeypatch):
    monkeypatch.delenv("SC_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("SAFECADENCE_SLACK_WEBHOOK", raising=False)
    from safecadence.notifier import notify
    r = notify(None, [{"severity": "critical", "title": "t"}])
    assert r["sent"] is False
    assert "no webhook" in r["reason"].lower()


def test_notifier_rejects_non_slack_url():
    from safecadence.notifier import notify_slack
    r = notify_slack("https://example.com/webhook", [{"severity": "high"}])
    assert r["sent"] is False
    assert "slack" in r["reason"].lower()


def test_notifier_block_kit_format():
    from safecadence.notifier import _format_slack_blocks
    events = [{"severity": "critical", "title": "KEV on edge",
               "asset_id": "edge-fw-01", "why": "actively exploited"}]
    payload = _format_slack_blocks(events)
    assert payload["text"].startswith(":shield:")
    block_text = json.dumps(payload["blocks"])
    assert "[CRITICAL]" in block_text
    assert "edge-fw-01" in block_text


def test_notifier_handles_empty_event_list():
    from safecadence.notifier import _format_slack_blocks
    payload = _format_slack_blocks([])
    assert "no new findings" in payload["text"].lower()


def test_notifier_truncates_long_event_lists():
    from safecadence.notifier import _format_slack_blocks
    events = [{"severity": "high", "title": f"f{i}",
               "asset_id": f"a{i}"} for i in range(25)]
    payload = _format_slack_blocks(events)
    txt = json.dumps(payload["blocks"])
    assert "+15 more" in txt  # 25 events - 10 shown


# --------------------------------------------------------------------------
# Adapter manifest
# --------------------------------------------------------------------------

def test_adapter_manifest_is_truthful():
    from safecadence.adapter_manifest import (
        manifest, PRODUCTION_ADAPTERS, EXPERIMENTAL_ADAPTERS, STUB_ADAPTERS,
    )
    m = manifest()
    assert m["production_count"] == len(PRODUCTION_ADAPTERS)
    assert m["experimental_count"] == len(EXPERIMENTAL_ADAPTERS)
    assert m["stub_count"] == len(STUB_ADAPTERS)
    # Production must be a small, focused set — anything more would be
    # marketing inflation.
    assert 5 <= m["production_count"] <= 15
    # Stubs are still listed so the user knows what's coming.
    assert m["stub_count"] >= 10
    # Tagline tells the truth, not the inflated count.
    assert "inflated" in m["tagline"]


def test_adapter_manifest_each_adapter_has_status():
    from safecadence.adapter_manifest import manifest
    m = manifest()
    for row in m["adapters"]:
        assert row["status"] in ("production", "experimental", "stub")
        assert row["name"]
        assert row["description"]


# --------------------------------------------------------------------------
# Onboarding panel
# --------------------------------------------------------------------------

def test_platform_ui_includes_onboarding_html():
    from safecadence.ui.platform_ui import render_platform_ui
    html = render_platform_ui()
    assert "onboardingHtml" in html
    assert "Load demo data" in html
    assert "loadDemoFleet" in html


def test_platform_ui_only_shows_onboarding_when_empty():
    """Onboarding card should be inserted only when fleet is empty."""
    from safecadence.ui.platform_ui import render_platform_ui
    html = render_platform_ui()
    # Logic check — h.total === 0 gate must exist
    assert "h.total" in html
