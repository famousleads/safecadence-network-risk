"""
v9.34.1 — daemon hook tests.

Pinned properties:
  * NHI stale-finder runs each cycle and merges findings.
  * Identity auto-resync iterates connected vault rows and pulls
    new data; one slow system never blocks others.
  * Both hooks are best-effort — a failure in one never aborts
    the daemon cycle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE",
                        str(tmp_path / "platform_assets"))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    monkeypatch.setenv("SC_SLACK_WEBHOOK", "")
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    yield


def test_daemon_runs_nhi_stale_finder(monkeypatch):
    """Stale NHIs should appear as findings in the daemon's run_cycle
    output without any HTTP call."""
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="legacy-key")
    saved = nhi_store.get(rec.nhi_id)
    saved.created_at = (
        datetime.now(timezone.utc) - timedelta(days=200)
    ).isoformat()
    nhi_store._save(saved)

    from safecadence import daemon
    out = daemon.run_cycle()
    hooks = out.get("compliance_hooks") or {}
    assert "nhi_stale_findings_emitted" in hooks
    assert hooks["nhi_stale_findings_emitted"] >= 1, (
        "daemon must emit at least one NHI stale finding"
    )
    nhi_findings = [f for f in (out.get("findings") or [])
                     if f.get("kind") == "nhi_stale"]
    assert len(nhi_findings) >= 1
    assert any(rec.nhi_id in (f.get("principal") or "")
                 for f in nhi_findings)


def test_daemon_resyncs_connected_identity_systems(monkeypatch):
    """Connected vault rows trigger collect+normalize+save_asset on
    every cycle. Read-only — no test_connection call required at
    sync time, only at connect time."""
    # Save creds via the vault directly (we already pinned the
    # test_passed gate elsewhere).
    from safecadence.identity.vault import IdentityVault
    IdentityVault().save_creds(
        system="okta", target="acme.okta.com",
        credentials={"api_token": "tok-INT"},
        test_passed=True, actor="test",
    )

    # Stub Okta's collect so the daemon doesn't try to reach the network.
    from safecadence.platform.adapters import identity_adapters as IA
    calls = {"collect": 0}

    def fake_collect(self, asset_id):
        calls["collect"] += 1
        return {"users": [{"id": "alice", "status": "ACTIVE"}],
                 "groups": []}

    monkeypatch.setattr(IA.OktaAdapter, "collect", fake_collect)

    from safecadence import daemon
    out = daemon.run_cycle()
    hooks = out.get("compliance_hooks") or {}
    assert hooks.get("identity_systems_resynced") == 1
    assert calls["collect"] == 1, (
        "daemon must call adapter.collect exactly once per connected system"
    )

    # Vault timestamp must be updated.
    rec = IdentityVault().load_creds("okta")
    assert rec.last_synced_at, "daemon must mark_synced after resync"

    # Asset must be in the platform store.
    from safecadence.server.platform_api import list_assets
    matching = [a for a in list_assets()
                 if (a.get("identity") or {}).get("asset_id")
                     == "okta:acme.okta.com"]
    assert len(matching) == 1


def test_daemon_resync_isolates_per_system_failures(monkeypatch):
    """If Okta's collect raises, the daemon records the error in
    identity_resync_errors but the cycle still completes successfully."""
    from safecadence.identity.vault import IdentityVault
    IdentityVault().save_creds(
        system="okta", target="acme.okta.com",
        credentials={"api_token": "x"},
        test_passed=True, actor="test",
    )
    from safecadence.platform.adapters import identity_adapters as IA

    def boom(self, asset_id):
        raise RuntimeError("simulated 500 from Okta")

    monkeypatch.setattr(IA.OktaAdapter, "collect", boom)

    from safecadence import daemon
    out = daemon.run_cycle()
    hooks = out.get("compliance_hooks") or {}
    # The cycle finished — that's the resilience property.
    assert "identity_systems_resynced" in hooks
    assert hooks["identity_systems_resynced"] == 0
    errs = hooks.get("identity_resync_errors") or {}
    assert "okta" in errs
    assert "simulated 500" in errs["okta"]
