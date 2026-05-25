"""
Tests for v15.2.0 — peer config persistence + WebUI form.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def writable_env(tmp_path, monkeypatch):
    """Pin HOME to a tmpdir so config writes don't touch the real ~/.safecadence."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SC_READONLY", raising=False)
    import importlib
    import safecadence.cluster.config_persistence as cp
    importlib.reload(cp)
    yield tmp_path
    importlib.reload(cp)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_read_returns_all_known_keys_when_file_missing(writable_env):
    from safecadence.cluster.config_persistence import KNOWN_KEYS, read_config
    cfg = read_config()
    assert cfg["exists"] is False
    for k in KNOWN_KEYS:
        assert k in cfg["values"]


def test_validate_rejects_unknown_mode():
    from safecadence.cluster.config_persistence import validate
    errors = validate({"SC_HA_MODE": "made-up-mode"})
    assert errors
    assert any("SC_HA_MODE" in e for e in errors)


def test_validate_requires_peer_host_for_peer_sync():
    from safecadence.cluster.config_persistence import validate
    errors = validate({"SC_HA_MODE": "peer-sync"})
    assert any("SC_PEER_HOST is required" in e for e in errors)


def test_validate_requires_long_secret_for_peer_sync():
    from safecadence.cluster.config_persistence import validate
    errors = validate({
        "SC_HA_MODE": "peer-sync",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_SECRET": "too-short",
    })
    assert any("SC_PEER_SECRET" in e and "24" in e for e in errors)


def test_validate_rejects_bad_port():
    from safecadence.cluster.config_persistence import validate
    errors = validate({"SC_HA_MODE": "peer-sync",
                        "SC_PEER_HOST": "x", "SC_PEER_PORT": "99999"})
    assert any("1–65535" in e for e in errors)


def test_validate_rejects_bad_redis_scheme():
    from safecadence.cluster.config_persistence import validate
    errors = validate({"SC_HA_MODE": "shared-stores",
                        "SC_REDIS_URL": "http://nope"})
    assert any("redis://" in e for e in errors)


def test_write_then_read_round_trip(writable_env):
    from safecadence.cluster.config_persistence import (
        read_config, write_config,
    )
    result = write_config({
        "SC_HA_MODE": "peer-sync",
        "SC_NODE_NAME": "node-1",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_PORT": "8767",
        "SC_PEER_SECRET": "a-fairly-long-shared-hmac-secret",
    })
    assert result["ok"]
    cfg = read_config()
    assert cfg["values"]["SC_HA_MODE"] == "peer-sync"
    assert cfg["values"]["SC_NODE_NAME"] == "node-1"
    assert cfg["values"]["SC_PEER_HOST"] == "10.0.0.20"


def test_write_masks_secret_on_read(writable_env):
    from safecadence.cluster.config_persistence import (
        read_config, write_config,
    )
    write_config({
        "SC_HA_MODE": "peer-sync",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_SECRET": "very-long-shared-hmac-secret-abcdef",
    })
    cfg = read_config()
    masked = cfg["masked"]["SC_PEER_SECRET"]
    assert masked.endswith("cdef")
    assert "•" in masked
    # The full secret should NOT appear in the masked view
    assert "very-long" not in masked


def test_empty_secret_on_rewrite_preserves_prior_value(writable_env):
    from safecadence.cluster.config_persistence import (
        read_config, write_config,
    )
    write_config({
        "SC_HA_MODE": "peer-sync",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_SECRET": "first-secret-aaaaaaaaaaaaaaaaaaaa",
    })
    write_config({
        "SC_HA_MODE": "peer-sync",
        "SC_NODE_NAME": "renamed",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_SECRET": "",   # empty = keep prior
    })
    cfg = read_config()
    assert cfg["values"]["SC_NODE_NAME"] == "renamed"
    assert cfg["values"]["SC_PEER_SECRET"] == "first-secret-aaaaaaaaaaaaaaaaaaaa"


def test_readonly_mode_blocks_writes(writable_env, monkeypatch):
    from safecadence.cluster.config_persistence import write_config
    monkeypatch.setenv("SC_READONLY", "1")
    result = write_config({"SC_HA_MODE": "none"})
    assert result["ok"] is False
    assert any("SC_READONLY" in e for e in result["errors"])
    assert result["wrote"] is False


def test_write_creates_file_with_owner_only_permissions(writable_env):
    import stat
    from safecadence.cluster.config_persistence import (
        DEFAULT_CONFIG_PATH, write_config,
    )
    write_config({
        "SC_HA_MODE": "peer-sync",
        "SC_PEER_HOST": "10.0.0.20",
        "SC_PEER_SECRET": "a-fairly-long-shared-hmac-secret",
    })
    mode = DEFAULT_CONFIG_PATH.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


# --------------------------------------------------------------------------
# WebUI
# --------------------------------------------------------------------------


@pytest.fixture()
def client(writable_env):
    os.environ["SC_AUTH_DISABLED"] = "1"
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def test_configure_page_renders(client):
    r = client.get("/cluster-status/configure")
    assert r.status_code == 200
    assert "SC_HA_MODE" in r.text
    assert "SC_PEER_SECRET" in r.text


def test_cluster_status_links_to_configure(client):
    r = client.get("/cluster-status")
    assert "Configure peers" in r.text
    assert "/cluster-status/configure" in r.text


def test_post_invalid_config_shows_errors(client):
    r = client.post(
        "/api/v1/cluster/configure",
        data={"SC_HA_MODE": "peer-sync"},  # missing host + secret
    )
    assert r.status_code == 400
    assert "SC_PEER_HOST is required" in r.text


def test_post_valid_config_redirects_with_saved_flag(client):
    r = client.post(
        "/api/v1/cluster/configure",
        data={
            "SC_HA_MODE": "peer-sync",
            "SC_PEER_HOST": "10.0.0.20",
            "SC_PEER_PORT": "8767",
            "SC_PEER_SECRET": "a-long-shared-hmac-secret-xxxxxx",
            "SC_NODE_NAME": "node-1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "saved=1" in r.headers.get("location", "")


def test_readonly_mode_shows_preview_banner(client, monkeypatch):
    monkeypatch.setenv("SC_READONLY", "1")
    r = client.get("/cluster-status/configure")
    assert r.status_code == 200
    assert "Preview only" in r.text or "SC_READONLY" in r.text


def test_readonly_mode_blocks_save(client, monkeypatch):
    monkeypatch.setenv("SC_READONLY", "1")
    r = client.post(
        "/api/v1/cluster/configure",
        data={"SC_HA_MODE": "peer-sync", "SC_PEER_HOST": "10.0.0.20",
              "SC_PEER_SECRET": "x" * 32},
    )
    assert r.status_code == 400
    assert "SC_READONLY" in r.text or "cannot save" in r.text.lower()
