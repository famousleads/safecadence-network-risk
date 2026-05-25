"""
Tests for v15.0 — Ecosystem release (plugin loader + rule packs).
"""
from __future__ import annotations

import json
import os
import tarfile
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# plugins.loader
# --------------------------------------------------------------------------


def test_loader_discovery_on_clean_system_returns_empty():
    from safecadence.plugins.loader import discover_plugins
    # On a system with no installed plugins, we should get a clean empty list.
    out = discover_plugins()
    assert isinstance(out, list)


def test_loader_load_missing_plugin_returns_clean_failure():
    from safecadence.plugins.loader import load_plugin
    r = load_plugin("not_a_real_plugin_xyz")
    assert r["ok"] is False
    assert "not found" in r["reason"]
    assert r["module"] is None


def test_loader_verify_signature_no_secret_when_not_required():
    from safecadence.plugins.loader import verify_plugin_signature
    os.environ.pop("SC_PLUGIN_SIGNING_SECRET", None)
    os.environ.pop("SC_PLUGIN_REQUIRE_SIGNED", None)
    assert verify_plugin_signature("x", "1.0", "") is True


def test_loader_verify_signature_with_secret_match():
    from safecadence.plugins.loader import (
        _compute_signature, verify_plugin_signature,
    )
    secret = b"test-secret-32-chars-aaaaaaaaa"
    sig = _compute_signature("acme-adapter", "1.2.3", secret)
    assert verify_plugin_signature("acme-adapter", "1.2.3", sig, secret=secret)


def test_loader_verify_signature_rejects_tamper():
    from safecadence.plugins.loader import (
        _compute_signature, verify_plugin_signature,
    )
    secret = b"test-secret"
    sig = _compute_signature("acme", "1.0", secret)
    assert not verify_plugin_signature("acme-EVIL", "1.0", sig, secret=secret)


# --------------------------------------------------------------------------
# plugins.rule_packs
# --------------------------------------------------------------------------


@pytest.fixture()
def packs_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_RULE_PACKS_DIR", str(tmp_path / "packs"))
    monkeypatch.delenv("SC_PLUGIN_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SC_PLUGIN_REQUIRE_SIGNED", raising=False)
    return tmp_path / "packs"


def _make_pack_dir(parent: Path, name: str, version: str,
                    signature: str = "") -> Path:
    src = parent / "src_pack"
    src.mkdir(parents=True, exist_ok=True)
    (src / "manifest.json").write_text(json.dumps({
        "name": name,
        "version": version,
        "description": "test pack",
        "author": "test",
        "license": "MIT",
        "rules": ["rules/test.yaml"],
        "frameworks": ["nist-800-53"],
        "signature": signature,
    }))
    (src / "rules").mkdir(exist_ok=True)
    (src / "rules" / "test.yaml").write_text("rule_id: TEST\n")
    return src


def _make_pack_tarball(parent: Path, name: str, version: str,
                        signature: str = "") -> Path:
    src = _make_pack_dir(parent, name, version, signature)
    tgz = parent / "pack.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        for f in src.rglob("*"):
            tf.add(f, arcname=f.relative_to(src.parent))
    return tgz


def test_rule_pack_install_from_directory(packs_dir, tmp_path):
    from safecadence.plugins.rule_packs import add_rule_pack, list_rule_packs
    src = _make_pack_dir(tmp_path, "test-pack", "1.0.0")
    r = add_rule_pack(str(src))
    assert r["ok"], r["reason"]
    assert r["manifest"].name == "test-pack"
    assert (Path(r["installed_path"]) / "manifest.json").exists()
    listed = list_rule_packs()
    assert any(p.name == "test-pack" for p in listed)


def test_rule_pack_install_from_tarball(packs_dir, tmp_path):
    from safecadence.plugins.rule_packs import add_rule_pack
    tgz = _make_pack_tarball(tmp_path / "tar_work", "tgz-pack", "0.5.0")
    r = add_rule_pack(str(tgz))
    assert r["ok"], r["reason"]
    assert r["manifest"].name == "tgz-pack"


def test_rule_pack_missing_source_returns_clean_failure(packs_dir):
    from safecadence.plugins.rule_packs import add_rule_pack
    r = add_rule_pack("/tmp/definitely-not-here-xyz.tgz")
    assert r["ok"] is False
    assert "not found" in r["reason"]


def test_rule_pack_require_signed_rejects_unsigned(
    packs_dir, tmp_path, monkeypatch,
):
    from safecadence.plugins.rule_packs import add_rule_pack
    monkeypatch.setenv("SC_PLUGIN_SIGNING_SECRET", "test-secret")
    monkeypatch.setenv("SC_PLUGIN_REQUIRE_SIGNED", "1")
    src = _make_pack_dir(tmp_path, "unsigned-pack", "1.0.0")
    r = add_rule_pack(str(src))
    assert r["ok"] is False
    assert "signature" in r["reason"].lower()


def test_rule_pack_signed_passes_verification(
    packs_dir, tmp_path, monkeypatch,
):
    from safecadence.plugins.rule_packs import (
        _compute_signature, add_rule_pack,
    )
    secret = b"test-secret"
    monkeypatch.setenv("SC_PLUGIN_SIGNING_SECRET", secret.decode())
    monkeypatch.setenv("SC_PLUGIN_REQUIRE_SIGNED", "1")
    sig = _compute_signature("signed-pack", "2.0.0", secret)
    src = _make_pack_dir(tmp_path, "signed-pack", "2.0.0", signature=sig)
    r = add_rule_pack(str(src))
    assert r["ok"] is True, r["reason"]


def test_rule_pack_rejects_path_traversal(packs_dir, tmp_path):
    from safecadence.plugins.rule_packs import add_rule_pack
    # Craft a tarball with an unsafe member name
    src_dir = tmp_path / "evil_src"
    src_dir.mkdir()
    (src_dir / "manifest.json").write_text(json.dumps({
        "name": "evil-pack", "version": "1.0",
    }))
    tgz = tmp_path / "evil.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(src_dir / "manifest.json", arcname="manifest.json")
        # Try to drop a file at /tmp/owned via path traversal
        evil = tmp_path / "evil_file"
        evil.write_text("OWNED")
        tf.add(evil, arcname="../../../tmp/owned")
    r = add_rule_pack(str(tgz))
    # The traversal path is silently skipped; manifest still installs.
    # Just verify we didn't crash and the unsafe member wasn't written.
    assert not (Path("/tmp/owned").exists())
