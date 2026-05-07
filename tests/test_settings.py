"""
v9.25 — unit tests for the file-backed settings store.

Covers:
  * empty/missing file → defaults
  * round-trip save/load
  * token masking on read
  * mask is preserved on save (UI re-submitting the masked token
    must not overwrite the real one)
  * env vars override stored values
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    # Clear any global env override so tests are deterministic.
    for k in ("SC_SPLUNK_HEC_URL", "SC_SPLUNK_HEC_TOKEN",
                "SC_SPLUNK_INDEX", "SC_SPLUNK_SOURCE",
                "SC_SPLUNK_SOURCETYPE"):
        monkeypatch.delenv(k, raising=False)
    yield


def test_empty_settings_returns_defaults():
    from safecadence.settings import get_splunk_config
    cfg = get_splunk_config()
    assert cfg["hec_url"] == ""
    assert cfg["hec_token"] == ""
    assert cfg["enabled"] is False
    assert cfg["source"] == "safecadence"


def test_save_then_load_roundtrip():
    from safecadence.settings import set_splunk_config, get_splunk_config
    set_splunk_config(hec_url="https://splunk.example/services/collector",
                       hec_token="real-secret-token-1234567890",
                       index="netsec", enabled=True)
    cfg = get_splunk_config(masked=False)
    assert cfg["hec_url"] == "https://splunk.example/services/collector"
    assert cfg["hec_token"] == "real-secret-token-1234567890"
    assert cfg["index"] == "netsec"
    assert cfg["enabled"] is True


def test_token_is_masked_on_read():
    from safecadence.settings import set_splunk_config, get_splunk_config
    set_splunk_config(hec_token="real-secret-token-1234567890")
    cfg = get_splunk_config(masked=True)
    assert cfg["hec_token"] != "real-secret-token-1234567890"
    assert "real" in cfg["hec_token"] or "…" in cfg["hec_token"]
    # Real value still retrievable when explicitly unmasked.
    assert get_splunk_config(masked=False)["hec_token"] == \
        "real-secret-token-1234567890"


def test_resaving_with_masked_token_preserves_real_value():
    """The UI shows the masked token. If the operator only edits the
    URL and re-submits, we must NOT overwrite the real token with
    the mask string."""
    from safecadence.settings import set_splunk_config, get_splunk_config
    set_splunk_config(hec_token="real-secret-token-1234567890")
    masked = get_splunk_config(masked=True)["hec_token"]
    # Re-save with the masked value (simulates UI form submit).
    set_splunk_config(hec_url="https://new.example/services/collector",
                       hec_token=masked)
    cfg = get_splunk_config(masked=False)
    assert cfg["hec_token"] == "real-secret-token-1234567890"
    assert cfg["hec_url"] == "https://new.example/services/collector"


def test_env_var_overrides_stored_value(monkeypatch):
    from safecadence.settings import set_splunk_config, get_splunk_config
    set_splunk_config(hec_url="https://stored.example/c")
    monkeypatch.setenv("SC_SPLUNK_HEC_URL", "https://env.example/c")
    cfg = get_splunk_config()
    assert cfg["hec_url"] == "https://env.example/c"


def test_explicit_empty_token_clears():
    """Passing an empty string clears the token (operator wants to
    disable Splunk by zeroing the credential)."""
    from safecadence.settings import set_splunk_config, get_splunk_config
    set_splunk_config(hec_token="real-secret-1234567890")
    set_splunk_config(hec_token="")
    assert get_splunk_config(masked=False)["hec_token"] == ""
