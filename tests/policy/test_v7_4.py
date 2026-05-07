"""v7.4 — OIDC + SAML stub + MSP agent + adapter harness +
Phase 3 Next.js scaffold."""

from __future__ import annotations

import json
from pathlib import Path


# --------------------------------------------------------------------------
# OIDC
# --------------------------------------------------------------------------

def test_oidc_pkce_pair_format():
    from safecadence.sso import _new_pkce
    verifier, challenge = _new_pkce()
    assert len(verifier) >= 43
    # Challenge is the SHA-256 of the verifier, b64url, no padding
    import base64, hashlib
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode("ascii")
    assert challenge == expected


def test_oidc_resolve_role_from_groups():
    from safecadence.sso import SSOConfig, resolve_role
    cfg = SSOConfig(role_map={"sec-admins": "security_admin",
                                "operators":  "operator"},
                     default_role="viewer")
    claims = {"groups": ["sec-admins", "everyone"]}
    assert resolve_role(cfg, claims) == "security_admin"
    claims = {"groups": ["everyone"]}
    assert resolve_role(cfg, claims) == "viewer"


def test_oidc_resolve_role_from_email_string():
    from safecadence.sso import SSOConfig, resolve_role
    cfg = SSOConfig(role_map={"alice@acme.com": "super_admin"},
                     default_role="viewer")
    assert resolve_role(cfg, {"email": "alice@acme.com"}) == "super_admin"
    assert resolve_role(cfg, {"email": "bob@acme.com"}) == "viewer"


def test_oidc_login_url_includes_pkce_and_state():
    from safecadence.sso import SSOConfig, oidc_login_url, _oidc_pending
    # We have to mock httpx.get for discovery. Easier path: directly
    # test that the URL builder uses the discovery doc structure we
    # expect by stubbing oidc_discover at import time.
    import safecadence.sso as sso
    sso.oidc_discover = lambda issuer: {
        "authorization_endpoint": "https://idp/oauth2/authorize",
        "token_endpoint":         "https://idp/oauth2/token",
        "jwks_uri":               "https://idp/oauth2/keys",
    }
    cfg = SSOConfig(oidc_issuer="https://idp",
                     oidc_client_id="client123",
                     oidc_redirect_uri="https://sc/api/auth/oidc/callback")
    url = oidc_login_url(cfg)
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "state=" in url
    # The state is now in the pending dict
    state = url.split("state=")[1].split("&")[0]
    assert state in _oidc_pending


# --------------------------------------------------------------------------
# SAML — metadata + AuthnRequest builders
# --------------------------------------------------------------------------

def test_saml_metadata_xml_well_formed():
    from xml.etree import ElementTree as ET
    from safecadence.sso import SSOConfig, saml_sp_metadata
    cfg = SSOConfig(saml_sp_entity_id="https://sc.acme.com",
                     saml_sp_acs_url="https://sc.acme.com/api/auth/saml/acs")
    md = saml_sp_metadata(cfg)
    # Parsing must succeed
    root = ET.fromstring(md)
    assert root.tag.endswith("EntityDescriptor")
    assert "https://sc.acme.com" in md
    assert "AssertionConsumerService" in md


def test_saml_authn_request_returns_redirect_url():
    from safecadence.sso import SSOConfig, saml_authn_request
    cfg = SSOConfig(saml_sp_entity_id="https://sc.acme.com",
                     saml_sp_acs_url="https://sc.acme.com/api/auth/saml/acs",
                     saml_idp_sso_url="https://idp.example.com/sso")
    url = saml_authn_request(cfg, relay_state="/dashboard")
    assert url.startswith("https://idp.example.com/sso?")
    assert "SAMLRequest=" in url
    assert "RelayState=%2Fdashboard" in url


def test_saml_consume_raises_until_v75():
    """v7.4 deliberately does NOT honour SAML responses; the contract
    is documented but the xmlsec-based verify lands in v7.5."""
    from safecadence.sso import SSOConfig, saml_consume_response
    import pytest
    with pytest.raises(NotImplementedError) as exc:
        saml_consume_response(SSOConfig(), saml_response_b64="fake")
    assert "v7.5" in str(exc.value)


# --------------------------------------------------------------------------
# MSP control-plane agent
# --------------------------------------------------------------------------

def test_msp_keypair_generated_once(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_MSP_KEY_DIR", str(tmp_path))
    from safecadence.msp_agent import _ensure_keypair
    priv1, pub1 = _ensure_keypair()
    priv2, pub2 = _ensure_keypair()
    assert priv1 == priv2 and pub1 == pub2


def test_msp_state_round_trip(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    monkeypatch.setenv("SC_MSP_STATE", str(state_path))
    from safecadence.msp_agent import AgentState
    s = AgentState(agent_id="acme-prod", agent_token="abc",
                    heartbeat_interval_s=30)
    s.save()
    s2 = AgentState.load()
    assert s2.agent_id == "acme-prod"
    assert s2.heartbeat_interval_s == 30


def test_msp_builtin_command_handlers_registered():
    from safecadence.msp_agent import _HANDLERS
    for name in ("trigger_briefing", "trigger_evaluate", "run_dry_run"):
        assert name in _HANDLERS, f"builtin handler missing: {name}"


# --------------------------------------------------------------------------
# Adapter contract harness
# --------------------------------------------------------------------------

def test_adapter_harness_validates_unified_asset_shape():
    from safecadence.adapter_harness import _validate_unified_asset
    issues = _validate_unified_asset({
        "identity": {"asset_id": "x", "asset_type": "network",
                       "vendor": "cisco"},
        "tags": ["env:prod"],
    })
    assert issues == []
    issues = _validate_unified_asset({
        "identity": {"asset_id": ""},   # missing fields
        "tags": "not-a-list",            # wrong type
        "network": "not-a-dict",         # wrong type
    })
    assert any("asset_id" in i for i in issues)
    assert any("vendor" in i for i in issues)
    assert any("tags" in i for i in issues)
    assert any("network" in i for i in issues)


def test_adapter_harness_run_fixture_handles_missing_dir(tmp_path):
    from safecadence.adapter_harness import run_fixture
    class FakeAdapter:
        def test_connection(self, *a, **kw): return False
        def collect(self, *a, **kw): return {}
        def normalize(self, aid, raw):
            return {"identity": {"asset_id": aid, "asset_type": "network",
                                  "vendor": "cisco"}}
    r = run_fixture(FakeAdapter(), tmp_path / "missing")
    assert r.ok is False
    assert r.fail_count >= 1


def test_adapter_harness_sweep_returns_results():
    from safecadence.adapter_harness import sweep_fixtures
    results = sweep_fixtures()
    # We have 10 production adapters per the manifest. Even without
    # captured fixtures the sweep returns one ContractResult per name.
    assert len(results) >= 5
    for name, r in results.items():
        assert r.adapter == name


# --------------------------------------------------------------------------
# Phase 3 Next.js scaffold
# --------------------------------------------------------------------------

def test_phase3_views_exist():
    repo = Path(__file__).resolve().parents[2]
    web = repo / "webui" / "app"
    for must in ("builder/page.tsx", "remediation/page.tsx",
                  "queue/page.tsx", "rollback/page.tsx",
                  "audit/page.tsx", "settings/page.tsx"):
        assert (web / must).exists(), f"missing webui/app/{must}"


def test_phase3_layout_includes_all_views():
    repo = Path(__file__).resolve().parents[2]
    layout = (repo / "webui" / "app" / "layout.tsx").read_text()
    for path in ("/builder", "/remediation", "/queue", "/rollback",
                  "/audit", "/settings"):
        assert f'href="{path}"' in layout, f"layout nav missing {path}"


# --------------------------------------------------------------------------
# CLI new subcommands
# --------------------------------------------------------------------------

def test_cli_adapter_subcommand_registered():
    from safecadence.cli import cli
    assert "adapter" in cli.commands
    assert "test" in cli.commands["adapter"].commands
    assert "sweep" in cli.commands["adapter"].commands


def test_cli_msp_subcommand_registered():
    from safecadence.cli import cli
    assert "msp" in cli.commands
    for sub in ("register", "heartbeat", "run"):
        assert sub in cli.commands["msp"].commands


# --------------------------------------------------------------------------
# Endpoints registered
# --------------------------------------------------------------------------

def test_sso_endpoints_registered():
    src = (Path(__file__).resolve().parents[2]
           / "src" / "safecadence" / "server" / "platform_api.py").read_text()
    for path in ("/api/auth/oidc/login",
                  "/api/auth/oidc/callback",
                  "/api/auth/saml/metadata",
                  "/api/auth/saml/login",
                  "/api/auth/saml/acs"):
        assert path in src, f"endpoint not registered: {path}"
