"""v9.50 — adapter list_groups() implementations.

Each adapter is tested with its real list_groups() method but a
mocked HTTP transport so we can verify the structure without a real
IdP. Empty-credentials path returns [] for every adapter.
"""
from __future__ import annotations

from unittest.mock import patch


# ----------------------------------------------------------- Okta

def test_okta_list_groups_empty_when_no_token():
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com", credentials={})
    assert a.list_groups() == []


def test_okta_list_groups_real_shape():
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com",
                      credentials={"api_token": "fake"})
    # First call returns the groups list; subsequent calls return
    # the per-group members.
    responses = [
        {"ok": True, "json": [
            {"id": "g1", "profile": {"name": "eng-leads"}},
            {"id": "g2", "profile": {"name": "secops"}},
        ]},
        {"ok": True, "json": [
            {"id": "u1", "profile": {"login": "alice@x.com"}},
            {"id": "u2", "profile": {"login": "bob@x.com"}},
        ]},
        {"ok": True, "json": [
            {"id": "u3", "profile": {"login": "carol@x.com"}},
        ]},
    ]
    with patch.object(a.cm, "http_get", side_effect=responses):
        out = a.list_groups()
    assert len(out) == 2
    assert out[0]["name"] == "eng-leads"
    assert out[0]["members"] == ["alice@x.com", "bob@x.com"]
    assert out[1]["members"] == ["carol@x.com"]


def test_okta_list_groups_handles_http_failure():
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com",
                      credentials={"api_token": "fake"})
    with patch.object(a.cm, "http_get",
                       return_value={"ok": False, "error": "401"}):
        assert a.list_groups() == []


# ----------------------------------------------------------- Entra

def test_entra_list_groups_empty_when_no_token():
    from safecadence.platform.adapters.identity_adapters import (
        EntraIDAdapter,
    )
    a = EntraIDAdapter(target="contoso", credentials={})
    assert a.list_groups() == []


def test_entra_list_groups_real_shape():
    from safecadence.platform.adapters.identity_adapters import (
        EntraIDAdapter,
    )
    a = EntraIDAdapter(target="contoso",
                         credentials={"tenant_id": "t",
                                       "client_id": "c",
                                       "client_secret": "s"})
    a._token = "fake-token"
    responses = [
        {"ok": True, "json": {"value": [
            {"id": "g1", "displayName": "eng-leads"},
        ]}},
        {"ok": True, "json": {"value": [
            {"id": "u1", "userPrincipalName": "alice@contoso.com"},
            {"id": "u2", "userPrincipalName": "bob@contoso.com"},
        ]}},
    ]
    with patch.object(a.cm, "http_get", side_effect=responses):
        out = a.list_groups()
    assert len(out) == 1
    assert out[0]["name"] == "eng-leads"
    assert out[0]["members"] == ["alice@contoso.com",
                                    "bob@contoso.com"]


# ----------------------------------------------------------- AD

def test_ad_list_groups_empty_when_no_ldap3():
    from safecadence.platform.adapters import identity_adapters as ia
    a = ia.ActiveDirectoryAdapter(target="ad.local", credentials={})
    a._ldap3 = None    # simulate ldap3 missing
    assert a.list_groups() == []


# ----------------------------------------------------------- ISE

def test_ise_list_groups_empty_when_no_creds():
    from safecadence.platform.adapters.identity_adapters import (
        CiscoISEAdapter,
    )
    a = CiscoISEAdapter(target="ise.local", credentials={})
    assert a.list_groups() == []


def test_ise_list_groups_returns_groups_with_empty_members():
    from safecadence.platform.adapters.identity_adapters import (
        CiscoISEAdapter,
    )
    a = CiscoISEAdapter(target="ise.local",
                          credentials={"username": "ers",
                                        "password": "ers"})
    response = {"ok": True, "json": {"SearchResult": {"resources": [
        {"id": "g1", "name": "BYOD-devices"},
        {"id": "g2", "name": "Contractors"},
    ]}}}
    with patch.object(a.cm, "http_get", return_value=response):
        out = a.list_groups()
    assert len(out) == 2
    assert out[0]["name"] == "BYOD-devices"
    # ISE adapter returns groups but empty members (documented
    # limitation — see adapter docstring).
    assert out[0]["members"] == []


# ----------------------------------------------------------- ClearPass

def test_clearpass_list_groups_empty_when_no_creds():
    from safecadence.platform.adapters.identity_adapters import (
        HPEClearPassAdapter,
    )
    a = HPEClearPassAdapter(target="clearpass.local", credentials={})
    assert a.list_groups() == []


def test_clearpass_list_groups_returns_groups_with_empty_members():
    from safecadence.platform.adapters.identity_adapters import (
        HPEClearPassAdapter,
    )
    a = HPEClearPassAdapter(target="clearpass.local",
                              credentials={"client_id": "x",
                                            "client_secret": "y"})
    response = {"ok": True, "json": {"_embedded": {"items": [
        {"id": 1, "name": "Employees"},
    ]}}}
    with patch.object(a.cm, "http_get", return_value=response):
        out = a.list_groups()
    assert out == [{"id": "1", "name": "Employees", "members": []}]
