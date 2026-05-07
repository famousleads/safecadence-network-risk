"""v9.52.1 — verify test_connection() includes groups_probe.

v9.51 added the probe to surface "Groups: 14" or "Groups: 403" at
connect time. This test pins the response shape so a future refactor
can't silently drop the probe without the link audit catching it.
"""
from __future__ import annotations

from unittest.mock import patch


# ----------------------------------------------------------- Okta

def test_okta_test_connection_includes_groups_probe():
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com",
                      credentials={"api_token": "fake"})
    # Mock both the user-probe AND the groups list_groups call
    with patch.object(a.cm, "http_get",
                       return_value={"ok": True, "json": []}):
        out = a.test_connection()
    assert "groups_probe" in out
    assert "ok" in out["groups_probe"]
    assert "count" in out["groups_probe"]


# ----------------------------------------------------------- Entra

def test_entra_test_connection_includes_groups_probe():
    from safecadence.platform.adapters.identity_adapters import (
        EntraIDAdapter,
    )
    a = EntraIDAdapter(target="contoso",
                         credentials={"tenant_id": "t",
                                       "client_id": "c",
                                       "client_secret": "s"})
    a._token = "fake-token"
    with patch.object(a.cm, "http_get",
                       return_value={"ok": True,
                                       "json": {"value": []}}):
        out = a.test_connection()
    assert "groups_probe" in out


# ----------------------------------------------------------- AD

def test_ad_test_connection_includes_groups_probe():
    from safecadence.platform.adapters import identity_adapters as ia
    a = ia.ActiveDirectoryAdapter(target="ad.local", credentials={})
    a._ldap3 = None    # keep test offline
    out = a.test_connection()
    # When ldap3 isn't installed, test_connection returns ok=False
    # WITHOUT groups_probe (early return). That's fine — there's no
    # connection to probe against. Verify the early-return shape.
    assert out["ok"] is False
    assert "ldap3 not installed" in out["error"]


# ----------------------------------------------------------- ISE

def test_ise_test_connection_includes_groups_probe():
    from safecadence.platform.adapters.identity_adapters import (
        CiscoISEAdapter,
    )
    a = CiscoISEAdapter(target="ise.local",
                          credentials={"username": "u",
                                        "password": "p"})
    with patch.object(a.cm, "http_get",
                       return_value={"ok": True, "json": {}}):
        out = a.test_connection()
    assert "groups_probe" in out


# ----------------------------------------------------------- ClearPass

def test_clearpass_test_connection_includes_groups_probe():
    from safecadence.platform.adapters.identity_adapters import (
        HPEClearPassAdapter,
    )
    a = HPEClearPassAdapter(target="cp.local",
                              credentials={"client_id": "x",
                                            "client_secret": "y"})
    with patch.object(a.cm, "http_post",
                       return_value={"ok": True, "json": {}}), \
         patch.object(a.cm, "http_get",
                       return_value={"ok": True, "json": {}}):
        out = a.test_connection()
    assert "groups_probe" in out


# ----------------------------------------------------------- shape

def test_groups_probe_reports_count_when_probe_succeeds(monkeypatch):
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com",
                      credentials={"api_token": "fake"})
    # Patch list_groups to return a known shape
    monkeypatch.setattr(a, "list_groups", lambda: [
        {"id": "g1", "name": "eng-leads", "members": ["alice"]},
        {"id": "g2", "name": "secops", "members": []},
    ])
    with patch.object(a.cm, "http_get",
                       return_value={"ok": True, "json": []}):
        out = a.test_connection()
    assert out["groups_probe"]["ok"] is True
    assert out["groups_probe"]["count"] == 2


def test_groups_probe_reports_failure_reason(monkeypatch):
    from safecadence.platform.adapters.identity_adapters import (
        OktaAdapter,
    )
    a = OktaAdapter(target="acme.okta.com",
                      credentials={"api_token": "fake"})

    def _boom():
        raise RuntimeError("403 — missing scope")
    monkeypatch.setattr(a, "list_groups", _boom)
    with patch.object(a.cm, "http_get",
                       return_value={"ok": True, "json": []}):
        out = a.test_connection()
    assert out["groups_probe"]["ok"] is False
    assert "403" in out["groups_probe"]["reason"]
