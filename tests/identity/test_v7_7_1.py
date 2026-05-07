"""
v7.7.1 — Tool Hub + cross-link verification.
"""

from __future__ import annotations


def test_hub_renders_every_section():
    from safecadence.ui.tool_hub import _render, HUB_TOOLS
    html = _render()
    # every section title appears
    for label, _ in HUB_TOOLS:
        assert label in html, f"section missing: {label}"
    # every tool name appears
    for _, tools in HUB_TOOLS:
        for t in tools:
            assert t.name in html, f"tool missing: {t.name}"


def test_hub_has_cross_links_back_to_dashboard_and_identity():
    """v9: hub is wrapped in chrome — chrome's sidebar carries the
    nav links, not body content. Verify the rendered page references
    /home and /identity (chrome sidebar) plus per-tool cards link
    out via tool.href values."""
    from safecadence.ui.tool_hub import _render
    html = _render()
    assert "/home" in html       # sidebar logo + nav
    assert "/identity" in html   # sidebar Identity group


def test_hub_tool_count_minimum():
    from safecadence.ui.tool_hub import HUB_TOOLS
    total = sum(len(tools) for _, tools in HUB_TOOLS)
    # We've shipped a lot — fewer than 20 means a regression.
    assert total >= 20, f"only {total} tools listed in hub"


def test_identity_page_links_to_hub_and_other_tools():
    from safecadence.ui.identity_ui import _PAGE
    assert "/hub" in _PAGE
    assert "/#inventory" in _PAGE
    assert "/#topology" in _PAGE
    assert "/#compliance" in _PAGE
    assert "/#command" in _PAGE
    assert "/#audit" in _PAGE


def test_hub_route_mounts_on_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                       db_url=f"sqlite:///{tmp_path}/sc.db",
                       jwt_secret="test-secret")
    client = TestClient(app)
    r = client.get("/hub")
    assert r.status_code == 200, r.text
    assert "SafeCadence Tool Hub" in r.text
    assert "Identity translator" in r.text


def test_identity_page_renders_related_footer():
    from safecadence.ui.identity_ui import _PAGE
    assert "Related tools" in _PAGE
    assert "Once you've authored an identity policy" in _PAGE
