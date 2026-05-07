"""
v9.0 — UI redesign tests.

Verify:
  * The new chrome renders with sidebar + topbar + palette + slide-over
  * Every navigated route returns 200 with the same chrome
  * Theme toggle JS is present
  * Keyboard shortcuts are wired
  * Home page has the v9 layout (hero + 3 cards + actions + feed)
"""

from __future__ import annotations

import os
import yaml
from pathlib import Path

import pytest


# ---------------------------------------------------------------- chrome


def test_v9_chrome_has_sidebar_with_seven_groups():
    from safecadence.ui._chrome import wrap
    html = wrap("Test", "<h1>x</h1>")
    # sidebar shell
    assert 'class="sc-sidebar"' in html
    # all 7 groups present
    for g in ("Discover", "Compliance", "Identity", "Execute",
                "Automation", "Audit", "Settings"):
        assert g in html, f"sidebar missing group: {g}"


def test_v9_chrome_has_palette_and_slideover_and_drawer():
    from safecadence.ui._chrome import wrap
    html = wrap("Test", "")
    assert 'id="sc-palette-bg"' in html
    assert 'id="sc-slideover"' in html
    assert 'id="sc-drawer"' in html
    assert "scOpenPalette" in html
    assert "scOpenSlide" in html


def test_v9_chrome_includes_theme_toggle_and_persistence():
    from safecadence.ui._chrome import wrap
    html = wrap("Test", "")
    assert "scToggleTheme" in html
    assert 'data-theme="dark"' in html
    assert "SC_THEME" in html  # localStorage key


def test_v9_chrome_keyboard_shortcuts():
    from safecadence.ui._chrome import wrap
    html = wrap("Test", "")
    assert "Cmd+K" in html or "⌘ K" in html or "⌘K" in html
    # vim-style g{x} navigations
    for combo in ("gh", "gi", "gf", "gj", "ga", "gs", "gk"):
        assert combo in html, f"shortcut missing: {combo}"


def test_v9_chrome_has_breadcrumb_and_topbar_actions():
    from safecadence.ui._chrome import wrap
    html = wrap("Inventory", "")
    assert 'id="sc-breadcrumb"' in html
    assert "Inventory" in html
    # top-bar action buttons
    assert "⌘K" in html
    assert "Ask AI" in html


def test_v9_chrome_includes_command_palette_tools():
    """Palette must list every page so users can navigate from Cmd+K."""
    from safecadence.ui._chrome import wrap
    html = wrap("Test", "")
    for tool in ("Inventory", "Findings", "Identity translator",
                  "JIT grants", "Attack paths", "Simulate",
                  "Automation rules", "Watchlists", "Morning briefing",
                  "Audit timeline", "Public shares", "All tools",
                  "Ask AI"):
        assert tool in html, f"palette missing: {tool}"


# ---------------------------------------------------------------- home


def test_v9_home_has_hero_score_and_three_cards():
    """The redesigned home must include hero compliance circle + 3 stat cards."""
    from safecadence.ui import smart_home
    body = smart_home._HOME_BODY_INLINE
    assert "score-circle" in body
    assert "stat-crit" in body
    assert "stat-paths" in body
    assert "stat-jit" in body
    assert "Critical findings" in body
    assert "Open attack paths" in body
    assert "Active JIT grants" in body


def test_v9_home_has_top3_actions_and_activity_feed():
    from safecadence.ui import smart_home
    body = smart_home._HOME_BODY_INLINE
    assert "Your next 3 actions" in body
    assert "Live activity" in body
    assert "Ask anything" in body or "Ask anything…" in body


def test_v9_home_has_empty_state_with_load_demo():
    from safecadence.ui import smart_home
    body = smart_home._HOME_BODY_INLINE
    assert 'id="empty"' in body
    assert "Load demo data" in body


# ---------------------------------------------------------------- routes + nav


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                       db_url=f"sqlite:///{tmp_path}/sc.db",
                       jwt_secret="test-secret")
    return TestClient(app)


def test_v9_home_renders_with_chrome(client):
    r = client.get("/home")
    assert r.status_code == 200
    # New chrome
    assert "sc-sidebar" in r.text
    assert "sc-topbar" in r.text
    assert "sc-palette" in r.text
    # New home content
    assert "score-circle" in r.text
    assert "Critical findings" in r.text


def test_v9_chromed_pages_pick_up_new_chrome(client):
    """Pages routed through the v9 chrome wrap() inherit the sidebar.

    /identity, /simulate, /share, /asset/{id} still have self-contained
    HTML from earlier versions — their migration is a v9.1 task. We
    test only the pages already on the new chrome here.
    """
    for path in ("/home", "/timeline", "/automation",
                  "/briefing", "/onboarding", "/ask", "/hub"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} failed: {r.text[:200]}"
        assert "sc-sidebar" in r.text, f"{path} missing v9 sidebar"
        assert "sc-palette" in r.text, f"{path} missing command palette"


def test_v9_legacy_pages_still_render_pending_migration(client):
    """Pages with their own self-contained HTML still work in v9.0,
    they just don't have the new chrome yet. Migration is v9.1."""
    for path in ("/identity", "/simulate", "/share"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} should still respond in v9"


def test_v9_palette_search_endpoint_exists(client):
    """The platform search endpoint underpins palette live-search."""
    from fastapi.testclient import TestClient
    # Use the same client; search requires auth token
    from safecadence.server.auth import hash_password
    p = Path(os.environ["SC_USERS_FILE"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump({
        "tenants": {"default": {"users": [{
            "username": "admin",
            "password_hash": hash_password("test-pw"),
            "roles": ["admin"]}]}}}), encoding="utf-8")
    tok = client.post("/api/login",
                       data={"username": "admin",
                             "password": "test-pw"}).json()["access_token"]
    r = client.get("/api/platform/search?q=&limit=5",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
