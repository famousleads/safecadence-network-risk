"""Security branding stays local, accessible and available in packaged UIs."""
import json
import xml.etree.ElementTree as ET

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from safecadence.ui._chrome import wrap
from safecadence.ui.pwa import register
from safecadence.ui.security_brand import ICON_NAMES, brand_mark, icon, theme_css


def test_shell_has_new_security_mark_and_no_unresolved_brand_tokens():
    html = wrap("NetRisk", "<h1>Evidence</h1>")
    assert 'class="sc-brand-mark"' in html
    assert 'class="sc-products"' in html
    assert 'href="/map" id="sc-product-safety"' in html
    assert "%ICON:" not in html and "%SECURITY_" not in html
    assert "scCloseMobileNav" in html
    assert 'aria-label="Close navigation menu"' in html
    assert 'aria-label="Switch light / dark theme"' in html
    assert 'role="link"' not in html


def test_demo_notice_is_explicit_and_only_enabled_for_demo(monkeypatch):
    monkeypatch.delenv("SC_DEMO_MODE", raising=False)
    assert '<div class="sc-demo-banner"' not in wrap("NetRisk", "")
    monkeypatch.setenv("SC_DEMO_MODE", "1")
    html = wrap("NetRisk", "")
    assert '<div class="sc-demo-banner" role="note">' in html
    assert 'Sample data, not live monitoring.' in html
    assert "%DEMO_NOTICE%" not in html and "%ICON:" not in html


@pytest.mark.parametrize("name", ICON_NAMES)
def test_bundled_icons_are_valid_decorative_local_svg(name):
    svg = ET.fromstring(icon(name))
    assert svg.tag.endswith("svg") and svg.attrib["viewBox"] == "0 0 24 24"
    assert svg.attrib["aria-hidden"] == "true"
    assert svg.attrib["focusable"] == "false"
    assert svg.attrib["stroke"] == "currentColor"
    assert not list(svg.iter("{http://www.w3.org/2000/svg}script"))
    assert not list(svg.iter("{http://www.w3.org/2000/svg}image"))


def test_no_arbitrary_icon_file_access():
    with pytest.raises(ValueError):
        icon("../../secret")


def test_theme_does_not_need_remote_fonts_or_scripts():
    css = theme_css()
    assert "url(" not in css and "@import" not in css
    assert '--bg: #101518' in css
    assert 'body[data-theme="light"]' in css
    assert "prefers-reduced-motion" in css
    assert ".sc-sidebar-open .sc-nav-scrim" in css
    assert "#7c5cff" not in css


def test_brand_and_installed_app_icon_routes():
    app = FastAPI()
    register(app)
    with TestClient(app) as client:
        manifest = client.get("/manifest.webmanifest").json()
        for entry in manifest["icons"]:
            assert entry["src"].startswith("/static/security-")
            response = client.get(entry["src"])
            assert response.status_code == 200
            assert "image/svg+xml" in response.headers["content-type"]
            ET.fromstring(response.text)
        assert "security-mark.svg" in client.get("/sw.js").text
        assert client.get("/static/security-mark.svg").text == brand_mark()
        assert json.loads(client.get("/manifest.webmanifest").text)["theme_color"] == "#141A1F"
