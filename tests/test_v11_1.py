"""Tests for v11.1 — mobile-responsive CSS, PWA, accessibility, and i18n.

These tests exercise the four deliverables that landed in v11.1:

* ``/static/responsive.css`` is served and contains the required
  ``@media (max-width: 768px)`` and ``@media (max-width: 480px)`` blocks.
* ``/manifest.webmanifest`` returns valid JSON with the required PWA
  fields (``name``, ``short_name``, ``start_url``, ``display``, ``icons``).
* ``/sw.js`` is served with the correct JS Content-Type and references a
  cache name versioned with the release.
* The reports wizard HTML includes a "Skip to main content" link, a
  ``role="main"`` landmark, and at least one ``aria-live`` region.
* The i18n module returns the English fallback when a key is missing,
  resolves language from query/cookie/header in the correct order, and
  exposes catalogs for the four stub languages plus English.

All tests are stdlib-only + ``pytest`` + ``fastapi.testclient``.
"""

from __future__ import annotations

import importlib
import json
import os
import pathlib

import pytest


# --------------------------------------------------------------------------
# i18n — framework
# --------------------------------------------------------------------------


def test_i18n_returns_english_fallback_for_missing_key():
    from safecadence import i18n
    i18n.reload_catalogs()
    i18n.set_lang("en")
    # A key that definitely doesn't exist in any catalog.
    assert i18n.t("nonexistent.key.zzz") == "nonexistent.key.zzz"


def test_i18n_returns_english_when_key_missing_in_target_lang():
    from safecadence import i18n
    i18n.reload_catalogs()
    # "common.save" exists only in English (the stubs have it too, but it's
    # always present in en). Pull a key that only English has.
    i18n.set_lang("en")
    val_en = i18n.t("common.required")
    assert val_en == "Required"

    # In Spanish, "common.required" is missing → must fall back to English.
    i18n.set_lang("es")
    assert i18n.t("common.required") == "Required"


def test_i18n_french_catalog_loads_and_returns_stub():
    from safecadence import i18n
    i18n.reload_catalogs()
    i18n.set_lang("fr")
    val = i18n.t("reports.title")
    # Stubs are prefixed with [TODO-FR] until translators fill them in.
    assert "[TODO-FR]" in val


def test_i18n_resolve_lang_query_wins_over_everything():
    from safecadence import i18n
    out = i18n.resolve_lang("fr", "de", "ja-JP,ja;q=0.9")
    assert out == "fr"


def test_i18n_resolve_lang_cookie_wins_over_header():
    from safecadence import i18n
    out = i18n.resolve_lang(None, "de", "ja-JP,ja;q=0.9,en;q=0.5")
    assert out == "de"


def test_i18n_resolve_lang_accept_language_used_when_no_query_no_cookie():
    from safecadence import i18n
    out = i18n.resolve_lang(None, None, "ja-JP,ja;q=0.9,en;q=0.5")
    assert out == "ja"


def test_i18n_resolve_lang_unsupported_falls_back_to_english():
    from safecadence import i18n
    out = i18n.resolve_lang("xx", "yy", "zz-ZZ,zz")
    assert out == "en"


def test_i18n_available_langs_includes_all_five():
    from safecadence import i18n
    i18n.reload_catalogs()
    langs = set(i18n.available_langs())
    assert {"en", "es", "fr", "de", "ja"}.issubset(langs)


def test_i18n_format_substitution_works():
    from safecadence import i18n
    # The catalog ships a few keys without variables; we test the fallback
    # path through to a key that doesn't exist but has format vars.
    i18n.reload_catalogs()
    i18n.set_lang("en")
    out = i18n.t("welcome.message {name}", name="Ada")
    # Missing key → returns the key itself, then formats it.
    assert "Ada" in out


# --------------------------------------------------------------------------
# accessibility.md exists + has the audit
# --------------------------------------------------------------------------


def test_accessibility_doc_exists_and_lists_checks():
    here = pathlib.Path(__file__).resolve()
    repo = here.parents[1]
    md = repo / "src" / "safecadence" / "ui" / "accessibility.md"
    assert md.exists(), "v11.1 must ship src/safecadence/ui/accessibility.md"
    txt = md.read_text(encoding="utf-8")
    # The audit must cover at least these WCAG SCs.
    for sc in ("1.1.1", "2.4.1", "2.4.7", "1.4.3", "4.1.3"):
        assert sc in txt, f"accessibility.md should reference WCAG SC {sc}"
    # And must list what's still TODO.
    assert "TODO" in txt.upper()


# --------------------------------------------------------------------------
# Mobile scaffold doc exists
# --------------------------------------------------------------------------


def test_mobile_readme_exists():
    here = pathlib.Path(__file__).resolve()
    repo = here.parents[1]
    readme = repo / "mobile" / "README.md"
    assert readme.exists()
    txt = readme.read_text(encoding="utf-8")
    assert "react-native" in txt.lower()


# --------------------------------------------------------------------------
# responsive.css served + breakpoint blocks present
# --------------------------------------------------------------------------


def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def test_responsive_css_is_served():
    client = _client()
    r = client.get("/static/responsive.css")
    assert r.status_code == 200
    body = r.text
    assert "@media (max-width: 768px)" in body
    assert "@media (max-width: 480px)" in body
    # tap-target a11y rule
    assert "44px" in body
    # skip-to-content helper
    assert ".skip-to-content" in body


# --------------------------------------------------------------------------
# PWA — manifest + service worker
# --------------------------------------------------------------------------


def test_manifest_is_valid_pwa_json():
    client = _client()
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200
    # Content-Type should at least include "manifest+json".
    ct = r.headers.get("content-type", "")
    assert "manifest" in ct or "json" in ct
    data = json.loads(r.text)
    for required in ("name", "short_name", "start_url", "display", "icons"):
        assert required in data, f"manifest missing required field {required}"
    assert data["display"] == "standalone"
    assert isinstance(data["icons"], list) and len(data["icons"]) >= 1
    # Each icon must have src, sizes, type.
    for icon in data["icons"]:
        assert "src" in icon and "sizes" in icon and "type" in icon


def test_service_worker_is_served_with_js_content_type():
    client = _client()
    r = client.get("/sw.js")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "javascript" in ct
    body = r.text
    # Must declare the install + fetch handlers and a versioned cache name.
    assert "addEventListener('install'" in body
    assert "addEventListener('fetch'" in body
    assert "sc-v" in body  # versioned cache prefix


# --------------------------------------------------------------------------
# Reports wizard — accessibility surface
# --------------------------------------------------------------------------


def test_reports_wizard_has_skip_to_content_and_main_landmark():
    client = _client()
    r = client.get("/reports")
    assert r.status_code == 200
    html = r.text
    assert "Skip to main content" in html
    assert 'id="sc-main-content"' in html
    assert 'role="main"' in html
    # at least one aria-live region (preview or stamp)
    assert "aria-live" in html


def test_reports_wizard_uses_i18n_substitution_default_english():
    client = _client()
    r = client.get("/reports")
    html = r.text
    # The substitution should have happened — raw "%T:..." placeholders
    # must not leak into the rendered HTML.
    assert "%T:" not in html
    # English defaults end up in the page.
    assert "Choose a starting point" in html


def test_reports_wizard_lang_query_switches_to_french_stub():
    client = _client()
    r = client.get("/reports?lang=fr")
    html = r.text
    assert "%T:" not in html
    # The French stub for reports.choose_start has [TODO-FR] prefix.
    assert "[TODO-FR]" in html


# --------------------------------------------------------------------------
# Version + CHANGELOG bump
# --------------------------------------------------------------------------


def test_version_string_is_at_least_11_1():
    import safecadence
    # Accept 11.1.x or any later 11.x — the test guarantees v11.1
    # shipped without pinning to the exact release.
    parts = safecadence.__version__.split(".")
    assert len(parts) >= 2
    major, minor = int(parts[0]), int(parts[1])
    assert (major, minor) >= (11, 1), (
        f"Expected version >= 11.1, got {safecadence.__version__}"
    )


def test_changelog_has_v11_1_entry():
    here = pathlib.Path(__file__).resolve()
    repo = here.parents[1]
    cl = repo / "CHANGELOG.md"
    txt = cl.read_text(encoding="utf-8")
    assert "[11.1.0]" in txt or "[11.1.1]" in txt
