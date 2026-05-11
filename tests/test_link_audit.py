"""
v9.22 — link audit: crawl every v9 navigable page and assert the
sidebar + page-body links don't 404 and don't serve JSON to a click.

Why we have this:
    Through v9.16.1 and v9.20.1 we kept tripping over broken links —
    audit-log linking to a JSON dump, /mitre 404, coverage CTAs that
    didn't deep-link to /inventory, etc. This test catches the next
    regression *in CI* instead of waiting for the operator to find it.

What it covers:
    * Every page reachable from the sidebar returns 200 with text/html.
    * Every internal href on those pages resolves: 200 / 302 / 401 are
      acceptable (401 = auth-gated API endpoints, intentional).
    * Navigation links never serve `application/json` — that's the
      "click goes to a JSON dump" foot-gun we hit in v9.16.1.

What it intentionally does NOT cover:
    * External links (http://, https://) — out of scope for nav.
    * Routes that legitimately need a path param without a default
      (e.g. /share/{token}, /asset/{asset_id}) — those are spot-checked
      separately with a known-good ID.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

import pytest

fastapi = pytest.importorskip("fastapi", reason="server extras not installed")


# ----------------------------------------------------------- fixtures


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Boot a clean FastAPI app under a fresh tenant + data dir."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "scdata"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret-do-not-use-in-prod")
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret-do-not-use-in-prod")
    return TestClient(app)


# Pages that *must* render with the v9 chrome and never 404.
# Drawn from the sidebar in src/safecadence/ui/_chrome.py.
_NAV_PAGES = [
    "/home",
    # Discover
    "/inventory", "/groups", "/topology", "/shadow-it",
    "/coverage", "/changes", "/discovery-jobs", "/tags", "/scope",
    # Compliance
    "/policies", "/findings", "/drift", "/evidence",
    # Identity
    "/identity", "/jit", "/paths", "/simulate", "/access",
    # Execute
    "/execute", "/builder", "/approvals", "/queue", "/rollback",
    "/per-device-diff", "/blast-radius",
    "/scores", "/compliance", "/risks", "/vendors", "/policies/new",
    # Automation
    "/automation", "/watchlists", "/briefing",
    # Audit
    "/timeline", "/audit", "/idp-groups", "/share",
    # Settings
    "/settings", "/users", "/capabilities",
    "/onboarding", "/hub", "/help",
    # Misc
    "/tour", "/ask",
]


# Path params that don't have a default route — skip when seen as a
# bare pattern in extracted hrefs but spot-check below with sample IDs.
_SKIP_TEMPLATE = re.compile(r"\{[^}]+\}")


# Hrefs that legitimately point at API endpoints we don't expect a
# browser-friendly HTML response from. These are allowed to return
# 200 OR 401 (auth required) but we don't load them as nav links.
_API_PREFIXES = ("/api/",)


# Hrefs on a few pages that point at downloadable files / non-page
# resources — exclude from the "every nav link must be HTML" check.
_DOWNLOAD_HINTS = ("/download", ".csv", ".pdf", ".json", "?format=csv")


# v11.1 — PWA endpoints are not HTML pages by design. The manifest is
# application/manifest+json, the service worker is text/javascript.
# They're referenced from chrome <head> via <link rel="manifest"> and
# the SW boot script — never as nav clicks — so they don't need to
# satisfy the "nav link must serve HTML" contract.
_PWA_PATHS = ("/manifest.webmanifest", "/sw.js")


# ----------------------------------------------------------- helpers


_HREF_RE = re.compile(
    r"""href\s*=\s*["'](?P<u>/[^"'\s>#]+)["']""", re.IGNORECASE
)
_LOC_RE = re.compile(
    r"""location\.href\s*=\s*["'](?P<u>/[^"'\s>?]+)["']"""
)


def _extract_internal_links(html: str) -> set[str]:
    found = set()
    for rx in (_HREF_RE, _LOC_RE):
        for m in rx.finditer(html):
            u = m.group("u")
            # strip the query string for the audit — query params often
            # come from JS string concatenation we can't statically reason
            # about (e.g. "/inventory?open=" + key).
            u = u.split("?", 1)[0].rstrip("/")
            if not u:
                u = "/"
            if _SKIP_TEMPLATE.search(u):
                continue
            if any(u.endswith(s) or s in u for s in _DOWNLOAD_HINTS):
                continue
            found.add(u)
    return found


def _is_html(resp) -> bool:
    return "text/html" in (resp.headers.get("content-type") or "").lower()


# ----------------------------------------------------------- tests


@pytest.mark.parametrize("path", _NAV_PAGES)
def test_nav_page_renders_html(client, path):
    """Every page reachable from the sidebar renders 200 text/html."""
    r = client.get(path)
    # Some pages may redirect (e.g. trailing slash) — accept 2xx/3xx.
    assert r.status_code < 400, f"{path} → {r.status_code}: {r.text[:200]}"
    if r.status_code == 200:
        assert _is_html(r), (
            f"{path} returned content-type "
            f"{r.headers.get('content-type')} — nav links must be HTML, "
            f"not JSON dumps (regression like v9.16.1 audit-log link)"
        )


@pytest.mark.parametrize("path,wiring", [
    # v9.32.1 — /drift is now a 3-tab roll-up (policy / baseline /
    # cross-system) backed by /api/drift/all instead of just the
    # single cross-system table. Guard the new wiring.
    ("/drift",      ["drLoad", "dr-tbl", "dr-cnt-policy"]),
    ("/evidence",   ["evGen", "ev-tbl"]),
    # v9.41 — Builder redesigned: bldPreview replaces builderPlan,
    # bld-intent replaces builder-intent.
    ("/builder",    ["bldPreview", "bld-intent"]),
    # v9.43 — /users admin page calls the directory API + has CRUD handlers.
    ("/users",      ["uxLoad", "ux-tbl", "uxOpenAdd"]),
    # v9.43-v9.44 — /settings has email tab + tenant defaults + my prefs +
    # webhooks tab. Pin the JS entry points so a future refactor can't
    # silently regress any tab.
    ("/settings",   ["stLoadEmail", "stLoadDefaults", "stLoadPrefs",
                       "whLoad"]),
    # v9.47 — /audit is the JSONL activity log surfaced via /api/activity.
    ("/audit",      ["auLoad", "au-tbl", "/api/activity"]),
    # v9.50.1 — /capabilities is the org-wide capability matrix.
    ("/capabilities", ["cmLoad", "cm-tbl", "/api/capabilities"]),
    ("/approvals",  ["apvRefresh", "apv-tbl"]),
    ("/queue",      ["qRefresh", "q-tbl"]),
    ("/rollback",   ["rbRefresh", "rb-tbl"]),
])
def test_v9_23_graduated_pages_have_real_wiring(client, path, wiring):
    """v9.23 graduated 6 stubs to real pages. Each must include its
    fetch+render JS hooks so we don't regress to the placeholder body."""
    r = client.get(path)
    assert r.status_code == 200
    body = r.text
    # The placeholder body said "This view ships in v9.1" — make sure it's gone.
    assert "This view ships in v9.1" not in body, (
        f"{path} still showing the v9.0 placeholder stub"
    )
    for token in wiring:
        assert token in body, f"{path} missing wiring token {token}"


def test_per_device_diff_renders_with_pdd_wiring(client):
    """v9.22 graduated /per-device-diff from stub to real page —
    confirm the JS hooks for the A/B picker + diff render are present."""
    r = client.get("/per-device-diff")
    assert r.status_code == 200
    body = r.text
    for token in ("pddRun", "pddCfg", "pddRender"):
        assert token in body, f"/per-device-diff missing {token}"


def test_per_device_diff_accepts_query_params(client):
    """The page accepts ?a=...&b=... so deep-links from /asset/{id}
    actions can pre-fill both sides."""
    r = client.get("/per-device-diff?a=router-1&b=router-2")
    assert r.status_code == 200


def test_chrome_sidebar_links_resolve(client):
    """Hit every link visible on /home — none of them may 404, and
    none of them may return JSON to a navigation click."""
    r = client.get("/home")
    assert r.status_code == 200
    links = _extract_internal_links(r.text)
    # Sanity: home must surface a fair chunk of the sidebar.
    assert len(links) >= 20, f"/home only emitted {len(links)} links"

    failures = []
    for url in sorted(links):
        if url.startswith(_API_PREFIXES):
            continue
        # Static asset paths we don't ship from FastAPI — skip.
        if url.startswith(("/static/", "/_next/")):
            continue
        # v11.1 PWA endpoints — not HTML by design.
        if url in _PWA_PATHS:
            continue
        resp = client.get(url, follow_redirects=False)
        # 401 = needs login (acceptable; means the route exists).
        # 405 = method not allowed (route exists, GET not supported);
        # we still accept since the URL resolves.
        if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 405):
            if resp.status_code == 200 and not _is_html(resp):
                failures.append(
                    f"{url} → {resp.headers.get('content-type')} "
                    f"(navigation link served non-HTML)"
                )
            continue
        failures.append(f"{url} → {resp.status_code}")
    assert not failures, "broken nav links:\n  " + "\n  ".join(failures)


def test_no_duplicate_html_routes_registered(client):
    """v9.22 cleanup: /per-device-diff was registered both as the real
    page and as a stub. FastAPI honored the first one but the dupe was
    confusing — guard against it coming back."""
    seen: dict[str, list[str]] = {}
    for r in client.app.routes:
        path = getattr(r, "path", None)
        if not path:
            continue
        # Only HTML page routes (the ones that render the v9 chrome).
        # API endpoints with the same path under different methods
        # are fine — those have unique (path, method) pairs.
        methods = getattr(r, "methods", None) or set()
        if "GET" not in methods:
            continue
        seen.setdefault(path, []).append(getattr(r, "name", "?"))
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    assert not dupes, f"duplicate GET routes: {dupes}"


def test_asset_detail_links_resolve(client):
    """Spot-check the asset cockpit page's links — that's where v9.16.1
    regressions kept landing (audit-log → JSON, mitre 404, etc.)."""
    # Use a sample asset_id; /asset/{id} renders even if asset doesn't
    # exist (it shows an empty state) — the goal here is just to crawl
    # the page chrome's outbound links.
    r = client.get("/asset/sample-asset-id")
    if r.status_code == 404:
        pytest.skip("/asset/{id} not registered in this build")
    assert r.status_code == 200
    links = _extract_internal_links(r.text)
    failures = []
    for url in sorted(links):
        if url.startswith(_API_PREFIXES):
            continue
        if url.startswith(("/static/", "/_next/")):
            continue
        if url in _PWA_PATHS:
            continue
        if url.startswith("/asset/"):
            # Self-link — already known to render.
            continue
        resp = client.get(url, follow_redirects=False)
        if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 405):
            if resp.status_code == 200 and not _is_html(resp):
                failures.append(
                    f"{url} → {resp.headers.get('content-type')} (non-HTML)"
                )
            continue
        failures.append(f"{url} → {resp.status_code}")
    assert not failures, (
        "broken asset-cockpit links:\n  " + "\n  ".join(failures)
    )
