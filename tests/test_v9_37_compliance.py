"""
v9.37 — Compliance section audit fixes.

The audit found all 7 surfaces real and wired. Two small UX gaps
shipped in this release:

  1. /policies slide-over: replaced the stale "(coming v9.2)" alert()
     buttons with real wiring to /api/policy/preview-config and
     /api/policy/changes (both shipped in v9.31 / v9.32 — were never
     surfaced in the UI).
  2. /policies/new editor: added an "Import from config…" button that
     wires to POST /api/policy/import-from-config (the brownfield
     import endpoint that's been live since v9.32 #1 but was only
     reachable via curl).

These tests pin both.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


# Anchors in the rendered HTML — if these change, the UI wiring
# regressed and operators are back to seeing alert() boxes.

def test_policies_slideover_no_longer_has_stale_v9_2_labels():
    """Before v9.37 the /policies slide-over had two `alert('coming
    v9.2')` buttons that mocked the user. Confirm they're gone — both
    in the placeholder string AND in the slide-over template."""
    from safecadence.ui import v9_pages
    src = v9_pages._POLICIES_SCRIPT
    assert "coming v9.2" not in src, (
        "Slide-over still has the stale 'coming v9.2' label — the "
        "v9.31 + v9.32 features are wired, the labels lied."
    )
    assert "coming v9.2" not in v9_pages._POLICIES_BODY


def test_policies_slideover_wires_real_preview_endpoint():
    """The slide-over's Preview button now POSTs to the real
    /api/policy/preview-config endpoint that shipped in v9.31."""
    from safecadence.ui import v9_pages
    src = v9_pages._POLICIES_SCRIPT
    assert "policyPreviewVendor" in src
    assert "/api/policy/preview-config" in src


def test_policies_slideover_wires_real_exception_endpoint():
    """The slide-over's Add Exception button POSTs to the real
    /api/policy/changes endpoint that shipped in v9.32."""
    from safecadence.ui import v9_pages
    src = v9_pages._POLICIES_SCRIPT
    assert "policyAddException" in src
    assert "/api/policy/changes" in src
    # Match the request body shape regardless of JS key-quote style
    assert "kind:" in src and '"exception"' in src


# /policies/new — brownfield import wiring


def test_policies_new_has_import_from_config_button():
    """The YAML editor at /policies/new now exposes the brownfield
    import that was only reachable via curl before v9.37."""
    from safecadence.ui import v9_pages
    body = v9_pages._POLICY_NEW_BODY
    assert "Import from config" in body, (
        "Brownfield import button missing from /policies/new — "
        "operators have to use curl to reach POST "
        "/api/policy/import-from-config."
    )
    assert "pnImportFromConfig" in body


def test_policies_new_import_handler_calls_real_endpoint():
    """The import handler must call /api/policy/import-from-config
    (shipped v9.32 #1) and load the returned YAML into the editor."""
    from safecadence.ui import v9_pages
    src = v9_pages._POLICY_NEW_SCRIPT
    assert "pnImportFromConfig" in src
    assert "/api/policy/import-from-config" in src
    # On success, the returned YAML should be loaded into the
    # editor and the preview pane should refresh
    assert "pn-yaml" in src
    assert "pnPreview()" in src


# Compliance section — confirm the prior audit's claim that all the
# surfaces shipped (no regressions to /risks, /compliance, /drift).


def test_compliance_endpoints_wired_in_platform_api():
    """The audit doc claims these compliance + risk endpoints are
    real. This test pins their existence so a refactor doesn't
    silently drop them."""
    from safecadence.server import platform_api as P
    src = open(P.__file__).read()
    for ep in (
        "/api/compliance/frameworks",
        "/api/compliance/coverage/{framework}",
        "/api/compliance/control/{control_id}",
        "/api/compliance/risks",
        "/api/drift/all",
        "/api/policy/preview-config",
        "/api/policy/import-from-config",
        "/api/policy/changes",
        "/api/platform/evidence-pack",
    ):
        assert ep in src, f"endpoint missing: {ep}"
