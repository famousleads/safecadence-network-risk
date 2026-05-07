"""v9.55.1 #5 — capability_changed must surface in the notify-prefs UI.

v9.53 added the 8th NOTIFY_CATEGORIES key. The /settings notify-prefs
matrix is auto-rendered from /api/notify/categories. If a future PR
drops the entry from the registry list, the matrix silently loses
its row and security teams stop seeing capability-change notifications
for new users.

These tests prevent that regression:
  1. NOTIFY_CATEGORIES includes the capability_changed entry with the
     fields the front-end needs (key, label, description, defaults).
  2. category_keys() returns it (used by prefs.py validation).
  3. The /api/notify/categories endpoint surfaces it end-to-end.
"""
from __future__ import annotations


def test_capability_changed_in_NOTIFY_CATEGORIES():
    from safecadence.notifier.registry import NOTIFY_CATEGORIES
    rec = next((c for c in NOTIFY_CATEGORIES
                  if c.get("key") == "capability_changed"), None)
    assert rec is not None, (
        "capability_changed must remain in NOTIFY_CATEGORIES — "
        "the /settings notify-prefs UI consumes this list directly."
    )
    # Front-end uses these fields to render the row + tooltip
    assert rec.get("label")
    assert rec.get("description")
    assert "default_invitee_only" in rec
    assert "default_channels" in rec


def test_category_keys_includes_capability_changed():
    """The validators in notifier.prefs.save_user_prefs and
    save_tenant_defaults check incoming categories against
    category_keys(). If capability_changed disappears here, valid
    user prefs silently get dropped."""
    from safecadence.notifier.registry import category_keys
    assert "capability_changed" in category_keys()


def test_notify_categories_endpoint_surfaces_capability_changed():
    """End-to-end: the HTTP endpoint that drives the UI matrix
    actually returns the row."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.server.platform_api import register
    from safecadence.server.auth import CurrentUser

    app = FastAPI()

    # Monkeypatch the auth dependency to a permissive one for this
    # test so we can hit the endpoint without a real JWT.
    def _fake_user():
        return CurrentUser(username="t", tenant="default",
                            roles=["admin"])

    register(app, get_current_user=_fake_user,
              require_writer=_fake_user)
    client = TestClient(app)
    r = client.get("/api/notify/categories")
    assert r.status_code == 200
    body = r.json()
    keys = [c["key"] for c in body.get("categories", [])]
    assert "capability_changed" in keys, (
        f"/api/notify/categories must return capability_changed; "
        f"got {keys!r}"
    )


def test_capability_changed_description_mentions_privilege():
    """The description shown in the UI tooltip should clearly tell
    operators what kind of event this is — not just the literal
    category key. Catches a future PR that nukes the description."""
    from safecadence.notifier.registry import NOTIFY_CATEGORIES
    rec = next(c for c in NOTIFY_CATEGORIES
                if c["key"] == "capability_changed")
    desc = (rec.get("description") or "").lower()
    # Either word is fine — what we want is "the operator reading
    # this knows it's about privilege changes, not webhook health."
    assert "privilege" in desc or "capabilit" in desc, (
        f"capability_changed description should mention "
        f"privilege/capability; got: {rec.get('description')!r}"
    )
