"""
v9.41 — Command Builder redesign.

The pre-v9.41 /builder page was confusing: free-text "target asset
group" input, JSON dump for the result, single Save button that went
straight to /approvals. Operators couldn't tell which devices the
plan would actually touch, what risk tier it landed in, or how to
sit on a draft and refine it.

The redesign keeps the API surface and ships a three-step shell:
  (1) Intent — example pills + textarea
  (2) Target — asset-group dropdown + live device-count preview
  (3) Plan — risk badge, blast radius, per-vendor expandable, rollback indicator

These tests pin the visible structure so the next refactor doesn't
silently regress the UX, plus the new save-as-draft endpoint that
backs the second save button.
"""

from __future__ import annotations

import pytest


# --------------------------------------------------- UI structure


def test_builder_has_three_step_layout():
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    # The three numbered step headings drive the operator's eye.
    assert "What do you want to do?" in body
    assert "Where should it run?" in body
    # The plan card is hidden until preview but its container is in the DOM.
    assert 'id="bld-plan"' in body


def test_builder_has_intent_pills_with_canonical_starters():
    """Operator with no idea what shape of intent works should see
    six common starters — clicking one fills the textarea."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "BLD_INTENT_PILLS" in src
    # The six starter pills the v9.41 audit doc committed to
    for label in (
        "Block service inbound",
        "Add log destination",
        "Disable insecure protocol",
        "Update NTP server",
        "Tighten management ACL",
        "Rotate SNMP community",
    ):
        assert label in src, f"missing starter pill: {label}"


def test_builder_target_uses_dropdown_not_freetext():
    """Old UI made operators type the group name. New UI populates a
    dropdown from /api/platform/asset-groups so they pick from the
    canonical list."""
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    src = v9_pages._BUILDER_SCRIPT
    assert '<select id="bld-group"' in body, (
        "target must be a dropdown, not a free-text input"
    )
    assert "/api/platform/asset-groups" in src


def test_builder_resolves_device_list_on_group_change():
    """The 'Resolved devices' card on step 2 must hit the per-group
    detail endpoint to render '→ N devices: a, b, c…'."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "bldOnGroupChange" in src
    assert "/api/platform/asset-groups/" in src
    assert "member_count" in src or "members" in src


def test_builder_renders_risk_badge_and_required_approver():
    """Plan card surfaces risk tier visually (badge) AND the role
    that's required to approve it. Pre-v9.41 the operator only found
    out the approver tier when they got rejected on /approvals."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "_bldRiskBadge" in src
    assert "_bldApproverFor" in src
    # The 5-tier scale must all be present
    for tier in ("safe", "low", "medium", "high", "critical"):
        assert tier in src, f"risk badge missing tier: {tier}"
    # Medium → SUPER_ADMIN is the v9.35 rule we surface to the operator
    assert "SUPER_ADMIN" in src


def test_builder_renders_per_vendor_expandable_groups():
    """commands_by_vendor in the plan response → one <details> per
    vendor, first one auto-expanded so the operator sees something
    immediately. JSON-dump-only is the regression to prevent."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "<details" in src
    assert "commands_by_vendor" in src
    # Should NOT just dump JSON like the pre-v9.41 UI did
    assert "JSON.stringify(plan, null, 2)" not in src, (
        "plan output must be structured, not a raw JSON dump"
    )


def test_builder_has_rollback_indicator():
    """Operator should see whether a rollback plan will be generated
    BEFORE they submit. Surfaces the v9.35 rollback work in the
    /builder flow."""
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    src = v9_pages._BUILDER_SCRIPT
    assert "Rollback plan" in body
    assert "bld-rollback-card" in body
    # When mode is config we link to /rollback for the slide-over
    assert "/rollback" in src


def test_builder_has_separate_draft_and_submit_buttons():
    """Pre-v9.41 had ONE Save button that submitted straight to
    /approvals. Now the operator can save as DRAFT and iterate, OR
    submit for approval — two distinct buttons with different
    consequences."""
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    src = v9_pages._BUILDER_SCRIPT
    assert "Save as draft" in body
    assert "Submit for approval" in body
    assert "bldSaveDraft" in src
    assert "bldSubmit" in src
    assert "/api/execute/builder/save-draft" in src
    assert "/api/execute/builder/plan-and-save" in src


def test_builder_blocked_plan_shows_block_reasons_not_raw_json():
    """When guardrails block a plan, the operator must see the human
    reasons (block_reasons list), not a JSON dump."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "Blocked by guardrails" in src
    assert "block_reasons" in src


def test_builder_no_match_shows_helpful_message():
    """When the intent doesn't match a pack and BYO-AI can't help
    either, the operator gets a coachable message — not silence."""
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    assert "couldn" in src.lower() and "translate" in src.lower()


# --------------------------------------------------- HTTP endpoint


@pytest.fixture
def builder_client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("yaml")
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    import yaml
    from safecadence.server.auth import hash_password
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [{
            "username": "alice",
            "password_hash": hash_password("hunter2"),
            "roles": ["admin"],
        }]}}
    }))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret")
    c = TestClient(app)
    tok = c.post("/api/login",
                  data={"username": "alice", "password": "hunter2"}
                  ).json()["access_token"]
    c._hdr = {"Authorization": f"Bearer {tok}"}
    return c


def test_save_draft_endpoint_creates_job_in_draft_status(builder_client):
    """POST /api/execute/builder/save-draft must persist the job in
    DRAFT (not REVIEW). That's the whole point of the second save
    button — let the operator iterate without paging an approver."""
    r = builder_client.post(
        "/api/execute/builder/save-draft",
        headers=builder_client._hdr,
        json={"intent": "check version on cisco devices"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "draft"
    job = body.get("job") or {}
    # plan_to_job creates with status=DRAFT; save-draft preserves that
    assert (job.get("status") or "").lower() == "draft", (
        f"save-draft must keep status=DRAFT, got {job.get('status')}"
    )
    job_id = job.get("job_id")
    assert job_id

    # Verify the job is actually persisted and still DRAFT
    from safecadence.execution import store as exec_store
    persisted = exec_store.get_job(job_id)
    assert persisted is not None
    assert persisted.status.value.lower() == "draft"


def test_save_draft_does_not_send_to_approvals_queue(builder_client):
    """A draft job must NOT appear on the /approvals review queue.
    The whole point of save-draft is not paging an approver yet."""
    r = builder_client.post(
        "/api/execute/builder/save-draft",
        headers=builder_client._hdr,
        json={"intent": "check version on cisco devices"},
    )
    assert r.status_code == 200, r.text
    job_id = r.json()["job"]["job_id"]

    # /api/execute/queue surfaces REVIEW/APPROVED/SCHEDULED/RUNNING
    # jobs — DRAFT must NOT be in there.
    qr = builder_client.get("/api/execute/queue",
                             headers=builder_client._hdr)
    assert qr.status_code == 200
    queue = qr.json().get("queue", [])
    ids_in_queue = {j.get("job_id") for j in queue}
    assert job_id not in ids_in_queue, (
        f"DRAFT job {job_id} leaked into the review queue"
    )


def test_save_draft_rejects_no_pack_match(builder_client):
    """If the intent doesn't match any pack and AI fallback didn't
    rescue it, save-draft should return 400 with the reason — not
    silently persist an empty plan."""
    r = builder_client.post(
        "/api/execute/builder/save-draft",
        headers=builder_client._hdr,
        json={"intent": "qwerty does not match anything"},
    )
    assert r.status_code == 400


def test_plan_and_save_still_works_and_returns_a_job(builder_client):
    """Regression check on the existing submit-for-approval path.
    The second save button on /builder must keep working. Whether the
    job lands in REVIEW or stays DRAFT depends on the risk classifier
    (read-only intents don't need approval); we just assert the
    endpoint still returns a valid job."""
    r = builder_client.post(
        "/api/execute/builder/plan-and-save",
        headers=builder_client._hdr,
        json={"intent": "check version on cisco devices"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    job = body.get("job") or {}
    assert job.get("job_id"), "plan-and-save must return a job_id"
    assert job.get("status"), "plan-and-save must return a status"
    # plan-and-save is the "submit" path even if the workflow elects
    # to keep low-risk jobs in DRAFT — what matters is that it
    # contrasts with save-draft by going through workflow.create_job
    assert "plan" in body
