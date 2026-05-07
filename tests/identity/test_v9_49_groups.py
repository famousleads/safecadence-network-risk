"""v9.49 — Phase B: IdP-sourced approver groups.

Covers store round-trips, group lookup, invitee expansion, and
stale detection.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta


def test_upsert_and_list(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g123", name="eng-leads",
        members=["alice", "bob"],
    ))
    g.upsert_group(g.GroupRecord(
        system="ad", id="cn-secops", name="secops",
        members=["carol"],
    ))
    rows = g.list_groups()
    assert len(rows) == 2
    names = sorted(r.name for r in rows)
    assert names == ["eng-leads", "secops"]
    assert g.list_groups(system="okta")[0].name == "eng-leads"


def test_get_group_by_name_then_id(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g123", name="eng-leads",
        members=["alice"],
    ))
    assert g.get_group("eng-leads").members == ["alice"]
    assert g.get_group("00g123").members == ["alice"]
    assert g.get_group("nonexistent") is None


def test_members_of_returns_empty_for_unknown(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    assert g.members_of("nope") == []


def test_resolve_invitees_expands_groups(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g1", name="eng-leads",
        members=["alice", "bob"],
    ))
    out = g.resolve_invitees(["@group:eng-leads", "carol"])
    # alice + bob from group, then carol; de-duped, in first-seen order
    assert out == ["alice", "bob", "carol"]


def test_resolve_invitees_dedups(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g1", name="eng-leads",
        members=["alice"],
    ))
    out = g.resolve_invitees(["alice", "@group:eng-leads", "alice"])
    assert out == ["alice"]


def test_stale_groups_flags_old_syncs(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g1", name="old", members=[],
        synced_at=old,
    ))
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g2", name="fresh", members=[],
    ))
    stale = g.stale_groups()
    names = {r.name for r in stale}
    assert "old" in names
    assert "fresh" not in names


def test_resolve_invitees_unknown_group_silent(monkeypatch, tmp_path):
    """A missing group must not break the dispatcher — degrade
    gracefully into "no DM goes out" instead."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    out = g.resolve_invitees(["@group:does-not-exist", "carol"])
    assert out == ["carol"]


def test_dispatch_event_expands_group(monkeypatch, tmp_path):
    """dispatch_event() should call resolve_invitees() so
    @group:NAME entries reach actual users."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.identity import groups as g
    g.upsert_group(g.GroupRecord(
        system="okta", id="00g1", name="eng-leads",
        members=["alice", "bob"],
    ))
    # Patch the fan-out so we can inspect what invitees it got
    captured = {}

    def fake_fan_out(*, invitees, **_kw):
        captured["invitees"] = list(invitees)
        return []

    from safecadence.notifier import registry
    monkeypatch.setattr(registry, "_fan_out_to_invitees", fake_fan_out)
    registry.dispatch_event(
        kind="approval_requested",
        title="t", summary="s",
        invitees=["@group:eng-leads", "carol"],
    )
    assert captured.get("invitees") == ["alice", "bob", "carol"]
