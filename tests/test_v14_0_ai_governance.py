"""
Tests for v14.0 — AI & Machine Identity Governance (agents + api_keys + trust_score).
"""
from __future__ import annotations

import sqlite3
import time

import pytest

from safecadence.ai_governance.agents import (
    VALID_STATUS,
    ensure_agent_schema,
    get_agent,
    list_agents,
    record_invocation,
    register_agent,
    set_agent_status,
)
from safecadence.ai_governance.api_keys import (
    age_days,
    deprecate,
    ensure_api_key_schema,
    list_api_keys,
    record_seen,
    register_api_key,
    rotate,
)
from safecadence.ai_governance.trust_score import (
    DEFAULTS,
    score_agent,
    score_all_keys,
    score_api_key,
)


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:")
    ensure_agent_schema(c)
    ensure_api_key_schema(c)
    return c


# ---- agents ----------------------------------------------------- #


def test_register_agent_returns_active_row(conn):
    a = register_agent(conn, name="qa", owner_user_id="u1")
    assert a["agent_id"].startswith("agt_")
    assert a["status"] == "active"
    assert a["allowed_tools"] == []


def test_list_agents_filters_by_org(conn):
    register_agent(conn, name="a1", owner_user_id="u1", org_id="acme")
    register_agent(conn, name="a2", owner_user_id="u1", org_id="other")
    assert len(list_agents(conn, org_id="acme")) == 1
    assert len(list_agents(conn)) == 2


def test_set_agent_status_round_trip(conn):
    a = register_agent(conn, name="qa", owner_user_id="u1")
    assert set_agent_status(conn, a["agent_id"], "paused") is True
    assert get_agent(conn, a["agent_id"])["status"] == "paused"


def test_set_agent_status_rejects_unknown(conn):
    a = register_agent(conn, name="qa", owner_user_id="u1")
    with pytest.raises(ValueError):
        set_agent_status(conn, a["agent_id"], "not-a-status")


def test_valid_status_constants():
    assert set(VALID_STATUS) == {"active", "paused", "deprecated"}


def test_record_invocation_persists(conn):
    a = register_agent(conn, name="qa", owner_user_id="u1")
    record_invocation(conn, a["agent_id"], "query_topology")
    row = conn.execute(
        "SELECT COUNT(*) FROM ai_agent_invocations WHERE agent_id = ?",
        (a["agent_id"],),
    ).fetchone()
    assert row[0] == 1


# ---- api_keys --------------------------------------------------- #


def test_register_api_key_truncates_to_last_four(conn):
    k = register_api_key(
        conn, provider="openai", label="x", owner_user_id="u1",
        last_four="abcdef9876",
    )
    assert k["last_four"] == "9876"
    assert k["is_deprecated"] is False


def test_list_api_keys_excludes_deprecated_by_default(conn):
    k1 = register_api_key(conn, provider="openai", label="a", owner_user_id="u1")
    k2 = register_api_key(conn, provider="openai", label="b", owner_user_id="u1")
    deprecate(conn, k2["key_id"])
    visible = list_api_keys(conn)
    assert len(visible) == 1
    assert visible[0]["key_id"] == k1["key_id"]
    assert len(list_api_keys(conn, include_deprecated=True)) == 2


def test_record_seen_updates_last_seen(conn):
    k = register_api_key(conn, provider="openai", label="x", owner_user_id="u1")
    assert list_api_keys(conn)[0]["last_seen_at"] is None
    assert record_seen(conn, k["key_id"]) is True
    assert list_api_keys(conn)[0]["last_seen_at"] is not None


def test_rotate_updates_last_four_and_rotated_at(conn):
    k = register_api_key(conn, provider="openai", label="x",
                         owner_user_id="u1", last_four="1111")
    assert rotate(conn, k["key_id"], "2222") is True
    updated = list_api_keys(conn)[0]
    assert updated["last_four"] == "2222"
    assert updated["rotated_at"] >= k["rotated_at"]


def test_age_days_for_fresh_key_is_zero(conn):
    k = register_api_key(conn, provider="openai", label="x", owner_user_id="u1")
    assert age_days(k) == 0


def test_age_days_handles_known_offset():
    fake = {"created_at": int(time.time()) - 10 * 86400,
            "rotated_at": int(time.time()) - 10 * 86400}
    assert age_days(fake) == 10


# ---- trust_score ----------------------------------------------- #


def test_score_api_key_fresh_with_owner_scores_full(conn):
    k = register_api_key(conn, provider="openai", label="x",
                         owner_user_id="u1", scopes=["chat"])
    record_seen(conn, k["key_id"])
    s = score_api_key(list_api_keys(conn)[0])
    assert s["score"] == 100.0
    assert s["recommendation"].startswith("Healthy")


def test_score_api_key_orphan_loses_owner_points(conn):
    k = register_api_key(conn, provider="openai", label="x",
                         owner_user_id="", scopes=["chat"])
    record_seen(conn, k["key_id"])
    s = score_api_key(list_api_keys(conn)[0])
    assert s["score"] < 100.0
    # Owner factor must be 0
    owner_factor = next(f for f in s["factors"] if f["name"] == "owner")
    assert owner_factor["value"] == 0.0


def test_score_api_key_broad_scope_loses_scope_points(conn):
    big_scope = [f"scope{i}" for i in range(20)]
    k = register_api_key(conn, provider="openai", label="x",
                         owner_user_id="u1", scopes=big_scope)
    record_seen(conn, k["key_id"])
    s = score_api_key(list_api_keys(conn)[0])
    scope_factor = next(f for f in s["factors"] if f["name"] == "scope")
    assert scope_factor["value"] < 20.0


def test_score_api_key_deprecated_returns_zero(conn):
    k = register_api_key(conn, provider="openai", label="x",
                         owner_user_id="u1")
    deprecate(conn, k["key_id"])
    s = score_api_key(list_api_keys(conn, include_deprecated=True)[0])
    assert s["score"] == 0.0


def test_score_agent_active_scores_high(conn):
    a = register_agent(conn, name="qa", owner_user_id="u1",
                       allowed_tools=["t1", "t2"])
    s = score_agent(a, recent_invocations=3)
    assert s["score"] >= 95


def test_score_agent_orphan_loses_owner_points(conn):
    a = register_agent(conn, name="qa", owner_user_id="",
                       allowed_tools=["t1"])
    s = score_agent(a, recent_invocations=1)
    owner = next(f for f in s["factors"] if f["name"] == "owner")
    assert owner["value"] == 0


def test_score_agent_broad_tool_surface_loses_points(conn):
    big_tools = [f"tool{i}" for i in range(20)]
    a = register_agent(conn, name="qa", owner_user_id="u1",
                       allowed_tools=big_tools)
    s = score_agent(a, recent_invocations=1)
    surf = next(f for f in s["factors"] if f["name"] == "tool_surface")
    assert surf["value"] < 30.0


def test_score_all_keys_bulk(conn):
    for i in range(3):
        register_api_key(conn, provider="openai", label=f"k{i}",
                         owner_user_id="u1")
    out = score_all_keys(conn)
    assert len(out) == 3
    assert all("score" in r and "factors" in r for r in out)


def test_defaults_loaded():
    assert "max_age_days" in DEFAULTS
    assert "rotation_policy_days" in DEFAULTS
