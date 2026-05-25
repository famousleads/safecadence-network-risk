"""
Tests for v12.2 — peer-to-peer continuous sync (Architecture B).

Covers all five submodules + the end-to-end live socket loopback.
"""
from __future__ import annotations

import os
import socket
import sqlite3
import threading
import time

import pytest


os.environ.setdefault("SC_PEER_SECRET", "test-secret-at-least-24-chars-long")


# --------------------------------------------------------------------------
# writer.py
# --------------------------------------------------------------------------


@pytest.fixture()
def writer_conn():
    from safecadence.cluster.peer_sync.writer import ensure_event_schema
    c = sqlite3.connect(":memory:")
    ensure_event_schema(c)
    return c


def test_writer_record_returns_monotonic_seq(writer_conn):
    from safecadence.cluster.peer_sync.writer import record_event
    s1 = record_event(writer_conn, "k", {"i": 1})
    s2 = record_event(writer_conn, "k", {"i": 2})
    s3 = record_event(writer_conn, "k", {"i": 3})
    assert s1 < s2 < s3


def test_writer_hmac_round_trips(writer_conn):
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
        verify_hmac,
    )
    record_event(writer_conn, "kind1", {"x": "y"})
    e = list_events_since(writer_conn, 0)[0]
    assert verify_hmac(e["seq"], e["kind"], e["payload"], e["hmac"]) is True


def test_writer_hmac_rejects_tamper(writer_conn):
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
        verify_hmac,
    )
    record_event(writer_conn, "k", {"a": 1})
    e = list_events_since(writer_conn, 0)[0]
    assert verify_hmac(e["seq"], "tampered_kind", e["payload"], e["hmac"]) is False


def test_writer_list_since_filters(writer_conn):
    from safecadence.cluster.peer_sync.writer import list_events_since, record_event
    for i in range(5):
        record_event(writer_conn, "k", {"i": i})
    out = list_events_since(writer_conn, 3)
    assert [e["seq"] for e in out] == [4, 5]


def test_writer_trim_below(writer_conn):
    from safecadence.cluster.peer_sync.writer import (
        newest_seq,
        oldest_seq,
        record_event,
        trim_events_below,
    )
    for i in range(5):
        record_event(writer_conn, "k", {"i": i})
    n = trim_events_below(writer_conn, 4)
    assert n == 3
    assert oldest_seq(writer_conn) == 4
    assert newest_seq(writer_conn) == 5


# --------------------------------------------------------------------------
# transport.py
# --------------------------------------------------------------------------


def test_transport_loopback_frames():
    """A frame written by send_frame() must round-trip through recv_frame()."""
    from safecadence.cluster.peer_sync.transport import recv_frame, send_frame

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    received = []
    def server():
        conn, _ = srv.accept()
        received.append(recv_frame(conn))
        received.append(recv_frame(conn))
        received.append(recv_frame(conn))  # clean close
        conn.close()

    t = threading.Thread(target=server)
    t.start()

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(("127.0.0.1", port))
    send_frame(c, {"type": "event", "seq": 1})
    send_frame(c, {"type": "heartbeat", "ts": 999})
    c.close()
    t.join(timeout=3)
    srv.close()

    assert received[0] == {"type": "event", "seq": 1}
    assert received[1] == {"type": "heartbeat", "ts": 999}
    assert received[2] is None  # clean close


def test_transport_rejects_oversized_frame():
    from safecadence.cluster.peer_sync.transport import (
        FrameError,
        MAX_FRAME_BYTES,
        send_frame,
    )
    s, _ = socket.socketpair()
    huge = {"x": "a" * (MAX_FRAME_BYTES + 100)}
    with pytest.raises(FrameError):
        send_frame(s, huge)
    s.close()


# --------------------------------------------------------------------------
# applier.py
# --------------------------------------------------------------------------


@pytest.fixture()
def applier_pair():
    """Returns (active_conn, standby_conn, recv_log)."""
    from safecadence.cluster.peer_sync.applier import (
        ensure_applier_schema,
        register_handler,
    )
    from safecadence.cluster.peer_sync.writer import ensure_event_schema

    active = sqlite3.connect(":memory:")
    standby = sqlite3.connect(":memory:")
    ensure_event_schema(active)
    ensure_applier_schema(standby)

    recv = []
    register_handler("test_event", lambda c, p: recv.append(p))
    return active, standby, recv


def test_applier_applies_in_order(applier_pair):
    from safecadence.cluster.peer_sync.applier import (
        apply_event,
        last_applied_seq,
    )
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
    )
    active, standby, recv = applier_pair
    for i in range(3):
        record_event(active, "test_event", {"i": i})
    for e in list_events_since(active, 0):
        ok, note = apply_event(standby, e)
        assert ok and note == "applied"
    assert last_applied_seq(standby) == 3
    assert [r["i"] for r in recv] == [0, 1, 2]


def test_applier_dedupes_replay(applier_pair):
    from safecadence.cluster.peer_sync.applier import apply_event
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
    )
    active, standby, recv = applier_pair
    record_event(active, "test_event", {"i": 0})
    e = list_events_since(active, 0)[0]
    apply_event(standby, e)
    ok, note = apply_event(standby, e)  # replay
    assert ok and note == "duplicate_dropped"
    assert len(recv) == 1  # handler called only once


def test_applier_rejects_bad_hmac(applier_pair):
    from safecadence.cluster.peer_sync.applier import apply_event
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
    )
    active, standby, _ = applier_pair
    record_event(active, "test_event", {"i": 0})
    e = dict(list_events_since(active, 0)[0])
    e["hmac"] = "0" * 64
    ok, note = apply_event(standby, e)
    assert ok is False
    assert note == "bad_hmac"


def test_applier_unknown_kind_drops_but_bumps_seq(applier_pair):
    from safecadence.cluster.peer_sync.applier import (
        apply_event,
        last_applied_seq,
    )
    from safecadence.cluster.peer_sync.writer import (
        list_events_since,
        record_event,
    )
    active, standby, _ = applier_pair
    record_event(active, "no_such_kind", {"x": 1})
    e = list_events_since(active, 0)[0]
    ok, note = apply_event(standby, e)
    assert ok and note == "no_handler"
    # seq bumped so we don't re-receive forever
    assert last_applied_seq(standby) == e["seq"]


# --------------------------------------------------------------------------
# heartbeat.py
# --------------------------------------------------------------------------


@pytest.fixture()
def role_conn():
    from safecadence.cluster.peer_sync.heartbeat import ensure_role_schema
    c = sqlite3.connect(":memory:")
    ensure_role_schema(c)
    return c


def test_heartbeat_default_role_is_standby(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import get_role
    assert get_role(role_conn) == "standby"


def test_heartbeat_promote_demote_round_trip(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import (
        demote_self,
        get_role,
        promote_self,
    )
    promote_self(role_conn)
    assert get_role(role_conn) == "active"
    demote_self(role_conn)
    assert get_role(role_conn) == "standby"


def test_heartbeat_request_demotion_flag(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import (
        clear_demotion,
        is_demotion_requested,
        request_demotion,
    )
    assert is_demotion_requested(role_conn) is False
    request_demotion(role_conn)
    assert is_demotion_requested(role_conn) is True
    clear_demotion(role_conn)
    assert is_demotion_requested(role_conn) is False


def test_heartbeat_monitor_promotes_on_silence(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import (
        LivenessMonitor,
        LivenessSignals,
        get_role,
    )
    m = LivenessMonitor(role_conn, promote_after_s=10.0)
    # Standby + never received anything → promote
    out = m.tick(LivenessSignals(
        last_event_received_at=0.0,
        last_heartbeat_received_at=0.0,
        now=time.time(),
    ))
    assert out["action"] == "promoted"
    assert get_role(role_conn) == "active"


def test_heartbeat_monitor_no_promote_when_events_recent(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import (
        LivenessMonitor,
        LivenessSignals,
        get_role,
    )
    m = LivenessMonitor(role_conn, promote_after_s=10.0)
    now = time.time()
    # Recent inbound event = active is alive
    out = m.tick(LivenessSignals(
        last_event_received_at=now - 2.0,
        last_heartbeat_received_at=0.0,
        now=now,
    ))
    assert out["action"] == "noop"
    assert get_role(role_conn) == "standby"


def test_heartbeat_monitor_demotes_on_request(role_conn):
    from safecadence.cluster.peer_sync.heartbeat import (
        LivenessMonitor,
        LivenessSignals,
        get_role,
        promote_self,
        request_demotion,
    )
    promote_self(role_conn)
    request_demotion(role_conn)
    m = LivenessMonitor(role_conn)
    out = m.tick(LivenessSignals(0, 0, time.time()))
    assert out["action"] == "demoted"
    assert get_role(role_conn) == "standby"


# --------------------------------------------------------------------------
# End-to-end (live socket loopback)
# --------------------------------------------------------------------------


def test_end_to_end_active_to_standby():
    """Active writes events; streamer ships them over real TCP; standby
    applier verifies + dispatches + ACKs."""
    from safecadence.cluster.peer_sync.applier import (
        ensure_applier_schema,
        last_applied_seq,
        register_handler,
        serve,
    )
    from safecadence.cluster.peer_sync.streamer import Streamer, StreamerConfig
    from safecadence.cluster.peer_sync.writer import (
        ensure_event_schema,
        record_event,
    )

    standby = sqlite3.connect(":memory:", check_same_thread=False)
    ensure_applier_schema(standby)

    recv_log: list[dict] = []
    register_handler("e2e", lambda c, p: recv_log.append(p))

    # Pick a free port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    stop = threading.Event()
    srv_t = threading.Thread(
        target=serve, args=(standby, "127.0.0.1", port),
        kwargs={"stop_event": stop, "accept_timeout": 0.5},
    )
    srv_t.start()
    time.sleep(0.3)

    active = sqlite3.connect(":memory:", check_same_thread=False)
    ensure_event_schema(active)
    streamer = Streamer(active, StreamerConfig(
        peer_host="127.0.0.1", peer_port=port, node_name="node-1",
    ))
    stop_streamer = threading.Event()
    st_t = threading.Thread(target=streamer.run, args=(stop_streamer,))
    st_t.start()
    time.sleep(0.5)

    for i in range(4):
        record_event(active, "e2e", {"i": i})

    time.sleep(2.0)

    try:
        assert last_applied_seq(standby) == 4
        assert [r["i"] for r in recv_log] == [0, 1, 2, 3]
        assert streamer.status()["last_acked_seq"] == 4
    finally:
        stop_streamer.set()
        stop.set()
        st_t.join(timeout=3)
        srv_t.join(timeout=3)
