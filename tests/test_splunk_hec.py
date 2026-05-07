"""
v9.24 — unit tests for the Splunk HEC notifier.

Uses httpx.MockTransport so no real network is touched. Verifies:
  * envelope shape (one JSON-per-line, 'event' key wraps the payload)
  * Authorization header uses the Splunk token scheme
  * empty events short-circuit
  * non-2xx responses are surfaced as sent=False
  * exceptions are caught (notifier never raises)
"""

from __future__ import annotations

import json
import pytest

httpx = pytest.importorskip("httpx", reason="httpx not installed")

from safecadence.notifier import notify_splunk_hec


# ----------------------------------------------------------- helpers


def _mock_transport(handler):
    return httpx.MockTransport(handler)


# ----------------------------------------------------------- tests


def test_splunk_hec_empty_events_short_circuits():
    r = notify_splunk_hec("https://splunk.example/services/collector",
                            "tok", [])
    assert r["sent"] is False
    assert "no events" in r["reason"]


def test_splunk_hec_envelope_shape_and_auth(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200, text='{"text":"Success","code":0}')

    # Patch httpx.Client to use our mock transport
    real_client = httpx.Client
    def _client(**kwargs):
        kwargs.pop("verify", None)
        return real_client(transport=_mock_transport(handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", _client)

    events = [
        {"asset_id": "edge-fw-01", "kind": "finding",
          "severity": "critical"},
        {"asset_id": "core-sw-01", "kind": "score_change",
          "old": 78, "new": 64},
    ]
    r = notify_splunk_hec(
        "https://splunk.example:8088/services/collector",
        "abc-token-123", events,
        source="safecadence", sourcetype="safecadence:event",
        index="netsec",
    )

    assert r["sent"] is True
    assert r["status"] == 200
    assert r["events"] == 2

    # Auth header
    assert captured["headers"]["authorization"] == "Splunk abc-token-123"
    assert captured["headers"]["content-type"] == "application/json"

    # Newline-delimited JSON, two envelopes
    lines = captured["body"].splitlines()
    assert len(lines) == 2
    env0 = json.loads(lines[0])
    assert env0["event"]["asset_id"] == "edge-fw-01"
    assert env0["source"] == "safecadence"
    assert env0["sourcetype"] == "safecadence:event"
    assert env0["index"] == "netsec"
    assert env0["host"] == "edge-fw-01"  # falls back to asset_id


def test_splunk_hec_non_2xx_returns_not_sent(monkeypatch):
    def handler(_request):
        return httpx.Response(403, text='{"text":"Token disabled","code":3}')

    real_client = httpx.Client
    def _client(**kwargs):
        kwargs.pop("verify", None)
        return real_client(transport=_mock_transport(handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", _client)

    r = notify_splunk_hec("https://splunk.example/services/collector",
                            "bad-token", [{"kind": "x"}])
    assert r["sent"] is False
    assert r["status"] == 403
    assert "Token disabled" in r["reason"]


def test_splunk_hec_network_error_caught(monkeypatch):
    def handler(_request):
        raise httpx.ConnectError("connection refused")

    real_client = httpx.Client
    def _client(**kwargs):
        kwargs.pop("verify", None)
        return real_client(transport=_mock_transport(handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", _client)

    r = notify_splunk_hec("https://splunk.example/services/collector",
                            "tok", [{"kind": "x"}])
    assert r["sent"] is False
    assert "ConnectError" in r["reason"]
