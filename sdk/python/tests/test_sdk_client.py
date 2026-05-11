"""Tests for the SafeCadence Python SDK client.

These tests mock ``requests.Session`` so they don't need a running API.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from safecadence_sdk import (
    AuthError,
    Client,
    NotFound,
    RateLimitError,
    SafeCadenceError,
)


def _mock_response(status_code=200, json_body=None, content=None,
                   headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = json.dumps(json_body) if json_body is not None else (content or "")
    resp.content = content if content is not None else (
        json.dumps(json_body).encode("utf-8") if json_body is not None else b""
    )
    resp.json.return_value = json_body
    return resp


def _client_with_response(resp):
    session = MagicMock()
    session.request.return_value = resp
    return Client("https://api.example.com", api_key="scapi_test", session=session), session


def test_list_inventory_returns_items_array():
    resp = _mock_response(json_body=[{"id": "a1", "hostname": "core-sw-1"}])
    c, sess = _client_with_response(resp)
    items = c.list_inventory()
    assert items[0]["hostname"] == "core-sw-1"
    args, kwargs = sess.request.call_args
    assert args[0] == "GET"
    assert args[1] == "https://api.example.com/api/v1/inventory"
    assert kwargs["headers"]["Authorization"] == "Bearer scapi_test"


def test_list_inventory_unwraps_items_envelope():
    resp = _mock_response(json_body={"items": [{"id": "x"}, {"id": "y"}], "total": 2})
    c, _ = _client_with_response(resp)
    items = c.list_inventory()
    assert len(items) == 2
    assert items[0]["id"] == "x"


def test_get_asset_hits_correct_path():
    resp = _mock_response(json_body={"id": "a1", "hostname": "core-sw-1"})
    c, sess = _client_with_response(resp)
    asset = c.get_asset("a1")
    assert asset["hostname"] == "core-sw-1"
    args, _ = sess.request.call_args
    assert args[1].endswith("/api/v1/inventory/a1")


def test_list_reports():
    resp = _mock_response(json_body=[{"id": "r1"}])
    c, sess = _client_with_response(resp)
    reports = c.list_reports()
    assert reports[0]["id"] == "r1"
    args, _ = sess.request.call_args
    assert args[1].endswith("/api/v1/reports")


def test_compose_report_returns_bytes():
    resp = _mock_response(
        status_code=200,
        content=b"%PDF-1.4 fake bytes",
        headers={"Content-Type": "application/pdf"},
    )
    c, sess = _client_with_response(resp)
    data = c.compose_report(preset="exec_brief", format="pdf")
    assert data.startswith(b"%PDF")
    args, kwargs = sess.request.call_args
    assert args[0] == "POST"
    assert args[1].endswith("/api/reports/render-download")
    assert kwargs["json"]["preset_id"] == "exec_brief"
    assert kwargs["json"]["format"] == "pdf"


def test_generate_report_async_endpoint():
    resp = _mock_response(json_body={"id": "job_42", "status": "queued"})
    c, sess = _client_with_response(resp)
    job = c.generate_report(preset="technical_deepdive", format="docx")
    assert job["id"] == "job_42"
    args, kwargs = sess.request.call_args
    assert args[1].endswith("/api/v1/reports/generate")
    assert kwargs["json"]["preset"] == "technical_deepdive"


def test_get_findings_filters_by_severity():
    resp = _mock_response(json_body=[{"id": "f1", "severity": "critical"}])
    c, sess = _client_with_response(resp)
    findings = c.get_findings(severity="critical")
    assert findings[0]["severity"] == "critical"
    _, kwargs = sess.request.call_args
    assert kwargs["params"]["severity"] == "critical"


def test_get_compliance_status_with_framework():
    resp = _mock_response(json_body={"nist": 78, "cis": 84})
    c, sess = _client_with_response(resp)
    status = c.get_compliance_status(framework="nist")
    assert status["nist"] == 78
    _, kwargs = sess.request.call_args
    assert kwargs["params"]["framework"] == "nist"


def test_list_templates():
    resp = _mock_response(json_body=[{"id": "t1", "name": "Exec"}])
    c, sess = _client_with_response(resp)
    tpls = c.list_templates()
    assert tpls[0]["name"] == "Exec"
    args, _ = sess.request.call_args
    assert args[1].endswith("/api/reports/templates")


def test_save_template_posts_payload():
    resp = _mock_response(json_body={"id": "t99", "name": "Board pack"})
    c, sess = _client_with_response(resp)
    result = c.save_template(
        name="Board pack",
        sections=["compliance_executive_summary", "risk_register"],
        scope={"sites": ["nyc"]},
    )
    assert result["id"] == "t99"
    _, kwargs = sess.request.call_args
    body = kwargs["json"]
    assert body["name"] == "Board pack"
    assert body["sections"] == ["compliance_executive_summary", "risk_register"]
    assert body["scope"] == {"sites": ["nyc"]}


def test_auth_error_on_401():
    resp = _mock_response(status_code=401, json_body={"detail": "unauthorized"})
    c, _ = _client_with_response(resp)
    with pytest.raises(AuthError) as exc:
        c.list_inventory()
    assert exc.value.status_code == 401


def test_not_found_on_404():
    resp = _mock_response(status_code=404, json_body={"detail": "missing"})
    c, _ = _client_with_response(resp)
    with pytest.raises(NotFound):
        c.get_asset("does-not-exist")


def test_rate_limit_carries_retry_after():
    resp = _mock_response(
        status_code=429,
        json_body={"detail": "slow down"},
        headers={"Content-Type": "application/json", "Retry-After": "30"},
    )
    c, _ = _client_with_response(resp)
    with pytest.raises(RateLimitError) as exc:
        c.list_inventory()
    assert exc.value.retry_after == 30.0


def test_generic_error_for_500():
    resp = _mock_response(status_code=500, content="boom")
    c, _ = _client_with_response(resp)
    with pytest.raises(SafeCadenceError) as exc:
        c.list_inventory()
    assert exc.value.status_code == 500
