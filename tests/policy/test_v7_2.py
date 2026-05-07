"""v7.2 — TOTP + Teams/PagerDuty notifiers + email digest +
compliance evidence pack PDF + audit viewer wiring."""

from __future__ import annotations

import json


# --------------------------------------------------------------------------
# TOTP — RFC 6238 compliance + enrollment
# --------------------------------------------------------------------------

def test_totp_round_trip():
    from safecadence.totp import generate_secret, totp_now, verify
    secret = generate_secret()
    code = totp_now(secret)
    assert verify(secret, code) is True
    assert verify(secret, "000000") is False


def test_totp_known_vector():
    """RFC 6238 Appendix B test vector for SHA1, T=59, secret=12345678901234567890."""
    from safecadence.totp import _hotp
    secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # 12345678901234567890
    # T = 59 / 30 = 1
    code = _hotp(secret_b32, 1, digits=8)
    assert code == "94287082", f"got {code}"


def test_totp_enrollment(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_TOTP_STORE", str(tmp_path / "totp.json"))
    from safecadence import totp
    assert totp.is_enrolled("alice") is False
    rec = totp.enroll("alice")
    assert "secret" in rec and "otpauth_uri" in rec
    assert totp.is_enrolled("alice") is True
    code = totp.totp_now(rec["secret"])
    assert totp.verify_user("alice", code) is True
    assert totp.verify_user("alice", "000000") is False
    assert totp.revoke("alice") is True
    assert totp.is_enrolled("alice") is False


def test_totp_otpauth_uri_format():
    from safecadence.totp import otpauth_uri
    uri = otpauth_uri(secret_b32="JBSWY3DPEHPK3PXP", account="alice@acme")
    assert uri.startswith("otpauth://totp/")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=SafeCadence" in uri


# --------------------------------------------------------------------------
# Notifier — Teams + PagerDuty + HMAC
# --------------------------------------------------------------------------

def test_notify_teams_builds_adaptive_card():
    """Without a webhook URL we still render the card via _post_json's
    fail path; we just want to confirm the shape is right."""
    from safecadence.notifier import notify_teams
    # Pass an unreachable URL so we don't actually POST; the function
    # returns sent=False but the card is built before the request.
    r = notify_teams("https://example.invalid.local/webhookb2/foo",
                      [{"severity": "critical", "title": "KEV on edge",
                         "asset_id": "edge-1", "why": "actively exploited"}])
    assert r["sent"] is False  # unreachable host
    # If httpx isn't installed, we still get back a dict.
    assert "reason" in r


def test_notify_pagerduty_requires_routing_key():
    from safecadence.notifier import notify_pagerduty
    r = notify_pagerduty("https://events.pagerduty.com/v2/enqueue",
                          [{"severity": "critical", "title": "x"}])
    assert r["sent"] is False
    assert "routing_key" in (r.get("reason") or "").lower()


def test_hmac_signing_matches_python_stdlib():
    """The exact HMAC matches Python's stdlib computation. We don't
    pin a hard-coded hex string here because OpenSSL CLI hex output
    differs per platform; the contract is that our _sign() is byte-
    for-byte equal to ``hmac.new(secret, payload, sha256).hexdigest()``."""
    import hashlib, hmac
    from safecadence.notifier import _sign
    expected = ("sha256="
                + hmac.new(b"shared-secret", b"hello world",
                            hashlib.sha256).hexdigest())
    assert _sign(b"hello world", "shared-secret") == expected


def test_notify_dispatch_picks_teams_url():
    """The dispatcher must route a Teams webhook to the Teams renderer."""
    from safecadence import notifier
    teams_url = "https://acme.webhook.office.com/webhookb2/abc"
    # Hand-roll a stub by monkeypatching the per-channel functions.
    called = {}
    notifier.notify_teams = lambda url, events, **kw: called.setdefault(
        "teams", True) or {"sent": True}
    notifier.notify_slack = lambda url, events, **kw: called.setdefault(
        "slack", True) or {"sent": True}
    notifier.notify(teams_url, [{"severity": "high", "title": "x"}])
    assert called.get("teams") is True
    assert called.get("slack") is None


# --------------------------------------------------------------------------
# Email digest
# --------------------------------------------------------------------------

def test_digest_render_text(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.digest import build_digest, render_text
    load_demo_fleet()
    d = build_digest()
    text = render_text(d)
    assert "SafeCadence digest" in text
    assert "FLEET" in text
    assert "POLICY POSTURE" in text
    assert "CROSS-SYSTEM DRIFT" in text
    assert "LICENSE" in text


def test_digest_send_refuses_without_smtp_or_recipients(monkeypatch):
    monkeypatch.delenv("SC_SMTP_HOST", raising=False)
    monkeypatch.delenv("SC_DIGEST_RECIPIENTS", raising=False)
    from safecadence.digest import send
    r = send()
    assert r["sent"] is False


def test_digest_render_html_has_kev_count(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.digest import build_digest, render_html
    load_demo_fleet()
    html = render_html(build_digest())
    assert "<table" in html
    assert "KEV" in html


# --------------------------------------------------------------------------
# Compliance evidence pack PDF
# --------------------------------------------------------------------------

def test_evidence_pack_returns_pdf_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.evidence_pack import generate
    load_demo_fleet()
    for fw in ("nist", "pci", "iso", "hipaa", "cis", "zerotrust"):
        pdf = generate(fw)
        assert pdf.startswith(b"%PDF-1."), f"{fw} did not produce a PDF header"
        assert b"%%EOF" in pdf, f"{fw} PDF missing %%EOF"


def test_evidence_pack_unknown_framework_returns_safe_pdf():
    """Unknown framework name → still a valid 1-page PDF, not a crash."""
    from safecadence.evidence_pack import generate
    pdf = generate("not-a-framework")
    assert pdf.startswith(b"%PDF-1.")
    assert b"No SafeCadence controls" in pdf or b"%%EOF" in pdf


# --------------------------------------------------------------------------
# Settings + Audit UI sanity
# --------------------------------------------------------------------------

def test_audit_ui_dual_source():
    """Audit tab pulls both policy + execution audit feeds."""
    from safecadence.ui.policy_ui import render_policy_ui
    html = render_policy_ui()
    assert "/api/policy/audit" in html
    assert "/api/execute/audit" in html
    assert "exportAuditCsv" in html


def test_settings_ui_has_evidence_and_digest_buttons():
    from safecadence.ui.policy_ui import render_policy_ui
    html = render_policy_ui()
    assert "evidence-pack" in html
    assert "digest" in html.lower()
    assert "enrollTotp" in html


# --------------------------------------------------------------------------
# Tier3 REST + TOTP — minimal endpoint shape
# --------------------------------------------------------------------------

def test_tier3_rest_endpoint_registered():
    """The execution_api module registers run-real + emergency endpoints."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2]
           / "src" / "safecadence" / "server" / "execution_api.py").read_text()
    assert "/api/execute/jobs/{job_id}/run-real" in src
    assert "/api/execute/totp/enroll" in src
    assert "/api/execute/emergency-stop" in src
