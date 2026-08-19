"""
SAML 2.0 Service Provider (v16.4 — production signature path).

Two verification paths, strongest available wins:

1. **XML-DSig (production)** — when an IdP signing certificate is
   configured (``SC_SAML_IDP_CERT_FILE`` or inline ``SC_SAML_IDP_CERT``)
   and the optional ``signxml`` dependency is installed
   (``pip install safecadence-netrisk[saml]``), responses are verified
   with real W3C XML-DSig (RSA-SHA256, exc-c14n) and — critically —
   the NameID/attributes are extracted from the **verified** subtree
   only, which closes the classic signature-wrapping attacks.
2. **HMAC stub (dev/lab only)** — the original shared-secret path
   (``SC_SAML_IDP_SHARED_SECRET``) kept for tests and friendly lab
   IdPs. Never configure it in production; when a cert is present the
   stub path is not consulted.

Also enforced on every accepted assertion:
  * ``Conditions`` NotBefore / NotOnOrAfter (90 s clock skew)
  * ``AudienceRestriction`` must contain our SP entity id
  * assertion-ID replay cache (in-process, TTL = assertion lifetime)

SP-initiated login: ``GET /auth/saml/login`` issues an AuthnRequest
via HTTP-Redirect binding to ``SC_SAML_IDP_SSO_URL``.

Env-gated on ``SC_SAML_IDP_METADATA_URL`` + ``SC_SAML_SP_ENTITY_ID``.
Without those, every public function returns "not configured" so the
``/auth/saml/*`` routes can still mount safely.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import threading
import time
import uuid
import zlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def is_configured() -> bool:
    return bool(
        os.environ.get("SC_SAML_IDP_METADATA_URL")
        and os.environ.get("SC_SAML_SP_ENTITY_ID")
    )


def _sp_entity_id() -> str:
    return os.environ.get("SC_SAML_SP_ENTITY_ID", "")


def _sp_acs_url() -> str:
    return os.environ.get(
        "SC_SAML_SP_ACS_URL",
        "https://app.safecadence.com/auth/saml/acs",
    )


def _idp_shared_secret() -> str:
    """Optional shared secret for the (HMAC-SHA256) stub signature path."""
    return os.environ.get("SC_SAML_IDP_SHARED_SECRET", "")


def _idp_cert_pem() -> str:
    """IdP signing certificate (PEM). File path wins over inline env."""
    path = os.environ.get("SC_SAML_IDP_CERT_FILE", "")
    if path:
        try:
            return open(path, encoding="utf-8").read()
        except OSError:
            return ""
    return os.environ.get("SC_SAML_IDP_CERT", "")


def _idp_sso_url() -> str:
    """IdP single-sign-on URL for SP-initiated login (HTTP-Redirect)."""
    return os.environ.get("SC_SAML_IDP_SSO_URL", "")


_CLOCK_SKEW_SEC = 90

# Replay cache: assertion_id -> monotonic expiry.
_SEEN_ASSERTIONS: dict[str, float] = {}
_SEEN_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# SP metadata
# --------------------------------------------------------------------------


def metadata_xml() -> str:
    """Return the SP metadata XML, or a "not configured" stub message."""
    if not is_configured():
        return (
            '<?xml version="1.0"?>'
            '<error xmlns="urn:safecadence:saml">'
            '<message>SAML is not configured. Set SC_SAML_IDP_METADATA_URL '
            'and SC_SAML_SP_ENTITY_ID.</message>'
            '</error>'
        )
    entity_id = _sp_entity_id()
    acs = _sp_acs_url()
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor '
        'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}">\n'
        '  <md:SPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
        'AuthnRequestsSigned="false" WantAssertionsSigned="true">\n'
        '    <md:NameIDFormat>'
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        '</md:NameIDFormat>\n'
        '    <md:AssertionConsumerService '
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs}" index="0" isDefault="true"/>\n'
        '  </md:SPSSODescriptor>\n'
        '</md:EntityDescriptor>\n'
    )
    return xml


# --------------------------------------------------------------------------
# Assertion validation + extraction
# --------------------------------------------------------------------------


def _decode_saml_response(saml_response: str) -> bytes | None:
    if not saml_response:
        return None
    try:
        return base64.b64decode(saml_response)
    except Exception:
        return None


def _canonical_assertion(xml_bytes: bytes) -> bytes:
    """Strip every <ds:Signature> element + collapse whitespace.

    This is the stub canonicalisation we sign over with HMAC-SHA256.
    It is intentionally simple — see the module docstring for why.
    """
    text = xml_bytes.decode("utf-8", errors="replace")
    # Strip everything between <ds:Signature ...> and </ds:Signature>.
    text = re.sub(
        r"<(?:[a-zA-Z0-9]+:)?Signature\b[^>]*>.*?</(?:[a-zA-Z0-9]+:)?Signature>",
        "",
        text,
        flags=re.DOTALL,
    )
    # Collapse runs of whitespace between tags so trivial reformatting
    # doesn't invalidate the signature.
    text = re.sub(r">\s+<", "><", text).strip()
    return text.encode("utf-8")


def _verify_signature(xml_bytes: bytes) -> bool:
    """Verify the HMAC-SHA256 signature carried in the response.

    Looks for ``<ds:Signature><ds:SignatureValue>``base64``</…><…>``
    inside the XML. When :envvar:`SC_SAML_IDP_SHARED_SECRET` is unset
    we conservatively reject (the production path is "real IdP cert
    or bust"). When a shared secret IS set, we compute
    ``HMAC-SHA256(canonical_assertion, secret)`` and compare with the
    signature value.
    """
    secret = _idp_shared_secret()
    if not secret:
        return False
    try:
        # Locate <SignatureValue>…</SignatureValue> via regex; ET is too
        # strict about default namespaces inside namespaced inner trees.
        m = re.search(
            r"<(?:[a-zA-Z0-9]+:)?SignatureValue[^>]*>([^<]+)"
            r"</(?:[a-zA-Z0-9]+:)?SignatureValue>",
            xml_bytes.decode("utf-8", errors="replace"),
        )
        if not m:
            return False
        provided = base64.b64decode(m.group(1).strip())
    except Exception:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        _canonical_assertion(xml_bytes),
        hashlib.sha256,
    ).digest()
    return hmac.compare_digest(provided, expected)


def _verify_signature_xmldsig(xml_bytes: bytes) -> bytes | None:
    """Production path: verify the W3C XML-DSig signature with the
    configured IdP certificate via ``signxml``.

    Returns the canonical bytes of the VERIFIED subtree (extract
    identity from these, never from the raw response — that's the
    signature-wrapping defense), or ``None`` when verification fails.
    Raises ``RuntimeError`` when a cert is configured but ``signxml``
    isn't installed — silent downgrade would be a vulnerability.
    """
    cert = _idp_cert_pem()
    if not cert:
        return None
    try:
        from lxml import etree                          # noqa: PLC0415
        from signxml import XMLVerifier                 # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "SC_SAML_IDP_CERT[_FILE] is set but the 'signxml' package is "
            "not installed — install with: pip install safecadence-netrisk[saml]"
        ) from exc
    try:
        verified = XMLVerifier().verify(xml_bytes, x509_cert=cert)
        return etree.tostring(verified.signed_xml)
    except Exception:
        return None


def _parse_iso8601(s: str) -> float | None:
    """SAML instants → epoch seconds. Accepts trailing 'Z'."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _check_conditions(xml_bytes: bytes) -> str | None:
    """Enforce Conditions (validity window + audience) and replay.
    Returns an error string, or None when the assertion is acceptable."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return "assertion_unparseable"

    now = datetime.now(timezone.utc).timestamp()
    cond = root.find(".//saml:Conditions", NS)
    not_on_or_after = None
    if cond is not None:
        nb = _parse_iso8601(cond.get("NotBefore", ""))
        if nb is not None and now + _CLOCK_SKEW_SEC < nb:
            return "assertion_not_yet_valid"
        not_on_or_after = _parse_iso8601(cond.get("NotOnOrAfter", ""))
        if not_on_or_after is not None and now - _CLOCK_SKEW_SEC >= not_on_or_after:
            return "assertion_expired"
        audiences = [
            (a.text or "").strip()
            for a in cond.findall(".//saml:Audience", NS)
        ]
        if audiences and _sp_entity_id() not in audiences:
            return "audience_mismatch"

    assertion = root.find(".//saml:Assertion", NS)
    if assertion is None and root.tag.endswith("Assertion"):
        assertion = root
    assertion_id = assertion.get("ID", "") if assertion is not None else ""
    if assertion_id:
        ttl = max(60.0, (not_on_or_after - now)
                   if not_on_or_after else 300.0) + _CLOCK_SKEW_SEC
        mono = time.monotonic()
        with _SEEN_LOCK:
            for k in [k for k, exp in _SEEN_ASSERTIONS.items() if exp < mono]:
                _SEEN_ASSERTIONS.pop(k, None)
            if assertion_id in _SEEN_ASSERTIONS:
                return "assertion_replayed"
            _SEEN_ASSERTIONS[assertion_id] = mono + ttl
    return None


def _extract_email_and_groups(xml_bytes: bytes) -> tuple[str | None, list[str]]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None, []

    email: str | None = None
    groups: list[str] = []

    # NameID may carry the email when format=emailAddress.
    name_id = root.find(".//saml:NameID", NS)
    if name_id is not None and (name_id.text or "").strip():
        candidate = (name_id.text or "").strip()
        if "@" in candidate:
            email = candidate

    # AttributeStatement → fall back for email + load groups.
    for attr in root.findall(".//saml:Attribute", NS):
        name = (attr.get("Name") or "").lower()
        values = [
            (v.text or "").strip()
            for v in attr.findall("saml:AttributeValue", NS)
            if (v.text or "").strip()
        ]
        if not values:
            continue
        if not email and name in {
            "email", "emailaddress", "mail",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "urn:oid:0.9.2342.19200300.100.1.3",
        }:
            email = values[0]
        if name in {"groups", "memberof", "roles"}:
            groups.extend(values)

    return email, sorted({g for g in groups if g})


# --------------------------------------------------------------------------
# Public ACS handler
# --------------------------------------------------------------------------


def handle_acs_response(saml_response: str) -> dict:
    """Validate the SAMLResponse + create a session.

    Returns ``{"ok": True, "session_token": "...", "email": "..."}``
    on success, or ``{"ok": False, "error": "..."}`` otherwise.
    """
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    raw = _decode_saml_response(saml_response)
    if not raw:
        return {"ok": False, "error": "bad_saml_response"}

    # Strongest configured verification wins. With an IdP cert present
    # the HMAC stub path is never consulted, and identity is extracted
    # from the VERIFIED subtree only (signature-wrapping defense).
    identity_source = raw
    if _idp_cert_pem():
        try:
            verified = _verify_signature_xmldsig(raw)
        except RuntimeError as exc:
            return {"ok": False, "error": f"saml_dependency_missing: {exc}"}
        if verified is None:
            return {"ok": False, "error": "signature_invalid"}
        identity_source = verified
    elif not _verify_signature(raw):
        return {"ok": False, "error": "signature_invalid"}

    cond_err = _check_conditions(identity_source)
    if cond_err:
        return {"ok": False, "error": cond_err}

    email, groups = _extract_email_and_groups(identity_source)
    if not email:
        return {"ok": False, "error": "no_email_in_assertion"}
    try:
        from safecadence.auth.magic_link import create_session, _user_id_for
        uid = _user_id_for(email)
        token = create_session(uid, email)
        return {
            "ok": True,
            "session_token": token,
            "user_id": uid,
            "email": email,
            "groups": groups,
        }
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "error": f"session_create_failed: {exc}"}


# --------------------------------------------------------------------------
# SP-initiated login (HTTP-Redirect binding)
# --------------------------------------------------------------------------


def build_authn_request() -> tuple[str, str]:
    """Return ``(request_id, redirect_url)`` for SP-initiated login, or
    raise ``ValueError`` when SC_SAML_IDP_SSO_URL is unset."""
    sso = _idp_sso_url()
    if not sso:
        raise ValueError("SC_SAML_IDP_SSO_URL is not set")
    request_id = f"_sc{uuid.uuid4().hex}"
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        '<samlp:AuthnRequest '
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{sso}" '
        'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'AssertionConsumerServiceURL="{_sp_acs_url()}">'
        f'<saml:Issuer>{_sp_entity_id()}</saml:Issuer>'
        '<samlp:NameIDPolicy '
        'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" '
        'AllowCreate="true"/>'
        '</samlp:AuthnRequest>'
    )
    # HTTP-Redirect binding: raw-DEFLATE, base64, URL-encode.
    deflated = zlib.compress(xml.encode("utf-8"))[2:-4]
    from urllib.parse import quote, urlencode
    sep = "&" if "?" in sso else "?"
    query = urlencode({"SAMLRequest": base64.b64encode(deflated).decode()},
                        quote_via=quote)
    return request_id, f"{sso}{sep}{query}"


# --------------------------------------------------------------------------
# FastAPI router
# --------------------------------------------------------------------------


def build_router():
    try:
        from fastapi import APIRouter, Form, Request, Response
        from fastapi.responses import (
            JSONResponse, PlainTextResponse, RedirectResponse,
        )
    except Exception:  # pragma: no cover
        return None

    router = APIRouter(tags=["saml"])

    @router.get("/auth/saml/login")
    def saml_login():
        if not is_configured():
            return JSONResponse(status_code=503,
                                  content={"error": "not_configured"})
        try:
            _, url = build_authn_request()
        except ValueError as exc:
            return JSONResponse(status_code=503, content={"error": str(exc)})
        return RedirectResponse(url=url, status_code=302)

    @router.get("/auth/saml/metadata")
    def saml_metadata():
        if not is_configured():
            return PlainTextResponse(
                metadata_xml(),
                media_type="application/xml",
                status_code=503,
            )
        return Response(content=metadata_xml(), media_type="application/xml")

    @router.post("/auth/saml/acs")
    def saml_acs(request: Request, SAMLResponse: str = Form(...)):
        result = handle_acs_response(SAMLResponse)
        if not result.get("ok"):
            return JSONResponse(
                status_code=400 if result.get("error") != "not_configured" else 503,
                content=result,
            )
        from safecadence.auth.deps import SESSION_COOKIE
        resp = RedirectResponse(url="/home", status_code=303)
        resp.set_cookie(
            key=SESSION_COOKIE,
            value=result["session_token"],
            max_age=30 * 86400,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
            path="/",
        )
        return resp

    return router


__all__ = [
    "is_configured",
    "metadata_xml",
    "handle_acs_response",
    "build_router",
]
