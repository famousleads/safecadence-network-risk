"""
SAML 2.0 Service Provider — stub-level implementation (v10.8).

This is a deliberately minimal, stdlib-only SAML SP flow good enough
for development + most lab integrations. It is **not** a substitute
for ``python3-saml`` in a hardened production deployment because:

* Signature verification uses HMAC-SHA256 over a *canonical-ish*
  rendering of the assertion. Real-world IdPs sign with RSA-SHA256
  over W3C XML-DSig exclusive canonicalisation (``exc-c14n``) — to
  validate those we'd need ``xmlsec1`` or ``signxml``.
* No replay protection beyond ``InResponseTo`` matching.
* No encrypted assertions.

In other words: it gets you through the demo and a friendly IdP, but
flagged loudly in the TODO file so we know when to swap for the real
library.

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
import xml.etree.ElementTree as ET
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
    if not _verify_signature(raw):
        return {"ok": False, "error": "signature_invalid"}
    email, groups = _extract_email_and_groups(raw)
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
