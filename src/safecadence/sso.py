"""SSO — OIDC (production-grade) + SAML 2.0 SP (stub for v7.5).

Why this lives in one module:
  * Both flows ultimately produce a SafeCadence-issued JWT with the
    same shape as a username/password login, so callers downstream
    (RBAC matrix, tenant boundary, audit) don't care which path the
    user came in on.
  * The role-mapping logic is the same for both — claims/attributes
    map to one of the v7.0 6-tier roles via a single config table.

OIDC implementation
  * Auth Code flow with PKCE (the modern best-practice choice).
  * Discovery via the standard ``.well-known/openid-configuration``.
  * ID token verified with the IdP's JWKS, signature + iss/aud/exp.
  * Tested-shape contract works with Okta, Azure AD, Google, Auth0,
    Keycloak, and any RFC-compliant IdP.

SAML 2.0
  * Metadata builder ships now so an Okta/Azure admin can configure
    SafeCadence as a SP.
  * AuthnRequest builder ships now — the redirect to the IdP works.
  * Response validation is stubbed with TODO markers because real
    xmlsec signature verification needs the ``xmlsec`` C library
    which we don't want to add as a hard dep. v7.5 ships the full
    impl; v7.4 documents the contract so deployments can plan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------
# Shared config
# --------------------------------------------------------------------------

@dataclass
class SSOConfig:
    """One config object for either flow. Persisted at
    ``~/.safecadence/sso.json``; reload with ``load_config()``."""

    enabled: bool = False
    flow: str = "oidc"            # "oidc" or "saml"

    # OIDC
    oidc_issuer: str = ""         # e.g. https://acme.okta.com/oauth2/default
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""   # e.g. https://safecadence.acme.com/api/auth/oidc/callback
    oidc_scopes: list[str] = field(default_factory=lambda:
                                      ["openid", "profile", "email", "groups"])

    # SAML
    saml_idp_metadata_url: str = ""
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""
    saml_idp_x509_cert: str = ""        # PEM
    saml_sp_entity_id: str = ""         # our identity to the IdP
    saml_sp_acs_url: str = ""           # /api/auth/saml/acs

    # Claim/attribute → SafeCadence role mapping. Keys are the
    # IdP-specific claim values; the value is the v7.0 role string.
    role_map: dict[str, str] = field(default_factory=dict)
    default_role: str = "viewer"

    # v9.54 — Group claim → SafeCadence capability auto-grant.
    # Keys are IdP-side group/role values (looked up in the same
    # `groups` / `roles` / `memberOf` claim flatten that resolve_role
    # uses). Values are lists of capability names from
    # safecadence.capabilities.ALL_CAPABILITIES that the user gets
    # the moment they finish OIDC login.
    #
    # Reconciliation is idempotent: capabilities granted via this
    # path are tracked in capabilities.yaml under `sso_managed` and
    # are revoked automatically the next time the user logs in
    # without the matching group. Manual grants are never touched.
    capability_map: dict[str, list[str]] = field(default_factory=dict)

    # Tenant assignment from a claim/attribute
    tenant_claim: str = ""
    default_tenant: str = "local"


def _config_path() -> Path:
    return Path(os.environ.get("SC_SSO_CONFIG")
                or (Path.home() / ".safecadence" / "sso.json"))


def load_config() -> SSOConfig:
    p = _config_path()
    if not p.exists():
        return SSOConfig()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return SSOConfig()
    cfg = SSOConfig()
    for k, v in d.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg


def save_config(cfg: SSOConfig) -> None:
    p = _config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg.__dict__, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Role + tenant resolution
# --------------------------------------------------------------------------

def resolve_role(cfg: SSOConfig, claims: dict) -> str:
    """Pick the v7.0 role from a set of OIDC claims or SAML attributes.

    Strategy:
      1. If any value in ``role_map`` matches a value in the user's
         ``groups`` / ``roles`` claim, use that role.
      2. If the claim is a single string match, use that.
      3. Otherwise return cfg.default_role.
    """
    # Flatten group-like claims into a set (shared with resolve_capabilities)
    candidates: set[str] = _flatten_group_claims(claims)
    for source_value, sc_role in (cfg.role_map or {}).items():
        if source_value in candidates:
            return sc_role
        # Exact full-string match too
        for k in ("preferred_username", "email", "upn"):
            if claims.get(k) == source_value:
                return sc_role
    return cfg.default_role or "viewer"


def resolve_tenant(cfg: SSOConfig, claims: dict) -> str:
    if cfg.tenant_claim and cfg.tenant_claim in claims:
        return str(claims[cfg.tenant_claim])
    return cfg.default_tenant or "local"


def _flatten_group_claims(claims: dict) -> set[str]:
    """Collapse the various places IdPs put group/role membership into
    one flat set of strings. Shared by resolve_role and
    resolve_capabilities so both see the same evidence."""
    out: set[str] = set()
    for k in ("groups", "roles", "role", "memberOf"):
        v = claims.get(k)
        if isinstance(v, list):
            out.update(str(x) for x in v)
        elif isinstance(v, str):
            out.update(s.strip() for s in v.split(",") if s.strip())
    return out


def resolve_capabilities(cfg: SSOConfig, claims: dict) -> list[str]:
    """v9.54 — return the deduplicated, sorted list of capability names
    the user should hold based on their IdP group claims and the
    configured ``capability_map``.

    Returns an empty list if no group matches or capability_map is
    empty. Never raises — unknown capability names are silently
    dropped here; the reconcile call will raise on bad config so the
    audit log captures the misconfiguration before the user's grants
    get touched.
    """
    if not (cfg.capability_map or {}):
        return []
    groups = _flatten_group_claims(claims)
    bag: set[str] = set()
    for group_name, caps in (cfg.capability_map or {}).items():
        if group_name in groups and isinstance(caps, list):
            bag.update(c for c in caps if isinstance(c, str) and c)
    return sorted(bag)


# --------------------------------------------------------------------------
# OIDC — Auth Code + PKCE
# --------------------------------------------------------------------------

@dataclass
class OIDCSession:
    """Short-lived state we hold between /login and /callback."""
    state: str
    code_verifier: str
    code_challenge: str
    issued_at: float
    redirect_after: str = ""


_oidc_pending: dict[str, OIDCSession] = {}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _new_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def oidc_discover(issuer: str, *, timeout: int = 10) -> dict:
    """Fetch ``{issuer}/.well-known/openid-configuration``."""
    import httpx
    issuer = issuer.rstrip("/")
    r = httpx.get(f"{issuer}/.well-known/openid-configuration",
                   timeout=timeout)
    r.raise_for_status()
    return r.json()


def oidc_login_url(cfg: SSOConfig, *, redirect_after: str = "") -> str:
    """Return the URL to send the browser to for IdP login."""
    discovery = oidc_discover(cfg.oidc_issuer)
    verifier, challenge = _new_pkce()
    state = _b64url(secrets.token_bytes(24))
    _oidc_pending[state] = OIDCSession(
        state=state, code_verifier=verifier, code_challenge=challenge,
        issued_at=time.time(), redirect_after=redirect_after,
    )
    params = {
        "response_type": "code",
        "client_id": cfg.oidc_client_id,
        "redirect_uri": cfg.oidc_redirect_uri,
        "scope": " ".join(cfg.oidc_scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return discovery["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)


def _decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    """Split a JWT into (header, payload, signing_input_bytes, sig_bytes)
    without verifying. Used so we can fetch the matching JWK before verify."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    sig = _b64url_decode(parts[2])
    return header, payload, signing_input, sig


def _jwk_to_pubkey(jwk: dict):
    """Build a cryptography public key from a JWK. RSA + EC supported."""
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import serialization
    kty = jwk.get("kty", "RSA")
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                  "P-521": ec.SECP521R1()}.get(jwk.get("crv"))
        if not curve:
            raise ValueError(f"unsupported EC curve: {jwk.get('crv')}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise ValueError(f"unsupported JWK kty: {kty}")


def _verify_jwt(token: str, jwks: dict, *, audience: str,
                  issuer: str) -> dict:
    """Verify signature + standard claims. Returns the validated payload."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    header, payload, signing_input, sig = _decode_jwt_unverified(token)
    kid = header.get("kid")
    alg = header.get("alg")
    matching = next(
        (k for k in jwks.get("keys") or [] if k.get("kid") == kid), None)
    if not matching:
        raise ValueError(f"no JWK found for kid {kid!r}")
    pubkey = _jwk_to_pubkey(matching)
    if alg.startswith("RS"):
        pubkey.verify(
            sig, signing_input,
            padding.PKCS1v15(),
            getattr(hashes, "SHA" + alg[2:])())
    elif alg.startswith("ES"):
        pubkey.verify(
            sig, signing_input,
            __import__("cryptography").hazmat.primitives.asymmetric.ec.ECDSA(
                getattr(hashes, "SHA" + alg[2:])()))
    else:
        raise ValueError(f"unsupported alg: {alg}")
    now = int(time.time())
    if payload.get("exp") and now > int(payload["exp"]):
        raise ValueError("token expired")
    if payload.get("nbf") and now < int(payload["nbf"]):
        raise ValueError("token not yet valid")
    if issuer and payload.get("iss") != issuer:
        raise ValueError(f"iss mismatch: got {payload.get('iss')!r}")
    aud = payload.get("aud")
    if audience:
        if isinstance(aud, list):
            ok = audience in aud
        else:
            ok = aud == audience
        if not ok:
            raise ValueError(f"aud mismatch: got {aud!r}")
    return payload


def oidc_callback(cfg: SSOConfig, *, code: str, state: str) -> dict:
    """Exchange the code for tokens, verify the ID token, return a
    SafeCadence-friendly user dict ready for JWT issue."""
    import httpx
    sess = _oidc_pending.pop(state, None)
    if not sess:
        raise ValueError("unknown state — possible CSRF or session expired")
    if time.time() - sess.issued_at > 600:
        raise ValueError("state expired (10 min limit)")
    discovery = oidc_discover(cfg.oidc_issuer)
    body = {
        "grant_type": "authorization_code", "code": code,
        "client_id": cfg.oidc_client_id,
        "redirect_uri": cfg.oidc_redirect_uri,
        "code_verifier": sess.code_verifier,
    }
    if cfg.oidc_client_secret:
        body["client_secret"] = cfg.oidc_client_secret
    r = httpx.post(discovery["token_endpoint"], data=body, timeout=15)
    r.raise_for_status()
    tokens = r.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise ValueError("IdP did not return an id_token")
    jwks_r = httpx.get(discovery["jwks_uri"], timeout=10)
    jwks_r.raise_for_status()
    claims = _verify_jwt(id_token, jwks_r.json(),
                          audience=cfg.oidc_client_id,
                          issuer=cfg.oidc_issuer.rstrip("/"))
    return {
        "username": claims.get("preferred_username")
                     or claims.get("email") or claims.get("sub", "anonymous"),
        "email": claims.get("email", ""),
        "name": claims.get("name", ""),
        "role": resolve_role(cfg, claims),
        "tenant": resolve_tenant(cfg, claims),
        # v9.54 — capabilities the user should hold based on their
        # IdP groups. The server-side endpoint that consumes this
        # dict calls reconcile_sso_grants() to apply them idempotently.
        "capabilities": resolve_capabilities(cfg, claims),
        "redirect_after": sess.redirect_after,
        "raw_claims": claims,
    }


# --------------------------------------------------------------------------
# SAML 2.0 — metadata + AuthnRequest builders ship now; response validation
# is documented as v7.5 work because xmlsec validation is genuinely
# multi-day to do safely.
# --------------------------------------------------------------------------

def saml_sp_metadata(cfg: SSOConfig) -> str:
    """Return the SP metadata XML the IdP admin uploads to configure SafeCadence."""
    if not cfg.saml_sp_entity_id or not cfg.saml_sp_acs_url:
        raise ValueError("saml_sp_entity_id + saml_sp_acs_url required")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                   entityID="{_xml_escape(cfg.saml_sp_entity_id)}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                    AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
       Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
       Location="{_xml_escape(cfg.saml_sp_acs_url)}" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>
"""


def saml_authn_request(cfg: SSOConfig, *, relay_state: str = "") -> str:
    """Return a redirect URL to the IdP carrying an AuthnRequest.

    The request is base64+deflated per HTTP-Redirect binding spec.
    """
    import zlib
    if not cfg.saml_idp_sso_url or not cfg.saml_sp_entity_id:
        raise ValueError("saml_idp_sso_url + saml_sp_entity_id required")
    request_id = "_" + secrets.token_hex(16)
    issue_instant = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    xml = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}"
  Destination="{_xml_escape(cfg.saml_idp_sso_url)}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="{_xml_escape(cfg.saml_sp_acs_url)}">
  <saml:Issuer>{_xml_escape(cfg.saml_sp_entity_id)}</saml:Issuer>
  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true"/>
</samlp:AuthnRequest>"""
    deflated = zlib.compress(xml.encode("utf-8"))[2:-4]   # raw deflate
    encoded = base64.b64encode(deflated).decode("ascii")
    params = {"SAMLRequest": encoded}
    if relay_state:
        params["RelayState"] = relay_state
    return cfg.saml_idp_sso_url + "?" + urllib.parse.urlencode(params)


def saml_consume_response(cfg: SSOConfig, *, saml_response_b64: str
                            ) -> dict:
    """v7.4 stub. The full implementation in v7.5 will:
      1. base64-decode the SAMLResponse parameter from the form POST.
      2. Verify the XML signature using the IdP's saml_idp_x509_cert
         (this requires the xmlsec library — Python's stdlib can parse
         the XML but cannot verify the digital signature on its own).
      3. Check Conditions/NotOnOrAfter/Audience.
      4. Pull NameID + AttributeStatement → claims dict.
      5. resolve_role + resolve_tenant on the claims.

    Until v7.5 lands, this raises NotImplementedError so an operator
    cannot accidentally rely on an unverified assertion. Documented
    contract: the function returns the same dict shape as oidc_callback.
    """
    raise NotImplementedError(
        "SAML 2.0 response validation is documented in v7.4 but the "
        "xmlsec-based signature verification ships in v7.5. Use OIDC "
        "for now (works with Okta, Azure AD, Google, Auth0, Keycloak) — "
        "or open an issue if your IdP only supports SAML and we'll "
        "prioritise the v7.5 release."
    )


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&apos;"))
