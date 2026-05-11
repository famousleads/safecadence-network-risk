"""
AWS Security Hub finding ingestion (v10.8).

Pulls findings from the Security Hub ``GetFindings`` API via stdlib
HTTP + AWS Signature V4 signing (reusing the SigV4 helpers from
``safecadence.storage.s3_store``). No boto3 dependency.

Auth env:
  * ``AWS_ACCESS_KEY_ID``
  * ``AWS_SECRET_ACCESS_KEY``
  * ``AWS_SESSION_TOKEN`` (optional, for STS-assumed roles)
  * ``AWS_REGION`` (or pass ``region=`` explicitly)

Public surface:

    is_configured() -> bool
    ingest_findings(profile=None, region=None, max=100) -> list[dict]
    normalize_finding(securityhub_finding) -> dict

CLI: ``safecadence ingest aws-security-hub --region us-east-1``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq

_log = logging.getLogger("safecadence.integrations.aws_security_hub")

_SERVICE = "securityhub"
_HOST_FMT = "securityhub.{region}.amazonaws.com"


# --------------------------------------------------------------------------
# SigV4 — same shape as s3_store but for service="securityhub"
# --------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def is_configured() -> bool:
    return bool(
        os.environ.get("AWS_ACCESS_KEY_ID")
        and os.environ.get("AWS_SECRET_ACCESS_KEY")
    )


def _resolve_region(region: str | None = None) -> str:
    return (
        region
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )


def _signed_request(
    *,
    method: str,
    region: str,
    path: str,
    body: bytes,
    extra_headers: dict | None = None,
    timeout: float = 30.0,
) -> tuple[int, bytes, dict]:
    access = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    session_token = os.environ.get("AWS_SESSION_TOKEN")
    if not access or not secret:
        raise RuntimeError("AWS credentials missing")
    host = _HOST_FMT.format(region=region)

    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = _sha256_hex(body)

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
        "content-type": "application/json",
    }
    if extra_headers:
        for k, v in extra_headers.items():
            headers[k.lower()] = v
    if session_token:
        headers["x-amz-security-token"] = session_token

    signed_headers_list = sorted(headers.keys())
    canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in signed_headers_list)
    signed_headers = ";".join(signed_headers_list)
    canonical_qs = ""

    canonical_request = "\n".join([
        method.upper(),
        path,
        canonical_qs,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{_SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        _sha256_hex(canonical_request.encode()),
    ])
    signing_key = _signing_key(secret, date_stamp, region, _SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    url = f"https://{host}{path}"
    req = _urlreq.Request(url, data=body, method=method.upper())
    for h, v in headers.items():
        req.add_header(h, v)
    req.add_header("Authorization", auth)

    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except _urlerr.HTTPError as e:
        err_body = e.read() if hasattr(e, "read") else b""
        return e.code, err_body, {}


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


_SEV_LABEL_TO_SAFE = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}


def _first_resource_id(finding: dict) -> str | None:
    resources = finding.get("Resources") or []
    if not resources:
        return None
    first = resources[0]
    if not isinstance(first, dict):
        return None
    return first.get("Id") or first.get("Type")


def normalize_finding(finding: dict) -> dict:
    """Map a Security Hub finding into SafeCadence's internal shape."""
    sev = finding.get("Severity") or {}
    label = (sev.get("Label") or "MEDIUM").upper()
    norm_sev = _SEV_LABEL_TO_SAFE.get(label, "medium")
    types = finding.get("Types") or []
    asset = _first_resource_id(finding) or ""
    return {
        "id": finding.get("Id") or finding.get("GeneratorId") or "",
        "source": "aws-security-hub",
        "title": finding.get("Title") or "AWS Security Hub finding",
        "severity": norm_sev,
        "description": finding.get("Description") or "",
        "hostname": asset,
        "asset_id": asset,
        "cve": _extract_cve(finding),
        "labels": ["aws-security-hub"] + [str(t) for t in types[:3]],
        "raw_severity": label,
        "remediation": (finding.get("Remediation") or {}).get(
            "Recommendation", {}
        ).get("Text") or "",
        "first_observed_at": finding.get("FirstObservedAt"),
        "last_observed_at": finding.get("LastObservedAt"),
        "aws_account_id": finding.get("AwsAccountId"),
        "region": finding.get("Region"),
        "workflow_state": (finding.get("Workflow") or {}).get("Status"),
        "raw": finding,
    }


def _extract_cve(finding: dict) -> str | None:
    """Best-effort CVE extraction. Security Hub surfaces CVEs under
    multiple keys; pick the first one we find."""
    vulns = finding.get("Vulnerabilities") or []
    for v in vulns:
        if isinstance(v, dict) and v.get("Id", "").startswith("CVE-"):
            return v["Id"]
    title = (finding.get("Title") or "").upper()
    for tok in title.split():
        if tok.startswith("CVE-"):
            return tok.strip(":.,")
    return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def ingest_findings(
    *,
    profile: str | None = None,
    region: str | None = None,
    max: int = 100,
    filters: dict | None = None,
) -> list[dict]:
    """Fetch up to ``max`` findings from Security Hub and return them
    normalised to SafeCadence's finding shape.

    Returns ``[]`` if AWS credentials aren't configured (so the demo
    keeps working).
    """
    # ``profile`` is accepted for CLI symmetry; we only read env creds.
    if profile and not os.environ.get("AWS_ACCESS_KEY_ID"):
        # Optional convenience: tests / CI may pass profile=… in which
        # case we accept the call but still rely on env. Implementing
        # full profile-file parsing would mean shipping ~/.aws/config
        # logic which is out of scope for a stub.
        _log.info("aws profile arg ignored — env credentials are required")
    if not is_configured():
        _log.info("aws security hub not configured — set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY")
        return []
    reg = _resolve_region(region)
    body_payload: dict[str, Any] = {"MaxResults": max}
    if filters:
        body_payload["Filters"] = filters
    body = json.dumps(body_payload).encode("utf-8")
    status, payload, _headers = _signed_request(
        method="POST",
        region=reg,
        path="/findings",
        body=body,
        extra_headers={
            # SDK uses "/findings" as the GetFindings path; the API
            # accepts JSON on POST.
            "x-amz-target": "SecurityHub.GetFindings",
        },
    )
    if status >= 300:
        _log.warning("security hub GetFindings → HTTP %s: %s", status,
                     payload[:200].decode("utf-8", errors="replace"))
        return []
    try:
        parsed = json.loads(payload.decode("utf-8") or "{}")
    except Exception:
        return []
    findings = parsed.get("Findings") or []
    return [normalize_finding(f) for f in findings if isinstance(f, dict)]


__all__ = [
    "is_configured",
    "ingest_findings",
    "normalize_finding",
]
