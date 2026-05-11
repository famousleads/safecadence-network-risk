"""
S3 / DigitalOcean Spaces object store (v10.7).

Stdlib-only HTTP + AWS Signature V4. No boto3 dependency. Works with
real S3, DO Spaces, Backblaze B2, MinIO — anything that speaks the
S3 REST API.

Public surface:

    >>> s = S3Store()
    >>> url = s.put_object("reports/2026/05/foo.pdf", b"%PDF-1.4...", "application/pdf")
    >>> body = s.get_object("reports/2026/05/foo.pdf")
    >>> s.list_objects("reports/2026/")
    >>> s.delete_object("reports/2026/05/foo.pdf")

Env:
    SC_S3_ENDPOINT   e.g. https://nyc3.digitaloceanspaces.com
    SC_S3_REGION     e.g. nyc3 (or us-east-1)
    SC_S3_BUCKET     bucket name
    SC_S3_ACCESS_KEY
    SC_S3_SECRET_KEY

If any of those are missing, :func:`is_configured` returns False and
direct construction raises a clear error. Module never crashes on
import — :mod:`safecadence.reports.templates` checks
``is_configured()`` before trying to write to S3 and falls back to
local disk otherwise.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os
import xml.etree.ElementTree as ET
from typing import Any
from urllib import error as _urlerr
from urllib import parse as _urlparse
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# SigV4 helpers
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


def _amz_canonical_uri(key: str) -> str:
    """Each URL segment must be quoted *except* "/" which separates segments."""
    return "/" + "/".join(_urlparse.quote(seg, safe="") for seg in key.split("/"))


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def is_configured() -> bool:
    return all(os.environ.get(k) for k in
               ("SC_S3_ENDPOINT", "SC_S3_BUCKET", "SC_S3_ACCESS_KEY", "SC_S3_SECRET_KEY"))


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class S3Store:
    """Tiny stdlib S3 client.

    Operations sign with SigV4 over the path-style URL
    ``{endpoint}/{bucket}/{key}``. Path-style works for both S3 (us-east-1
    legacy) and DO Spaces, which is what we care about.
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        region: str | None = None,
        bucket: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ):
        self.endpoint = (endpoint or os.environ.get("SC_S3_ENDPOINT", "")).rstrip("/")
        self.region = region or os.environ.get("SC_S3_REGION", "us-east-1")
        self.bucket = bucket or os.environ.get("SC_S3_BUCKET", "")
        self.access_key = access_key or os.environ.get("SC_S3_ACCESS_KEY", "")
        self.secret_key = secret_key or os.environ.get("SC_S3_SECRET_KEY", "")
        if not (self.endpoint and self.bucket and self.access_key and self.secret_key):
            raise RuntimeError(
                "S3Store: missing config — set SC_S3_ENDPOINT, SC_S3_BUCKET, "
                "SC_S3_ACCESS_KEY, SC_S3_SECRET_KEY."
            )
        parsed = _urlparse.urlparse(self.endpoint)
        self.host = parsed.netloc
        self.scheme = parsed.scheme or "https"
        self.service = "s3"

    # ---- signing -------------------------------------------------- #

    def _request(self, method: str, key: str, *, body: bytes = b"",
                 content_type: str | None = None,
                 query: dict[str, str] | None = None) -> tuple[int, bytes, dict]:
        now = _dt.datetime.now(_dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = _sha256_hex(body)

        canonical_uri = f"/{self.bucket}" + _amz_canonical_uri(key) if key else f"/{self.bucket}"
        # Build & sort canonical query string
        qs = query or {}
        canonical_qs = "&".join(
            f"{_urlparse.quote(k, safe='-_.~')}={_urlparse.quote(v, safe='-_.~')}"
            for k, v in sorted(qs.items())
        )

        headers = {
            "host": self.host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if content_type:
            headers["content-type"] = content_type

        signed_headers_list = sorted(headers.keys())
        canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in signed_headers_list)
        signed_headers = ";".join(signed_headers_list)

        canonical_request = "\n".join([
            method.upper(), canonical_uri, canonical_qs,
            canonical_headers, signed_headers, payload_hash,
        ])
        scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request.encode()),
        ])
        signing_key = _signing_key(self.secret_key, date_stamp, self.region, self.service)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        url = f"{self.scheme}://{self.host}{canonical_uri}"
        if canonical_qs:
            url += "?" + canonical_qs

        req = _urlreq.Request(url, data=body if body else None, method=method.upper())
        for h, v in headers.items():
            req.add_header(h, v)
        req.add_header("Authorization", authorization)

        try:
            with _urlreq.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except _urlerr.HTTPError as e:
            err_body = e.read() if hasattr(e, "read") else b""
            raise RuntimeError(f"S3 {method} {key} → HTTP {e.code}: {err_body.decode(errors='replace')[:400]}") from e

    # ---- public API ----------------------------------------------- #

    def put_object(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Upload bytes to ``key``. Returns the canonical URL."""
        status, _body, _hdrs = self._request("PUT", key, body=data, content_type=content_type)
        if status not in (200, 204):
            raise RuntimeError(f"S3 PUT returned status {status}")
        return f"{self.scheme}://{self.host}/{self.bucket}/{key}"

    def get_object(self, key: str) -> bytes:
        status, body, _ = self._request("GET", key)
        if status != 200:
            raise RuntimeError(f"S3 GET returned status {status}")
        return body

    def delete_object(self, key: str) -> None:
        status, _b, _h = self._request("DELETE", key)
        if status not in (200, 204):
            raise RuntimeError(f"S3 DELETE returned status {status}")

    def list_objects(self, prefix: str = "") -> list[dict]:
        """ListObjectsV2. Returns ``[{key, size, last_modified, etag}, ...]``."""
        query = {"list-type": "2"}
        if prefix:
            query["prefix"] = prefix
        status, body, _h = self._request("GET", "", query=query)
        if status != 200:
            raise RuntimeError(f"S3 LIST returned status {status}")
        # Strip xmlns for ease of parsing
        text = body.decode("utf-8", errors="replace")
        # crude namespace strip
        text = text.replace('xmlns="http://s3.amazonaws.com/doc/2006-03-01/"', "")
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        out: list[dict] = []
        for c in root.findall("Contents"):
            out.append({
                "key": (c.findtext("Key") or "").strip(),
                "size": int(c.findtext("Size") or 0),
                "last_modified": c.findtext("LastModified") or "",
                "etag": (c.findtext("ETag") or "").strip('"'),
            })
        return out


__all__ = ["S3Store", "is_configured"]
