"""SafeCadence NetRisk SDK — HTTP client.

The ``Client`` is the single entry point. It wraps ``requests.Session``
with bearer-auth, JSON encoding, error mapping, and a small set of
endpoint-specific helpers.

The shape mirrors the REST API documented at ``/api/v1/*``. Methods that
return reports come back as raw bytes so the caller can save them to
disk; everything else returns parsed JSON.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import requests

from .exceptions import (
    AuthError,
    NotFound,
    RateLimitError,
    SafeCadenceError,
)


JSON = Union[Dict[str, Any], List[Any]]


class Client:
    """SafeCadence NetRisk API client.

    Parameters
    ----------
    base_url:
        Origin of the API (e.g. ``"https://demo.safecadence.com"``).
        Trailing slashes are stripped.
    api_key:
        Bearer token. The SDK sends it as ``Authorization: Bearer <key>``.
        Pass ``None`` to skip auth (read-only demo endpoints work without it).
    timeout:
        Per-request timeout in seconds. Default ``30.0``.
    session:
        Optional pre-configured ``requests.Session`` (useful for testing).
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session = session or requests.Session()

    # ------------------------------------------------------------------ #
    # Internal request helper                                             #
    # ------------------------------------------------------------------ #

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "safecadence-sdk-python/0.1.0",
        }
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        expect_bytes: bool = False,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.request(
                method,
                url,
                headers=self._headers(),
                params=params,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SafeCadenceError(f"network error: {exc}") from exc

        # Map HTTP errors to typed exceptions.
        status = resp.status_code
        if status in (401, 403):
            raise AuthError(
                f"auth failed ({status})",
                status_code=status,
                response_body=resp.text,
            )
        if status == 404:
            raise NotFound(
                f"not found: {path}",
                status_code=status,
                response_body=resp.text,
            )
        if status == 429:
            retry_after_raw = resp.headers.get("Retry-After")
            retry_after: Optional[float]
            try:
                retry_after = float(retry_after_raw) if retry_after_raw else None
            except (TypeError, ValueError):
                retry_after = None
            raise RateLimitError(
                "rate limited",
                retry_after=retry_after,
                status_code=status,
                response_body=resp.text,
            )
        if status >= 400:
            raise SafeCadenceError(
                f"HTTP {status}: {resp.text[:200]}",
                status_code=status,
                response_body=resp.text,
            )

        if expect_bytes:
            return resp.content
        if not resp.content:
            return None
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return resp.json()
        return resp.text

    # ------------------------------------------------------------------ #
    # Inventory                                                           #
    # ------------------------------------------------------------------ #

    def list_inventory(self) -> List[Dict[str, Any]]:
        """Return all platform assets known to the system."""
        data = self._request("GET", "/api/v1/inventory")
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data or []

    def get_asset(self, asset_id: str) -> Dict[str, Any]:
        """Return the full record for a single asset."""
        return self._request("GET", f"/api/v1/inventory/{asset_id}")

    # ------------------------------------------------------------------ #
    # Findings + compliance                                               #
    # ------------------------------------------------------------------ #

    def get_findings(self, *, severity: Optional[str] = None,
                     asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return findings, optionally filtered by severity or asset."""
        params: Dict[str, Any] = {}
        if severity:
            params["severity"] = severity
        if asset_id:
            params["asset_id"] = asset_id
        data = self._request("GET", "/api/v1/findings", params=params or None)
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data or []

    def get_compliance_status(self, framework: Optional[str] = None) -> Dict[str, Any]:
        """Return compliance roll-up keyed by framework."""
        params = {"framework": framework} if framework else None
        return self._request("GET", "/api/v1/compliance/status", params=params)

    # ------------------------------------------------------------------ #
    # Reports                                                             #
    # ------------------------------------------------------------------ #

    def list_reports(self) -> List[Dict[str, Any]]:
        """List all saved/composed reports."""
        data = self._request("GET", "/api/v1/reports")
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data or []

    def compose_report(
        self,
        preset: Optional[str] = None,
        format: str = "html",
        **kwargs: Any,
    ) -> bytes:
        """Compose a one-shot report and return the rendered bytes.

        Hits ``POST /api/reports/render-download`` — the same one-shot
        endpoint the wizard uses. The response is the raw report payload
        (HTML / PDF / DOCX / PPTX / JSON).
        """
        body: Dict[str, Any] = {
            "format": format,
        }
        if preset:
            body["preset_id"] = preset
        body.update(kwargs)
        return self._request(
            "POST",
            "/api/reports/render-download",
            json_body=body,
            expect_bytes=True,
        )

    def generate_report(self, preset: str, format: str = "pdf") -> Dict[str, Any]:
        """Trigger an async report generation job.

        Returns the job descriptor (with an ``id`` and ``status_url``). Poll
        the status URL until ``status`` is ``"completed"``.
        """
        return self._request(
            "POST",
            "/api/v1/reports/generate",
            json_body={"preset": preset, "format": format},
        )

    # ------------------------------------------------------------------ #
    # Templates                                                           #
    # ------------------------------------------------------------------ #

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all report templates."""
        data = self._request("GET", "/api/reports/templates")
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data or []

    def save_template(
        self,
        name: str,
        sections: List[str],
        scope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Persist a new report template."""
        return self._request(
            "POST",
            "/api/reports/templates",
            json_body={
                "name": name,
                "sections": sections,
                "scope": scope or {},
            },
        )
