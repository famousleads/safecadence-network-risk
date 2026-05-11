"""
v11.3 — FastAPI routes for the ops module.

Mounted by :func:`safecadence.ui.app.create_app` when FastAPI is
available. All endpoints sit under ``/api/v1/orgs/`` and are admin-only
(the existing auth middleware enforces this). On read-only demo nodes
(``SC_READONLY=1``) every mutation returns 403; here we only expose a
read endpoint (``export``) plus two read-only verifies, so the
read-only filter is a no-op for this router.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from pathlib import Path

try:
    from fastapi import APIRouter, HTTPException, Query
    from fastapi.responses import JSONResponse, Response
except Exception:                                    # pragma: no cover
    APIRouter = None                                 # type: ignore[assignment]


router = None
if APIRouter is not None:
    router = APIRouter(prefix="/api/v1", tags=["ops"])

    @router.get("/orgs/{org_id}/export")
    def export_org_endpoint(org_id: str, include_blobs: bool = Query(False)):
        """Return a GDPR-style export of one org's data.

        With ``include_blobs=false`` (default) the body is JSON. With
        ``include_blobs=true`` it's a ``application/zip`` containing the
        JSON plus a ``blobs/`` tree of the inlined evidence files.
        """
        from safecadence.ops.export_org import export_org

        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / f"{org_id}.json"
            try:
                export_org(org_id, json_path, include_blobs=include_blobs)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except Exception as exc:                  # pragma: no cover
                raise HTTPException(status_code=500, detail=str(exc))
            if not include_blobs:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
                return JSONResponse(payload)
            # include_blobs=True ⇒ wrap in a zip so binary content is
            # delivered cleanly (b64-encoded inside the JSON otherwise).
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(json_path, arcname=f"{org_id}.json")
            buf.seek(0)
            return Response(
                content=buf.read(),
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="{org_id}-export.zip"',
                },
            )

    @router.get("/orgs/{org_id}/audit-chain/verify")
    def verify_audit_chain_endpoint(org_id: str):
        """Walk the hash-chained audit log and return integrity status."""
        from safecadence.audit.log import verify_chain
        return verify_chain(org_id)

    @router.get("/orgs/{org_id}/retention")
    def retention_show_endpoint(org_id: str):
        from safecadence.ops.retention import get_retention
        pol = get_retention(org_id)
        return {k: p.to_dict() for k, p in pol.items()}


__all__ = ["router"]
