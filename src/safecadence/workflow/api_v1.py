"""
FastAPI routes for the v10.8 workflow + governance modules.

Mounts (every route is org-scoped via the ``X-SafeCadence-Org`` header
or ``?org_id=`` query param):

  Approvals
  ---------
    POST   /api/v1/approvals                      → start_approval
    POST   /api/v1/approvals/{id}/sign            → sign_step
    POST   /api/v1/approvals/{id}/cancel          → cancel_approval
    GET    /api/v1/approvals                      → list_approvals
    GET    /api/v1/approvals/chains               → list_chains
    POST   /api/v1/approvals/chains               → define_chain

  Evidence
  --------
    POST   /api/v1/evidence                       (multipart) → attach
    GET    /api/v1/evidence                       → list
    GET    /api/v1/evidence/export                → ZIP

  Change log
  ----------
    GET    /api/v1/changes                        → list_changes

  Pentests
  --------
    POST   /api/v1/pentests                       → create
    GET    /api/v1/pentests                       → list
    GET    /api/v1/pentests/{id}                  → get
    POST   /api/v1/pentests/{id}/start
    POST   /api/v1/pentests/{id}/complete
    POST   /api/v1/pentests/{id}/findings         → add_finding
    POST   /api/v1/pentests/{id}/signoff
    GET    /api/v1/pentests/{id}/gap

Every mutating route honours ``SC_READONLY=1`` — the underlying module
will raise ``PermissionError`` which we convert to HTTP 403.
"""

from __future__ import annotations

from typing import Any

from safecadence.workflow import (
    approval_chains as _ac,
    change_mgmt as _cm,
    pentest as _pt,
    soc2_evidence as _ev,
)


def _org_from_request(request) -> str:
    org = (
        request.headers.get("X-SafeCadence-Org")
        or request.query_params.get("org_id")
        or ""
    ).strip()
    if not org:
        raise _http_400("X-SafeCadence-Org header or ?org_id= query param is required")
    return org


def _http_400(detail: str):
    try:
        from fastapi import HTTPException
        return HTTPException(status_code=400, detail=detail)
    except Exception:  # pragma: no cover
        return RuntimeError(detail)


def _http_403(detail: str):
    try:
        from fastapi import HTTPException
        return HTTPException(status_code=403, detail=detail)
    except Exception:  # pragma: no cover
        return RuntimeError(detail)


def _http_404(detail: str):
    try:
        from fastapi import HTTPException
        return HTTPException(status_code=404, detail=detail)
    except Exception:  # pragma: no cover
        return RuntimeError(detail)


def build_router():
    try:
        from fastapi import APIRouter, File, Form, Request, UploadFile
        from fastapi.responses import JSONResponse, Response
    except Exception:  # pragma: no cover
        return None

    router = APIRouter(tags=["workflow"])

    # ---- Approvals --------------------------------------------------
    @router.post("/api/v1/approvals/chains")
    async def chains_create(request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            saved = _ac.define_chain(
                org,
                body.get("name") or "",
                body.get("role_steps") or [],
            )
            return saved
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (ValueError, TypeError) as exc:
            raise _http_400(str(exc))

    @router.get("/api/v1/approvals/chains")
    def chains_list(request: Request):
        org = _org_from_request(request)
        return {"chains": _ac.list_chains(org)}

    @router.post("/api/v1/approvals")
    async def approvals_create(request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            ap = _ac.start_approval(
                org,
                body.get("finding_id") or "",
                body.get("chain_name") or "",
                host=body.get("host"),
                rationale=body.get("rationale"),
                expires_at=body.get("expires_at"),
            )
            return _ac._approval_to_jsonable(ap)
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (ValueError, KeyError) as exc:
            raise _http_400(str(exc))

    @router.post("/api/v1/approvals/{approval_id}/sign")
    async def approvals_sign(approval_id: str, request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            ap = _ac.sign_step(
                approval_id,
                body.get("user_email") or "",
                body.get("role") or "",
                note=body.get("note"),
                org_id=org,
            )
            return _ac._approval_to_jsonable(ap)
        except PermissionError as exc:
            raise _http_403(str(exc))
        except ValueError as exc:
            raise _http_400(str(exc))

    @router.post("/api/v1/approvals/{approval_id}/cancel")
    async def approvals_cancel(approval_id: str, request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            ap = _ac.cancel_approval(
                approval_id,
                body.get("reason") or "",
                org_id=org,
                actor=body.get("actor"),
            )
            return _ac._approval_to_jsonable(ap)
        except PermissionError as exc:
            raise _http_403(str(exc))
        except ValueError as exc:
            raise _http_400(str(exc))

    @router.get("/api/v1/approvals")
    def approvals_list(request: Request):
        org = _org_from_request(request)
        status = request.query_params.get("status") or None
        items = _ac.list_approvals(org, status=status)
        return {"approvals": [_ac._approval_to_jsonable(a) for a in items]}

    # ---- Evidence ---------------------------------------------------
    @router.post("/api/v1/evidence")
    async def evidence_attach(
        request: Request,
        control_id: str = Form(...),
        framework: str = Form(...),
        kind: str = Form(...),
        file: UploadFile = File(...),
        note: str | None = Form(None),
        user: str | None = Form(None),
    ):
        org = _org_from_request(request)
        try:
            data = await file.read()
            item = _ev.attach_evidence(
                org, control_id, framework, kind,
                data, file.filename or "evidence.bin",
                note=note, user=user,
            )
            return item.to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (ValueError, TypeError) as exc:
            raise _http_400(str(exc))

    @router.get("/api/v1/evidence")
    def evidence_list(request: Request):
        org = _org_from_request(request)
        fw = request.query_params.get("framework") or None
        cid = request.query_params.get("control_id") or None
        items = _ev.list_evidence(org, framework=fw, control_id=cid)
        return {"items": [i.to_dict() for i in items]}

    @router.get("/api/v1/evidence/export")
    def evidence_export(request: Request):
        org = _org_from_request(request)
        fw = request.query_params.get("framework")
        if not fw:
            raise _http_400("framework query param is required")
        payload = _ev.export_evidence_pack(org, fw)
        return Response(
            content=payload,
            media_type="application/zip",
            headers={
                "Content-Disposition":
                    f'attachment; filename="evidence-{fw}.zip"',
            },
        )

    # ---- Change log -------------------------------------------------
    @router.get("/api/v1/changes")
    def changes_list(request: Request):
        org = _org_from_request(request)
        since = request.query_params.get("since") or None
        kind = request.query_params.get("kind") or None
        limit = int(request.query_params.get("limit") or "500")
        items = _cm.list_changes(org, since=since, kind=kind, limit=limit)
        return {"changes": [c.to_dict() for c in items]}

    # ---- Pentests ---------------------------------------------------
    @router.post("/api/v1/pentests")
    async def pentest_create(request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            pt = _pt.create_pentest(
                org, body.get("name") or "", body.get("scope") or "",
                body.get("planned_start"), body.get("planned_end"),
            )
            return pt.to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except ValueError as exc:
            raise _http_400(str(exc))

    @router.get("/api/v1/pentests")
    def pentest_list(request: Request):
        org = _org_from_request(request)
        status = request.query_params.get("status") or None
        items = _pt.list_pentests(org, status=status)
        return {"pentests": [p.to_dict() for p in items]}

    @router.get("/api/v1/pentests/{pentest_id}")
    def pentest_get(pentest_id: str, request: Request):
        org = _org_from_request(request)
        pt = _pt.get_pentest(org, pentest_id)
        if not pt:
            raise _http_404("no such pentest")
        return pt.to_dict()

    @router.post("/api/v1/pentests/{pentest_id}/start")
    def pentest_start(pentest_id: str, request: Request):
        org = _org_from_request(request)
        try:
            return _pt.start_pentest(org, pentest_id).to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (KeyError, ValueError) as exc:
            raise _http_400(str(exc))

    @router.post("/api/v1/pentests/{pentest_id}/complete")
    def pentest_complete(pentest_id: str, request: Request):
        org = _org_from_request(request)
        try:
            return _pt.complete_pentest(org, pentest_id).to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (KeyError, ValueError) as exc:
            raise _http_400(str(exc))

    @router.post("/api/v1/pentests/{pentest_id}/findings")
    async def pentest_add_finding(pentest_id: str, request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            f = _pt.add_finding(
                org, pentest_id,
                body.get("title") or "",
                body.get("severity") or "info",
                evidence=body.get("evidence"),
                cve=body.get("cve"),
                asset=body.get("asset"),
            )
            return f.to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (KeyError, ValueError) as exc:
            raise _http_400(str(exc))

    @router.post("/api/v1/pentests/{pentest_id}/signoff")
    async def pentest_signoff(pentest_id: str, request: Request):
        org = _org_from_request(request)
        body = await request.json()
        try:
            return _pt.signoff(
                org, pentest_id,
                body.get("user_email") or "",
                note=body.get("note"),
            ).to_dict()
        except PermissionError as exc:
            raise _http_403(str(exc))
        except (KeyError, ValueError) as exc:
            raise _http_400(str(exc))

    @router.get("/api/v1/pentests/{pentest_id}/gap")
    def pentest_gap(pentest_id: str, request: Request):
        org = _org_from_request(request)
        rows = _pt.gap_to_remediation(org, pentest_id)
        return {"rows": rows}

    return router


__all__ = ["build_router"]
