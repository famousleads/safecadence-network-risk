"""
Public REST API for asynchronous report generation.

Mount path: ``/api/v1/reports`` (mounted by the main FastAPI app).

Endpoints
---------

* ``POST /api/v1/reports/generate`` — kick off a background render job.

  Body::

      {
        "preset":       "exec_brief",
        "format":       "pdf",
        "sections":     ["kpi_summary", "executive_summary"],   # optional override
        "scope":        {...},                                  # optional
        "prepared_for": "Acme Corp",                            # optional
        "brand":        {"org_name": "...", "primary_color": "#1f6f6a"},
        "deliver_via":  "download" | "email",                   # optional
        "to":           ["ciso@acme.com"],                      # required if email
        "cc":           [...],                                  # optional
        "subject":      "..."                                   # optional
      }

  Response: ``{"job_id": "...", "status_url": "...", "eta_seconds": 30}``

* ``GET /api/v1/reports/{job_id}`` — poll status.
* ``GET /api/v1/reports/{job_id}/download`` — fetch the rendered file.

Job state is held in-memory (process-local) — fine for the
single-process Python app on the demo / droplet. Jobs older than 1 hour
are reaped on each request. After successful generation we fire a
``report.ready`` event via the existing webhooks module so Slack /
Teams / generic listeners can pick it up.
"""

from __future__ import annotations

import datetime as _dt
import threading
import time as _time
import uuid
from typing import Any

try:
    from fastapi import APIRouter, Body, HTTPException
    from fastapi.responses import JSONResponse, Response
    _FASTAPI_OK = True
except Exception:  # pragma: no cover
    _FASTAPI_OK = False
    APIRouter = None  # type: ignore


# --------------------------------------------------------------------------
# In-memory job table
# --------------------------------------------------------------------------


_JOB_TTL_SECONDS = 60 * 60  # 1 hour
_REPORT_JOBS: dict[str, dict[str, Any]] = {}
_JOB_LOCK = threading.Lock()


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reap_expired() -> None:
    cutoff = _time.time() - _JOB_TTL_SECONDS
    with _JOB_LOCK:
        for jid in list(_REPORT_JOBS.keys()):
            if _REPORT_JOBS[jid].get("created_ts", 0) < cutoff:
                _REPORT_JOBS.pop(jid, None)


def get_job(job_id: str) -> dict | None:
    """Helper for tests/UI to peek at a job. Mainly internal."""
    return _REPORT_JOBS.get(job_id)


def _mirror_status(job_id: str) -> None:
    """When ``SC_REDIS_URL`` is set, mirror status to the Redis-backed
    queue so other nodes (and ``safecadence.queue.get_status``) can see
    it. Always safe — silently no-ops if Redis is unconfigured or down.
    Demo behaviour is unchanged.
    """
    try:
        from safecadence import queue as _q
        if not _q.is_redis_configured():
            return
        job = _REPORT_JOBS.get(job_id)
        if not job:
            return
        # Don't ship raw bytes through Redis — strip large payloads.
        publishable = {k: v for k, v in job.items()
                       if k not in ("bytes",) and not isinstance(v, (bytes, bytearray))}
        _q.set_status(job_id, job.get("status", "unknown"), result=publishable)
    except Exception:  # pragma: no cover
        pass


def _format_to_mimetype(fmt: str) -> str:
    from safecadence.reports.email_delivery import mimetype_for_format
    return mimetype_for_format(fmt)


def _eta_for_format(fmt: str) -> int:
    """Best-guess wait time so the client knows how often to poll."""
    return {
        "json": 2, "html": 4, "pdf": 25, "docx": 18, "pptx": 30, "xlsx": 12,
    }.get((fmt or "").lower(), 15)


# --------------------------------------------------------------------------
# Background renderer
# --------------------------------------------------------------------------


def _run_job(job_id: str, body: dict) -> None:
    """The worker thread target: compose → render → email (if asked) → webhook."""
    try:
        from safecadence.reports.builder import compose_report
        from safecadence.reports.presets import apply_preset
        from safecadence.reports import renderers as _r
        from safecadence.reports import email_delivery as _email
        from safecadence.reports import webhooks as _wh

        preset_id = body.get("preset") or "exec_brief"
        fmt = (body.get("format") or "pdf").lower()
        deliver_via = (body.get("deliver_via") or "download").lower()
        recipients = list(body.get("to") or [])
        cc = list(body.get("cc") or [])
        prepared_for = (body.get("prepared_for") or "").strip()
        brand = body.get("brand") or {}
        sections_override = body.get("sections")

        with _JOB_LOCK:
            _REPORT_JOBS[job_id]["status"] = "running"
            _REPORT_JOBS[job_id]["started_at"] = _now_iso()
        _mirror_status(job_id)

        applied = apply_preset(preset_id, body.get("scope") or {})
        sections = list(sections_override) if sections_override else applied["sections"]
        report = compose_report(
            sections=sections,
            scope=applied["scope"],
            title=f"SafeCadence NetRisk — {applied['name']}",
        )
        if prepared_for:
            report.setdefault("brand", {})["prepared_for"] = prepared_for
        if brand:
            report.setdefault("brand", {}).update(brand)

        render_map = {
            "html":  ("render_html", "html",  True),
            "pdf":   ("render_pdf",  "pdf",   True),
            "json":  ("render_json", "json",  False),
            "docx":  ("render_docx", "docx",  True),
            "pptx":  ("render_pptx", "pptx",  True),
            "xlsx":  ("render_xlsx", "xlsx",  True),
        }
        if fmt not in render_map:
            raise ValueError(f"unsupported format: {fmt}")
        fn_name, ext, accepts_preset = render_map[fmt]
        fn = getattr(_r, fn_name)
        rendered = fn(report, preset=applied) if accepts_preset else fn(report)
        body_bytes = rendered.encode("utf-8") if isinstance(rendered, str) else rendered

        with _JOB_LOCK:
            _REPORT_JOBS[job_id]["bytes"] = body_bytes
            _REPORT_JOBS[job_id]["size_bytes"] = len(body_bytes)
            _REPORT_JOBS[job_id]["filename"] = f"safecadence-{preset_id}.{ext}"
            _REPORT_JOBS[job_id]["mimetype"] = _format_to_mimetype(fmt)

        # Email delivery (optional)
        delivery_status: dict | None = None
        if deliver_via == "email":
            err = _email.send_report(
                recipients=recipients,
                cc=cc,
                subject=body.get("subject") or f"SafeCadence {applied['name']}",
                body_text=(
                    f"Attached: SafeCadence NetRisk {applied['name']} "
                    f"({fmt.upper()})."
                ),
                attachment_bytes=body_bytes,
                attachment_filename=f"safecadence-{preset_id}.{ext}",
                attachment_mimetype=_format_to_mimetype(fmt),
            )
            delivery_status = {"ok": err is None, "error": err,
                               "recipients": recipients}

        # Fire completion webhook (best-effort, never raises into the job)
        try:
            _wh.notify_completion({
                "kind": "report.ready",
                "job_id": job_id,
                "preset": preset_id,
                "format": fmt,
                "size_bytes": len(body_bytes),
            })
        except Exception:
            pass

        with _JOB_LOCK:
            _REPORT_JOBS[job_id]["status"] = "complete"
            _REPORT_JOBS[job_id]["completed_at"] = _now_iso()
            if delivery_status is not None:
                _REPORT_JOBS[job_id]["delivery"] = delivery_status
        _mirror_status(job_id)
    except Exception as exc:
        with _JOB_LOCK:
            if job_id in _REPORT_JOBS:
                _REPORT_JOBS[job_id]["status"] = "failed"
                _REPORT_JOBS[job_id]["error"] = str(exc)
                _REPORT_JOBS[job_id]["completed_at"] = _now_iso()
        _mirror_status(job_id)


def submit_job(body: dict, *, background: bool = True) -> dict:
    """Create a job entry and (optionally) start the worker thread.

    Returns ``{job_id, status, status_url, eta_seconds}``.

    ``background=False`` runs the job inline — useful for tests that need
    deterministic completion without polling.
    """
    _reap_expired()
    job_id = "rpt_" + uuid.uuid4().hex[:16]
    fmt = (body.get("format") or "pdf").lower()
    with _JOB_LOCK:
        _REPORT_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "created_at": _now_iso(),
            "created_ts": _time.time(),
            "format": fmt,
            "preset": body.get("preset") or "exec_brief",
        }
    _mirror_status(job_id)
    if background:
        t = threading.Thread(target=_run_job, args=(job_id, body), daemon=True)
        t.start()
    else:
        _run_job(job_id, body)
    return {
        "job_id": job_id,
        "status": _REPORT_JOBS[job_id]["status"],
        "status_url": f"/api/v1/reports/{job_id}",
        "eta_seconds": _eta_for_format(fmt),
    }


# --------------------------------------------------------------------------
# FastAPI router
# --------------------------------------------------------------------------


def build_router() -> Any:
    """Return a FastAPI ``APIRouter`` for /api/v1/reports.

    Raises ``RuntimeError`` if FastAPI is not installed (the CLI / tests
    that don't need the router can still import the module).
    """
    if not _FASTAPI_OK:
        raise RuntimeError("FastAPI is required for the v1 reports router")

    router = APIRouter(prefix="/api/v1/reports", tags=["reports-v1"])

    @router.post("/generate")
    def _generate(body: dict = Body(...)) -> JSONResponse:
        if not body.get("preset"):
            raise HTTPException(status_code=400, detail="preset is required")
        if not body.get("format"):
            raise HTTPException(status_code=400, detail="format is required")
        deliver_via = (body.get("deliver_via") or "download").lower()
        if deliver_via == "email" and not body.get("to"):
            raise HTTPException(
                status_code=400,
                detail="'to' is required when deliver_via='email'",
            )
        result = submit_job(body, background=True)
        return JSONResponse(result, status_code=202)

    @router.get("/{job_id}")
    def _status(job_id: str) -> JSONResponse:
        _reap_expired()
        job = _REPORT_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown job_id")
        out = {
            "job_id": job_id,
            "status": job.get("status"),
            "format": job.get("format"),
            "preset": job.get("preset"),
            "created_at": job.get("created_at"),
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
            "size_bytes": job.get("size_bytes"),
            "error": job.get("error"),
            "delivery": job.get("delivery"),
        }
        return JSONResponse({k: v for k, v in out.items() if v is not None})

    @router.get("/{job_id}/download")
    def _download(job_id: str) -> Response:
        _reap_expired()
        job = _REPORT_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown job_id")
        if job.get("status") != "complete":
            raise HTTPException(
                status_code=409,
                detail=f"job not complete (status={job.get('status')})",
            )
        data = job.get("bytes") or b""
        return Response(
            content=data,
            media_type=job.get("mimetype") or "application/octet-stream",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{job.get("filename") or "report.bin"}"',
            },
        )

    return router


__all__ = ["build_router", "submit_job", "get_job"]
