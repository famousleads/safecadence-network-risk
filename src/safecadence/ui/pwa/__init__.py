"""SafeCadence PWA assets — manifest + service worker + FastAPI routes.

v11.1 ships a Progressive Web App layer on top of the existing UI:

* ``GET /manifest.webmanifest`` — app manifest (icons inline as data URLs)
* ``GET /sw.js`` — service worker (cache-first static, network-first API)
* ``GET /static/responsive.css`` — the mobile/tablet responsive sheet

These three are mounted by :func:`register` (called from ``ui.app.create_app``).
"""

from __future__ import annotations

import pathlib
from typing import Any


_PWA_DIR = pathlib.Path(__file__).resolve().parent
_UI_DIR = _PWA_DIR.parent


def _read(rel: pathlib.Path) -> str:
    return rel.read_text(encoding="utf-8")


def manifest_text() -> str:
    """Return the raw manifest.json text."""
    return _read(_PWA_DIR / "manifest.json")


def service_worker_text() -> str:
    """Return the raw service worker JS text."""
    return _read(_PWA_DIR / "service_worker.js")


def responsive_css_text() -> str:
    """Return the raw responsive.css text."""
    return _read(_UI_DIR / "responsive.css")


def register(app: Any) -> None:
    """Mount the PWA + static routes on a FastAPI app."""
    try:
        from fastapi.responses import Response
    except Exception:                                # pragma: no cover
        return

    @app.get("/manifest.webmanifest")
    def _manifest():                                # pragma: no cover - thin wrapper
        return Response(
            content=manifest_text(),
            media_type="application/manifest+json",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.get("/sw.js")
    def _service_worker():                          # pragma: no cover
        return Response(
            content=service_worker_text(),
            media_type="text/javascript",
            headers={
                "Cache-Control": "no-cache",
                "Service-Worker-Allowed": "/",
            },
        )

    @app.get("/static/responsive.css")
    def _responsive_css():                          # pragma: no cover
        return Response(
            content=responsive_css_text(),
            media_type="text/css",
            headers={"Cache-Control": "public, max-age=3600"},
        )
