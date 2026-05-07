"""
Local web UI for SafeCadence Network Risk.

Run with `safecadence ui` to launch a localhost FastAPI server + SPA dashboard
that exposes every CLI capability through a browser. Single-user, no auth,
100% local — designed for a network engineer running on their own laptop.

The UI does not replace the CLI; it sits alongside it. Both share the same
parsers, rule engine, scoring, and storage so a scan run from the UI shows
up in `safecadence history` and vice-versa.
"""

from __future__ import annotations

__all__ = ["run_ui"]


def run_ui(*, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
           password: str | None = None) -> None:
    """Start the local UI server. Imported lazily so `[server]` extras can be optional."""
    from safecadence.ui.app import run as _run
    _run(host=host, port=port, open_browser=open_browser, password=password)
