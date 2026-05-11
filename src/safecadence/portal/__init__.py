"""
SafeCadence customer-facing portal (v10.9).

Server-rendered HTML — no React build step, consistent with the rest of
the codebase. Mounts under ``/portal/*``. Every route requires an
authenticated session + org membership (or ``SC_AUTH_DISABLED=1`` for
the demo).
"""
