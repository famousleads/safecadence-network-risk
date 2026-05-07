"""
SafeCadence FastAPI server.

Wraps the existing engine in a REST API with JWT auth, RBAC (admin /
analyst / viewer), and multi-tenant scoping. Default deployment mode is
private/local — bind to 127.0.0.1 only.

Run:
    pip install 'safecadence-network-risk[server]'
    safecadence api --bind 127.0.0.1 --port 8765 --db-url sqlite:///sc.db
"""

from safecadence.server.app import create_app

__all__ = ["create_app"]
