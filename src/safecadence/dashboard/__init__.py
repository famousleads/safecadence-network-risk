"""
Fleet dashboard — single-file HTML SPA.

Reads a directory of scan-result JSON files and produces a self-contained
HTML page with KPI cards, fleet overview, per-device drill-downs, CVE +
EOL summaries, and (optional) topology embed. Works offline.
"""

from safecadence.dashboard.builder import (
    DashboardData, build_dashboard_data, load_scan_dir,
)
from safecadence.dashboard.renderer import render_dashboard

__all__ = [
    "DashboardData",
    "build_dashboard_data",
    "load_scan_dir",
    "render_dashboard",
]
