"""Public Safety stub pages — core fallback when the add-on is absent.

The shared navigation chrome links to /map, /evidence-infrastructure,
/incidents, and /events. Those pages ship in the separate
``safecadence-publicsafety`` distribution; when it isn't installed this
tiny module registers friendly placeholder pages instead, so a
core-only install never shows dead sidebar links (the exact bug class
the link-audit test exists to prevent).

Registered by ui/app.py and server/app.py ONLY when importing
``safecadence.ui.desat_pages`` fails.
"""
from __future__ import annotations

try:
    from fastapi.responses import HTMLResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False

try:
    from safecadence.ui._chrome import wrap
except Exception:                                       # pragma: no cover
    def wrap(title: str, body: str, script: str = "") -> str:
        return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


_STUB_BODY = """
<div class="card" style="max-width:640px;margin:40px auto;text-align:center;padding:34px">
  <div style="font-size:38px">🛡️</div>
  <h1 style="margin:8px 0 4px">SafeCadence Public Safety</h1>
  <p class="muted" style="font-size:13px;margin:0 0 14px">
    This page is part of the Public Safety add-on: asset map,
    evidence-infrastructure health, incidents, events, and CJIS Security
    Policy mapping for law-enforcement agencies.
  </p>
  <p style="font-size:13px;margin:0 0 6px">
    Install it in one line — the <b>free 90-day trial</b> starts on
    first use, on your own data, with no signup and no call home:
  </p>
  <p style="margin:10px 0 18px">
    <code style="font-size:13px;background:rgba(14,124,134,.10);
                  border:1px solid var(--accent);border-radius:8px;
                  padding:8px 14px;display:inline-block">
      pip install safecadence-publicsafety</code>
  </p>
  <a href="https://safecadence.com/public-safety-command"
     style="display:inline-block;background:var(--accent);color:#fff;border-radius:8px;
            padding:10px 18px;font-weight:700;text-decoration:none">
    Learn more &amp; see the live demo</a>
  <p class="muted" style="font-size:11px;margin-top:14px">
    The open-source core you're running stays free forever.
  </p>
</div>
"""

_PS_PAGES = {
    "/map": "Asset map",
    "/evidence-infrastructure": "Evidence infrastructure",
    "/incidents": "Incidents",
    "/events": "Events",
    "/evidencewatch": "EvidenceWatch weekly report",
    "/campuswatch": "CampusWatch weekly report",
    "/facilitywatch": "FacilityWatch weekly report",
    "/community": "Community programs",
}


def register(app) -> None:                              # pragma: no cover
    if not _FASTAPI_OK:
        return
    for path, title in _PS_PAGES.items():
        def _page(_title=title):
            return HTMLResponse(wrap(_title, _STUB_BODY, ""))
        app.get(path, response_class=HTMLResponse)(_page)
