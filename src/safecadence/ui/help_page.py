"""
v9.1 — /help page.

Single index of every help topic in SafeCadence. Categorized + searchable.
Linked from the sidebar Settings group and from the keyboard help overlay.
"""

from __future__ import annotations

from safecadence.ui._chrome import wrap
from safecadence.ui.help_registry import HELP


# Group help topics by domain — keeps the page scannable
_GROUPS = [
    ("🔐 Identity translator + simulator", [
        "translator-intent", "translator-effect", "translator-targets",
        "translator-conditions", "translator-severity",
        "simulator-input", "simulator-risk-delta",
    ]),
    ("🔎 Effective permissions + JIT", [
        "who-can-principal", "who-can-action", "who-can-resource",
        "jit-duration", "jit-target", "jit-reason",
    ]),
    ("🚩 Findings + automation", [
        "finding-severity", "finding-kind",
        "automation-when-kind", "automation-when-severity",
        "automation-action", "automation-rate-limit",
    ]),
    ("📌 Watchlists + sharing", [
        "watchlist-entity-kind", "share-scope", "share-ttl",
    ]),
    ("🎯 Identity attack paths", [
        "path-risk", "path-chain",
    ]),
    ("📊 Dashboard + observability", [
        "compliance-score", "next-3-actions", "live-activity",
    ]),
    ("⚙️ Operational", [
        "demo-data", "tier-3-totp", "byo-ai",
    ]),
]


def _build_body() -> str:
    rows: list[str] = []
    rows.append("""
<h1>📖 Help</h1>
<p class="muted">Every contextual help topic in SafeCadence, in one place.
Hover the <span class="sc-help" data-help="compliance-score"
   style="display:inline-flex;vertical-align:baseline"></span>
icons anywhere in the product for the same content inline.
Press <kbd>?</kbd> on any page for keyboard shortcuts.</p>

<input id="help-search" placeholder="Filter topics…"
       style="margin:12px 0; max-width:480px" />
""")

    for label, ids in _GROUPS:
        rows.append(f'<h2>{label}</h2>')
        rows.append('<div class="card" style="padding:0">')
        rows.append('<table style="width:100%"><tbody>')
        for hid in ids:
            entry = HELP.get(hid)
            if not entry:
                continue
            title = entry.get("title", hid)
            body = entry.get("body", "")
            values = entry.get("values") or []
            example = entry.get("example") or ""
            values_html = ""
            if values:
                items = "".join(f"<li>{v}</li>" for v in values)
                values_html = (f'<div style="margin-top:6px;font-size:12px">'
                                f'<strong style="color:var(--muted);'
                                f'text-transform:uppercase;letter-spacing:0.5px;'
                                f'font-size:10px">Accepted values</strong>'
                                f'<ul style="margin:2px 0 0 18px">{items}</ul>'
                                f'</div>')
            example_html = ""
            if example:
                example_html = (f'<div style="margin-top:6px;font-size:12px">'
                                 f'<strong style="color:var(--muted);'
                                 f'text-transform:uppercase;letter-spacing:0.5px;'
                                 f'font-size:10px">Example</strong>'
                                 f'<code style="background:var(--bg);'
                                 f'padding:2px 6px;border-radius:4px;'
                                 f'font-family:ui-monospace,Menlo,monospace">'
                                 f'{example}</code></div>')
            rows.append(f"""
                <tr class="help-row" data-search="{title.lower()} {body.lower()}">
                  <td style="vertical-align:top;padding:14px 18px;
                              border-bottom:1px solid var(--border);
                              width:200px;font-weight:600">
                    {title}
                    <div class="muted" style="font-size:10px;margin-top:2px;
                         font-family:ui-monospace,Menlo,monospace">{hid}</div>
                  </td>
                  <td style="vertical-align:top;padding:14px 18px;
                              border-bottom:1px solid var(--border)">
                    <div>{body}</div>
                    {values_html}
                    {example_html}
                  </td>
                </tr>
            """)
        rows.append('</tbody></table></div>')

    rows.append("""
<div class="card" style="text-align:center;padding:24px;background:var(--panel-2);margin-top:16px">
  <h3 style="margin:0 0 8px">Missing a topic?</h3>
  <p class="muted" style="margin:0">Help text lives in
    <code>src/safecadence/ui/help_registry.py</code>. Add an entry,
    drop a <code>&lt;span class="sc-help" data-help="..."&gt;&lt;/span&gt;</code>
    next to the field, and it shows up automatically.</p>
</div>
""")

    return "\n".join(rows)


_SCRIPT = r"""
const search = document.getElementById("help-search");
if (search) {
  search.addEventListener("input", e => {
    const q = e.target.value.trim().toLowerCase();
    document.querySelectorAll(".help-row").forEach(row => {
      const data = row.dataset.search || "";
      row.style.display = (!q || data.includes(q)) ? "" : "none";
    });
  });
}
"""


def register(app):
    from fastapi.responses import HTMLResponse

    @app.get("/help", response_class=HTMLResponse)
    def help_page():
        return HTMLResponse(wrap("Help", _build_body(), _SCRIPT))
