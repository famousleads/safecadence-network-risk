"""
FastAPI router for the report wizard.

Mounts at:
  GET  /reports                              -> wizard page (chrome-wrapped HTML)
  GET  /api/reports/sections                 -> section metadata list
  GET  /api/reports/scopes                   -> scope filter metadata + valid values
  POST /api/reports/compose                  -> render the report dict for live preview
  GET  /api/reports/templates                -> list saved templates
  POST /api/reports/templates                -> save a template (403 in read-only)
  GET  /api/reports/templates/{id}           -> load one template
  DELETE /api/reports/templates/{id}         -> delete one template (403 in read-only)
  GET  /api/reports/templates/{id}/preview   -> rendered HTML fragment
  GET  /api/reports/templates/{id}/download  -> ?format=pdf|html|json
  POST /api/reports/templates/{id}/share     -> issue / return existing share token
  GET  /r/{token}                            -> public read-only report

Designed to be ``app.include_router()``-ed into the main UI FastAPI app.
"""

from __future__ import annotations

import os
from typing import Any

try:
    from fastapi import APIRouter, Body, HTTPException, Path as PathParam, Query
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    _FASTAPI_OK = True
except Exception:  # pragma: no cover
    _FASTAPI_OK = False

from safecadence.reports.builder import (
    compose_report,
    list_scope_keys,
    list_section_keys,
)
from safecadence.reports import templates as _tpl
from safecadence.reports.renderers import render_html, render_json, render_pdf


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _readonly_response() -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": "read_only",
            "message": "Demo is read-only. Install the platform to save reports.",
        },
    )


def _open_store() -> Any | None:
    try:
        from pathlib import Path
        from safecadence.storage import open_store
        db_path = Path.home() / ".safecadence" / "ui.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return open_store(sqlite_path=str(db_path))
    except Exception:
        return None


def _wizard_html() -> str:
    """Return the wizard HTML (full page, chrome-wrapped if possible)."""
    body, page_script = _wizard_body()
    try:
        from safecadence.ui._chrome import wrap
        return wrap("Reports", body, page_script)
    except Exception:
        # Standalone fallback (e.g. tests, older versions): minimal wrapper.
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>SafeCadence Reports</title>"
            f"<style>{_FALLBACK_CSS}</style></head><body>{body}"
            f"<script>{page_script}</script></body></html>"
        )


_FALLBACK_CSS = (
    "body{font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif;"
    "background:#f6f7fb;color:#0b1020;margin:0;padding:24px}"
)


# --------------------------------------------------------------------------
# Wizard HTML body + JS — single page, vanilla JS
# --------------------------------------------------------------------------


_WIZARD_BODY = """
<style>
.rep-wrap{max-width:1100px;margin:0 auto;padding:18px}
.rep-steps{display:flex;gap:8px;margin-bottom:18px}
.rep-step{flex:1;padding:10px 14px;border-radius:8px;background:#1a2240;color:#cbd2e6;
  cursor:pointer;font-weight:600;font-size:13px;text-align:center;border:1px solid #26315b}
.rep-step.active{background:#7c5cff;color:#fff;border-color:#7c5cff}
.rep-card{background:#121a33;border:1px solid #26315b;border-radius:12px;padding:18px;margin-bottom:14px}
.rep-card h3{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#8b95b1}
.rep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px}
.rep-section{display:flex;align-items:flex-start;gap:8px;padding:10px;border-radius:8px;
  background:#0b1020;border:1px solid #26315b;cursor:pointer}
.rep-section:hover{border-color:#7c5cff}
.rep-section input{margin-top:3px}
.rep-section .name{font-weight:600;color:#e7ecf5;font-size:13px}
.rep-section .desc{color:#8b95b1;font-size:12px;margin-top:2px}
.rep-section .cat{font-size:10px;color:#7c5cff;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
.rep-chips{display:flex;gap:6px;flex-wrap:wrap}
.rep-chip{padding:6px 10px;border-radius:999px;background:#0b1020;border:1px solid #26315b;
  color:#cbd2e6;cursor:pointer;font-size:12px;user-select:none}
.rep-chip.on{background:#7c5cff;border-color:#7c5cff;color:#fff}
.rep-row{display:flex;gap:18px;flex-wrap:wrap}
.rep-row > div{flex:1;min-width:240px}
.rep-row label{display:block;color:#8b95b1;font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.rep-row select,.rep-row input{width:100%;padding:8px 10px;background:#0b1020;color:#e7ecf5;
  border:1px solid #26315b;border-radius:8px;font:inherit}
.rep-actions{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.rep-btn{padding:8px 14px;border-radius:8px;border:1px solid #26315b;background:#1a2240;color:#e7ecf5;
  cursor:pointer;font-weight:600;font-size:13px}
.rep-btn.primary{background:#7c5cff;border-color:#7c5cff;color:#fff}
.rep-btn:disabled{opacity:.5;cursor:not-allowed}
.rep-preview{background:#fff;border-radius:10px;min-height:520px;border:1px solid #26315b;overflow:auto}
.rep-toolbar{display:flex;align-items:center;gap:10px;padding:10px;background:#0b1020;border-bottom:1px solid #26315b;
  border-radius:10px 10px 0 0;color:#cbd2e6;font-size:12px;position:sticky;top:0;z-index:2}
.rep-stamp{margin-left:auto;color:#8b95b1}
.rep-tpls{display:grid;gap:6px;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.rep-tpl{padding:10px;background:#0b1020;border:1px solid #26315b;border-radius:8px;cursor:pointer}
.rep-tpl:hover{border-color:#7c5cff}
.rep-msg{padding:10px;border-radius:8px;background:#1a2240;color:#cbd2e6;font-size:13px}
.rep-readonly{background:#3a1f1f;color:#fda4af;border:1px solid #7f1d1d;border-radius:8px;padding:8px 12px;
  font-size:12px;margin-bottom:14px}
</style>

<div class="rep-wrap">
  <div id="rep-readonly-banner" class="rep-readonly" style="display:none">
    Read-only demo &mdash; saves and share-links are disabled. Install NetRisk locally to use the full builder.
  </div>

  <div class="rep-steps">
    <div class="rep-step active" data-step="1" onclick="repGo(1)">1. Sections</div>
    <div class="rep-step" data-step="2" onclick="repGo(2)">2. Scope</div>
    <div class="rep-step" data-step="3" onclick="repGo(3)">3. Preview</div>
    <div class="rep-step" data-step="4" onclick="repGo(4)">4. Export</div>
  </div>

  <div id="rep-step1" class="rep-card">
    <h3>Pick the sections to include</h3>
    <div id="rep-section-grid" class="rep-grid"></div>
    <div class="rep-actions">
      <button class="rep-btn primary" onclick="repGo(2)">Next &rarr; Scope</button>
    </div>
  </div>

  <div id="rep-step2" class="rep-card" style="display:none">
    <h3>Filter the data</h3>
    <div class="rep-row">
      <div>
        <label>Site</label>
        <select id="rep-site"><option value="">(all)</option></select>
      </div>
      <div>
        <label>Date range</label>
        <select id="rep-daterange" onchange="repDateRange()">
          <option value="">All time</option>
          <option value="1">Last 24h</option>
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
        </select>
      </div>
    </div>
    <div style="margin-top:12px">
      <label style="color:#8b95b1;font-size:12px;text-transform:uppercase;letter-spacing:.05em">Criticality</label>
      <div id="rep-crit" class="rep-chips" style="margin-top:6px"></div>
    </div>
    <div style="margin-top:12px">
      <label style="color:#8b95b1;font-size:12px;text-transform:uppercase;letter-spacing:.05em">Asset types</label>
      <div id="rep-atype" class="rep-chips" style="margin-top:6px"></div>
    </div>
    <div style="margin-top:12px">
      <label style="color:#8b95b1;font-size:12px;text-transform:uppercase;letter-spacing:.05em">Vendors</label>
      <div id="rep-vendor" class="rep-chips" style="margin-top:6px"></div>
    </div>
    <div class="rep-actions">
      <button class="rep-btn" onclick="repGo(1)">&larr; Back</button>
      <button class="rep-btn primary" onclick="repGo(3)">Preview &rarr;</button>
    </div>
  </div>

  <div id="rep-step3" class="rep-card" style="display:none">
    <div class="rep-toolbar">
      <button class="rep-btn" onclick="repGo(2)">&larr; Back to edit</button>
      <button class="rep-btn" onclick="repSaveAsTemplate()">Save as template</button>
      <button class="rep-btn primary" onclick="repGo(4)">Export &rarr;</button>
      <span id="rep-stamp" class="rep-stamp"></span>
    </div>
    <div id="rep-preview" class="rep-preview">
      <div style="padding:24px;color:#5b6685">Building preview...</div>
    </div>
  </div>

  <div id="rep-step4" class="rep-card" style="display:none">
    <h3>Export this report</h3>
    <div class="rep-actions">
      <button class="rep-btn primary" onclick="repDownload('html')">Download HTML</button>
      <button class="rep-btn primary" onclick="repDownload('pdf')">Download PDF</button>
      <button class="rep-btn primary" onclick="repDownload('json')">Download JSON</button>
      <button class="rep-btn" onclick="repSaveAsTemplate()">Save as template</button>
      <button class="rep-btn" onclick="repShareLink()">Get share link</button>
    </div>
    <div id="rep-export-msg" class="rep-msg" style="margin-top:12px;display:none"></div>
    <h3 style="margin-top:18px">Saved templates</h3>
    <div id="rep-tpl-list" class="rep-tpls"></div>
  </div>
</div>
"""


_WIZARD_JS = """
const repState = {
  step: 1,
  sections: [],
  scope: { site:'', criticality:[], asset_type:[], vendor:[], date_range:{} },
  meta: { sections: [], scopes: [] },
  scopeValues: { sites: [], vendors: [] },
  templateId: null,
  readonly: false,
};
let repTimer = null;

function repGo(n) {
  repState.step = n;
  for (let i=1;i<=4;i++) {
    document.getElementById('rep-step'+i).style.display = (i===n) ? '' : 'none';
    document.querySelectorAll('.rep-step').forEach(el=>{
      el.classList.toggle('active', String(el.dataset.step)===String(n));
    });
  }
  if (n===3) repPreview();
  if (n===4) repLoadTemplates();
}

async function repLoadMeta() {
  try {
    const sec = await fetch('/api/reports/sections').then(r=>r.json());
    const sco = await fetch('/api/reports/scopes').then(r=>r.json());
    repState.meta.sections = sec.sections || [];
    repState.meta.scopes = sco.scopes || [];
    repState.scopeValues.sites = sco.values?.sites || [];
    repState.scopeValues.vendors = sco.values?.vendors || [];
    repState.readonly = !!sco.readonly;
    if (repState.readonly) document.getElementById('rep-readonly-banner').style.display='block';
    repState.sections = repState.meta.sections.filter(s=>s.default_enabled).map(s=>s.key);
    repRenderSections();
    repRenderScope();
  } catch(e) {
    console.error(e);
  }
}

function repRenderSections() {
  const grid = document.getElementById('rep-section-grid');
  const groups = {};
  repState.meta.sections.forEach(s => {
    (groups[s.category] = groups[s.category] || []).push(s);
  });
  const order = ['Overview','Inventory','Risk','Compliance','Operations'];
  let html = '';
  order.forEach(cat => {
    if (!groups[cat]) return;
    groups[cat].forEach(s => {
      const checked = repState.sections.includes(s.key) ? 'checked' : '';
      html += `<label class="rep-section">
        <input type="checkbox" ${checked} value="${repEsc(s.key)}" onchange="repToggleSection(this)">
        <div>
          <div class="name">${repEsc(s.name)}</div>
          <div class="desc">${repEsc(s.description)}</div>
          <div class="cat">${repEsc(s.category)}</div>
        </div>
      </label>`;
    });
  });
  grid.innerHTML = html;
}

function repToggleSection(input) {
  const k = input.value;
  if (input.checked) {
    if (!repState.sections.includes(k)) repState.sections.push(k);
  } else {
    repState.sections = repState.sections.filter(x => x !== k);
  }
  repSchedulePreview();
}

function repRenderScope() {
  const siteSel = document.getElementById('rep-site');
  siteSel.innerHTML = '<option value="">(all)</option>' +
    repState.scopeValues.sites.map(s=>`<option value="${repEsc(s)}">${repEsc(s)}</option>`).join('');
  siteSel.onchange = () => { repState.scope.site = siteSel.value; repSchedulePreview(); };

  repRenderChips('rep-crit',['low','medium','high','critical'], 'criticality');
  repRenderChips('rep-atype',['network','server','identity','cloud','backup'], 'asset_type');
  repRenderChips('rep-vendor', repState.scopeValues.vendors, 'vendor');
}

function repRenderChips(elId, values, scopeKey) {
  const el = document.getElementById(elId);
  if (!values.length) { el.innerHTML = '<span style="color:#8b95b1;font-size:12px">No values in this dataset</span>'; return; }
  el.innerHTML = values.map(v => {
    const on = repState.scope[scopeKey].includes(v) ? 'on' : '';
    return `<span class="rep-chip ${on}" data-key="${repEsc(scopeKey)}" data-v="${repEsc(v)}" onclick="repToggleChip(this)">${repEsc(v)}</span>`;
  }).join('');
}

function repToggleChip(el) {
  const k = el.dataset.key;
  const v = el.dataset.v;
  const arr = repState.scope[k];
  const i = arr.indexOf(v);
  if (i>=0) arr.splice(i,1); else arr.push(v);
  el.classList.toggle('on');
  repSchedulePreview();
}

function repDateRange() {
  const d = parseInt(document.getElementById('rep-daterange').value, 10);
  if (!d) { repState.scope.date_range = {}; }
  else {
    const now = new Date();
    const from = new Date(now.getTime() - d*86400*1000);
    repState.scope.date_range = {
      from: from.toISOString().slice(0,19) + 'Z',
      to:   now.toISOString().slice(0,19) + 'Z',
    };
  }
  repSchedulePreview();
}

function repSchedulePreview() {
  if (repState.step === 3) {
    if (repTimer) clearTimeout(repTimer);
    repTimer = setTimeout(repPreview, 350);
  }
}

async function repPreview() {
  const pv = document.getElementById('rep-preview');
  pv.innerHTML = '<div style="padding:24px;color:#5b6685">Building preview...</div>';
  try {
    const r = await fetch('/api/reports/compose', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({sections: repState.sections, scope: repState.scope})
    });
    const j = await r.json();
    const stamp = document.getElementById('rep-stamp');
    if (stamp) stamp.textContent = 'Generated ' + new Date(j.generated_at || Date.now()).toLocaleTimeString();
    pv.innerHTML = '<iframe srcdoc="" id="rep-iframe" style="width:100%;height:640px;border:0;border-radius:0 0 10px 10px"></iframe>';
    const iframe = document.getElementById('rep-iframe');
    const html = await fetch('/api/reports/render-html', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({sections: repState.sections, scope: repState.scope})
    }).then(r=>r.text());
    iframe.srcdoc = html;
  } catch(e) {
    pv.innerHTML = '<div style="padding:24px;color:#b91c1c">Preview failed: ' + repEsc(String(e)) + '</div>';
  }
}

async function repSaveAsTemplate() {
  if (repState.readonly) {
    alert('This demo is read-only. Install NetRisk locally to save templates.');
    return;
  }
  const name = prompt('Template name?', 'My report');
  if (!name) return;
  const r = await fetch('/api/reports/templates', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, sections: repState.sections, scope: repState.scope})
  });
  if (r.status === 403) {
    alert('Read-only demo: cannot save templates.');
    return;
  }
  const j = await r.json();
  repState.templateId = j.id;
  alert('Saved as: ' + j.id);
  if (repState.step === 4) repLoadTemplates();
}

async function repShareLink() {
  if (!repState.templateId) {
    await repSaveAsTemplate();
    if (!repState.templateId) return;
  }
  const r = await fetch('/api/reports/templates/' + repState.templateId + '/share', {method:'POST'});
  if (r.status === 403) { alert('Read-only demo: cannot create share links.'); return; }
  const j = await r.json();
  const url = location.origin + '/r/' + j.share_token;
  const msg = document.getElementById('rep-export-msg');
  msg.style.display = '';
  msg.innerHTML = 'Share link: <a href="' + repEsc(url) + '" target="_blank">' + repEsc(url) + '</a>';
}

async function repDownload(fmt) {
  if (!repState.templateId) {
    if (!repState.readonly) {
      await repSaveAsTemplate();
      if (!repState.templateId) return;
    } else {
      // In read-only mode, fetch a one-shot composed download
      const r = await fetch('/api/reports/render-' + fmt, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({sections: repState.sections, scope: repState.scope})
      });
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'safecadence-report.' + fmt;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }
  }
  location.href = '/api/reports/templates/' + repState.templateId + '/download?format=' + fmt;
}

async function repLoadTemplates() {
  const list = await fetch('/api/reports/templates').then(r=>r.json());
  const el = document.getElementById('rep-tpl-list');
  if (!list.templates || !list.templates.length) {
    el.innerHTML = '<div class="rep-msg">No saved templates yet.</div>';
    return;
  }
  el.innerHTML = list.templates.map(t =>
    `<div class="rep-tpl" onclick="repLoadTemplate('${repEsc(t.id)}')">
       <strong>${repEsc(t.name)}</strong><br>
       <small style="color:#8b95b1">${(t.sections||[]).length} sections &middot; ${repEsc(t.updated_at||'')}</small>
     </div>`
  ).join('');
}

async function repLoadTemplate(id) {
  const j = await fetch('/api/reports/templates/'+id).then(r=>r.json());
  if (!j || !j.id) return;
  repState.templateId = j.id;
  repState.sections = j.sections || [];
  repState.scope = Object.assign({site:'',criticality:[],asset_type:[],vendor:[],date_range:{}}, j.scope || {});
  repRenderSections();
  repRenderScope();
  repGo(3);
}

function repEsc(s) {
  return String(s==null?'':s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

repLoadMeta();
"""


def _wizard_body() -> tuple[str, str]:
    return _WIZARD_BODY, _WIZARD_JS


# --------------------------------------------------------------------------
# router
# --------------------------------------------------------------------------


def _make_router():
    if not _FASTAPI_OK:  # pragma: no cover
        return None
    router = APIRouter()

    @router.get("/reports", response_class=HTMLResponse)
    def reports_page() -> str:
        return _wizard_html()

    @router.get("/api/reports/sections")
    def api_sections() -> dict:
        return {"sections": list_section_keys()}

    @router.get("/api/reports/scopes")
    def api_scopes() -> dict:
        scopes = list_scope_keys()
        sites: list[str] = []
        vendors: list[str] = []
        store = _open_store()
        try:
            if store:
                rows = []
                try:
                    rows = store.latest_per_host()
                except Exception:
                    rows = []
                for r in rows or []:
                    asset = r.get("asset") or {}
                    site = (asset.get("location") or {}).get("site") or r.get("site") or ""
                    vendor = (r.get("vendor") or asset.get("vendor") or "")
                    if site and site not in sites:
                        sites.append(site)
                    if vendor and vendor not in vendors:
                        vendors.append(vendor)
        finally:
            try:
                if store:
                    store.close()
            except Exception:
                pass
        # Augment with values pulled from the platform_assets store, so the
        # demo wizard (and any deployment without scan history) still has
        # site / vendor chips populated.
        try:
            from safecadence.reports.sections import _scope_values_from_assets
            extra = _scope_values_from_assets()
            for s in extra.get("sites") or []:
                if s and s not in sites:
                    sites.append(s)
            for v in extra.get("vendors") or []:
                if v and v not in vendors:
                    vendors.append(v)
        except Exception:
            pass
        return {
            "scopes": scopes,
            "values": {"sites": sorted(sites), "vendors": sorted(vendors)},
            "readonly": _is_readonly(),
        }

    @router.post("/api/reports/compose")
    def api_compose(payload: dict = Body(default={})) -> dict:
        sections = payload.get("sections") or None
        scope = payload.get("scope") or {}
        return compose_report(sections=sections, scope=scope)

    @router.post("/api/reports/render-html", response_class=HTMLResponse)
    def api_render_html(payload: dict = Body(default={})) -> str:
        report = compose_report(
            sections=payload.get("sections") or None,
            scope=payload.get("scope") or {},
        )
        return render_html(report, standalone=True)

    @router.post("/api/reports/render-json")
    def api_render_json(payload: dict = Body(default={})) -> Response:
        report = compose_report(
            sections=payload.get("sections") or None,
            scope=payload.get("scope") or {},
        )
        return Response(content=render_json(report), media_type="application/json")

    @router.post("/api/reports/render-pdf")
    def api_render_pdf(payload: dict = Body(default={})) -> Response:
        report = compose_report(
            sections=payload.get("sections") or None,
            scope=payload.get("scope") or {},
        )
        return Response(content=render_pdf(report), media_type="application/pdf")

    @router.get("/api/reports/templates")
    def api_list_templates() -> dict:
        return {"templates": _tpl.list_templates()}

    @router.post("/api/reports/templates")
    def api_save_template(body: dict = Body(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            saved = _tpl.save_template(body)
        except PermissionError:
            return _readonly_response()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return saved

    @router.get("/api/reports/templates/{tpl_id}")
    def api_load_template(tpl_id: str = PathParam(...)) -> Any:
        tpl = _tpl.load_template(tpl_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="not_found")
        return tpl

    @router.delete("/api/reports/templates/{tpl_id}")
    def api_delete_template(tpl_id: str = PathParam(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            ok = _tpl.delete_template(tpl_id)
        except PermissionError:
            return _readonly_response()
        if not ok:
            raise HTTPException(status_code=404, detail="not_found")
        return {"ok": True}

    @router.get("/api/reports/templates/{tpl_id}/preview", response_class=HTMLResponse)
    def api_preview_template(tpl_id: str = PathParam(...)) -> str:
        tpl = _tpl.load_template(tpl_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="not_found")
        report = compose_report(sections=tpl.get("sections"), scope=tpl.get("scope") or {},
                                title=tpl.get("name") or "Report")
        return render_html(report, standalone=False)

    @router.get("/api/reports/templates/{tpl_id}/download")
    def api_download_template(
        tpl_id: str = PathParam(...),
        format: str = Query("html", pattern="^(html|json|pdf)$"),
    ) -> Response:
        tpl = _tpl.load_template(tpl_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="not_found")
        report = compose_report(sections=tpl.get("sections"), scope=tpl.get("scope") or {},
                                title=tpl.get("name") or "Report")
        fname = (tpl.get("id") or "report") + "." + format
        if format == "json":
            return Response(
                content=render_json(report),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{fname}"'},
            )
        if format == "pdf":
            data = render_pdf(report)
            mime = "application/pdf" if data[:4] == b"%PDF" else "text/html"
            return Response(
                content=data, media_type=mime,
                headers={"Content-Disposition": f'attachment; filename="{fname}"'},
            )
        return Response(
            content=render_html(report, standalone=True),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @router.post("/api/reports/templates/{tpl_id}/share")
    def api_share(tpl_id: str = PathParam(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            tpl = _tpl.ensure_share_token(tpl_id)
        except PermissionError:
            return _readonly_response()
        except KeyError:
            raise HTTPException(status_code=404, detail="not_found")
        return {"share_token": tpl.get("share_token"), "id": tpl.get("id")}

    @router.get("/r/{token}", response_class=HTMLResponse)
    def public_share(token: str = PathParam(...)) -> str:
        tpl = _tpl.find_by_share_token(token)
        if not tpl:
            raise HTTPException(status_code=404, detail="not_found")
        report = compose_report(sections=tpl.get("sections"), scope=tpl.get("scope") or {},
                                title=tpl.get("name") or "Report")
        return render_html(report, standalone=True)

    return router


router = _make_router() if _FASTAPI_OK else None


__all__ = ["router"]
