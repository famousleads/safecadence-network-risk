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
from safecadence.reports.renderers import (
    render_docx,
    render_html,
    render_json,
    render_pdf,
    render_pptx,
    render_xlsx,
)
from safecadence.reports.presets import (
    apply_preset,
    get_preset,
    list_presets,
    render_preset_card_html,
)
from safecadence.reports import delta as _delta
from safecadence.reports import webhooks as _wh
from safecadence.reports import industry as _industry
from safecadence.reports import ticketing as _tk


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
.rep-presets{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.rep-preset-card{display:flex;gap:12px;align-items:flex-start;padding:14px;border-radius:10px;
  background:#0b1020;border:1px solid #26315b;color:#e7ecf5;cursor:pointer;text-align:left;
  font:inherit;transition:border-color .15s ease}
.rep-preset-card:hover{border-color:#7c5cff;background:#13193a}
.rep-preset-card.active{border-color:#1f6f6a;box-shadow:0 0 0 2px #1f6f6a55}
.rep-preset-icon{display:inline-flex;width:36px;height:36px;border-radius:8px;background:#1f6f6a22;
  align-items:center;justify-content:center;color:#5fc6bc;flex:none}
.rep-preset-body{display:flex;flex-direction:column;gap:4px;min-width:0}
.rep-preset-name{font-weight:700;font-size:14px;color:#fff}
.rep-preset-desc{font-size:12px;color:#cbd2e6;line-height:1.45}
.rep-preset-meta{display:flex;gap:10px;font-size:10px;text-transform:uppercase;
  letter-spacing:0.06em;color:#8b95b1;margin-top:6px}
</style>

<div class="rep-wrap">
  <div id="rep-readonly-banner" class="rep-readonly" style="display:none">
    Read-only demo &mdash; saves and share-links are disabled. Install NetRisk locally to use the full builder.
  </div>

  <div class="rep-steps">
    <div class="rep-step active" data-step="0" onclick="repGo(0)">0. Template</div>
    <div class="rep-step" data-step="1" onclick="repGo(1)">1. Sections</div>
    <div class="rep-step" data-step="2" onclick="repGo(2)">2. Scope</div>
    <div class="rep-step" data-step="3" onclick="repGo(3)">3. Preview</div>
    <div class="rep-step" data-step="4" onclick="repGo(4)">4. Export</div>
    <div class="rep-step" data-step="5" onclick="repGo(5)">5. Notify</div>
    <div class="rep-step" data-step="6" onclick="repGo(6)">6. Tickets</div>
  </div>

  <div id="rep-step0" class="rep-card">
    <h3>Choose a starting point</h3>
    <p style="color:#8b95b1;font-size:13px;margin:0 0 14px">
      Pick a stakeholder template to pre-fill sections, scope, and tone &mdash; or pick an industry template.
    </p>
    <div class="rep-tabs" style="display:flex;gap:8px;margin-bottom:12px">
      <button class="rep-btn rep-tab active" data-tab="stakeholder" onclick="repTab(this,'stakeholder')">Stakeholder</button>
      <button class="rep-btn rep-tab" data-tab="industry" onclick="repTab(this,'industry')">By industry</button>
    </div>
    <div id="rep-presets-grid" class="rep-presets" data-tab="stakeholder"></div>
    <div id="rep-industry-grid" class="rep-presets" data-tab="industry" style="display:none"></div>
    <div class="rep-actions">
      <button class="rep-btn" onclick="repApplyPreset('')">Custom (start blank)</button>
      <button class="rep-btn primary" onclick="repGo(1)">Skip &rarr; Sections</button>
    </div>
  </div>

  <div id="rep-step1" class="rep-card" style="display:none">
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
    <div style="margin-top:14px"><label style="font-size:12px;color:#cbd2e6">Prepared for (optional)
      <input id="rep-prepared-for" type="text" placeholder="Acme Corp"
       oninput="repState.preparedFor=this.value; repSchedulePreview()"
       style="width:100%;padding:8px;border:1px solid #26315b;background:#0b1020;color:#e7ecf5;border-radius:6px"/>
    </label></div>
    <div style="margin-top:10px">
      <label style="font-size:12px;color:#cbd2e6">Org name on cover (optional)
        <input id="rep-brand-org" type="text" placeholder="Your company"
          oninput="repState.brand=repState.brand||{}; repState.brand.org_name=this.value; repSchedulePreview()"
          style="width:100%;padding:8px;border:1px solid #26315b;background:#0b1020;color:#e7ecf5;border-radius:6px"/>
      </label>
    </div>
    <div style="margin-top:10px;display:flex;gap:10px">
      <label style="font-size:12px;color:#cbd2e6;flex:1">Brand primary
        <input id="rep-brand-primary" type="color" value="#1F6F6A"
          onchange="repState.brand=repState.brand||{}; repState.brand.primary_color=this.value.replace('#',''); repSchedulePreview()"
          style="width:100%;height:36px"/>
      </label>
      <label style="font-size:12px;color:#cbd2e6;flex:1">Brand accent
        <input id="rep-brand-accent" type="color" value="#5FC6BC"
          onchange="repState.brand=repState.brand||{}; repState.brand.accent_color=this.value.replace('#',''); repSchedulePreview()"
          style="width:100%;height:36px"/>
      </label>
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

  <div id="rep-step5" class="rep-card" style="display:none">
    <h3>Notifications &mdash; webhooks</h3>
    <p style="color:#8b95b1;font-size:13px">
      Slack, Teams, or generic JSON. Outgoing requests carry an
      <code>X-SafeCadence-Signature</code> header when a secret is set.
    </p>
    <div id="rep-wh-list" class="rep-tpls" style="margin-bottom:14px"></div>
    <div class="rep-row">
      <div><label>URL</label><input id="rep-wh-url" placeholder="https://hooks.slack.com/..."></div>
      <div><label>Kind</label>
        <select id="rep-wh-kind">
          <option value="slack">Slack</option>
          <option value="teams">Microsoft Teams</option>
          <option value="generic">Generic JSON</option>
        </select>
      </div>
      <div><label>Secret (optional)</label><input id="rep-wh-secret" type="password" placeholder="HMAC secret"></div>
    </div>
    <div class="rep-actions">
      <button class="rep-btn primary" onclick="repAddWebhook()">+ Add webhook</button>
    </div>
    <div id="rep-wh-msg" class="rep-msg" style="display:none;margin-top:10px"></div>
  </div>

  <div id="rep-step6" class="rep-card" style="display:none">
    <h3>Push findings to ticketing</h3>
    <p style="color:#8b95b1;font-size:13px">
      Auto-create tickets in Jira, ServiceNow, GitHub, or Linear. Findings are
      deduped by external id so re-running is safe.
    </p>
    <div id="rep-tk-list" class="rep-tpls" style="margin-bottom:14px"></div>
    <div class="rep-row">
      <div><label>Kind</label>
        <select id="rep-tk-kind">
          <option value="jira">Jira</option>
          <option value="servicenow">ServiceNow</option>
          <option value="github">GitHub Issues</option>
          <option value="linear">Linear</option>
          <option value="generic">Generic</option>
        </select>
      </div>
      <div><label>URL / repo / instance</label><input id="rep-tk-url"></div>
      <div><label>Project / team key</label><input id="rep-tk-project"></div>
    </div>
    <div class="rep-row">
      <div><label>Auth email</label><input id="rep-tk-email"></div>
      <div><label>Auth token</label><input id="rep-tk-token" type="password"></div>
    </div>
    <div class="rep-actions">
      <button class="rep-btn" onclick="repAddTicketing()">+ Add integration</button>
      <label style="color:#8b95b1;font-size:12px;display:flex;align-items:center;gap:6px">
        Threshold
        <select id="rep-tk-threshold">
          <option value="critical">Critical only</option>
          <option value="high" selected>High and above</option>
          <option value="medium">Medium and above</option>
        </select>
      </label>
      <button class="rep-btn primary" onclick="repCreateTickets()">Create tickets now</button>
    </div>
    <div id="rep-tk-msg" class="rep-msg" style="display:none;margin-top:10px"></div>
  </div>

  <div id="rep-step4" class="rep-card" style="display:none">
    <h3>Export this report</h3>
    <p style="color:#5b6685;font-size:13px;margin:0 0 12px">
      Choose any combination of formats. Downloads work in read-only demo mode &mdash;
      no signup required.
    </p>
    <div class="rep-actions" style="flex-wrap:wrap;gap:8px">
      <button class="rep-btn primary" onclick="repDownload('html')">Download HTML</button>
      <button class="rep-btn primary" onclick="repDownload('pdf')">Download PDF</button>
      <button class="rep-btn primary" onclick="repDownload('docx')">Download Word (.docx)</button>
      <button class="rep-btn primary" onclick="repDownload('pptx')">Download PowerPoint (.pptx)</button>
      <button class="rep-btn primary" onclick="repDownload('xlsx')">Download Excel (.xlsx)</button>
      <button class="rep-btn primary" onclick="repDownload('json')">Download JSON</button>
      <button class="rep-btn" onclick="repShareLink()">Get share link</button>
      <button class="rep-btn" onclick="repSaveAsTemplate()">Save as template</button>
    </div>
    <div id="rep-export-msg" class="rep-msg" style="margin-top:12px;display:none"></div>
    <h3 style="margin-top:18px">Saved templates</h3>
    <div id="rep-tpl-list" class="rep-tpls"></div>
  </div>
</div>
"""


_WIZARD_JS = """
const repState = {
  step: 0,
  sections: [],
  scope: { site:'', criticality:[], asset_type:[], vendor:[], date_range:{} },
  meta: { sections: [], scopes: [], presets: [] },
  scopeValues: { sites: [], vendors: [] },
  templateId: null,
  presetId: null,
  readonly: false,
  preparedFor: '',
  brand: null,
};
let repTimer = null;

function repGo(n) {
  repState.step = n;
  for (let i=0;i<=6;i++) {
    const el = document.getElementById('rep-step'+i);
    if (el) el.style.display = (i===n) ? '' : 'none';
  }
  document.querySelectorAll('.rep-step').forEach(el=>{
    el.classList.toggle('active', String(el.dataset.step)===String(n));
  });
  if (n===3) repPreview();
  if (n===4) repLoadTemplates();
  if (n===5) repLoadWebhooks();
  if (n===6) repLoadTicketing();
}

function repTab(btn, name) {
  document.querySelectorAll('.rep-tab').forEach(b => b.classList.toggle('active', b===btn));
  document.querySelectorAll('[data-tab]').forEach(el => {
    if (el.classList.contains('rep-tab')) return;
    el.style.display = (el.dataset.tab === name) ? '' : 'none';
  });
}

async function repLoadMeta() {
  try {
    const sec = await fetch('/api/reports/sections').then(r=>r.json());
    const sco = await fetch('/api/reports/scopes').then(r=>r.json());
    let pre = {presets: []};
    try { pre = await fetch('/api/reports/presets').then(r=>r.json()); } catch(e){}
    let ind = {templates: []};
    try { ind = await fetch('/api/reports/industry-templates').then(r=>r.json()); } catch(e){}
    repState.meta.sections = sec.sections || [];
    repState.meta.scopes = sco.scopes || [];
    repState.meta.presets = pre.presets || [];
    repState.meta.industry = ind.templates || [];
    repState.scopeValues.sites = sco.values?.sites || [];
    repState.scopeValues.vendors = sco.values?.vendors || [];
    repState.readonly = !!sco.readonly;
    if (repState.readonly) document.getElementById('rep-readonly-banner').style.display='block';
    repState.sections = repState.meta.sections.filter(s=>s.default_enabled).map(s=>s.key);
    repRenderPresets();
    repRenderIndustry();
    repRenderSections();
    repRenderScope();
  } catch(e) {
    console.error(e);
  }
}

function repRenderIndustry() {
  const grid = document.getElementById('rep-industry-grid');
  if (!grid) return;
  const items = repState.meta.industry || [];
  if (!items.length) { grid.innerHTML = '<div class="rep-msg">No industry templates installed.</div>'; return; }
  grid.innerHTML = items.map(t => (
    `<button type="button" class="rep-preset-card" onclick="repApplyIndustry('${repEsc(t.id)}')">
      <span class="rep-preset-icon">${t.icon_svg || ''}</span>
      <span class="rep-preset-body">
        <span class="rep-preset-name">${repEsc(t.name)}</span>
        <span class="rep-preset-desc">${repEsc(t.description||'')}</span>
        <span class="rep-preset-meta">
          <span>${repEsc((t.industry||'').toUpperCase())}</span>
          <span>${(t.regulations||[]).length} frameworks</span>
        </span>
      </span>
    </button>`
  )).join('');
}

async function repApplyIndustry(tplId) {
  // Visual feedback first — mark the chosen card as active so the user
  // sees an immediate response even before the network call returns.
  document.querySelectorAll('#rep-industry-grid .rep-preset-card').forEach(el => {
    el.classList.remove('active');
  });
  const ev = window.event && window.event.currentTarget;
  if (ev) ev.classList.add('active');

  try {
    const r = await fetch('/api/reports/industry-templates/' + encodeURIComponent(tplId) + '/apply', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'
    }).then(r=>r.json());
    if (r && r.sections) {
      repState.presetId = null;
      repState.industryTemplateId = tplId;
      repState.sections = r.sections;
      repState.scope = Object.assign({site:'',criticality:[],asset_type:[],vendor:[],date_range:{}}, r.scope || {});
      repRenderSections();
      repRenderScope();
      // Land on Step 1 (Sections) so the user can review/tweak before preview.
      repGo(1);
    } else {
      alert('Could not apply that industry template. Try again.');
    }
  } catch(e) {
    console.error(e);
    alert('Could not apply that industry template: ' + e.message);
  }
}

function repRenderPresets() {
  const grid = document.getElementById('rep-presets-grid');
  if (!grid) return;
  if (!repState.meta.presets.length) {
    grid.innerHTML = '<div class="rep-msg">No presets installed.</div>';
    return;
  }
  grid.innerHTML = repState.meta.presets.map(p => p.card_html || '').join('');
}

async function repApplyPreset(presetId) {
  // Immediate visual feedback on the clicked card.
  document.querySelectorAll('#rep-presets-grid .rep-preset-card').forEach(el => {
    el.classList.remove('active');
  });
  const ev = window.event && window.event.currentTarget;
  if (ev) ev.classList.add('active');

  if (!presetId) {
    repState.presetId = null;
    repGo(1);
    return;
  }
  try {
    const r = await fetch('/api/reports/presets/' + encodeURIComponent(presetId) + '/apply', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'
    }).then(r=>r.json());
    if (r && r.sections) {
      repState.presetId = presetId;
      repState.sections = r.sections;
      repState.scope = Object.assign({site:'',criticality:[],asset_type:[],vendor:[],date_range:{}}, r.scope || {});
      repRenderSections();
      repRenderScope();
      // Land on Step 1 (Sections) so the user can review/tweak the pre-filled
      // section list before previewing.
      repGo(1);
    } else if (r && r.detail) {
      alert('Could not apply preset: ' + r.detail);
    } else {
      alert('Could not apply that preset. Try again or pick Custom (start blank).');
    }
  } catch(e) {
    console.error(e);
    alert('Could not apply preset: ' + e.message);
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
    const payload = {
      sections: repState.sections, scope: repState.scope,
      preset_id: repState.presetId || null,
      prepared_for: repState.preparedFor || null,
      brand: repState.brand || null,
    };
    const r = await fetch('/api/reports/compose', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    const stamp = document.getElementById('rep-stamp');
    if (stamp) stamp.textContent = 'Generated ' + new Date(j.generated_at || Date.now()).toLocaleTimeString();
    pv.innerHTML = '<iframe srcdoc="" id="rep-iframe" style="width:100%;height:640px;border:0;border-radius:0 0 10px 10px"></iframe>';
    const iframe = document.getElementById('rep-iframe');
    const html = await fetch('/api/reports/render-html', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
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
  const msg = document.getElementById('rep-export-msg');
  msg.style.display = '';
  msg.innerHTML = 'Generating share link...';

  // Try ephemeral share link first — works in read-only mode without a save.
  try {
    const r = await fetch('/api/reports/share-link', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        sections: repState.sections,
        scope: repState.scope,
        preset_id: repState.presetId || null,
        industry_template_id: repState.industryTemplateId || null,
        prepared_for: repState.preparedFor || null,
        brand: repState.brand || null,
      })
    });
    if (r.ok) {
      const j = await r.json();
      const url = location.origin + (j.path || ('/r-live/' + j.share_token));
      msg.innerHTML =
        'Share link (anyone with the link can view): ' +
        '<a href="' + repEsc(url) + '" target="_blank">' + repEsc(url) + '</a>' +
        ' <button type="button" class="rep-btn" id="rep-copy-share">Copy</button>';
      const cbtn = document.getElementById('rep-copy-share');
      if (cbtn) cbtn.addEventListener('click', () => {
        navigator.clipboard.writeText(url).then(() => { cbtn.textContent = 'Copied'; });
      });
      return;
    }
  } catch(e) { /* fall through to saved-template path */ }

  // Fallback: persistent share for saved template (requires write access).
  if (!repState.templateId) {
    await repSaveAsTemplate();
    if (!repState.templateId) {
      msg.innerHTML = 'Read-only demo: install NetRisk locally for persistent share links.';
      return;
    }
  }
  const r2 = await fetch('/api/reports/templates/' + repState.templateId + '/share',
                        {method:'POST'});
  if (r2.status === 403) {
    msg.innerHTML = 'Read-only demo: cannot create persistent share links.';
    return;
  }
  const j2 = await r2.json();
  const url2 = location.origin + '/r/' + j2.share_token;
  msg.innerHTML =
    'Share link (persistent): ' +
    '<a href="' + repEsc(url2) + '" target="_blank">' + repEsc(url2) + '</a>';
}

async function repDownload(fmt) {
  const btn = (window.event && window.event.currentTarget) || null;
  let oldText = '';
  if (btn) { oldText = btn.textContent; btn.textContent = 'Generating...'; btn.disabled = true; }

  const msg = document.getElementById('rep-export-msg');
  msg.style.display = 'none';

  const payload = {
    sections: repState.sections,
    scope: repState.scope,
    preset_id: repState.presetId || null,
    industry_template_id: repState.industryTemplateId || null,
    format: fmt,
    filename: 'safecadence-report',
    prepared_for: repState.preparedFor || null,
    brand: repState.brand || null,
  };

  try {
    const r = await fetch('/api/reports/render-download', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error('HTTP ' + r.status + ' — ' + (txt || 'see console'));
    }
    const blob = await r.blob();
    if (blob.size === 0) throw new Error('Empty file returned by server');
    // Derive filename from Content-Disposition if present, else default.
    let filename = 'safecadence-report.' + fmt;
    const cd = r.headers.get('Content-Disposition') || '';
    const m = /filename="([^"]+)"/.exec(cd);
    if (m) filename = m[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    msg.style.display = '';
    msg.innerHTML = 'Downloaded ' + repEsc(filename) +
                    ' (' + Math.round(blob.size/1024) + ' KB).';
  } catch(e) {
    console.error(e);
    msg.style.display = '';
    msg.innerHTML = '<span style="color:#dc2626">Download failed: ' +
                    repEsc(e.message) + '</span>';
  } finally {
    if (btn) { btn.textContent = oldText; btn.disabled = false; }
  }
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

// --- webhooks ---
async function repLoadWebhooks() {
  try {
    const r = await fetch('/api/reports/webhooks').then(r=>r.json());
    const el = document.getElementById('rep-wh-list');
    if (!r.webhooks || !r.webhooks.length) {
      el.innerHTML = '<div class="rep-msg">No webhooks configured.</div>';
      return;
    }
    el.innerHTML = r.webhooks.map(w => (
      `<div class="rep-tpl">
        <strong>${repEsc(w.kind)}</strong> &middot; <small style="color:#8b95b1">${repEsc(w.url)}</small><br>
        <small style="color:#8b95b1">last status: ${repEsc(w.last_status==null?'—':w.last_status)} &middot; ${repEsc(w.last_fired_at||'never fired')}</small>
        <div style="margin-top:6px;display:flex;gap:6px">
          <button class="rep-btn" onclick="repTestWebhook('${repEsc(w.id)}')">Test</button>
          <button class="rep-btn" onclick="repRemoveWebhook('${repEsc(w.id)}')">Remove</button>
        </div>
      </div>`
    )).join('');
  } catch(e) { console.error(e); }
}

async function repAddWebhook() {
  if (repState.readonly) { alert('Read-only demo: cannot add webhooks.'); return; }
  const url = document.getElementById('rep-wh-url').value.trim();
  const kind = document.getElementById('rep-wh-kind').value;
  const secret = document.getElementById('rep-wh-secret').value || null;
  if (!url) { alert('URL is required'); return; }
  const r = await fetch('/api/reports/webhooks', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url, kind, secret})
  });
  if (r.status === 403) { alert('Read-only demo: cannot add webhooks.'); return; }
  document.getElementById('rep-wh-url').value = '';
  document.getElementById('rep-wh-secret').value = '';
  repLoadWebhooks();
}

async function repRemoveWebhook(id) {
  if (repState.readonly) return;
  await fetch('/api/reports/webhooks/' + encodeURIComponent(id), {method:'DELETE'});
  repLoadWebhooks();
}

async function repTestWebhook(id) {
  const r = await fetch('/api/reports/webhooks/test', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id})
  }).then(r=>r.json());
  const m = document.getElementById('rep-wh-msg');
  m.style.display=''; m.textContent = 'Webhook test: status=' + (r.status||0) + (r.ok?' (ok)':' (failed)');
}

// --- ticketing ---
async function repLoadTicketing() {
  try {
    const r = await fetch('/api/reports/ticketing/integrations').then(r=>r.json());
    const el = document.getElementById('rep-tk-list');
    if (!r.integrations || !r.integrations.length) {
      el.innerHTML = '<div class="rep-msg">No ticketing integrations configured.</div>';
      return;
    }
    el.innerHTML = r.integrations.map(i => (
      `<div class="rep-tpl">
        <strong>${repEsc(i.kind)}</strong> &middot; ${repEsc(i.project)}<br>
        <small style="color:#8b95b1">${repEsc(i.url)} &middot; tickets created: ${repEsc(i.tickets_created||0)}</small>
        <div style="margin-top:6px"><button class="rep-btn" onclick="repRemoveTicketing('${repEsc(i.id)}')">Remove</button></div>
      </div>`
    )).join('');
  } catch(e) { console.error(e); }
}

async function repAddTicketing() {
  if (repState.readonly) { alert('Read-only demo: cannot add integrations.'); return; }
  const body = {
    kind: document.getElementById('rep-tk-kind').value,
    url: document.getElementById('rep-tk-url').value.trim(),
    project: document.getElementById('rep-tk-project').value.trim(),
    auth_email: document.getElementById('rep-tk-email').value.trim() || null,
    auth_token: document.getElementById('rep-tk-token').value || null,
  };
  const r = await fetch('/api/reports/ticketing/integrations', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  if (r.status === 403) { alert('Read-only demo.'); return; }
  if (!r.ok) { alert('Add failed: '+r.status); return; }
  ['rep-tk-url','rep-tk-project','rep-tk-email','rep-tk-token'].forEach(id => document.getElementById(id).value='');
  repLoadTicketing();
}

async function repRemoveTicketing(id) {
  if (repState.readonly) return;
  await fetch('/api/reports/ticketing/integrations/' + encodeURIComponent(id), {method:'DELETE'});
  repLoadTicketing();
}

async function repCreateTickets() {
  if (repState.readonly) { alert('Read-only demo: tickets not created.'); return; }
  const sel = document.getElementById('rep-tk-threshold').value;
  const r = await fetch('/api/reports/ticketing/auto-create', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({sections: repState.sections, scope: repState.scope,
                          severity_threshold: sel})
  }).then(r=>r.json()).catch(e=>({error:String(e)}));
  const m = document.getElementById('rep-tk-msg');
  m.style.display=''; m.textContent = 'Created: ' + (r.created||0) + ', deduped: ' + (r.skipped_existing||0);
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

    def _resolve_payload(payload: dict) -> tuple[list | None, dict, dict | None, bool]:
        """Pull (sections, scope, preset, include_delta) out of a payload."""
        preset = None
        sections = payload.get("sections") or None
        scope = payload.get("scope") or {}
        pid = payload.get("preset_id")
        iid = payload.get("industry_template_id")
        include_delta = bool(payload.get("include_delta") or False)
        if pid:
            try:
                preset = apply_preset(pid, scope)
            except ValueError:
                preset = None
            if preset:
                if not sections:
                    sections = preset.get("sections")
                if not scope:
                    scope = preset.get("scope") or {}
                if (preset.get("render_options") or {}).get("extras", {}).get("include_delta"):
                    include_delta = True
        if iid and not preset:
            try:
                preset = _industry.apply_industry_template(iid, scope)
            except ValueError:
                preset = None
            if preset:
                if not sections:
                    sections = preset.get("sections")
                if not scope:
                    scope = preset.get("scope") or {}
        return sections, scope, preset, include_delta

    def _enrich_report(report: dict, payload: dict) -> dict:
        """Attach top-level ``prepared_for`` and ``brand`` to a composed report.

        Keeps both keys optional — when absent or empty, the report dict is
        returned unchanged so renderers fall back to SafeCadence defaults.
        """
        prepared_for = (payload.get("prepared_for") or "").strip()
        if prepared_for:
            report["prepared_for"] = prepared_for
        brand = payload.get("brand") or None
        if isinstance(brand, dict):
            # Strip empties so renderers cleanly detect "no brand"
            cleaned = {k: v for k, v in brand.items()
                        if v not in (None, "", [], {})}
            if cleaned:
                report["brand"] = cleaned
        return report

    @router.get("/api/reports/presets")
    def api_presets() -> dict:
        out = []
        for p in list_presets():
            p["card_html"] = render_preset_card_html(p)
            out.append(p)
        return {"presets": out, "readonly": _is_readonly()}

    @router.get("/api/reports/presets/{preset_id}")
    def api_preset(preset_id: str = PathParam(...)) -> Any:
        p = get_preset(preset_id)
        if not p:
            raise HTTPException(status_code=404, detail="not_found")
        return p

    @router.post("/api/reports/presets/{preset_id}/apply")
    def api_preset_apply(preset_id: str = PathParam(...),
                         payload: dict = Body(default={})) -> Any:
        try:
            return apply_preset(preset_id, payload.get("scope") or {})
        except ValueError:
            raise HTTPException(status_code=404, detail="not_found")

    @router.post("/api/reports/compose")
    def api_compose(payload: dict = Body(default={})) -> dict:
        sections, scope, _preset, incl = _resolve_payload(payload)
        report = compose_report(sections=sections, scope=scope, include_delta=incl)
        return _enrich_report(report, payload)

    @router.post("/api/reports/render-html", response_class=HTMLResponse)
    def api_render_html(payload: dict = Body(default={})) -> str:
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        # Notify webhooks (best effort) when not in read-only mode.
        if not _is_readonly():
            try:
                _wh.notify_completion({
                    "title": report.get("title"),
                    "kpi": next((s.get("data") for s in report.get("sections", [])
                                 if s.get("key") == "kpi_summary"), {}),
                })
            except Exception:
                pass
        return render_html(report, standalone=True, preset=preset)

    @router.post("/api/reports/render-json")
    def api_render_json(payload: dict = Body(default={})) -> Response:
        sections, scope, _preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        return Response(content=render_json(report), media_type="application/json")

    @router.post("/api/reports/render-pdf")
    def api_render_pdf(payload: dict = Body(default={})) -> Response:
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        return Response(content=render_pdf(report, preset=preset),
                        media_type="application/pdf")

    @router.post("/api/reports/render-docx")
    def api_render_docx(payload: dict = Body(default={})) -> Response:
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        return Response(
            content=render_docx(report, preset=preset),
            media_type=("application/vnd.openxmlformats-officedocument."
                        "wordprocessingml.document"),
            headers={"Content-Disposition":
                     'attachment; filename="safecadence-report.docx"'},
        )

    @router.post("/api/reports/render-pptx")
    def api_render_pptx(payload: dict = Body(default={})) -> Response:
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        return Response(
            content=render_pptx(report, preset=preset),
            media_type=("application/vnd.openxmlformats-officedocument."
                        "presentationml.presentation"),
            headers={"Content-Disposition":
                     'attachment; filename="safecadence-report.pptx"'},
        )

    @router.post("/api/reports/render-xlsx")
    def api_render_xlsx(payload: dict = Body(default={})) -> Response:
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        return Response(
            content=render_xlsx(report, preset=preset),
            media_type=("application/vnd.openxmlformats-officedocument."
                        "spreadsheetml.sheet"),
            headers={"Content-Disposition":
                     'attachment; filename="safecadence-report.xlsx"'},
        )

    @router.post("/api/reports/render-download")
    def api_render_download(payload: dict = Body(default={})) -> Response:
        """One-shot composed download — works in read-only mode (no template save).

        Body: {sections, scope, preset_id, industry_template_id, format,
               filename, prepared_for, brand}
        format: html | pdf | json | docx | pptx | xlsx
        """
        fmt = (payload.get("format") or "html").lower()
        if fmt not in ("html", "pdf", "json", "docx", "pptx", "xlsx"):
            raise HTTPException(status_code=400, detail="bad_format")
        sections, scope, preset, incl = _resolve_payload(payload)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope, include_delta=incl),
            payload,
        )
        base = str(payload.get("filename") or "safecadence-report").strip() or "safecadence-report"
        # Strip dangerous chars
        base = "".join(c for c in base if c.isalnum() or c in "-_") or "safecadence-report"
        fname = f"{base}.{fmt}"

        if fmt == "json":
            data = render_json(report).encode("utf-8")
            mime = "application/json"
        elif fmt == "pdf":
            data = render_pdf(report, preset=preset)
            mime = "application/pdf" if data[:4] == b"%PDF" else "text/html"
            if mime == "text/html":
                fname = f"{base}.html"
        elif fmt == "docx":
            data = render_docx(report, preset=preset)
            mime = ("application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document")
        elif fmt == "pptx":
            data = render_pptx(report, preset=preset)
            mime = ("application/vnd.openxmlformats-officedocument."
                    "presentationml.presentation")
        elif fmt == "xlsx":
            data = render_xlsx(report, preset=preset)
            mime = ("application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.sheet")
        else:  # html
            data = render_html(report, standalone=True, preset=preset).encode("utf-8")
            mime = "text/html"
        return Response(
            content=data,
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @router.post("/api/reports/share-link")
    def api_share_link(payload: dict = Body(default={})) -> dict:
        """Build an ephemeral share URL that encodes the wizard state.

        Works in read-only mode (doesn't need a saved template). The /r-live/
        endpoint below decodes & renders it.
        """
        import base64
        import json as _json2
        body = {
            "sections": payload.get("sections") or [],
            "scope": payload.get("scope") or {},
            "preset_id": payload.get("preset_id"),
            "industry_template_id": payload.get("industry_template_id"),
            "title": payload.get("title") or "SafeCadence NetRisk Report",
            "prepared_for": payload.get("prepared_for") or None,
            "brand": payload.get("brand") or None,
        }
        token = base64.urlsafe_b64encode(
            _json2.dumps(body, default=str).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        return {"share_token": token, "kind": "ephemeral",
                "path": f"/r-live/{token}"}

    @router.get("/r-live/{token}", response_class=HTMLResponse)
    def public_share_live(token: str = PathParam(...)) -> str:
        """Decode an ephemeral share token and render the report."""
        import base64
        import json as _json2
        try:
            padded = token + "=" * (-len(token) % 4)
            body = _json2.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=404, detail="not_found")
        sections, scope, preset, incl = _resolve_payload(body)
        report = _enrich_report(
            compose_report(sections=sections, scope=scope,
                           title=body.get("title") or "Report",
                           include_delta=incl),
            body,
        )
        return render_html(report, standalone=True, preset=preset)

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
        format: str = Query("html", pattern="^(html|json|pdf|docx|pptx)$"),
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
        if format == "docx":
            return Response(
                content=render_docx(report),
                media_type=("application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"),
                headers={"Content-Disposition": f'attachment; filename="{fname}"'},
            )
        if format == "pptx":
            return Response(
                content=render_pptx(report),
                media_type=("application/vnd.openxmlformats-officedocument."
                            "presentationml.presentation"),
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

    # ----------------------------------------------------------------------
    # Round 2: delta / webhooks / industry / ticketing
    # ----------------------------------------------------------------------

    @router.get("/api/reports/delta")
    def api_delta() -> dict:
        return _delta.compute_delta()

    @router.get("/api/reports/snapshots")
    def api_list_snapshots() -> dict:
        return {"snapshots": _delta.list_snapshots(), "readonly": _is_readonly()}

    @router.post("/api/reports/snapshots")
    def api_take_snapshot(body: dict = Body(default={})) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            return _delta.snapshot_now(label=(body or {}).get("label"))
        except PermissionError:
            return _readonly_response()

    @router.get("/api/reports/trend")
    def api_trend(metric: str = Query("critical"),
                  days: int = Query(30, ge=1, le=365)) -> dict:
        return {"metric": metric, "days": days,
                "values": _delta.trend_series(metric, days=days)}

    # webhooks ---------------------------------------------------------------

    @router.get("/api/reports/webhooks")
    def api_list_webhooks() -> dict:
        return {"webhooks": _wh.list_webhook_endpoints(),
                "readonly": _is_readonly()}

    @router.post("/api/reports/webhooks")
    def api_add_webhook(body: dict = Body(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            return _wh.add_webhook_endpoint(
                url=body.get("url") or "",
                kind=body.get("kind") or "generic",
                secret=body.get("secret") or None,
            )
        except PermissionError:
            return _readonly_response()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.delete("/api/reports/webhooks/{wh_id}")
    def api_remove_webhook(wh_id: str = PathParam(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            ok = _wh.remove_webhook_endpoint(wh_id)
        except PermissionError:
            return _readonly_response()
        if not ok:
            raise HTTPException(status_code=404, detail="not_found")
        return {"ok": True}

    @router.post("/api/reports/webhooks/test")
    def api_test_webhook(body: dict = Body(default={})) -> Any:
        wh_id = (body or {}).get("id") or ""
        if not wh_id:
            raise HTTPException(status_code=400, detail="id required")
        return _wh.test_webhook(endpoint_id=wh_id)

    # industry ---------------------------------------------------------------

    @router.get("/api/reports/industry-templates")
    def api_list_industry() -> dict:
        return {"templates": _industry.list_industry_templates()}

    @router.get("/api/reports/industry-templates/{tpl_id}")
    def api_get_industry(tpl_id: str = PathParam(...)) -> Any:
        t = _industry.get_industry_template(tpl_id)
        if not t:
            raise HTTPException(status_code=404, detail="not_found")
        return t

    @router.post("/api/reports/industry-templates/{tpl_id}/apply")
    def api_apply_industry(tpl_id: str = PathParam(...),
                            payload: dict = Body(default={})) -> Any:
        try:
            return _industry.apply_industry_template(
                tpl_id, (payload or {}).get("scope") or {}
            )
        except ValueError:
            raise HTTPException(status_code=404, detail="not_found")

    # ticketing --------------------------------------------------------------

    @router.get("/api/reports/ticketing/integrations")
    def api_list_ticketing() -> dict:
        return {"integrations": _tk.list_ticketing_integrations(),
                "readonly": _is_readonly()}

    @router.post("/api/reports/ticketing/integrations")
    def api_add_ticketing(body: dict = Body(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            return _tk.add_ticketing_integration(
                kind=body.get("kind") or "",
                url=body.get("url") or "",
                project=body.get("project") or "",
                auth_email=body.get("auth_email"),
                auth_token=body.get("auth_token"),
            )
        except PermissionError:
            return _readonly_response()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @router.delete("/api/reports/ticketing/integrations/{integ_id}")
    def api_remove_ticketing(integ_id: str = PathParam(...)) -> Any:
        if _is_readonly():
            return _readonly_response()
        try:
            ok = _tk.remove_ticketing_integration(integ_id)
        except PermissionError:
            return _readonly_response()
        if not ok:
            raise HTTPException(status_code=404, detail="not_found")
        return {"ok": True}

    @router.post("/api/reports/ticketing/auto-create")
    def api_auto_create_tickets(body: dict = Body(default={})) -> Any:
        if _is_readonly():
            return _readonly_response()
        sections, scope, _preset, incl = _resolve_payload(body or {})
        report = compose_report(sections=sections, scope=scope, include_delta=incl)
        try:
            return _tk.auto_create_tickets(
                report,
                integration_id=(body or {}).get("integration_id"),
                severity_threshold=(body or {}).get("severity_threshold") or "high",
            )
        except PermissionError:
            return _readonly_response()

    @router.get("/api/reports/ticketing/tickets")
    def api_list_tickets(integration_id: str | None = Query(default=None)) -> dict:
        return {"tickets": _tk.list_created_tickets(integration_id=integration_id)}

    return router


router = _make_router() if _FASTAPI_OK else None


__all__ = ["router"]
