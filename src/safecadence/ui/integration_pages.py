"""Read-only synthetic explorers. Never read a customer DB or contact a sensor."""
from __future__ import annotations

import copy
import json
import tempfile
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from safecadence.integrations.public_safety_store import PublicSafetyEvidenceStore
from safecadence.integrations.security_catalog import catalog
from safecadence.integrations.security_import import ImportRejected
from safecadence.integrations.security_store import SecurityEvidenceStore

REFERENCE_TIME = "2026-10-06T12:02:00Z"
SECURITY_FILES = {"wazuh": "wazuh-alerts.json", "crowdsec": "crowdsec-alerts.json",
                  "zeek": "zeek-connections.json", "suricata": "suricata-alerts.json"}
SAFETY_FILES = {"frigate": "frigate-events.json", "home-assistant": "home-assistant-events.json",
                "thingsboard": "thingsboard-events.json", "sherlock": "sherlock-brand.csv",
                "maigret": "maigret-brand.csv"}


def demo_snapshot(mode):
    if mode not in ("security", "safety"):
        raise ValueError("unsupported demo")
    return copy.deepcopy(_snapshot(mode))


@lru_cache(maxsize=2)
def _snapshot(mode):
    fixtures = files("safecadence").joinpath("data", "integration_demo", mode)
    with tempfile.TemporaryDirectory(prefix="sc-synthetic-") as directory:
        root = Path(directory)
        store = (SecurityEvidenceStore if mode == "security" else PublicSafetyEvidenceStore)(root / "demo.db")
        try:
            receipts = []
            for source, name in (SECURITY_FILES if mode == "security" else SAFETY_FILES).items():
                export = root / name
                export.write_bytes(fixtures.joinpath(name).read_bytes())
                context = dict(source=source, tenant="synthetic-demo", instance="sample-sensor")
                if mode == "security":
                    context["source_version"] = "synthetic-v1"
                else:
                    context["site"] = "sample-station"
                    brand = source in ("sherlock", "maigret")
                    scope_name = "brand-scope.json" if brand else source + "-scope.json"
                    store.register(**context, source_version="synthetic-v1",
                                   purpose="brand-protection" if brand else "facility-safety",
                                   scope=json.loads(fixtures.joinpath(scope_name).read_text()))
                    if brand:
                        context["observed_at"] = "2026-10-06T12:00:00Z"
                receipts.append(dict(source=source, **store.import_file(export, **context)))
            # An intentionally invalid batch exercises the real rejection/audit path.
            bad = root / "rejected.json"
            bad.write_text('{"rule":{"level":99}}' if mode == "security" else '{"type":"rpc","device":"unapproved"}')
            try:
                store.import_file(bad, source="wazuh" if mode == "security" else "thingsboard",
                                  tenant="synthetic-demo", instance="sample-sensor",
                                  **({"source_version": "synthetic-v1"} if mode == "security" else {"site": "sample-station"}))
            except ImportRejected:
                pass
            args = dict(tenant="synthetic-demo")
            events = store.events(**args, **({"site": "sample-station"} if mode == "safety" else {}))
            status = store.status(**args, **({"site": "sample-station", "as_of": REFERENCE_TIME} if mode == "safety" else {}))
            audit = store.audit(**args)
            return dict(mode=mode, sample_data=True, reference_time=REFERENCE_TIME,
                        live_connector=False, controls_enabled=False, events=events,
                        sources=status, receipts=receipts, audit=audit,
                        catalog=catalog() if mode == "security" else [],
                        limitation="Fictional supplied exports, not live monitoring. Human review required. No sensor control, public-site lookups or person identification.")
        finally:
            store.close()


_BODY = """
<style>
.sc-topbar button{width:auto}
.ix {--accent:#1473E6;max-width:1240px;margin:auto;letter-spacing:0}
.ix *{box-sizing:border-box}.ix .notice{padding:12px 16px;background:#FFF4D9;color:#713F12;border-left:4px solid #F59E0B}
.ix header{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin:22px 0}
.ix h1{font-size:26px;margin:0 0 8px}.ix p{margin:6px 0;color:var(--muted)}
.ix .links{display:flex;gap:14px;flex-wrap:wrap}.ix .links a{color:var(--accent)}
.ix .metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-block:1px solid var(--border);padding:18px 0;margin-bottom:22px;gap:16px}
.ix .metrics strong{display:block;font-size:24px;margin-top:4px}.ix .layout{display:grid;grid-template-columns:260px minmax(0,1fr);gap:24px}
.ix button,.ix select{width:auto;font:inherit;border:1px solid var(--border);color:var(--text);background:var(--panel);border-radius:6px;padding:10px;cursor:pointer}
.ix .source{display:block;width:100%;text-align:left;margin-bottom:8px;border-left:4px solid #19B5E5;overflow-wrap:anywhere}
.ix .source[aria-pressed=true]{background:#E8F2FF;color:#0B1938;border-color:#1473E6}.ix .source small{display:block;margin-top:6px}
.ix .tabs{display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:14px;flex-wrap:wrap}
.ix .tabs button{border:0;border-bottom:3px solid transparent;border-radius:0;background:none}
.ix .tabs button[aria-selected=true]{border-bottom-color:#1473E6;color:#1473E6}
.ix .row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;border-bottom:1px solid var(--border);padding:14px 0;align-items:center}
.ix .row strong,.ix .row small{display:block;overflow-wrap:anywhere}.ix .row small{margin-top:6px;color:var(--muted)}
.ix .tag{display:inline-block;font-size:12px;padding:3px 7px;border-radius:4px;background:#E8F2FF;color:#0B1F4B;margin:4px 4px 0 0}
.ix .tag.warn{background:#FFF4D9;color:#713F12}.ix .tag.danger{background:#FFF0F1;color:#A31727}
.ix .error{color:#EF3340}.ix dialog{color:var(--text);background:var(--panel);border:1px solid var(--border);border-radius:8px;width:720px;max-width:calc(100vw - 32px);max-height:85vh;padding:22px}
.ix dialog::backdrop{background:rgba(7,21,47,.5)}.ix dialog header{margin:0 0 16px}.ix pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.6}
.ix .empty{padding:24px 0;color:var(--muted)}.ix footer{border-top:1px solid var(--border);margin-top:24px;padding-top:16px;font-size:13px}
@media(max-width:760px){.ix .layout{grid-template-columns:1fr}.ix .sources{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.ix .metrics{font-size:12px}.ix .metrics strong{font-size:18px}.ix h1{font-size:22px}.ix .row{grid-template-columns:1fr}.ix .row button{justify-self:start}}
</style>
<section class="ix" data-mode="__MODE__">
<div class="notice"><strong>SIMULATED SAMPLE DATA</strong> &middot; Read-only exports. No live sensors, account searches or automated actions.</div>
<header><div><h1>__TITLE__</h1><p>__SUBTITLE__</p></div><nav class="links" aria-label="Integration demos"><a href="/security-integrations">NetRisk</a><a href="/safety-integrations">Public Safety</a></nav></header>
<div class="metrics"><div>Offline import sources<strong id="ix-source-count">&mdash;</strong></div><div>Sample observations<strong id="ix-event-count">&mdash;</strong></div><div>Live sensor health<strong>Unknown</strong></div></div>
<div class="layout"><aside><h2 style="font-size:16px">Sources</h2><div class="sources" id="ix-sources"></div><p>Sensor health and coverage are not established by an import receipt.</p></aside>
<div><div class="tabs" role="tablist" aria-label="Evidence views"><button type="button" role="tab" data-view="events" aria-selected="true">Observations</button><button type="button" role="tab" data-view="sources" aria-selected="false">Source status</button><button type="button" role="tab" data-view="audit" aria-selected="false">Audit &amp; failures</button><button type="button" role="tab" data-view="catalog" aria-selected="false">Capabilities</button></div><div id="ix-content" role="tabpanel" aria-live="polite">Loading sample evidence...</div></div></div>
<footer><p id="ix-chain"></p><p>Reference clock: __CLOCK__. Receipt timestamps reflect when this sample was generated. Hash chains detect edits, not privileged tail deletion. Brand observations are not identity or impersonation proof.</p><button id="ix-download" type="button" disabled>Download sample report</button></footer>
<dialog id="ix-detail" aria-labelledby="ix-detail-title"><header><h2 id="ix-detail-title" style="font-size:18px">Sample evidence</h2><button type="button" id="ix-close" aria-label="Close evidence">Close</button></header><pre id="ix-json"></pre></dialog>
</section>
"""

_SCRIPT = r"""
(() => {
const root=document.querySelector('.ix'), content=document.getElementById('ix-content');
let data, source='', view='events';
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
function detail(record){document.getElementById('ix-json').textContent=JSON.stringify(record,null,2);document.getElementById('ix-detail').showModal();}
document.getElementById('ix-close').onclick=()=>document.getElementById('ix-detail').close();
function render(){
  content.replaceChildren();
  document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.view===view)));
  document.querySelectorAll('.source').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.source===source)));
  let records = view==='audit'?data.audit.records:view==='catalog'?data.catalog:data[view];
  if(source)records=records.filter(r=>r.source===source || (view==='catalog' && r.key===source));
  if(view==='catalog' && !data.catalog.length){content.append(el('p','Frigate / Home Assistant: scoped exports. ThingsBoard: explicit local envelope; engine license review required. Sherlock / Maigret: authorized organization-brand CSV only, human review required. All five are file-import workflows, not installed upstream engines.','empty'));return;}
  if(!records.length){content.append(el('p','No sample records in this view.','empty'));return;}
  records.forEach(r=>{
    const row=el('div',undefined,'row'), summary=el('div');
    summary.append(el('strong',r.title||r.name||r.action||r.source||'Observation'));
    summary.append(el('small',[r.source,r.asset_ref,r.observed_at||r.latest_observation||r.at,r.instance].filter(Boolean).join(' · ')));
    const state=r.reason||r.review?.decision||r.freshness||r.severity||r.status||'unknown';
    summary.append(el('span',state,'tag'+(r.status==='rejected'?' danger':state==='unreviewed'?' warn':'')));
    if(view==='sources')summary.append(el('span','Sensor health: unknown','tag warn'));
    if(view==='catalog')summary.append(el('span',r.live_connector?'Live connector':'No live connector','tag warn'));
    if(r.recommendation)summary.append(el('small',r.recommendation));
    const button=el('button','View evidence');button.type='button';button.onclick=()=>detail(r);
    row.append(summary,button);content.append(row);
  });
}
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>{view=b.dataset.view;render();});
fetch('/api/integration-demo/'+root.dataset.mode,{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Sample data unavailable');return r.json();}).then(result=>{
  data=result;document.getElementById('ix-source-count').textContent=data.sources.length;document.getElementById('ix-event-count').textContent=data.events.length;
  const all=el('button','All sources','source');all.type='button';all.dataset.source='';all.onclick=()=>{source='';render();};document.getElementById('ix-sources').append(all);
  data.sources.forEach(s=>{const b=el('button',s.source,'source');b.type='button';b.dataset.source=s.source;b.append(el('small','Offline export · controls disabled'));b.onclick=()=>{source=s.source;render();};document.getElementById('ix-sources').append(b);});
  document.getElementById('ix-chain').textContent='Sample audit chain: '+(data.audit.chain_valid?'valid at verification':'FAILED')+' · '+data.audit.records.length+' recorded actions. '+data.audit.limitation;
  const download=document.getElementById('ix-download');download.disabled=false;download.onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='safecadence-'+data.mode+'-sample.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};render();
}).catch(()=>{content.replaceChildren(el('p','Sample evidence could not load. Please reload the page.','error'));});
})();
"""


def register(app):
    from fastapi import HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    from safecadence.ui._chrome import wrap

    @app.get("/api/integration-demo/{mode}")
    def integration_data(mode: str):
        if mode not in ("security", "safety"):
            raise HTTPException(status_code=404, detail="Unknown demo")
        return JSONResponse(demo_snapshot(mode), headers={"Cache-Control": "no-store"})

    def page(mode):
        title = "NetRisk security integrations" if mode == "security" else "Public Safety integrations"
        subtitle = "Wazuh, CrowdSec, Zeek and Suricata evidence" if mode == "security" else "Camera presence, environmental events and reviewed brand exposure"
        body = _BODY.replace("__MODE__", mode).replace("__TITLE__", title).replace("__SUBTITLE__", subtitle).replace("__CLOCK__", REFERENCE_TIME)
        return HTMLResponse(wrap(title, body, _SCRIPT), headers={"Cache-Control": "no-store"})

    @app.get("/security-integrations", response_class=HTMLResponse)
    def security_page():
        return page("security")

    @app.get("/safety-integrations", response_class=HTMLResponse)
    def safety_page():
        return page("safety")
