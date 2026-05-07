"""
Attack-path HTML visualization — force-directed graph, single file, no CDN.

Renders the output of platform.attack_paths.blast_radius() as an interactive
SVG: drag nodes, click for details, color-coded by criticality, edge labels
explain the "via" reason. Pure vanilla JS, fits in one HTML doc, works
fully offline (air-gap friendly).
"""

from __future__ import annotations

import json
from typing import Any


def render_attack_path_viz(blast_result: dict[str, Any], *,
                           title: str = "SafeCadence Attack Path") -> str:
    """Build a self-contained HTML page that visualizes the blast-radius result."""
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    start = blast_result.get("start") or "start"
    nodes.append({"id": start, "kind": "start", "type": "internet" if start == "internet" else "asset",
                  "criticality": "high", "label": start})
    seen.add(start)

    for p in blast_result.get("paths") or []:
        aid = p.get("asset_id")
        if not aid or aid in seen: continue
        seen.add(aid)
        nodes.append({
            "id": aid,
            "kind": "reached",
            "type": p.get("asset_type", "unknown"),
            "criticality": (p.get("criticality") or "").lower(),
            "kev_cves": p.get("kev_cves", 0),
            "label": aid,
            "hops": p.get("hops"),
        })
        for hop in p.get("path") or []:
            edges.append({"source": hop["from"], "target": hop["to"],
                           "via": hop.get("via", "")})

    data_json = json.dumps({"nodes": nodes, "edges": edges,
                             "summary": blast_result.get("summary", "")},
                            separators=(",", ":"))

    return _TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data_json)


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>__TITLE__</title>
<style>
  :root { --bg:#0b1020; --panel:#121a33; --ink:#e7ecf5; --muted:#8b95b1;
          --good:#36d399; --warn:#f6c04d; --bad:#ef4f4f; --crit:#ff3b3b;
          --border:#26315b; --accent:#7c5cff; }
  * { box-sizing:border-box; }
  html,body { margin:0; padding:0; background:var(--bg); color:var(--ink);
              font:13px -apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif; }
  header { padding:14px 22px; border-bottom:1px solid var(--border);
           display:flex; align-items:center; gap:18px; background:#0a1029; }
  header h1 { font-size:15px; margin:0; font-weight:600; letter-spacing:.4px; }
  header .badge { font-size:11px; padding:2px 8px; border:1px solid var(--border);
                  border-radius:999px; color:var(--muted); }
  .stage { display:grid; grid-template-columns:1fr 320px; height:calc(100vh - 50px); }
  svg { width:100%; height:100%; cursor:grab; background:radial-gradient(ellipse at center,#101733 0%,#0b1020 100%); }
  svg:active { cursor:grabbing; }
  .node circle { stroke:#fff; stroke-width:1.5; cursor:pointer; }
  .node text { fill:#e7ecf5; font-size:11px; pointer-events:none;
               text-shadow:0 0 3px #0b1020,0 0 3px #0b1020; }
  .edge { stroke:#5a6b9a; stroke-width:1; opacity:.5; }
  .edge.hi { stroke:var(--accent); stroke-width:2; opacity:1; }
  .edge-label { fill:#8b95b1; font-size:9px; pointer-events:none; }
  .sidebar { background:var(--panel); border-left:1px solid var(--border);
             padding:18px 20px; overflow-y:auto; }
  .sidebar h2 { font-size:13px; color:var(--muted); text-transform:uppercase;
                letter-spacing:.6px; margin:0 0 10px; }
  .sidebar .summary { background:#0a1029; border:1px solid var(--border);
                       border-radius:8px; padding:10px 12px; font-size:12px; line-height:1.5; }
  .sidebar .legend { margin-top:14px; }
  .sidebar .legend div { display:flex; align-items:center; gap:8px; padding:3px 0; font-size:12px; }
  .sidebar .legend span.swatch { width:12px; height:12px; border-radius:50%;
                                  border:1px solid #fff; }
  .sidebar #detail { margin-top:18px; font-size:12px; line-height:1.5; }
  .sidebar #detail h3 { font-size:12px; margin:6px 0 4px; color:var(--ink); }
  .sidebar #detail .row { display:flex; justify-content:space-between;
                           border-bottom:1px solid var(--border); padding:4px 0; color:var(--muted); }
  .sidebar #detail .row span:last-child { color:var(--ink); font-weight:500; }
</style>
</head>
<body>
<header>
  <h1>SafeCadence Attack-Path Graph</h1>
  <span class="badge">force-directed · drag to move · click for detail</span>
  <span class="badge" style="margin-left:auto">v6.1</span>
</header>
<div class="stage">
  <svg id="svg"></svg>
  <aside class="sidebar">
    <h2>Summary</h2>
    <div class="summary" id="summary"></div>
    <div class="legend">
      <h2 style="margin-top:14px">Legend</h2>
      <div><span class="swatch" style="background:#7c5cff"></span> Start (compromised entry)</div>
      <div><span class="swatch" style="background:#ff3b3b"></span> Crown jewel reached</div>
      <div><span class="swatch" style="background:#ef4f4f"></span> Has KEV CVE</div>
      <div><span class="swatch" style="background:#36d399"></span> Reached, low risk</div>
      <div><span class="swatch" style="background:#5a6b9a"></span> Reached, unknown</div>
    </div>
    <div id="detail">
      <h2 style="margin-top:18px">Selected node</h2>
      <p style="color:var(--muted)">Click any node to see details + the path that gets the attacker there.</p>
    </div>
  </aside>
</div>

<script>
const DATA = __DATA__;
document.getElementById('summary').textContent = DATA.summary || 'No summary.';

const svg = document.getElementById('svg');
const W = svg.clientWidth, H = svg.clientHeight;

// Color by node properties
const nodeColor = n => {
  if (n.kind === 'start') return '#7c5cff';
  if ((n.criticality || '') === 'crown-jewel') return '#ff3b3b';
  if ((n.kev_cves || 0) > 0) return '#ef4f4f';
  if ((n.hops || 0) >= 3) return '#f6c04d';
  return '#36d399';
};

// --- minimal force-directed layout (vanilla, no d3) ---
const nodes = DATA.nodes.map((n,i) => ({
  ...n, x: W/2 + Math.cos(i*0.9)*120, y: H/2 + Math.sin(i*0.9)*120, vx:0, vy:0,
}));
const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));
const edges = (DATA.edges || []).map(e => ({...e, source: nodeMap[e.source], target: nodeMap[e.target]})).filter(e => e.source && e.target);

const REPULSE = 8000, ATTRACT = 0.01, CENTER = 0.005, FRICTION = 0.85;
function tick() {
  // repulsion
  for (let i=0;i<nodes.length;i++) for (let j=i+1;j<nodes.length;j++) {
    const a = nodes[i], b = nodes[j];
    const dx = a.x-b.x, dy = a.y-b.y; const d2 = dx*dx + dy*dy + 1;
    const f = REPULSE / d2;
    const fx = f*dx/Math.sqrt(d2), fy = f*dy/Math.sqrt(d2);
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  }
  // attraction along edges
  for (const e of edges) {
    const dx = e.target.x - e.source.x, dy = e.target.y - e.source.y;
    e.source.vx += dx * ATTRACT; e.source.vy += dy * ATTRACT;
    e.target.vx -= dx * ATTRACT; e.target.vy -= dy * ATTRACT;
  }
  // gravity to center
  for (const n of nodes) {
    n.vx += (W/2 - n.x) * CENTER;
    n.vy += (H/2 - n.y) * CENTER;
    n.vx *= FRICTION; n.vy *= FRICTION;
    if (!n.dragging) { n.x += n.vx; n.y += n.vy; }
  }
}

let selected = null;
function render() {
  const ns = 'http://www.w3.org/2000/svg';
  // edges
  const edgeEls = edges.map((e,i) => {
    const hi = selected && (selected === e.source.id || selected === e.target.id);
    return `<line class="edge ${hi?'hi':''}" x1="${e.source.x}" y1="${e.source.y}" x2="${e.target.x}" y2="${e.target.y}"/>`;
  }).join('');
  // nodes
  const nodeEls = nodes.map(n => {
    const r = n.kind === 'start' ? 18 : 10 + ((n.kev_cves||0)*2);
    return `<g class="node" data-id="${n.id}" transform="translate(${n.x},${n.y})">
      <circle r="${r}" fill="${nodeColor(n)}" />
      <text x="${r+4}" y="3">${n.label}</text>
    </g>`;
  }).join('');
  svg.innerHTML = edgeEls + nodeEls;
  // wire click + drag
  svg.querySelectorAll('.node').forEach(g => {
    const id = g.dataset.id;
    g.addEventListener('click', e => { e.stopPropagation(); selectNode(id); });
    g.addEventListener('mousedown', e => {
      const n = nodeMap[id]; n.dragging = true;
      const move = ev => {
        const rect = svg.getBoundingClientRect();
        n.x = ev.clientX - rect.left; n.y = ev.clientY - rect.top;
      };
      const up = () => { n.dragging = false; window.removeEventListener('mousemove', move);
                          window.removeEventListener('mouseup', up); };
      window.addEventListener('mousemove', move); window.addEventListener('mouseup', up);
    });
  });
}

function selectNode(id) {
  selected = id;
  const n = nodeMap[id]; if (!n) return;
  const path = (DATA.edges||[]).filter(e => e.target === id || e.source === id);
  let html = `<h2 style="margin-top:18px">Selected node</h2>
    <h3>${n.label}</h3>
    <div class="row"><span>type</span><span>${n.type||'?'}</span></div>
    <div class="row"><span>kind</span><span>${n.kind}</span></div>
    <div class="row"><span>hops</span><span>${n.hops==null?'—':n.hops}</span></div>
    <div class="row"><span>criticality</span><span>${n.criticality||'—'}</span></div>
    <div class="row"><span>KEV CVEs</span><span>${n.kev_cves||0}</span></div>`;
  if (path.length) {
    html += `<h3 style="margin-top:10px">Edges</h3>`;
    for (const p of path) {
      const other = p.target === id ? p.source : p.target;
      html += `<div class="row"><span>${p.target===id?'← from':'→ to'} ${other}</span><span>${p.via}</span></div>`;
    }
  }
  document.getElementById('detail').innerHTML = html;
}

(function loop(){ tick(); render(); requestAnimationFrame(loop); })();
</script>
</body>
</html>
"""
