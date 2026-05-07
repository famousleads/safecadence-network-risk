"""Topology renderers — text, Mermaid, Graphviz DOT, interactive HTML."""

from __future__ import annotations

import html as html_lib
import json

from safecadence.topology.graph import Topology


# ---------------------------------------------------------------------- #
# Text — for terminal display
# ---------------------------------------------------------------------- #
def render_text(topo: Topology) -> str:
    lines: list[str] = []
    lines.append(f"Topology: {len(topo.nodes)} nodes, {len(topo.edges)} edges")
    lines.append("")
    lines.append("Nodes:")
    for n in sorted(topo.nodes.values(), key=lambda x: x.name):
        meta = []
        if n.vendor:   meta.append(n.vendor)
        if n.role:     meta.append(n.role)
        if n.ip:       meta.append(n.ip)
        m = "  [" + " · ".join(meta) + "]" if meta else ""
        lines.append(f"  • {n.name}{m}")
    lines.append("")
    lines.append("Links:")
    for e in topo.edges:
        lines.append(f"  {e.local_device}:{e.local_port}  ⇄  {e.remote_device}:{e.remote_port}")
    return "\n".join(lines)


# ---------------------------------------------------------------------- #
# Mermaid — pasteable into GitHub markdown, Notion, etc.
# ---------------------------------------------------------------------- #
def _mermaid_id(name: str) -> str:
    """Strip characters Mermaid won't tolerate as a node id."""
    out = "".join(c if c.isalnum() else "_" for c in name)
    return out.lstrip("_") or "n"


def render_mermaid(topo: Topology) -> str:
    lines = ["graph LR"]
    for n in topo.nodes.values():
        nid = _mermaid_id(n.name)
        label_meta = " · ".join(filter(None, [n.vendor, n.role]))
        if label_meta:
            label = f'{n.name}<br/><small>{label_meta}</small>'
        else:
            label = n.name
        # Use a different shape per role
        if n.role == "router":
            lines.append(f'    {nid}(["{label}"])')
        elif n.role == "firewall":
            lines.append(f'    {nid}[/"{label}"\\]')
        elif n.role == "wireless":
            lines.append(f'    {nid}(("{label}"))')
        else:
            lines.append(f'    {nid}["{label}"]')
    for e in topo.edges:
        a = _mermaid_id(e.local_device)
        b = _mermaid_id(e.remote_device)
        edge_label = f'"{e.local_port} ↔ {e.remote_port}"'.replace("|", "/")
        lines.append(f'    {a} ---|{edge_label}| {b}')
    return "\n".join(lines)


# ---------------------------------------------------------------------- #
# Graphviz DOT — render with `dot -Tpng topology.dot -o topology.png`
# ---------------------------------------------------------------------- #
_DOT_SHAPES = {
    "router":   "ellipse",
    "switch":   "box",
    "firewall": "octagon",
    "wireless": "doublecircle",
}
_DOT_COLORS = {
    "Cisco":              "#1ba0d7",
    "Cisco Meraki":       "#5c2d91",
    "Aruba":              "#ff6900",
    "Arista":             "#0066cc",
    "Juniper":            "#84bd00",
    "Fortinet":           "#ee2722",
    "Palo Alto Networks": "#fa582d",
    "MikroTik":           "#f37021",
    "Ubiquiti":           "#0559c9",
}


def render_dot(topo: Topology) -> str:
    lines = ['digraph SafeCadence {',
             '    rankdir=LR;',
             '    bgcolor="#f8fafc";',
             '    node [style=filled, fontname="Helvetica", fontsize=11, color="#cbd5e1"];',
             '    edge [fontname="Helvetica", fontsize=9, color="#64748b"];']
    for n in topo.nodes.values():
        nid = _mermaid_id(n.name)
        shape = _DOT_SHAPES.get(n.role, "box")
        color = _DOT_COLORS.get(n.vendor, "#e2e8f0")
        meta = " · ".join(filter(None, [n.vendor, n.role]))
        label = f"{n.name}\\n{meta}" if meta else n.name
        lines.append(f'    {nid} [shape={shape}, fillcolor="{color}", label="{label}"];')
    for e in topo.edges:
        a = _mermaid_id(e.local_device)
        b = _mermaid_id(e.remote_device)
        elabel = f"{e.local_port} ↔ {e.remote_port}"
        lines.append(f'    {a} -> {b} [dir=none, label="{elabel}"];')
    lines.append('}')
    return "\n".join(lines)


# ---------------------------------------------------------------------- #
# Interactive HTML — single self-contained file using vis-network from CDN
# ---------------------------------------------------------------------- #
def render_html(topo: Topology, *, title: str = "SafeCadence Topology") -> str:
    nodes_data = []
    for n in topo.nodes.values():
        nodes_data.append({
            "id": n.name,
            "label": n.name,
            "vendor": n.vendor,
            "role": n.role,
            "ip": n.ip,
            "color": _DOT_COLORS.get(n.vendor, "#e2e8f0"),
        })
    edges_data = []
    for e in topo.edges:
        edges_data.append({
            "from": e.local_device,
            "to":   e.remote_device,
            "label": f"{e.local_port} ↔ {e.remote_port}",
        })

    # Build the per-node detail payload: base info + any attached scan_result
    node_details: dict[str, dict] = {}
    for n in topo.nodes.values():
        base = {
            "name": n.name,
            "ip": n.ip,
            "vendor": n.vendor,
            "platform": n.platform,
            "role": n.role,
            "capabilities": list(n.capabilities),
            "neighbors": topo.neighbors_of(n.name),
            "ports": [
                {"local_port": e.local_port, "remote": e.remote_device, "remote_port": e.remote_port}
                for e in topo.edges if e.local_device == n.name
            ] + [
                {"local_port": e.remote_port, "remote": e.local_device, "remote_port": e.local_port}
                for e in topo.edges if e.remote_device == n.name
            ],
        }
        if n.name in topo.node_details:
            base["scan"] = topo.node_details[n.name]
        node_details[n.name] = base

    title_esc = html_lib.escape(title)
    nodes_json   = json.dumps(nodes_data, indent=2)
    edges_json   = json.dumps(edges_data, indent=2)
    details_json = json.dumps(node_details, indent=2, default=str)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_esc}</title>
<style>
  *,*::before,*::after {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0;
          background: #f8fafc; color: #0f172a; height: 100vh; overflow: hidden; }}
  header {{ padding: 14px 24px; background: #fff; border-bottom: 1px solid #e2e8f0; }}
  header h1 {{ margin: 0; font-size: 18px; }}
  header .meta {{ color: #64748b; font-size: 12px; margin-top: 2px; }}
  .layout {{ display: grid; grid-template-columns: 1fr 380px; height: calc(100vh - 60px); }}
  #network {{ background: #fff; border-right: 1px solid #e2e8f0; }}
  #panel {{ background: #fff; padding: 20px; overflow-y: auto; border-left: 1px solid #e2e8f0; }}
  #panel.empty {{ display: flex; align-items: center; justify-content: center; color: #94a3b8; font-size: 13px; }}
  .panel-head {{ border-bottom: 1px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 14px; }}
  .panel-head h2 {{ margin: 0 0 4px; font-size: 18px; }}
  .panel-head .sub {{ color: #64748b; font-size: 12px; }}
  .kv {{ display: grid; grid-template-columns: 100px 1fr; gap: 4px 12px; font-size: 13px; margin-bottom: 14px; }}
  .kv dt {{ color: #64748b; }}
  .kv dd {{ margin: 0; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .badge-green {{ background:#dcfce7; color:#14532d; }}
  .badge-yellow {{ background:#fef3c7; color:#854d0e; }}
  .badge-red {{ background:#fee2e2; color:#7f1d1d; }}
  .badge-gray {{ background:#f1f5f9; color:#475569; }}
  .scores {{ display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:14px; }}
  .score {{ background:#f8fafc; padding:10px 12px; border-radius:8px; }}
  .score .lbl {{ font-size:10px; text-transform:uppercase; color:#64748b; letter-spacing:.06em; }}
  .score .v {{ font-size:22px; font-weight:700; }}
  details {{ background: #f8fafc; border-radius: 6px; padding: 8px 12px; margin-bottom: 10px; }}
  details > summary {{ font-size: 12px; font-weight: 600; cursor: pointer; color: #475569;
                        text-transform: uppercase; letter-spacing: .04em; padding: 4px 0; }}
  details[open] > summary {{ color: #0f172a; }}
  pre {{ background: #0f172a; color: #f1f5f9; padding: 10px 12px; border-radius: 6px;
         font-family: ui-monospace, Menlo, monospace; font-size: 11px; line-height: 1.45;
         max-height: 360px; overflow: auto; white-space: pre; }}
  .finding {{ font-size: 12px; padding: 6px 0; border-bottom: 1px solid #f1f5f9; }}
  .finding:last-child {{ border-bottom: 0; }}
  .finding .sev {{ font-size:10px; font-weight:700; padding:1px 6px; border-radius:3px; margin-right:6px; }}
  .sev-critical {{ background:#fee2e2; color:#7f1d1d; }}
  .sev-high     {{ background:#ffedd5; color:#9a3412; }}
  .sev-medium   {{ background:#fef3c7; color:#854d0e; }}
  .sev-low      {{ background:#e0f2fe; color:#075985; }}
  .sev-info     {{ background:#f3f4f6; color:#374151; }}
  .cve {{ font-size: 12px; padding: 6px 0; border-bottom: 1px solid #f1f5f9; }}
  .cve:last-child {{ border-bottom: 0; }}
  .cve a {{ color: #1d4ed8; text-decoration: none; }}
  .cve a:hover {{ text-decoration: underline; }}
  .cve .kev {{ background: #fee2e2; color: #7f1d1d; padding: 1px 6px; border-radius: 3px;
                font-size: 9px; font-weight: 700; margin-left: 6px; }}
  .ports-table {{ width: 100%; font-size: 12px; border-collapse: collapse; }}
  .ports-table td {{ padding: 4px 6px; border-bottom: 1px solid #f1f5f9; }}
  .empty-msg {{ color: #94a3b8; font-size: 12px; }}
  @media (max-width: 800px) {{ .layout {{ grid-template-columns: 1fr; }} #panel {{ display: none; }} }}
  /* SVG graph */
  #network {{ position: relative; }}
  #network svg {{ width: 100%; height: 100%; cursor: grab; user-select: none; }}
  #network svg:active {{ cursor: grabbing; }}
  .edge {{ stroke: #94a3b8; stroke-width: 2; }}
  .edge-label {{ fill: #64748b; font-size: 9px; pointer-events: none;
                  paint-order: stroke; stroke: #fff; stroke-width: 3; }}
  .node circle, .node rect, .node polygon {{ stroke: #1e293b; stroke-width: 1.5;
                                              cursor: pointer; transition: stroke-width .12s; }}
  .node:hover circle, .node:hover rect, .node:hover polygon {{ stroke-width: 3; }}
  .node.selected circle, .node.selected rect, .node.selected polygon {{ stroke: #0ea5e9; stroke-width: 3; }}
  .node text {{ fill: #0f172a; font-size: 11px; font-weight: 600; pointer-events: none; text-anchor: middle; }}
  .legend {{ position:absolute; bottom:8px; left:8px; background:rgba(255,255,255,.9);
              border:1px solid #e2e8f0; border-radius:6px; padding:6px 10px; font-size:11px; }}
</style>
</head>
<body>
  <header>
    <h1>{title_esc}</h1>
    <div class="meta">{len(topo.nodes)} nodes · {len(topo.edges)} links · <strong>double-click any node</strong> for full details · drag to reposition · scroll to zoom</div>
  </header>
  <div class="layout">
    <div id="network"></div>
    <div id="panel" class="empty">Double-click a node to see its details, scan results, CVEs, EOL status, and running config.</div>
  </div>

<script>
const NODE_DETAILS = {details_json};
const NODES = {nodes_json};
const EDGES = {edges_json};

// =============================================================== //
// Pure-SVG force-directed graph — no external dependencies        //
// =============================================================== //
(function buildGraph() {{
  const container = document.getElementById('network');
  const W = container.clientWidth, H = container.clientHeight;
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  container.appendChild(svg);

  // Initialize positions in a circle
  const nodeMap = {{}};
  const cx = W/2, cy = H/2, R = Math.min(W, H) * 0.32;
  NODES.forEach((n, i) => {{
    const angle = (i / NODES.length) * Math.PI * 2;
    nodeMap[n.id] = {{
      ...n,
      x: cx + R * Math.cos(angle),
      y: cy + R * Math.sin(angle),
      vx: 0, vy: 0,
      fixed: false,
    }};
  }});
  const nodeList = Object.values(nodeMap);

  // Force-directed simulation
  function simulate(iterations) {{
    const k = 200, kr = 24000;
    for (let it = 0; it < iterations; it++) {{
      // Repulsive
      for (let i = 0; i < nodeList.length; i++) {{
        for (let j = i+1; j < nodeList.length; j++) {{
          const a = nodeList[i], b = nodeList[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx*dx + dy*dy + 0.01;
          let f = kr / d2;
          let d = Math.sqrt(d2);
          a.vx += (dx/d) * f; a.vy += (dy/d) * f;
          b.vx -= (dx/d) * f; b.vy -= (dy/d) * f;
        }}
      }}
      // Spring (edges)
      EDGES.forEach(e => {{
        const a = nodeMap[e.from], b = nodeMap[e.to];
        if (!a || !b) return;
        let dx = b.x - a.x, dy = b.y - a.y;
        let d = Math.sqrt(dx*dx + dy*dy) + 0.01;
        let f = (d - k) * 0.05;
        a.vx += (dx/d) * f; a.vy += (dy/d) * f;
        b.vx -= (dx/d) * f; b.vy -= (dy/d) * f;
      }});
      // Apply velocity with damping; clamp to viewport
      nodeList.forEach(n => {{
        if (n.fixed) {{ n.vx = 0; n.vy = 0; return; }}
        n.x += n.vx * 0.04; n.y += n.vy * 0.04;
        n.vx *= 0.85; n.vy *= 0.85;
        n.x = Math.max(40, Math.min(W-40, n.x));
        n.y = Math.max(40, Math.min(H-40, n.y));
      }});
    }}
  }}
  simulate(220);

  // Draw edges
  const edgeEls = [];
  EDGES.forEach(e => {{
    const a = nodeMap[e.from], b = nodeMap[e.to];
    if (!a || !b) return;
    const line = document.createElementNS(svgNS, 'line');
    line.setAttribute('class', 'edge');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    svg.appendChild(line);
    const mx = (a.x + b.x)/2, my = (a.y + b.y)/2;
    const txt = document.createElementNS(svgNS, 'text');
    txt.setAttribute('class', 'edge-label');
    txt.setAttribute('x', mx); txt.setAttribute('y', my);
    txt.setAttribute('text-anchor', 'middle');
    txt.textContent = e.label.length > 20 ? e.label.slice(0, 20) + '…' : e.label;
    svg.appendChild(txt);
    edgeEls.push({{ line, txt, a, b }});
  }});

  // Draw nodes
  const nodeEls = {{}};
  function drawNode(n) {{
    const g = document.createElementNS(svgNS, 'g');
    g.setAttribute('class', 'node');
    g.setAttribute('data-id', n.id);
    g.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')');
    let shape;
    if (n.role === 'router') {{
      shape = document.createElementNS(svgNS, 'polygon');
      shape.setAttribute('points', '0,-22 22,0 0,22 -22,0');   // diamond
    }} else if (n.role === 'firewall') {{
      shape = document.createElementNS(svgNS, 'polygon');
      // hexagon
      const pts = [];
      for (let k=0; k<6; k++) {{
        const a = Math.PI/3 * k - Math.PI/2;
        pts.push((22*Math.cos(a)).toFixed(1) + ',' + (22*Math.sin(a)).toFixed(1));
      }}
      shape.setAttribute('points', pts.join(' '));
    }} else if (n.role === 'wireless') {{
      shape = document.createElementNS(svgNS, 'circle');
      shape.setAttribute('r', 18);
    }} else {{
      shape = document.createElementNS(svgNS, 'rect');
      shape.setAttribute('x', -28); shape.setAttribute('y', -18);
      shape.setAttribute('width', 56); shape.setAttribute('height', 36);
      shape.setAttribute('rx', 5);
    }}
    shape.setAttribute('fill', n.color || '#e2e8f0');
    g.appendChild(shape);
    const lbl = document.createElementNS(svgNS, 'text');
    lbl.setAttribute('y', 36);
    lbl.textContent = n.id.length > 16 ? n.id.slice(0, 16) + '…' : n.id;
    g.appendChild(lbl);
    svg.appendChild(g);
    nodeEls[n.id] = g;
    // Tooltip
    const ttl = document.createElementNS(svgNS, 'title');
    ttl.textContent = [n.id, n.vendor, n.role, n.ip].filter(Boolean).join(' · ');
    g.appendChild(ttl);
  }}
  nodeList.forEach(drawNode);

  // Drag handling
  let dragging = null, dragOffset = {{x:0, y:0}};
  function svgPoint(evt) {{
    const r = svg.getBoundingClientRect();
    return {{ x: (evt.clientX - r.left) * W / r.width,
             y: (evt.clientY - r.top)  * H / r.height }};
  }}
  function refreshPositions() {{
    Object.entries(nodeEls).forEach(([id, g]) => {{
      const n = nodeMap[id];
      g.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')');
    }});
    edgeEls.forEach(({{ line, txt, a, b }}) => {{
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
      txt.setAttribute('x', (a.x + b.x)/2);
      txt.setAttribute('y', (a.y + b.y)/2);
    }});
  }}
  svg.addEventListener('mousedown', e => {{
    const g = e.target.closest('.node');
    if (!g) return;
    e.preventDefault();
    const id = g.dataset.id;
    dragging = nodeMap[id];
    const p = svgPoint(e);
    dragOffset = {{ x: p.x - dragging.x, y: p.y - dragging.y }};
  }});
  window.addEventListener('mousemove', e => {{
    if (!dragging) return;
    const p = svgPoint(e);
    dragging.x = p.x - dragOffset.x;
    dragging.y = p.y - dragOffset.y;
    refreshPositions();
  }});
  window.addEventListener('mouseup', () => {{ dragging = null; }});

  // Click + double-click
  let lastClickTime = 0, lastClickId = null;
  svg.addEventListener('click', e => {{
    const g = e.target.closest('.node');
    if (!g) return;
    const id = g.dataset.id;
    Object.values(nodeEls).forEach(el => el.classList.remove('selected'));
    g.classList.add('selected');
    const now = Date.now();
    if (lastClickId === id && (now - lastClickTime) < 350) {{
      renderPanel(id);
      lastClickId = null;
    }} else {{
      renderPanel(id);   // also show on single click for convenience
      lastClickTime = now; lastClickId = id;
    }}
  }});

  // Legend
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = '◆ router · ⬢ firewall · ● wireless · ▭ switch';
  container.appendChild(legend);
}})();

function escapeHtml(s) {{
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => (
    {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]
  ));
}}

function bandClass(band) {{
  if (!band) return 'badge-gray';
  if (band === 'critical' || band === 'end-of-support' || band === 'poor') return 'badge-red';
  if (band === 'high' || band === 'end-of-software' || band === 'warning') return 'badge-yellow';
  if (band === 'low' || band === 'good' || band === 'excellent' || band === 'supported') return 'badge-green';
  return 'badge-gray';
}}

function renderPanel(nodeId) {{
  const d = NODE_DETAILS[nodeId];
  const panel = document.getElementById('panel');
  panel.classList.remove('empty');
  if (!d) {{
    panel.innerHTML = '<div class="empty-msg">No details for ' + escapeHtml(nodeId) + '</div>';
    return;
  }}

  let html = '';
  html += '<div class="panel-head">';
  html += '  <h2>' + escapeHtml(d.name) + '</h2>';
  html += '  <div class="sub">' + escapeHtml([d.vendor, d.role, d.ip].filter(Boolean).join(' · ')) + '</div>';
  html += '</div>';

  // Base device info
  html += '<dl class="kv">';
  if (d.ip)        html += '<dt>IP</dt><dd>' + escapeHtml(d.ip) + '</dd>';
  if (d.vendor)    html += '<dt>Vendor</dt><dd>' + escapeHtml(d.vendor) + '</dd>';
  if (d.role)      html += '<dt>Role</dt><dd>' + escapeHtml(d.role) + '</dd>';
  if (d.platform)  html += '<dt>Platform</dt><dd>' + escapeHtml(d.platform) + '</dd>';
  if (d.capabilities && d.capabilities.length)
    html += '<dt>Capabilities</dt><dd>' + escapeHtml(d.capabilities.join(', ')) + '</dd>';
  if (d.neighbors && d.neighbors.length)
    html += '<dt>Neighbors</dt><dd>' + escapeHtml(d.neighbors.join(', ')) + '</dd>';
  html += '</dl>';

  // Scan-derived data, if a scan result was attached
  const scan = d.scan;
  if (scan) {{
    // Scores
    html += '<div class="scores">';
    html += '  <div class="score"><div class="lbl">Health</div><div class="v">' + (scan.health_score|0) + '/100</div>';
    html += '    <span class="badge ' + bandClass(scan.health_band) + '">' + escapeHtml(scan.health_band || '') + '</span></div>';
    html += '  <div class="score"><div class="lbl">Risk</div><div class="v">' + (scan.risk_score|0) + '/100</div>';
    html += '    <span class="badge ' + bandClass(scan.risk_band) + '">' + escapeHtml(scan.risk_band || '') + '</span></div>';
    html += '</div>';

    // EOL
    if (scan.eol) {{
      const st = scan.eol.status_today || '';
      html += '<details open><summary>End-of-life status</summary>';
      html += '<dl class="kv">';
      html += '  <dt>Status</dt><dd><span class="badge ' + bandClass(st) + '">' + escapeHtml(st) + '</span></dd>';
      if (scan.eol.end_of_software) html += '<dt>End-of-SW</dt><dd>' + escapeHtml(scan.eol.end_of_software) + '</dd>';
      if (scan.eol.end_of_support)  html += '<dt>End-of-supp</dt><dd>' + escapeHtml(scan.eol.end_of_support) + '</dd>';
      if (scan.eol.notes) html += '<dt>Notes</dt><dd>' + escapeHtml(scan.eol.notes) + '</dd>';
      html += '</dl></details>';
    }}

    // CVEs
    if (scan.cves && scan.cves.length) {{
      html += '<details open><summary>CVEs (' + scan.cves.length + ')</summary>';
      scan.cves.forEach(c => {{
        html += '<div class="cve">';
        html += '  <span class="sev sev-' + escapeHtml(c.severity) + '">' + escapeHtml(c.severity.toUpperCase()) + '</span>';
        html += '  <strong>' + escapeHtml(c.cve_id) + '</strong>';
        if (c.kev) html += '<span class="kev">KEV</span>';
        if (c.cvss) html += ' <span style="color:#64748b">CVSS ' + c.cvss + '</span>';
        if (c.title) html += '<div style="margin-top:3px">' + escapeHtml(c.title) + '</div>';
        if (c.references && c.references.length) {{
          html += '<div style="margin-top:3px">';
          c.references.forEach(r => {{ html += '<a href="' + escapeHtml(r) + '" target="_blank">link</a> '; }});
          html += '</div>';
        }}
        html += '</div>';
      }});
      html += '</details>';
    }}

    // Findings
    if (scan.findings && scan.findings.length) {{
      html += '<details open><summary>Findings (' + scan.findings.length + ')</summary>';
      scan.findings.forEach(f => {{
        html += '<div class="finding">';
        html += '  <span class="sev sev-' + escapeHtml(f.severity) + '">' + escapeHtml(f.severity.toUpperCase()) + '</span>';
        html += '  ' + escapeHtml(f.title);
        html += '  <div style="color:#64748b;font-size:11px;margin-top:2px">' + escapeHtml(f.rule_id) + '</div>';
        html += '</div>';
      }});
      html += '</details>';
    }}

    // Asset interfaces
    if (scan.asset && scan.asset.interfaces && scan.asset.interfaces.length) {{
      html += '<details><summary>Interfaces (' + scan.asset.interfaces.length + ')</summary>';
      html += '<table class="ports-table">';
      scan.asset.interfaces.forEach(i => {{
        const up = i.admin_up !== false;
        html += '<tr><td>' + escapeHtml(i.name) + '</td>';
        html += '<td>' + escapeHtml(i.ip || '') + '</td>';
        html += '<td>' + (i.vlan ? 'vlan ' + i.vlan : '') + '</td>';
        html += '<td><span class="badge ' + (up ? 'badge-green' : 'badge-gray') + '">' + (up ? 'up' : 'shut') + '</span></td>';
        html += '</tr>';
      }});
      html += '</table></details>';
    }}

    // Running config — full text in a collapsible block
    if (scan.asset && scan.parsed_summary) {{
      // Look for raw_config — we store it under asset since asset has parsed
      // But our schema puts it on parsed not asset. Try both.
    }}
    const cfg = (scan.parsed_raw || (scan.asset && scan.asset.raw_config) || scan.raw_config || '');
    if (cfg) {{
      html += '<details><summary>Running config (' + cfg.length + ' bytes)</summary>';
      html += '<pre>' + escapeHtml(cfg) + '</pre>';
      html += '</details>';
    }}
  }} else {{
    html += '<div class="empty-msg">No scan attached for this node. Use ';
    html += '<code>safecadence topology --scans &lt;dir&gt;</code> ';
    html += 'to attach scan-result JSON files (matched by hostname / IP).</div>';
  }}

  // Local LLDP-discovered ports
  if (d.ports && d.ports.length) {{
    html += '<details><summary>Discovered LLDP links (' + d.ports.length + ')</summary>';
    html += '<table class="ports-table">';
    d.ports.forEach(p => {{
      html += '<tr><td>' + escapeHtml(p.local_port) + '</td>';
      html += '<td>↔ ' + escapeHtml(p.remote) + ':' + escapeHtml(p.remote_port) + '</td></tr>';
    }});
    html += '</table></details>';
  }}

  panel.innerHTML = html;
}}

network.on('doubleClick', params => {{
  if (params.nodes && params.nodes.length) {{
    renderPanel(params.nodes[0]);
  }}
}});
network.on('selectNode', params => {{
  if (params.nodes && params.nodes.length) {{
    renderPanel(params.nodes[0]);
  }}
}});
</script>
</body>
</html>"""
