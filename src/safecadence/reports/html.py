"""
Single-file HTML report renderer.

Pure-stdlib. The output is a complete, self-contained HTML page styled
to look like a professional consulting deliverable. Brand-able by editing
the inline CSS.
"""

from __future__ import annotations

import html as html_lib
from datetime import datetime

from safecadence.core.schema import Finding, ScanResult, Severity


_SEV_BADGE = {
    Severity.CRITICAL: ("CRITICAL", "#7f1d1d", "#fee2e2"),
    Severity.HIGH:     ("HIGH",     "#9a3412", "#ffedd5"),
    Severity.MEDIUM:   ("MEDIUM",   "#854d0e", "#fef3c7"),
    Severity.LOW:      ("LOW",      "#075985", "#e0f2fe"),
    Severity.INFO:     ("INFO",     "#374151", "#f3f4f6"),
}


_CSS = """
*,*::before,*::after { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 32px; background: #f8fafc; color: #0f172a; line-height: 1.55; }
.container { max-width: 1100px; margin: 0 auto; background: #fff; border-radius: 14px;
             box-shadow: 0 1px 3px rgba(0,0,0,.05), 0 8px 32px rgba(0,0,0,.04);
             overflow: hidden; }
header { background: linear-gradient(135deg,#0f172a,#1e3a8a); color: #fff; padding: 36px 40px; }
header h1 { margin: 0 0 6px; font-size: 28px; letter-spacing: -.01em; }
header .meta { color: #cbd5e1; font-size: 13px; }
section { padding: 28px 40px; border-top: 1px solid #f1f5f9; }
section h2 { margin: 0 0 18px; font-size: 18px; letter-spacing: -.01em; color: #0f172a; }
.kv { display: grid; grid-template-columns: 200px 1fr; gap: 6px 16px; font-size: 14px; }
.kv dt { color: #64748b; }
.kv dd { margin: 0; color: #0f172a; font-weight: 500; }
.scores { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.score-card { background: #f8fafc; border-radius: 10px; padding: 18px 22px; }
.score-card .label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .06em; }
.score-card .value { font-size: 40px; font-weight: 700; letter-spacing: -.02em; margin: 6px 0 4px; }
.score-card .band { font-size: 13px; color: #475569; }
.summary-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.pill { font-size: 12px; padding: 4px 10px; border-radius: 999px; }
.pill.crit { background: #fee2e2; color: #7f1d1d; }
.pill.high { background: #ffedd5; color: #9a3412; }
.pill.med  { background: #fef3c7; color: #854d0e; }
.pill.low  { background: #e0f2fe; color: #075985; }
.pill.info { background: #f3f4f6; color: #374151; }
.findings .finding { padding: 18px 0; border-bottom: 1px solid #f1f5f9; }
.findings .finding:last-child { border-bottom: 0; }
.finding-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.sev-badge { font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 4px;
             letter-spacing: .04em; }
.finding-title { font-size: 16px; font-weight: 600; margin: 0; }
.finding-rule { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                font-size: 12px; color: #64748b; }
.finding-body { margin-top: 8px; color: #1e293b; font-size: 14px; }
.finding-body h4 { margin: 14px 0 6px; font-size: 13px; text-transform: uppercase;
                   letter-spacing: .05em; color: #475569; }
.evidence { background: #f8fafc; border-left: 3px solid #cbd5e1; padding: 8px 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
            white-space: pre-wrap; word-break: break-word; border-radius: 4px; }
.code { background: #0f172a; color: #f1f5f9; padding: 12px 16px; border-radius: 6px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px;
        white-space: pre; overflow-x: auto; }
.refs { font-size: 12px; color: #475569; }
.refs a { color: #1d4ed8; text-decoration: none; }
.refs a:hover { text-decoration: underline; }
footer { padding: 20px 40px; color: #64748b; font-size: 12px; background: #f8fafc; }
@media print { body { background: #fff; padding: 0; } .container { box-shadow: none; } }
"""


def _esc(s: str) -> str:
    return html_lib.escape(s or "", quote=True)


def _finding_html(f: Finding) -> str:
    label, fg, bg = _SEV_BADGE[f.severity]
    out: list[str] = []
    out.append('<div class="finding">')
    out.append('  <div class="finding-head">')
    out.append(f'    <span class="sev-badge" style="color:{fg};background:{bg}">{label}</span>')
    out.append(f'    <h3 class="finding-title">{_esc(f.title)}</h3>')
    out.append(f'    <span class="finding-rule">{_esc(f.rule_id)}</span>')
    out.append('  </div>')
    out.append('  <div class="finding-body">')
    if f.description:
        out.append(f'    <p>{_esc(f.description.strip())}</p>')
    if f.evidence and f.evidence != "(absent)":
        out.append('    <h4>Evidence</h4>')
        out.append(f'    <div class="evidence">{_esc(f.evidence)}</div>')
    if f.remediation:
        out.append('    <h4>Remediation</h4>')
        out.append(f'    <p>{_esc(f.remediation.strip())}</p>')
    if f.fix_snippet:
        out.append('    <h4>Suggested config</h4>')
        out.append(f'    <pre class="code">{_esc(f.fix_snippet.strip())}</pre>')
    if f.references:
        out.append('    <h4>References</h4>')
        out.append('    <div class="refs">')
        for r in f.references:
            out.append(f'      <div><a href="{_esc(r)}" target="_blank" rel="noopener">{_esc(r)}</a></div>')
        out.append('    </div>')
    out.append('  </div>')
    out.append('</div>')
    return "\n".join(out)


def _summary_pills(result: ScanResult) -> str:
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    pills = [
        ("crit", f"{counts[Severity.CRITICAL]} critical"),
        ("high", f"{counts[Severity.HIGH]} high"),
        ("med",  f"{counts[Severity.MEDIUM]} medium"),
        ("low",  f"{counts[Severity.LOW]} low"),
        ("info", f"{counts[Severity.INFO]} info"),
    ]
    return '<div class="summary-pills">' + "".join(
        f'<span class="pill {cls}">{label}</span>' for cls, label in pills
    ) + '</div>'


def to_html(result: ScanResult) -> str:
    p = result.parsed
    title = f"SafeCadence Scan — {p.hostname or result.source}"
    findings_html = "\n".join(_finding_html(f) for f in result.findings) if result.findings else \
        '<p style="color:#16a34a">No findings — clean device or no rules matched.</p>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1>{_esc(title)}</h1>
    <div class="meta">Generated {datetime.fromisoformat(result.started_at.replace('Z','+00:00')).strftime('%B %d, %Y at %H:%M %Z') if result.started_at else ''} · SafeCadence Network Risk</div>
  </header>

  <section>
    <h2>Device</h2>
    <dl class="kv">
      <dt>Source</dt>      <dd>{_esc(result.source)}</dd>
      <dt>Vendor</dt>      <dd>{_esc(result.vendor)}</dd>
      <dt>Hostname</dt>    <dd>{_esc(p.hostname) or '—'}</dd>
      <dt>Model</dt>       <dd>{_esc(p.model) or '—'}</dd>
      <dt>OS</dt>          <dd>{_esc(p.os) or '—'}</dd>
      <dt>Version</dt>     <dd>{_esc(p.version) or '—'}</dd>
      <dt>Interfaces</dt>  <dd>{len(p.interfaces)}</dd>
      <dt>Neighbors</dt>   <dd>{len(p.neighbors)}</dd>
    </dl>
  </section>

  <section>
    <h2>Scores</h2>
    <div class="scores">
      <div class="score-card">
        <div class="label">Health</div>
        <div class="value">{result.health_score}<span style="font-size:18px;color:#94a3b8">/100</span></div>
        <div class="band">{_esc(result.health_band)}</div>
      </div>
      <div class="score-card">
        <div class="label">Risk</div>
        <div class="value">{result.risk_score}<span style="font-size:18px;color:#94a3b8">/100</span></div>
        <div class="band">{_esc(result.risk_band)}</div>
      </div>
    </div>
    {_summary_pills(result)}
  </section>

  <section class="findings">
    <h2>Findings ({len(result.findings)})</h2>
    {findings_html}
  </section>

  {_consulting_cta_html(result)}

  <footer>
    Generated by <a href="https://safecadence.com">SafeCadence Network Risk</a> —
    open source · MIT license · BYOK AI · zero data leaves your machine.
  </footer>
</div>
</body>
</html>"""


def _consulting_cta_html(result: ScanResult) -> str:
    """Show a consulting CTA when this scan is bad enough that a human should help."""
    crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    if not (result.risk_score >= 80 or crit_count >= 5):
        return ""
    return """
  <section style="background:linear-gradient(135deg,#7f1d1d,#b91c1c);color:#fff;padding:32px 40px">
    <h2 style="color:#fff;margin:0 0 10px;font-size:20px">Need help fixing these?</h2>
    <p style="margin:0 0 16px;color:#fee2e2;font-size:14px;line-height:1.55;max-width:680px">
      This device shows a critical risk profile. SafeCadence offers end-to-end
      remediation engagements: prioritized fix plan, implementation support,
      and post-change validation. We work with the same open-source engine you
      just ran — no lock-in, no SaaS, no data leaves your environment.
    </p>
    <a href="mailto:hello@safecadence.com?subject=SafeCadence%20Remediation%20-%20""" + _esc(result.parsed.hostname or result.source) + """"
       style="display:inline-block;background:#fff;color:#7f1d1d;padding:10px 20px;
              border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">
      Email hello@safecadence.com →
    </a>
    <a href="https://safecadence.com" target="_blank" rel="noopener"
       style="display:inline-block;color:#fee2e2;padding:10px 20px;
              text-decoration:none;font-size:14px">
      Learn more about SafeCadence →
    </a>
  </section>"""
