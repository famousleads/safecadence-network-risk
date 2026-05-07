"""
v7.7.1 — Tool Hub.

Single page at /hub that shows every SafeCadence capability grouped
by what the operator is trying to do. Each entry knows its name,
what it solves, and which other tools it commonly precedes or
follows in a workflow.

Designed to:
  * Replace "what does this product even have?" confusion
  * Make discovery sub-30-seconds for a new operator
  * Surface cross-links — every tool says "try this next"
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Tool:
    name: str
    icon: str
    blurb: str
    use_when: str           # plain-English prompt for "is this what I need?"
    href: str               # path or anchor
    related: list[str]      # names of related tools (loose match)
    cli: str = ""           # CLI command if there's one


HUB_TOOLS: list[tuple[str, list[Tool]]] = [

    # ---- Discover ---------------------------------------------------
    ("🔭 Discover & Inventory", [
        Tool(
            name="Inventory",
            icon="📋",
            blurb="Every device, identity, and NHI in one searchable list.",
            use_when="You want to see what's connected.",
            href="/#inventory",
            related=["Topology", "Onboarding wizard", "CSV importer"],
        ),
        Tool(
            name="Topology",
            icon="🗺️",
            blurb="9 named graph views — global, security-zone, lifecycle, "
                  "risk heat, KEV, etc.",
            use_when="You need to see the network and identity graph visually.",
            href="/#topology",
            related=["Inventory", "Identity attack paths"],
        ),
        Tool(
            name="Onboarding wizard",
            icon="🧭",
            blurb="Guided path to add real assets — CSV, scan, cloud, manual.",
            use_when="You're starting from zero and need to load real data.",
            href="/#onboarding",
            related=["Inventory", "CSV importer"],
            cli="safecadence onboard",
        ),
        Tool(
            name="CSV importer",
            icon="📥",
            blurb="Bulk-load assets or credentials from a spreadsheet.",
            use_when="You have a CMDB / asset list to import.",
            href="/#inventory",
            cli="safecadence import-assets file.csv",
            related=["Inventory", "Onboarding wizard"],
        ),
    ]),

    # ---- Comply -----------------------------------------------------
    ("📐 Policy & Compliance", [
        Tool(
            name="Policy Builder (5-step wizard)",
            icon="🪄",
            blurb="Build a policy from intent → controls → asset selection → "
                  "approvals → schedule.",
            use_when="You want to define a new compliance / hardening policy.",
            href="/#builder",
            related=["Compliance", "Drift", "Identity translator"],
            cli="safecadence policy create",
        ),
        Tool(
            name="Compliance dashboard",
            icon="✅",
            blurb="Per-policy pass/fail, drift counts, top failures, "
                  "executive-briefing card.",
            use_when="You need a fleet-wide compliance snapshot right now.",
            href="/#compliance",
            related=["Policy Builder", "Drift", "Evidence pack",
                      "Per-device diff"],
            cli="safecadence policy briefing",
        ),
        Tool(
            name="Drift",
            icon="📉",
            blurb="Cross-system drift detector (17 detectors) + per-policy "
                  "drift over time.",
            use_when="Two systems disagree, or compliance moved.",
            href="/#drift",
            related=["Compliance", "Conflict resolution",
                      "Identity who-can"],
            cli="safecadence policy drift-cross-system",
        ),
        Tool(
            name="Per-device diff",
            icon="🔍",
            blurb="Side-by-side: declared policy vs running config for "
                  "any single device.",
            use_when="A device is failing a policy — show me exactly what's wrong.",
            href="/#device-diff",
            related=["Compliance", "Inventory"],
        ),
        Tool(
            name="Evidence pack (compliance)",
            icon="📑",
            blurb="One-click PDF/CSV evidence for SOC 2 / ISO27001 / NIST 800-53.",
            use_when="Auditor asked for a compliance snapshot.",
            href="/#reports",
            cli="safecadence evidence-pack --framework soc2",
            related=["Compliance", "Identity evidence pack"],
        ),
        Tool(
            name="Remediation export",
            icon="🩹",
            blurb="Generate the per-vendor commands that fix a finding "
                  "(Ansible / Terraform / raw / Markdown / PowerShell).",
            use_when="You want to hand a fix to the existing automation team.",
            href="/#remediation",
            related=["Compliance", "Per-device diff", "Command Center"],
        ),
    ]),

    # ---- Identity ---------------------------------------------------
    ("🔐 Identity Intelligence", [
        Tool(
            name="Identity translator (NL → IR)",
            icon="🧠",
            blurb="Plain English → unified policy IR → preview → apply across "
                  "Cisco ISE, ClearPass, AD, Entra, Okta.",
            use_when="You want to express a single intent and have it enforced "
                  "across all 5 identity systems.",
            href="/identity",
            cli="safecadence identity translate \"...\"",
            related=["Identity preview", "Identity apply",
                      "Conflict resolution"],
        ),
        Tool(
            name="Effective-permission lookup (who-can)",
            icon="🔎",
            blurb="Compose ALL connected identity systems and answer "
                  '"can principal X do action Y on resource Z right now?"',
            use_when="You're investigating an incident or a permission question.",
            href="/identity#wc-principal",
            cli="safecadence identity who-can ssh prod-db --as alice@x",
            related=["Identity translator", "Identity attack paths"],
        ),
        Tool(
            name="Identity findings",
            icon="🚩",
            blurb="Stale NHIs, no-MFA tenants, over-privileged principals, "
                  "orphan service accounts.",
            use_when="You want to proactively clean up identity hygiene.",
            href="/identity#findings-tbl",
            related=["Identity attack paths", "Identity remediation",
                      "JIT"],
        ),
        Tool(
            name="Identity attack paths",
            icon="🎯",
            blurb="Human → group → SA → role → asset chains, ranked by reach.",
            use_when='You need to find "Alice → BuildBot → AdminRole → '
                  'crown-jewel" type chains.',
            href="/identity#paths-tbl",
            related=["Identity remediation", "Topology",
                      "Identity findings"],
        ),
        Tool(
            name="Identity remediation",
            icon="✂️",
            blurb="Given an attack path, generate the IR that severs it.",
            use_when="You found an attack path and want the fix.",
            href="/identity#paths-tbl",
            related=["Identity attack paths", "Identity translator"],
        ),
        Tool(
            name="JIT access grants",
            icon="⏱️",
            blurb="Time-bounded access grants with auto-revoke.",
            use_when='Someone needs prod-db read access for "the next 4 hours".',
            href="/identity#jit-tbl",
            cli="safecadence identity jit grant ...",
            related=["Identity translator", "Audit trail"],
        ),
        Tool(
            name="Conflict resolution policy",
            icon="⚖️",
            blurb='Configurable precedence — "AD wins over Okta on prod" — '
                  "applied when systems disagree.",
            use_when="ISE and AD declare different things; you need a rule.",
            href="/#settings",
            related=["Drift", "Effective-permission lookup"],
        ),
        Tool(
            name="Identity evidence pack",
            icon="📊",
            blurb="JSON / CSV / PDF: who has what, MFA %, JIT log, "
                  "attack paths — mapped to SOC 2 CC6, ISO 27001 A.9, "
                  "NIST AC-2.",
            use_when="Auditor asked for identity evidence specifically.",
            href="/identity",
            related=["Evidence pack (compliance)", "Audit trail"],
        ),
    ]),

    # ---- Execute ----------------------------------------------------
    ("⚙️ Secure Execution", [
        Tool(
            name="Command builder (AI-assisted)",
            icon="🤖",
            blurb="Natural language → per-vendor commands, RBAC + risk "
                  "classified, dry-runnable.",
            use_when="You want to build a network change job without writing "
                  "vendor-specific CLI from scratch.",
            href="/#command",
            related=["Execution queue", "Approvals", "Rollback"],
            cli="safecadence execute build \"...\"",
        ),
        Tool(
            name="Approvals queue",
            icon="🛡️",
            blurb="Risk-tiered approval flow with TOTP + audit row.",
            use_when="Job is built and waiting for sign-off.",
            href="/#approvals",
            related=["Command builder", "Execution queue", "Audit trail"],
        ),
        Tool(
            name="Execution queue",
            icon="📋",
            blurb="Active jobs by stage — review, approved, scheduled, running.",
            use_when="You want a snapshot of what's about to change.",
            href="/#queue",
            related=["Command builder", "Approvals", "Rollback"],
        ),
        Tool(
            name="Rollback manager",
            icon="⏮️",
            blurb="Generated-at-approval-time rollback plans, one-click revert.",
            use_when="A job ran and you want to undo it.",
            href="/#rollback",
            related=["Execution queue", "Audit trail"],
        ),
    ]),

    # ---- Audit ------------------------------------------------------
    ("📒 Audit & Reports", [
        Tool(
            name="Audit trail",
            icon="📜",
            blurb="Immutable log of every change — policy, identity, "
                  "execution, JIT — with full context.",
            use_when="You need to prove what happened, by whom, when.",
            href="/#audit",
            related=["Evidence pack (compliance)",
                      "Identity evidence pack"],
        ),
        Tool(
            name="Email digest",
            icon="📧",
            blurb="Daily / weekly summary of findings, JIT, drift, "
                  "approvals.",
            use_when="You don't want to babysit the dashboard.",
            href="/#settings",
            cli="safecadence digest --weekly",
            related=["Compliance", "Audit trail"],
        ),
    ]),

    # ---- Continuous -------------------------------------------------
    ("🔁 Continuous", [
        Tool(
            name="Daemon",
            icon="🌀",
            blurb="Continuous re-evaluation: policies, drift, attack paths, "
                  "JIT auto-revoke.",
            use_when="You want the dashboard to stay current without you running CLI.",
            href="",
            cli="safecadence daemon --interval 1800",
            related=["Compliance", "JIT access grants",
                      "Identity attack paths"],
        ),
        Tool(
            name="Webhooks (Slack / Teams / PagerDuty)",
            icon="📣",
            blurb="HMAC-signed alerts on new critical findings.",
            use_when="You want to know when prod compliance breaks.",
            href="/#settings",
            related=["Daemon", "Audit trail"],
        ),
        Tool(
            name="Scheduled re-eval",
            icon="⏰",
            blurb="Per-policy cadence — hourly, daily, weekly.",
            use_when="Different policies run on different schedules.",
            href="/#settings",
            related=["Daemon", "Compliance"],
        ),
    ]),

    # ---- Settings ---------------------------------------------------
    ("⚙️ Settings & Tenancy", [
        Tool(
            name="RBAC (6 roles)",
            icon="🔐",
            blurb="Viewer / Auditor / Operator / Engineer / Security Admin / "
                  "Super Admin.",
            use_when="You're delegating access to teammates.",
            href="/#settings",
            related=["TOTP", "Audit trail"],
        ),
        Tool(
            name="TOTP MFA",
            icon="🔑",
            blurb="Per-job step-up auth on Tier-3 commits.",
            use_when="Compliance requires MFA on production changes.",
            href="/#settings",
            related=["RBAC", "Approvals queue"],
        ),
        Tool(
            name="License manager",
            icon="📜",
            blurb="Free local-first, optional Enterprise / MSP modes.",
            use_when="You're moving from local install to MSP control plane.",
            href="/#settings",
            related=[],
        ),
    ]),
]


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SafeCadence — Tool Hub</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px;
    font: 14px/1.55 -apple-system, "Segoe UI", Inter, sans-serif;
    background: #0b1020; color: #e7ecf5;
  }
  .container { max-width: 1180px; margin: 0 auto; }
  h1 { font-size: 26px; margin: 0 0 6px; }
  .lede { color: #b6bfd9; max-width: 760px; margin: 0 0 32px; }
  h2 { font-size: 18px; margin: 32px 0 12px;
       border-bottom: 1px solid #26315b; padding-bottom: 6px; }
  .tools {
    display: grid; gap: 12px;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  }
  .tool {
    background: #121a33; border: 1px solid #26315b; border-radius: 10px;
    padding: 14px 16px;
  }
  .tool h3 { margin: 0 0 4px; font-size: 15px; }
  .tool .icon { margin-right: 4px; }
  .tool .use   { font-size: 12px; color: #a7b0cc; margin-top: 6px; }
  .tool .blurb { font-size: 13px; color: #d6deef; }
  .tool .cli   { font-family: ui-monospace, Menlo, monospace;
                  font-size: 11px; background: #07091a; padding: 4px 8px;
                  border-radius: 6px; margin-top: 8px; display: inline-block; }
  .tool .related {
    margin-top: 8px; font-size: 11px; color: #8b95b1;
  }
  .tool a.open {
    display: inline-block; margin-top: 8px;
    background: #7c5cff; color: #fff; padding: 4px 10px;
    border-radius: 6px; text-decoration: none; font-size: 12px;
    font-weight: 600;
  }
  .tool a.open[href=""] {
    background: #1f2a4a; color: #8b95b1; pointer-events: none;
  }
  a { color: #aab7ff; }
  .navtop {
    margin-bottom: 24px; font-size: 13px;
  }
  .navtop a { margin-right: 14px; }
</style>
</head>
<body>
<div class="container">

<div class="navtop">
  <a href="/">← Dashboard</a>
  <a href="/identity">Identity</a>
  <a href="#discover">Discover</a>
  <a href="#policy">Policy</a>
  <a href="#identity">Identity</a>
  <a href="#execute">Execute</a>
  <a href="#audit">Audit</a>
  <a href="#continuous">Continuous</a>
  <a href="#settings">Settings</a>
</div>

<h1>🧰 SafeCadence Tool Hub</h1>
<p class="lede">
Every capability in SafeCadence v7.7, organized by what you're trying to
do. Each tool tells you when it's the right one to reach for and links
to the others it commonly works alongside. New here? Start with
<a href="#discover">Discover &amp; Inventory</a>; auditing identity?
<a href="#identity">Identity Intelligence</a>; reviewing what changed?
<a href="#audit">Audit &amp; Reports</a>.
</p>

%SECTIONS%

</div>
</body>
</html>
"""


def _render_with_chrome() -> str:
    """v9: wrap the hub body in the universal chrome."""
    from safecadence.ui._chrome import wrap
    body = _build_body()
    return wrap("Tool Hub", body, "")


def _build_body() -> str:
    """Return just the body HTML — chrome supplies <html>/<head>/sidebar."""
    sections: list[str] = []
    sections.append('<h1>🧰 SafeCadence Tool Hub</h1>')
    sections.append('<p class="muted">Every capability, organized by what '
                     'you\'re trying to do. Each tool tells you when it\'s '
                     'the right one to reach for.</p>')
    sections.append('<style>'
                     '.tools{display:grid;gap:12px;'
                     'grid-template-columns:repeat(auto-fill,minmax(320px,1fr));}'
                     '.tool{background:var(--panel);border:1px solid var(--border);'
                     'border-radius:10px;padding:14px 16px;}'
                     '.tool h3{margin:0 0 4px;font-size:14px;}'
                     '.tool .blurb{color:var(--text);font-size:13px;}'
                     '.tool .use{color:var(--muted);font-size:12px;margin-top:6px;}'
                     '.tool .cli{font-family:ui-monospace,Menlo,monospace;'
                     'font-size:11px;background:var(--bg);padding:4px 8px;'
                     'border-radius:6px;margin-top:8px;display:inline-block;}'
                     '.tool .related{margin-top:8px;font-size:11px;color:var(--muted);}'
                     '.tool a.open{display:inline-block;margin-top:8px;'
                     'background:var(--accent);color:#fff;padding:4px 10px;'
                     'border-radius:6px;text-decoration:none;font-size:12px;'
                     'font-weight:600;}'
                     '</style>')
    for label, tools in HUB_TOOLS:
        sections.append(f'<h2>{label}</h2>')
        sections.append('<div class="tools">')
        for t in tools:
            cli = (f'<div class="cli">$ {t.cli}</div>' if t.cli else "")
            related = (f'<div class="related">Related: {", ".join(t.related)}</div>'
                        if t.related else "")
            href_safe = t.href or ""
            open_label = "Open →" if t.href else "(no UI)"
            sections.append(f"""
              <div class="tool">
                <h3>{t.icon} {t.name}</h3>
                <div class="blurb">{t.blurb}</div>
                <div class="use">Use when: {t.use_when}</div>
                {cli}
                {related}
                <a class="open" href="{href_safe}">{open_label}</a>
              </div>
            """)
        sections.append('</div>')
    return "\n".join(sections)


def _render() -> str:
    """v9: wrap body in chrome. Backwards-compat name for the old caller."""
    return _render_with_chrome()


def register(app):
    """Mount /hub. Called from server/app.py and ui/app.py."""
    from fastapi.responses import HTMLResponse

    @app.get("/hub", response_class=HTMLResponse)
    def hub_page():
        return HTMLResponse(_render_with_chrome())
