"""
v7.9 — Morning briefing.

A single function that pulls from every intel module and produces a
concise daily digest. Three render formats:

  * 'json'       structured (for automation / API)
  * 'text'       80-column terminal-friendly
  * 'html'       email-ready

Schedulable through the existing `safecadence schedule` system or by
the daemon. The briefing is the primary stickiness lever — once it
lands in your inbox at 8am every day, you open SafeCadence daily.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from safecadence.intel.watchlists import list_watches, watch_changes
from safecadence.intel.comments import list_assignments


@dataclass
class Briefing:
    generated_at: str = ""
    user: str = ""
    overnight_findings: list[dict] = field(default_factory=list)
    new_attack_paths: list[dict] = field(default_factory=list)
    jit_activity: dict = field(default_factory=dict)
    watchlist_changes: list[dict] = field(default_factory=list)
    your_assignments: list[dict] = field(default_factory=list)
    automation_fires: list[dict] = field(default_factory=list)
    top_actions: list[dict] = field(default_factory=list)
    summary_line: str = ""


def build_briefing(*, user: str = "default",
                   assets: Iterable[dict] | None = None,
                   findings: Iterable[object] | None = None,
                   attack_paths: Iterable[object] | None = None,
                   jit_grants: Iterable[object] | None = None,
                   automation_fires: Iterable[dict] | None = None) -> Briefing:
    """Compose the briefing from current state.

    Every dependency is overridable so tests can pass synthetic data
    instead of touching the real platform store.
    """
    assets = list(assets) if assets is not None else _load_assets()
    findings = list(findings) if findings is not None else _load_findings(assets)
    attack_paths = (list(attack_paths) if attack_paths is not None
                     else _load_attack_paths(assets))
    jit_grants = (list(jit_grants) if jit_grants is not None
                   else _load_jit())
    automation_fires = (list(automation_fires) if automation_fires is not None
                         else _load_recent_fires())

    b = Briefing(
        generated_at=datetime.now(timezone.utc).isoformat(),
        user=user,
    )

    # Findings — surface only critical+high
    b.overnight_findings = [
        {"finding_id": getattr(f, "finding_id", ""),
          "severity": getattr(f, "severity", ""),
          "kind": getattr(f, "kind", ""),
          "title": getattr(f, "title", ""),
          "principal": getattr(f, "principal", "")}
        for f in findings
        if getattr(f, "severity", "") in ("critical", "high")
    ][:10]

    # Attack paths — top 3
    b.new_attack_paths = [
        {"chain": p.chain_summary() if hasattr(p, "chain_summary") else "",
          "terminal_asset": getattr(p, "terminal_asset", ""),
          "risk_score": getattr(p, "risk_score", 0)}
        for p in attack_paths[:3]
    ]

    # JIT
    active = [g for g in jit_grants
               if (getattr(g, "status", "") if hasattr(g, "status")
                    else g.get("status", "")) == "active"]
    expired_recent = [g for g in jit_grants
                       if (getattr(g, "status", "") if hasattr(g, "status")
                            else g.get("status", "")) == "expired"]
    b.jit_activity = {
        "active_count": len(active),
        "recently_expired": len(expired_recent),
    }

    # Watchlist
    try:
        b.watchlist_changes = watch_changes(assets=assets, user=user)
    except Exception:
        b.watchlist_changes = []

    # Assignments
    try:
        b.your_assignments = [
            {"id": a.assignment_id, "entity_kind": a.entity_kind,
              "entity_id": a.entity_id, "status": a.status,
              "note": a.note}
            for a in list_assignments(assigned_to=user, status="open")
        ][:10]
    except Exception:
        b.your_assignments = []

    # Automation
    b.automation_fires = list(automation_fires)[-10:]

    # Top actions: a small ranked synthesis of "what to do today"
    b.top_actions = _top_actions(b)
    b.summary_line = _summary_line(b)
    return b


# ---------------------------------------------------------------- renderers

def render_text(b: Briefing) -> str:
    lines: list[str] = []
    lines.append(f"SafeCadence — Morning briefing for {b.user}")
    lines.append(f"Generated {b.generated_at}")
    lines.append("=" * 72)
    lines.append(b.summary_line)
    lines.append("")
    if b.top_actions:
        lines.append("Top actions today:")
        for i, a in enumerate(b.top_actions, 1):
            lines.append(f"  {i}. [{a['severity']:>8}] {a['title']}")
            if a.get("href"):
                lines.append(f"        → {a['href']}")
        lines.append("")
    if b.overnight_findings:
        lines.append(f"Findings (top 10): {len(b.overnight_findings)}")
        for f in b.overnight_findings:
            lines.append(f"  - [{f['severity']}] {f['title']}")
        lines.append("")
    if b.new_attack_paths:
        lines.append("Identity attack paths:")
        for p in b.new_attack_paths:
            lines.append(f"  - ({p['risk_score']:.1f}) {p['chain']}")
        lines.append("")
    lines.append(f"JIT — {b.jit_activity.get('active_count')} active, "
                 f"{b.jit_activity.get('recently_expired')} expired")
    if b.your_assignments:
        lines.append(f"Open assignments to you: {len(b.your_assignments)}")
        for a in b.your_assignments[:5]:
            lines.append(f"  - {a['entity_kind']}:{a['entity_id']} ({a['status']})")
    if b.watchlist_changes:
        lines.append(f"Watchlist changes: {len(b.watchlist_changes)}")
        for w in b.watchlist_changes[:5]:
            lines.append(f"  - {w['label']}: {w['summary']}")
    return "\n".join(lines)


def render_html(b: Briefing) -> str:
    rows: list[str] = []
    rows.append(f"<h2>SafeCadence morning briefing</h2>")
    rows.append(f"<p style='color:#888'>Generated {b.generated_at} for {b.user}</p>")
    rows.append(f"<p><strong>{b.summary_line}</strong></p>")
    if b.top_actions:
        rows.append("<h3>Top actions</h3><ol>")
        for a in b.top_actions:
            sev = a["severity"]
            href = a.get("href") or ""
            link = (' — <a href="' + href + '">open</a>') if href else ""
            rows.append(f"<li><strong>[{sev}]</strong> {a['title']}{link}</li>")
        rows.append("</ol>")
    if b.overnight_findings:
        rows.append(f"<h3>Findings ({len(b.overnight_findings)})</h3><ul>")
        for f in b.overnight_findings:
            rows.append(f"<li>[{f['severity']}] {f['title']}</li>")
        rows.append("</ul>")
    if b.new_attack_paths:
        rows.append(f"<h3>Identity attack paths</h3><ul>")
        for p in b.new_attack_paths:
            rows.append(f"<li>({p['risk_score']:.1f}) {p['chain']}</li>")
        rows.append("</ul>")
    rows.append(f"<p>JIT: {b.jit_activity.get('active_count')} active, "
                 f"{b.jit_activity.get('recently_expired')} expired</p>")
    return "\n".join(rows)


# ---------------------------------------------------------------- internals

def _top_actions(b: Briefing) -> list[dict]:
    out: list[dict] = []
    if b.new_attack_paths:
        p = b.new_attack_paths[0]
        out.append({"severity": "critical",
                     "title": f"Remediate identity attack path: {p['chain']}",
                     "href": "/identity#paths-tbl"})
    crit = [f for f in b.overnight_findings if f["severity"] == "critical"]
    if crit:
        out.append({"severity": "critical",
                     "title": f"{len(crit)} critical finding(s) need review",
                     "href": "/identity#findings-tbl"})
    if b.your_assignments:
        out.append({"severity": "high",
                     "title": f"{len(b.your_assignments)} open assignments",
                     "href": "/timeline"})
    if b.watchlist_changes:
        out.append({"severity": "medium",
                     "title": f"{len(b.watchlist_changes)} watchlist changes overnight",
                     "href": "/home"})
    if b.automation_fires:
        recent_critical = [
            f for f in b.automation_fires
            if f.get("severity") in ("critical", "high")
        ]
        if recent_critical:
            out.append({"severity": "high",
                         "title": (f"{len(recent_critical)} automation rule(s) "
                                    "fired on high-severity findings overnight"),
                         "href": "/timeline"})
    return out[:5]


def _summary_line(b: Briefing) -> str:
    parts = []
    parts.append(f"{len(b.overnight_findings)} new findings")
    parts.append(f"{len(b.new_attack_paths)} attack paths")
    parts.append(f"{b.jit_activity.get('active_count', 0)} JIT active")
    parts.append(f"{len(b.your_assignments)} assigned to you")
    if not any([b.overnight_findings, b.new_attack_paths,
                 b.your_assignments, b.watchlist_changes]):
        return "All quiet — no critical changes overnight."
    return ", ".join(parts)


def _load_assets() -> list[dict]:
    try:
        from safecadence.server.platform_api import list_assets
        return list_assets()
    except Exception:
        return []


def _load_findings(assets):
    try:
        from safecadence.identity.findings import scan_findings
        return scan_findings(assets)
    except Exception:
        return []


def _load_attack_paths(assets):
    try:
        from safecadence.identity.attack_paths import compute_identity_paths
        return compute_identity_paths(assets)
    except Exception:
        return []


def _load_jit():
    try:
        from safecadence.identity.jit import list_grants
        return list_grants()
    except Exception:
        return []


def _load_recent_fires() -> list[dict]:
    from safecadence.intel._store import read
    data = read("automation", {"rules": [], "fires": []})
    return list((data.get("fires") or [])[-20:])
