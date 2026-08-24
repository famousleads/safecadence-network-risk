"""Roll-Call Brief — the one page the 6 AM briefing room actually reads.

Pulls everything the platform learned overnight into a single
plain-language sheet: correlated situations, open incidents, dark
cameras, active SafeChecks, alerts sent, evidence-room activity.
Print it, read it aloud, get on the road. AI writes the top note when
a key is configured (grounded in the gathered facts only);
deterministic otherwise — the brief NEVER depends on a cloud.

Everything is a guarded import: whatever engines are present
contribute; missing ones are skipped silently.
"""
from __future__ import annotations

import html as _html
import json
import os
from datetime import datetime, timezone
from typing import Any


def _e(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""), quote=True)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_brief(window_hours: int = 12) -> dict[str, Any]:
    brief: dict[str, Any] = {
        "generated_at": _now().isoformat(),
        "window_hours": window_hours,
    }
    # situations ----------------------------------------------------
    try:
        from safecadence import situation
        cards = situation.assess(window_hours * 60)
        brief["situations"] = cards[:6]
        brief["situation_count"] = len(cards)
    except Exception:
        brief["situations"] = []
        brief["situation_count"] = 0
    # incidents -----------------------------------------------------
    try:
        from safecadence.incidents.store import list_incidents
        opens = []
        for inc in list_incidents():
            d = inc if isinstance(inc, dict) else getattr(inc, "__dict__", {})
            if d.get("status") not in ("resolved", "closed"):
                opens.append({"id": d.get("incident_id"),
                               "title": d.get("title"),
                               "severity": d.get("severity"),
                               "site": d.get("site"),
                               "owner": d.get("owner") or "unassigned"})
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        opens.sort(key=lambda i: sev.get(i.get("severity"), 9))
        brief["open_incidents"] = opens[:8]
        brief["incident_count"] = len(opens)
    except Exception:
        brief["open_incidents"] = []
        brief["incident_count"] = 0
    # dark cameras / watch ------------------------------------------
    try:
        from safecadence.evidencewatch import build_report
        r = build_report()
        brief["dark_devices"] = r.get("dark", [])[:5]
        brief["dark_count"] = r.get("dark_count", 0)
        brief["sense_total"] = r.get("sense_total", 0)
        brief["watch_overall"] = r.get("overall")
    except Exception:
        brief["dark_devices"] = []
        brief["dark_count"] = 0
        brief["sense_total"] = 0
        brief["watch_overall"] = "unknown"
    # safechecks ----------------------------------------------------
    try:
        from safecadence import safecheck
        active = safecheck.list_active()
        brief["safechecks_active"] = len(active)
        brief["safechecks_overdue"] = [
            {"officer": r["officer"], "location": r["location"],
              "due_at": r["due_at"]}
            for r in active if r.get("overdue")]
    except Exception:
        brief["safechecks_active"] = 0
        brief["safechecks_overdue"] = []
    # alerts sent ---------------------------------------------------
    try:
        from safecadence import mass_notify
        cutoff = _now().timestamp() - window_hours * 3600
        recent = []
        for e in mass_notify.alert_log(20):
            try:
                ts = datetime.fromisoformat(e["at"]).timestamp()
            except Exception:
                continue
            if ts >= cutoff:
                recent.append({"subject": e["subject"], "group": e["group"],
                                "mode": e["mode"],
                                "approved_by": e["approved_by"]})
        brief["alerts_sent"] = recent[:6]
    except Exception:
        brief["alerts_sent"] = []
    # custody activity ----------------------------------------------
    try:
        from safecadence import custody
        s = custody.summary()
        brief["custody"] = {"checked_out": s["checked_out"],
                             "items": s["items"], "log_ok": s["log_ok"]}
    except Exception:
        brief["custody"] = None
    brief["note"] = _note(brief)
    return brief


def _note(brief: dict) -> dict[str, Any]:
    facts = {k: brief.get(k) for k in
              ("situation_count", "situations", "incident_count",
               "dark_count", "safechecks_overdue", "alerts_sent")}
    ai_text = None
    if os.environ.get("SC_WATCH_AI", "1") != "0":
        try:
            from safecadence.ai.client import (
                AIProvider, _call_anthropic, detect_provider)
            key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
            if key and detect_provider() == AIProvider.ANTHROPIC:
                prompt = (
                    "Write the 3-sentence spoken opening for a police "
                    "shift roll-call, using ONLY these facts (JSON). "
                    "Plain words, calm tone, name the single most "
                    "important thing first. Never invent details.\n\n"
                    + json.dumps(facts, default=str)[:4000])
                ai_text = _call_anthropic(
                    prompt, api_key=key,
                    model=os.environ.get("SC_AI_MODEL", "claude-fable-5"),
                    timeout=45, effort="low")
                ai_text = (ai_text or "").strip()[:700] or None
        except Exception:
            ai_text = None
    if ai_text:
        return {"text": ai_text, "ai_generated": True}
    bits = []
    if brief["situation_count"]:
        top = brief["situations"][0]
        bits.append(f"Start with: {top['headline']}.")
    if brief["dark_count"]:
        bits.append(f"{brief['dark_count']} camera(s)/device(s) are dark "
                     "- assume no video coverage there.")
    if brief["incident_count"]:
        bits.append(f"{brief['incident_count']} incident(s) remain open.")
    if brief["safechecks_overdue"]:
        bits.append(f"{len(brief['safechecks_overdue'])} SafeCheck(s) "
                     "OVERDUE - resolve before anything else.")
    if not bits:
        bits.append("Quiet overnight. Systems reporting normally. "
                     "Good hunting out there.")
    return {"text": " ".join(bits), "ai_generated": False}


_SEV = {"critical": "#d93b3b", "high": "#b87513", "medium": "#0e7c86"}


def render_brief_html(brief: dict | None = None, agency: str = "",
                       shift: str = "") -> str:
    b = brief or build_brief()
    when = b["generated_at"][:16].replace("T", " ")
    note = b["note"]
    rows = ""
    for c in b["situations"]:
        col = _SEV.get(c["severity"], "#647386")
        rows += (f"<div style='border-left:4px solid {col};padding:6px 12px;"
                  f"margin:0 0 8px;background:#f7fafb'>"
                  f"<b>{_e(c['headline'])}</b><br>"
                  f"<span style='font-size:12px;color:#40556a'>"
                  f"&rarr; {_e(c['recommended_action'])}</span></div>")
    incs = "".join(
        f"<tr><td style='padding:4px 8px'><b>{_e(i['severity'])}</b></td>"
        f"<td style='padding:4px 8px'>{_e(i['title'])}</td>"
        f"<td style='padding:4px 8px'>{_e(i['site'])}</td>"
        f"<td style='padding:4px 8px'>{_e(i['owner'])}</td></tr>"
        for i in b["open_incidents"]) or (
        "<tr><td style='padding:4px 8px' colspan='4'>None open. "
        "&#9989;</td></tr>")
    dark = ", ".join(f"{_e(d['name'])} ({_e(d['site'])})"
                      for d in b["dark_devices"]) or "none - full coverage"
    sc = (f"{b['safechecks_active']} active"
           + (f", <b style='color:#d93b3b'>"
              f"{len(b['safechecks_overdue'])} OVERDUE</b>"
              if b["safechecks_overdue"] else ""))
    alerts = "".join(
        f"<li>{_e(a['subject'])} &rarr; {_e(a['group'])} "
        f"({_e(a['mode'])}, approved by {_e(a['approved_by'])})</li>"
        for a in b["alerts_sent"]) or "<li>none in the window</li>"
    cust = ""
    if b.get("custody"):
        c = b["custody"]
        cust = (f"<p style='margin:0 0 4px;font-size:12px;color:#647386;"
                 f"font-weight:800;letter-spacing:.06em'>EVIDENCE ROOM</p>"
                 f"<p style='margin:0 0 14px;font-size:13px'>"
                 f"{c['items']} item(s) tracked, {c['checked_out']} "
                 f"currently out. Custody chain "
                 f"{'verified' if c['log_ok'] else '<b>BROKEN</b>'}.</p>")
    title = f"Roll-Call Brief — {agency}" if agency else "Roll-Call Brief"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{_e(title)}</title></head>
<body style="margin:0;background:#f4f6f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#102033">
<div style="max-width:680px;margin:0 auto;padding:22px 14px">
 <div style="background:#fff;border:1px solid #dbe7e1;border-radius:12px;overflow:hidden">
  <div style="background:#10243a;color:#e8f0f2;padding:14px 18px">
   <div style="font-size:11px;letter-spacing:.08em;font-weight:800">ROLL-CALL BRIEF{_e(' · ' + shift.upper() if shift else '')}</div>
   <div style="font-size:19px;font-weight:800;margin-top:2px">{_e(agency or 'Your agency')} — {_e(when)}Z</div>
  </div>
  <div style="padding:16px 18px">
   <p style="margin:0 0 14px;font-size:14.5px;font-weight:650;border-left:4px solid #0e7c86;padding:8px 12px;background:#f2f8f7">
    {_e(note['text'])}{' <span style="font-size:10px;color:#647386">(AI, grounded)</span>' if note['ai_generated'] else ''}</p>
   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">SITUATIONS ({_e(b['situation_count'])})</p>
   {rows or "<p style='font-size:13px'>No correlated situations. &#9989;</p>"}
   <p style="margin:12px 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">OPEN INCIDENTS ({_e(b['incident_count'])})</p>
   <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:12px;border:1px solid #e4ede8">{incs}</table>
   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">DARK CAMERAS ({_e(b['dark_count'])} of {_e(b['sense_total'])})</p>
   <p style="margin:0 0 12px;font-size:13px">{dark}</p>
   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">SAFECHECKS</p>
   <p style="margin:0 0 12px;font-size:13px">{sc}</p>
   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">ALERTS SENT (LAST {_e(b['window_hours'])}H)</p>
   <ul style="margin:0 0 12px;font-size:13px;padding-left:20px">{alerts}</ul>
   {cust}
  </div>
  <div style="padding:10px 18px;border-top:1px solid #e4ede8;font-size:11px;color:#647386">
   Generated on your own hardware from your own records. SafeCadence Command.
  </div>
 </div>
</div></body></html>"""
