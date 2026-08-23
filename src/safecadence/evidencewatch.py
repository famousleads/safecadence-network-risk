"""EvidenceWatch — the Monday One-Pager.

The wedge product: a 90-second weekly report answering the two questions
that produce public embarrassments — *is the infrastructure our evidence
depends on healthy?* and *which cameras are dark, and for how long?* —
plus the Audit Button: a hash-chained history proving continuous
monitoring to a state auditor or accreditation assessor.

Everything is computed from the local asset store. No network, no
cloud, no evidentiary content — infrastructure health only.

CLI:
    safecadence evidencewatch report    # write the one-pager HTML
    safecadence evidencewatch audit     # write the audit pack (history + chain)
"""
from __future__ import annotations

import hashlib
import html as _html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

_SENSE_TYPES = {
    "camera", "vms_camera", "cctv", "vms", "alpr", "lpr", "body_camera",
    "bodycam", "iot_sensor", "sensor", "uas", "drone", "acoustic",
    "traffic_signal",
}
_DARK_STATUSES = {"offline", "down", "failed", "unreachable", "dead"}


def _e(s: Any) -> str:
    return _html.escape(str(s if s is not None else ""), quote=True)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _data_dir() -> Path:
    root = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(root) / "evidencewatch"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _days_since(iso: str) -> int | None:
    try:
        ts = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return max(0, (_now() - ts).days)
    except Exception:
        return None


# ------------------------------------------------------------------ build

def build_report(assets: list[dict] | None = None) -> dict[str, Any]:
    if assets is None:
        try:
            from safecadence.server.platform_api import list_assets
            assets = list_assets()
        except Exception:
            assets = []

    # --- camera / sensor fleet -------------------------------------
    sense, dark = [], []
    for a in assets:
        ident = a.get("identity") or {}
        ps = a.get("public_safety") or {}
        health = a.get("health") or {}
        atype = str(ps.get("ps_category") or ident.get("asset_type") or "").lower()
        if atype not in _SENSE_TYPES:
            continue
        status = str(ident.get("operational_status")
                      or a.get("operational_status") or "").lower()
        score = health.get("overall_score")
        is_dark = status in _DARK_STATUSES or (
            isinstance(score, (int, float)) and score <= 30)
        rec = {
            "name": ident.get("hostname") or ident.get("asset_id") or "camera",
            "site": ident.get("site") or ps.get("agency") or "",
            "type": atype,
            "status": status or "unknown",
            "score": score,
            "days_dark": _days_since(a.get("last_seen_at")
                                       or ident.get("last_seen_at")
                                       or ident.get("last_collected_at") or "")
                          if is_dark else 0,
        }
        sense.append(rec)
        if is_dark:
            dark.append(rec)
    dark.sort(key=lambda r: -(r["days_dark"] or 0))

    # --- evidence chain --------------------------------------------
    try:
        from safecadence.platform.evidence_health import (
            evidence_infrastructure_summary)
        chain = evidence_infrastructure_summary(assets or [])
    except Exception:
        chain = {"overall_status": "unknown", "headline":
                  "Evidence-health engine unavailable (install "
                  "safecadence-publicsafety).", "stages": {}, "guidance": ""}

    # --- storage runway --------------------------------------------
    storage = []
    for a in assets:
        st = a.get("storage") or {}
        tot, used = st.get("total_capacity_tb"), st.get("used_capacity_tb")
        if not tot:
            continue
        pct = round(100.0 * float(used or 0) / float(tot), 1)
        storage.append({
            "name": (a.get("identity") or {}).get("hostname") or "storage",
            "pct_used": pct,
            "replication": st.get("replication_status") or "unknown",
            "flag": pct >= 85 or st.get("replication_status") == "degraded",
        })
    storage.sort(key=lambda s: -s["pct_used"])

    # --- retention / purge-log integrity (C3 tie-in) ---------------
    try:
        from safecadence.platform import retention
        rstat = retention.status()
        ret = {"log_ok": rstat["log"]["ok"],
                "log_entries": rstat["log"]["entries"],
                "due": {k: v["count"] for k, v in rstat["due"].items()}}
    except Exception:
        ret = {"log_ok": None, "log_entries": 0, "due": {}}

    # --- the one recommended action --------------------------------
    action = "No action needed — keep the watch."
    if dark:
        d = dark[0]
        action = (f"Restore '{d['name']}' at {d['site'] or 'unknown site'} — "
                   f"dark {d['days_dark'] if d['days_dark'] is not None else '?'}"
                   " day(s). A dark camera near evidence is a future "
                   "suppression hearing.")
    elif any(s["flag"] for s in storage):
        s0 = next(s for s in storage if s["flag"])
        action = (f"Evidence storage '{s0['name']}' is at {s0['pct_used']}% "
                   f"with replication '{s0['replication']}' — add capacity or "
                   "repair replication this week.")
    elif chain.get("overall_status") in ("critical", "warning"):
        action = chain.get("guidance") or chain.get("headline") or action

    overall = "healthy"
    if dark or chain.get("overall_status") == "critical" or any(
            s["flag"] for s in storage):
        overall = "critical" if (dark or chain.get("overall_status") ==
                                   "critical") else "warning"
    elif chain.get("overall_status") == "warning":
        overall = "warning"

    return {
        "generated_at": _now().isoformat(),
        "week": _now().strftime("%G-W%V"),
        "overall": overall,
        "sense_total": len(sense),
        "dark": dark[:10],
        "dark_count": len(dark),
        "chain": {"overall_status": chain.get("overall_status"),
                   "headline": chain.get("headline"),
                   "stages": {k: v.get("status") for k, v in
                               (chain.get("stages") or {}).items()}},
        "storage": storage[:5],
        "retention": ret,
        "action": action,
        "asset_count": len(assets or []),
    }


# ------------------------------------------------------------------ history (the Audit Button)

def _hist_files() -> list[Path]:
    return sorted(_data_dir().glob("week-*.json"))


def _entry_hash(body: dict) -> str:
    canon = json.dumps({k: v for k, v in body.items() if k != "entry_hash"},
                        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def snapshot(report: dict | None = None) -> dict[str, Any]:
    """Persist this week's report into the hash-chained history."""
    report = report or build_report()
    target = _data_dir() / f"week-{report['week']}.json"
    files = [f for f in _hist_files() if f != target]
    prev = GENESIS
    if target.exists():
        try:                      # re-snapshot of the same week: keep its
            prev = json.loads(target.read_text())["prev_hash"]   # chain slot
        except Exception:
            prev = GENESIS
    elif files:
        try:
            prev = json.loads(files[-1].read_text())["entry_hash"]
        except Exception:
            prev = GENESIS
    body = {"week": report["week"], "generated_at": report["generated_at"],
             "overall": report["overall"], "dark_count": report["dark_count"],
             "sense_total": report["sense_total"],
             "chain_status": report["chain"]["overall_status"],
             "action": report["action"], "prev_hash": prev}
    body["entry_hash"] = _entry_hash(body)
    target.write_text(
        json.dumps(body, indent=1), encoding="utf-8")
    return body


def verify_history() -> dict[str, Any]:
    prev = GENESIS
    files = _hist_files()
    for i, f in enumerate(files):
        try:
            e = json.loads(f.read_text())
        except Exception:
            return {"ok": False, "weeks": len(files), "failed_at": f.name,
                     "reason": "unparseable"}
        if e.get("prev_hash") != prev or _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "weeks": len(files), "failed_at": f.name,
                     "reason": "chain break"}
        prev = e["entry_hash"]
    return {"ok": True, "weeks": len(files), "head": prev}


# ------------------------------------------------------------------ render

_BAND = {"healthy": "#16a34a", "warning": "#d97706", "critical": "#dc2626",
          "unknown": "#64748b"}


def render_report_html(report: dict | None = None,
                        agency: str = "") -> str:
    r = report or build_report()
    c = _BAND.get(r["overall"], "#64748b")
    dark_rows = "".join(
        f"<tr><td style='padding:6px 10px'><b>{_e(d['name'])}</b></td>"
        f"<td style='padding:6px 10px'>{_e(d['site'])}</td>"
        f"<td style='padding:6px 10px'>{_e(d['type'])}</td>"
        f"<td style='padding:6px 10px;color:#dc2626;font-weight:700'>"
        f"{_e(d['days_dark'] if d['days_dark'] is not None else '?')} day(s)</td></tr>"
        for d in r["dark"]) or (
        "<tr><td style='padding:6px 10px' colspan='4'>"
        "None — every monitored camera and sensor is reporting. ✅</td></tr>")
    stages = " · ".join(
        f"{_e(k)}: <b style='color:{_BAND.get(str(v), '#64748b')}'>{_e(v)}</b>"
        for k, v in (r["chain"]["stages"] or {}).items()) or "not assessed"
    storage_rows = "".join(
        f"<tr><td style='padding:6px 10px'>{_e(s['name'])}</td>"
        f"<td style='padding:6px 10px'><b>{_e(s['pct_used'])}%</b></td>"
        f"<td style='padding:6px 10px'>{_e(s['replication'])}</td></tr>"
        for s in r["storage"]) or (
        "<tr><td style='padding:6px 10px' colspan='3'>no storage systems "
        "reporting capacity</td></tr>")
    ret = r["retention"]
    ret_line = ("Purge log: <b>chain verified</b> "
                 f"({ret['log_entries']} entries)" if ret["log_ok"]
                 else ("Purge log: <b style='color:#dc2626'>CHAIN BROKEN — "
                        "investigate</b>" if ret["log_ok"] is False
                        else "Retention engine: not configured"))
    title = f"EvidenceWatch — {agency}" if agency else "EvidenceWatch"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{_e(title)} — week {_e(r['week'])}</title></head>
<body style="margin:0;background:#f4f6f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#102033">
<div style="max-width:640px;margin:0 auto;padding:22px 14px">
 <div style="background:#fff;border:1px solid #dbe7e1;border-radius:12px;overflow:hidden">
  <div style="background:#173d42;color:#dff4ed;padding:14px 18px">
   <div style="font-size:11px;letter-spacing:.08em;font-weight:800">EVIDENCEWATCH · WEEK {_e(r['week'])}</div>
   <div style="font-size:19px;font-weight:800;margin-top:2px">{_e(agency or 'Your agency')} —
    <span style="color:{c}">{_e(r['overall'].upper())}</span></div>
  </div>
  <div style="padding:16px 18px">
   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">THIS WEEK'S ONE ACTION</p>
   <p style="margin:0 0 16px;font-size:14.5px;font-weight:650;border-left:4px solid {c};padding:8px 12px;background:#f7fbf8">{_e(r['action'])}</p>

   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">DARK CAMERAS &amp; SENSORS ({_e(r['dark_count'])} of {_e(r['sense_total'])})</p>
   <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;border:1px solid #e4ede8">{dark_rows}</table>

   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">EVIDENCE CHAIN</p>
   <p style="margin:0 0 4px;font-size:13.5px">{_e(r['chain']['headline'] or '')}</p>
   <p style="margin:0 0 16px;font-size:12.5px;color:#40556a">{stages}</p>

   <p style="margin:0 0 4px;font-size:12px;color:#647386;font-weight:800;letter-spacing:.06em">EVIDENCE STORAGE</p>
   <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px;border:1px solid #e4ede8">{storage_rows}</table>

   <p style="margin:0;font-size:12.5px;color:#40556a">{ret_line} · {_e(r['asset_count'])} assets monitored · generated {_e(r['generated_at'][:16])}Z</p>
  </div>
  <div style="padding:10px 18px;border-top:1px solid #e4ede8;font-size:11px;color:#647386">
   Computed entirely on your hardware from your asset inventory — no evidentiary
   content is read, no data leaves your network. SafeCadence EvidenceWatch.
  </div>
 </div>
</div></body></html>"""


def audit_export(agency: str = "") -> str:
    """The Audit Button: every weekly snapshot + chain verification,
    one self-contained HTML an auditor can read and re-verify."""
    v = verify_history()
    rows = []
    for f in _hist_files():
        try:
            e = json.loads(f.read_text())
        except Exception:
            continue
        rows.append(
            f"<tr><td style='padding:6px 10px'>{_e(e.get('week'))}</td>"
            f"<td style='padding:6px 10px;color:{_BAND.get(str(e.get('overall')), '#64748b')};font-weight:700'>{_e(e.get('overall'))}</td>"
            f"<td style='padding:6px 10px'>{_e(e.get('dark_count'))}/{_e(e.get('sense_total'))}</td>"
            f"<td style='padding:6px 10px'>{_e(e.get('chain_status'))}</td>"
            f"<td style='padding:6px 10px;font-family:monospace;font-size:10px'>{_e(str(e.get('entry_hash'))[:16])}…</td></tr>")
    state = ("<b style='color:#16a34a'>VERIFIED</b> — every weekly entry is "
              "hash-chained to the previous; any alteration would break the chain."
              if v["ok"] else
              f"<b style='color:#dc2626'>CHAIN BROKEN at {_e(v.get('failed_at'))}</b>")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>EvidenceWatch Audit Pack {_e(('— ' + agency) if agency else '')}</title></head>
<body style="margin:0;background:#f4f6f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#102033">
<div style="max-width:720px;margin:0 auto;padding:22px 14px">
 <h1 style="font-size:20px">EvidenceWatch Audit Pack{_e((' — ' + agency) if agency else '')}</h1>
 <p style="font-size:13.5px">Continuous monitoring record for evidence
 infrastructure and camera/sensor fleet health. {v['weeks']} weekly
 snapshot(s). Integrity: {state}</p>
 <table style="width:100%;border-collapse:collapse;font-size:13px;border:1px solid #dbe7e1;background:#fff">
  <thead><tr style="background:#eef4f1;text-align:left">
   <th style="padding:7px 10px">Week</th><th style="padding:7px 10px">Overall</th>
   <th style="padding:7px 10px">Dark / total sensors</th>
   <th style="padding:7px 10px">Evidence chain</th>
   <th style="padding:7px 10px">Entry hash</th></tr></thead>
  <tbody>{''.join(rows) or '<tr><td style="padding:8px" colspan="5">no snapshots yet</td></tr>'}</tbody>
 </table>
 <p style="font-size:11.5px;color:#647386">Each entry embeds the SHA-256 of the
 previous entry; re-verify anytime with <code>safecadence evidencewatch verify</code>.
 Point-in-time monitoring support material — not an audit, attestation, or certification.</p>
</div></body></html>"""
