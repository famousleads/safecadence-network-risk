"""Watch Intelligence — the dot-connector behind EvidenceWatch/CampusWatch.

Everything the platform knows lives in silos: dark cameras, storage runway,
evidence chain, retention, incidents, community registry, weekly history.
This module CONNECTS them into grounded correlations a sheriff or district
IT director can act on, e.g.:

  * 3 devices dark at the same school + the site switch degraded
    → fix ONE switch, restore FOUR devices.
  * Recorder at 89% + 2 cameras already dark
    → evidence loss from both directions at once.
  * Open incident at a site where every camera is dark
    → you have no video record of the thing you're investigating.
  * Storage full + retention purges legally due
    → run retention before buying disks.
  * Camera dark this week AND in 3 prior weekly snapshots
    → chronic — replace it, stop re-fixing it.

Design rules (house style):
  * Deterministic FIRST. Every correlation is computed from real records
    and carries its evidence lines. Zero hallucination surface.
  * AI is narrative-only, on top, optional. If ANTHROPIC/OPENAI keys are
    present we ask for a short analyst's note grounded ONLY in the
    computed correlations; on any failure/refusal we fall back to the
    deterministic note. No key → still fully functional.
  * Guarded imports everywhere — works even when sibling modules are
    absent, and never breaks the report if a source is unavailable.
"""
from __future__ import annotations

import json
import os
from typing import Any

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _corr(kind: str, severity: str, headline: str,
          evidence: list[str], recommendation: str) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "headline": headline,
            "evidence": evidence, "recommendation": recommendation}


# ------------------------------------------------------------------ sources

def _open_incidents() -> list[dict]:
    try:
        from safecadence.incidents.store import list_incidents
        out = []
        for inc in list_incidents():
            d = inc if isinstance(inc, dict) else getattr(
                inc, "__dict__", {}) or {}
            if d.get("status") in ("resolved", "closed"):
                continue
            out.append(d)
        return out
    except Exception:
        return []


def _community() -> dict:
    try:
        from safecadence import community
        return community.summary()
    except Exception:
        return {}


def _prior_dark_names(profile: str, weeks: int = 4) -> dict[str, int]:
    """name -> number of PRIOR weekly snapshots in which it was dark."""
    counts: dict[str, int] = {}
    try:
        from safecadence.evidencewatch import _hist_files
        for f in _hist_files(profile)[-weeks:]:
            try:
                body = json.loads(f.read_text(encoding="utf-8"))
                rep = body.get("report") or body
                for d in rep.get("dark") or []:
                    n = d.get("name")
                    if n:
                        counts[n] = counts.get(n, 0) + 1
            except Exception:
                continue
    except Exception:
        pass
    return counts


def _infra_by_site(assets: list[dict]) -> dict[str, list[dict]]:
    """Non-watched infrastructure (switches, routers, servers) per site,
    flagged when degraded/offline — candidate root causes."""
    infra: dict[str, list[dict]] = {}
    bad = {"offline", "down", "failed", "unreachable", "degraded"}
    for a in assets or []:
        ident = a.get("identity") or {}
        atype = str(ident.get("asset_type") or "").lower()
        if atype not in ("switch", "router", "firewall", "server",
                         "network", "wireless_controller", "ups"):
            continue
        status = str(ident.get("operational_status")
                     or a.get("operational_status") or "").lower()
        score = (a.get("health") or {}).get("overall_score")
        flagged = status in bad or (
            isinstance(score, (int, float)) and score <= 40)
        if flagged:
            site = ident.get("site") or ""
            infra.setdefault(site, []).append({
                "name": ident.get("hostname") or ident.get("asset_id")
                or atype,
                "type": atype, "status": status or "degraded"})
    return infra


# ------------------------------------------------------------------ engine

def connect_dots(report: dict, assets: list[dict] | None = None,
                 profile: str = "agency") -> list[dict]:
    """Compute grounded cross-silo correlations. Pure + deterministic."""
    assets = assets or []
    site_word = "school" if profile == "campus" else "site"
    out: list[dict] = []

    dark = report.get("dark") or []
    dark_sites: dict[str, list[dict]] = {}
    for d in dark:
        dark_sites.setdefault(d.get("site") or "", []).append(d)

    # 1 — co-located failures + likely common cause -------------------
    infra = _infra_by_site(assets)
    for site, ds in dark_sites.items():
        if len(ds) < 2:
            continue
        ev = [f"{d['name']} — {d['status']}"
              + (f", dark {d['days_dark']}d" if d.get("days_dark") else "")
              for d in ds]
        culprit = (infra.get(site) or [None])[0]
        if culprit:
            out.append(_corr(
                "site_cluster", "critical",
                f"{len(ds)} devices dark at {site or 'one ' + site_word} — "
                f"likely ONE root cause: {culprit['name']} "
                f"({culprit['type']}, {culprit['status']})",
                ev + [f"{culprit['name']} ({culprit['type']}) at the same "
                      f"{site_word} is {culprit['status']}"],
                f"Check {culprit['name']} first. Fixing one {culprit['type']}"
                f" likely restores all {len(ds)} devices."))
        else:
            out.append(_corr(
                "site_cluster", "high",
                f"{len(ds)} devices dark at the same {site_word} "
                f"({site or 'unassigned'}) — common cause likely",
                ev,
                f"Multiple simultaneous failures at one {site_word} usually "
                "mean power, switch, or cabling — check shared "
                "infrastructure before touching each device."))

    # 2 — video AND access control blind at the same site -------------
    for site, ds in dark_sites.items():
        types = {d.get("type") for d in ds}
        if "camera" in types and ("door_controller" in types
                                  or "access_control" in types):
            out.append(_corr(
                "video_and_door", "critical",
                f"{site or 'One ' + site_word}: camera AND door controller "
                "both down — no video and no access control",
                [f"{d['name']} ({d['type']}) — {d['status']}" for d in ds],
                f"Treat as a physical-security outage, not an IT ticket. "
                f"Restore this {site_word} first."))

    # 3 — recorder double exposure ------------------------------------
    flagged_storage = [s for s in report.get("storage") or []
                       if s.get("flag")]
    if flagged_storage and dark:
        s0 = flagged_storage[0]
        out.append(_corr(
            "recorder_double_exposure", "critical",
            f"Evidence at risk from BOTH directions: {s0['name']} at "
            f"{s0['pct_used']}% while {len(dark)} camera(s) are dark",
            [f"{s0['name']} — {s0['pct_used']}% used, replication "
             f"{s0.get('replication', 'unknown')}",
             f"{len(dark)} device(s) recording nothing right now"],
            "New footage is at risk (recorder full) and some footage "
            "doesn't exist (dark cameras). Free recorder space AND "
            "restore the dark devices this week."))

    # 4 — storage full + retention purges due -------------------------
    ret = report.get("retention") or {}
    due_total = sum((ret.get("due") or {}).values())
    if flagged_storage and due_total:
        out.append(_corr(
            "retention_relief", "high",
            f"Storage pressure has a free fix: {due_total} record(s) are "
            "past retention and legally due for purge",
            [f"{s['name']} at {s['pct_used']}%" for s in flagged_storage]
            + [f"retention: {k} — {v} due"
               for k, v in (ret.get("due") or {}).items() if v],
            "Run `safecadence retention run` (dry-run first). Purging "
            "past-retention records frees space before you buy disks — "
            "and the purge log proves every deletion."))
    if ret.get("log_ok") is False:
        out.append(_corr(
            "purge_log_integrity", "critical",
            "Purge-log hash chain FAILED verification",
            ["retention purge log did not verify (tamper-evident chain "
             "broken)"],
            "Investigate before the next audit. Run "
            "`safecadence retention verify` and review who touched the "
            "log file."))

    # 5 — open incident at a blind site -------------------------------
    for inc in _open_incidents():
        isite = inc.get("site") or ""
        if isite and isite in dark_sites:
            nd = len(dark_sites[isite])
            out.append(_corr(
                "incident_blind_site", "critical",
                f"Open incident “{inc.get('title', '')[:60]}” at "
                f"{isite} — where {nd} camera(s) are dark",
                [f"incident {inc.get('incident_id', '')} "
                 f"({inc.get('severity')}, {inc.get('status')}) at {isite}",
                 f"{nd} watched device(s) dark at the same {site_word}"],
                "You may have no video record of this incident. Restore "
                "the cameras and preserve whatever footage exists NOW."))

    # 6 — community cameras as canvass leads --------------------------
    com = _community()
    if com.get("registered_cameras"):
        opens = [i for i in _open_incidents()
                 if i.get("severity") in ("critical", "high")]
        if opens:
            out.append(_corr(
                "community_leads", "medium",
                f"{com['registered_cameras']} registered community "
                f"camera(s) available for canvass on "
                f"{len(opens)} open high-severity incident(s)",
                [f"open: {i.get('title', '')[:50]} ({i.get('severity')})"
                 for i in opens[:3]]
                + [f"{com['registered_cameras']} consent-based registry "
                   "entries with owner contacts on file"],
                "Check the Community registry map around each incident "
                "location — owners volunteered to be contacted."))
    if com.get("active_watches") and dark:
        out.append(_corr(
            "watch_coverage", "medium",
            f"{com['active_watches']} active watch request(s) while "
            f"{len(dark)} agency camera(s) are dark",
            [f"{com['active_watches']} address(es) asked for extra "
             "patrols", f"{len(dark)} watched device(s) currently dark"],
            "Blind spots + watch requests = prioritize physical checks "
            "on those addresses this week."))

    # 7 — chronic repeat offenders ------------------------------------
    prior = _prior_dark_names(profile)
    for d in dark:
        n = d.get("name")
        if n and prior.get(n, 0) >= 2:
            out.append(_corr(
                "chronic_device", "high",
                f"{n} has now been dark in {prior[n] + 1} weekly reports",
                [f"{n} dark again this week ({d.get('status')})",
                 f"dark in {prior[n]} of the last {min(len(prior), 4)} "
                 "weekly snapshots"],
                f"Stop re-fixing it. Replace {n} — the repair cycle is "
                "costing more than the device."))

    out.sort(key=lambda c: _SEV_ORDER.get(c["severity"], 9))
    return out


# ------------------------------------------------------------------ note

def _deterministic_note(report: dict, correlations: list[dict],
                        profile: str) -> str:
    if not correlations:
        if report.get("overall") == "healthy":
            return ("All silos agree this week: fleet up, storage sane, "
                    "no cross-cutting risks found. Keep the watch.")
        return ("No cross-silo correlations this week — the issues in "
                "this report are independent of each other. Work the "
                "recommended action at the top.")
    top = correlations[0]
    parts = [f"The dots connect: {top['headline']}."]
    if len(correlations) > 1:
        kinds = ", ".join(c["headline"].split(" — ")[0]
                          for c in correlations[1:3])
        parts.append(f"Also connected this week: {kinds}.")
    parts.append(top["recommendation"])
    return " ".join(parts)


def _ai_note(correlations: list[dict], profile: str) -> str | None:
    """Optional AI-written analyst note, grounded ONLY in the computed
    correlations. Returns None on any failure — caller falls back."""
    try:
        from safecadence.ai.client import (
            AIProvider, _call_anthropic, detect_provider)
        if detect_provider() != AIProvider.ANTHROPIC:
            return None
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key:
            return None
        facts = json.dumps(correlations[:6], indent=1)
        prompt = (
            "You are the analyst for a "
            + ("school district" if profile == "campus"
               else "sheriff's office")
            + " infrastructure watch report. Below are the ONLY facts "
            "you may use — computed correlations from real device "
            "records. Write a 3-4 sentence plain-English analyst's "
            "note for a non-technical leader: what connects, why it "
            "matters, and the single most valuable action. Do NOT "
            "invent devices, numbers, or causes not in the facts. No "
            "preamble, no markdown.\n\nFACTS:\n" + facts)
        text = _call_anthropic(prompt, api_key=key,
                               model=os.environ.get(
                                   "SC_AI_MODEL", "claude-fable-5"),
                               timeout=45, effort="low")
        text = (text or "").strip()
        return text[:1200] if text else None
    except Exception:
        return None


def build_intel(report: dict, assets: list[dict] | None = None,
                profile: str = "agency") -> dict[str, Any]:
    """The full intelligence block for a report: correlations + note."""
    correlations = connect_dots(report, assets, profile)
    note = None
    ai_generated = False
    if correlations and os.environ.get("SC_WATCH_AI", "1") != "0":
        note = _ai_note(correlations, profile)
        ai_generated = note is not None
    if not note:
        note = _deterministic_note(report, correlations, profile)
    return {
        "correlations": correlations,
        "correlation_count": len(correlations),
        "note": note,
        "ai_generated": ai_generated,
    }
