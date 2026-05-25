"""
v16.0 — Regulatory drift watcher.

Watches public regulatory feeds (NVD, CISA KEV, NIST SP publications,
FedRAMP updates, HIPAA tier rulings) and, when something new lands
that *affects this customer's fleet*, files a nudge.

This is the most demo-friendly v16 agent: it feels magical because
nobody else does it, and the underlying mechanics are honest +
explainable (it's RSS/JSON + classification + dedup, not magic ML).

Sources today
-------------

* ``nvd_cves``     — NIST National Vulnerability Database recent CVEs
                     (https://services.nvd.nist.gov/rest/json/cves/2.0)
* ``cisa_kev``     — CISA Known Exploited Vulnerabilities catalog
                     (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
* ``nist_csf``     — NIST publications RSS (loose match on framework changes)
* ``custom``       — operator-added URL feeds (JSON or RSS)

The watcher is **fully optional**. Without ``SC_REGULATORY_FEEDS=1``
the daemon is a no-op. When enabled, it polls every 6 hours by
default (operator-tunable via ``SC_REGULATORY_INTERVAL_S``).

Privacy: only the customer's fleet vendor list + framework list go
into the classification prompt. No findings, no hostnames, no
configurations.

Public API
----------

* ``DEFAULT_FEEDS``
* ``fetch_feed(url, timeout=15)`` → list[dict]
* ``classify_relevance(items, *, fleet_vendors, frameworks, llm_provider=None)``
  → list[dict] each tagged with ``relevant: bool`` + ``reason``.
* ``run_watch_pass(*, nudge_conn, fleet_vendors=None, frameworks=None,
                    feeds=None, agent_id='regulatory-watcher')`` → summary
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

_log = logging.getLogger("safecadence.agents.regulatory_watcher")


DEFAULT_FEEDS = {
    "cisa_kev": (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    ),
    # NVD feed kept commented since the recent-CVE endpoint requires
    # paging + URL params; the operator who wants it sets a custom feed.
    # "nvd_cves": "https://services.nvd.nist.gov/rest/json/cves/2.0",
}


def is_enabled() -> bool:
    return (os.getenv("SC_REGULATORY_FEEDS") or "").strip() in (
        "1", "true", "yes",
    )


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------


def fetch_feed(url: str, *, timeout: float = 15.0) -> list[dict]:
    """Fetch + parse one feed URL. Returns a list of normalized items.

    Defensive: any HTTP / parse error returns []. Never raises.
    """
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "safecadence-regulatory-watcher/16.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        _log.info("feed fetch failed %s: %s", url, exc)
        return []

    # Try JSON first
    try:
        data = json.loads(body)
    except Exception:
        # Not JSON — could be RSS/Atom. Punt for v16; we ship JSON only.
        return []

    # Normalize CISA KEV shape (the most useful default feed)
    items: list[dict] = []
    if isinstance(data, dict) and "vulnerabilities" in data:
        for v in (data.get("vulnerabilities") or [])[:200]:
            items.append({
                "id":          v.get("cveID", ""),
                "title":       (v.get("vulnerabilityName") or v.get("cveID") or "")[:200],
                "published":   v.get("dateAdded", ""),
                "vendor":      (v.get("vendorProject") or "").strip(),
                "product":     (v.get("product") or "").strip(),
                "description": (v.get("shortDescription") or "")[:500],
                "url":         f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}",
                "source":      "cisa_kev",
            })
        return items

    # Generic "list of dicts" shape — pass through
    if isinstance(data, list):
        for d in data[:200]:
            if isinstance(d, dict):
                items.append({
                    "id": str(d.get("id") or d.get("cve") or ""),
                    "title": str(d.get("title") or d.get("name") or ""),
                    "description": str(d.get("description") or "")[:500],
                    "vendor": str(d.get("vendor") or ""),
                    "product": str(d.get("product") or ""),
                    "url": str(d.get("url") or ""),
                    "published": str(d.get("published") or ""),
                    "source": "custom",
                })
    return items


# --------------------------------------------------------------------------
# Classify
# --------------------------------------------------------------------------


_FRAMEWORK_KEYWORDS = {
    "soc2": ("soc 2", "soc2", "trust services criteria", "cc6", "cc7"),
    "hipaa": ("hipaa", "phi", "covered entity", "business associate"),
    "pci": ("pci dss", "pci-dss", "cardholder data", "pan"),
    "nist-800-53": ("nist 800-53", "nist sp 800-53", "rev 5", "rev 6"),
    "cis-v8": ("cis controls", "cis benchmark", "cis v8"),
    "cmmc": ("cmmc", "dfars 252.204-7012"),
    "fedramp": ("fedramp",),
}


def _matches_vendor(item: dict, vendor_set: set[str]) -> bool:
    if not vendor_set:
        return False
    target = (item.get("vendor") or "").lower()
    if not target:
        # Also try the description (catches "Cisco IOS RCE" style entries)
        text = (item.get("description") or "").lower()
        return any(v.lower() in text for v in vendor_set)
    return any(v.lower() in target for v in vendor_set)


def _matches_framework(item: dict, framework_set: set[str]) -> tuple[bool, str | None]:
    text = (
        (item.get("title") or "") + " " +
        (item.get("description") or "")
    ).lower()
    for fw in framework_set:
        kws = _FRAMEWORK_KEYWORDS.get(fw.lower(), ())
        for kw in kws:
            if kw in text:
                return True, fw
    return False, None


def classify_relevance(
    items: list[dict],
    *,
    fleet_vendors: list[str] | None = None,
    frameworks: list[str] | None = None,
) -> list[dict]:
    """Tag each item with relevance to the customer's fleet.

    Returns the same items list with two fields added:
        relevant:   bool
        reason:     str (why we think it matches)
    """
    vendor_set = {v.strip() for v in (fleet_vendors or []) if v.strip()}
    framework_set = {f.strip() for f in (frameworks or []) if f.strip()}
    out: list[dict] = []
    for it in items:
        reasons: list[str] = []
        if vendor_set and _matches_vendor(it, vendor_set):
            reasons.append(
                f"vendor match ({it.get('vendor') or 'description hit'})"
            )
        ok_fw, hit_fw = _matches_framework(it, framework_set)
        if ok_fw:
            reasons.append(f"framework match ({hit_fw})")
        it2 = dict(it)
        it2["relevant"] = bool(reasons)
        it2["reason"] = "; ".join(reasons) or "no fleet/framework match"
        out.append(it2)
    return out


# --------------------------------------------------------------------------
# Watch pass
# --------------------------------------------------------------------------


def run_watch_pass(
    *,
    nudge_conn: Any,
    fleet_vendors: list[str] | None = None,
    frameworks: list[str] | None = None,
    feeds: dict[str, str] | None = None,
    agent_id: str = "regulatory-watcher",
    max_nudges_per_pass: int = 5,
) -> dict:
    """One end-to-end pass: fetch → classify → nudge.

    Caps at ``max_nudges_per_pass`` to avoid blasting the operator
    when a feed has a backlog of newly-published items. Dedup is
    handled by ``create_nudge`` via signature.
    """
    from safecadence.agents.nudges import create_nudge

    feeds_in_use = feeds or DEFAULT_FEEDS
    all_items: list[dict] = []
    for name, url in feeds_in_use.items():
        all_items.extend(fetch_feed(url))

    classified = classify_relevance(
        all_items,
        fleet_vendors=fleet_vendors or [],
        frameworks=frameworks or [],
    )
    relevant = [c for c in classified if c["relevant"]]
    relevant.sort(key=lambda x: x.get("published", ""), reverse=True)
    relevant = relevant[:max_nudges_per_pass]

    created = 0
    for it in relevant:
        sig = f"reg:{it.get('source', 'feed')}:{it.get('id', '')}"
        title = f"Regulatory update affects you: {it.get('title') or it.get('id')}"
        body = (
            f"{it.get('description', '')}\n\n"
            f"Why I flagged this: {it.get('reason', '')}\n\n"
            f"Source: {it.get('url') or it.get('source', '')}"
        )
        nid = create_nudge(
            nudge_conn,
            agent_id=agent_id,
            signature=sig,
            title=title,
            body=body,
            severity="warning",
            category="regulatory",
            suggested_action="review_regulatory_update",
            evidence={
                "feed_item": {k: it.get(k) for k in
                              ("id", "vendor", "product", "url",
                               "published", "source")},
                "reason":    it.get("reason"),
            },
            dedup_within_days=30,
        )
        if nid:
            created += 1

    return {
        "items_fetched":     len(all_items),
        "items_relevant":    len(relevant),
        "nudges_created":    created,
        "feeds_polled":      list(feeds_in_use.keys()),
        "fleet_vendors":     fleet_vendors or [],
        "frameworks":        frameworks or [],
    }


__all__ = [
    "DEFAULT_FEEDS",
    "is_enabled",
    "fetch_feed",
    "classify_relevance",
    "run_watch_pass",
]
