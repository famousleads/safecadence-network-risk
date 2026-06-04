# v17 — Exposure & Vendor-Breach Watchers

> **Status:** Planned. No v17 branch yet. v16.0.0 shipped to PyPI on 2026-05-24
> and is intentionally getting two weeks of breathing room in front of
> real customers before any v17 code lands.

v17 is the natural sequel to v16's agents layer. It adds **two more
watchers** to the same framework that powers `regulatory_watcher`,
`adversarial`, `drift_explainer`, and the rest of v16's agents.

It does not add new asset types, new schemas, new tables, or new
infrastructure. The story is the same one v16 told — "an agent that
doesn't lose your trust is worth more than one that does more things"
— extended to two more risk categories that real operators care about.

---

## Two new agents

### 1. Executive Exposure Agent — `agents/exposure_watcher.py`

A continuous watcher over a customer-managed exec watchlist (CEO,
CFO, CISO, key engineers + their work emails + optionally their
personal emails).

Polls:

- **HIBP** (Have I Been Pwned) breach API for new hits on listed
  identities
- **Known mega-breach indexes** — NPD-style records aggregated by
  trusted public lookup services
- **Data-broker re-appearance** — when a broker re-lists someone the
  customer had removed
- **Optional: face-rec service** (FaceCheck.ID / PimEyes / custom)
  for new exec photo exposures on the public web

Output: nudges in the existing v16 inbox, deduped via v16's memory
layer so the same hit doesn't fire twice. Same alarm-fatigue defense
that the rest of the agents framework uses.

### 2. Vendor Breach Watcher — `agents/vendor_breach_watcher.py`

A close sibling of `regulatory_watcher.py` — same machinery, different
feeds. Polls:

- HIBP breach intelligence feeds
- News-scraped breach announcements (Mandiant blog, Bleeping
  Computer, BleepingComputer RSS, CrowdStrike intelligence summaries)
- Cross-references against the customer's vendor list (already
  collected by Vendor Risk Analyzer)

Output: "Snowflake confirmed incident at 09:14 UTC. You have 7
services using Snowflake. 2 store PII. Your DPA with Snowflake
requires customer notification within 72 hours — clock starts now."
Nudge filed with pre-filled notification clocks.

---

## What v17 is NOT

- **No OSINT Recon Agent.** That's v18 — the third lobe of
  red/blue, an agent that walks the customer's *external* attack
  surface continuously and disagrees with internal red on what's
  actually exposed.
- **No Canary Pack.** Also v18 — decoy tokens + decoy mailboxes +
  decoy admin accounts that route hits through the nudge inbox.
- **No new asset types.** No RF/IoT asset class (later — hardware-
  dependent), no face-recognition asset class (later).
- **No conversational MCP UI.** The MCP server stays as v16 left it.
- **No schema changes.** v17 inherits v16's graph + memory + nudges
  + audit-chain tables.
- **No autonomous remediation.** Everything still routes back to the
  Tier-3 SSH triple-gate when execution is needed. The agent's job
  is to surface a deduplicated, attributed, actionable nudge — not to
  act unilaterally.

---

## Scope estimate

- `agents/exposure_watcher.py` — ~600 lines, sibling of
  `regulatory_watcher.py`
- `agents/vendor_breach_watcher.py` — ~400 lines
- 2 new UI pages — `/exposure-watch`, `/vendor-breach-watch`,
  same pattern as `/nudges`
- ~20 new tests in `tests/test_v17_*.py`
- README + sidebar nav + CHANGELOG entries
- 1 PyPI release + 1 droplet hotpatch for the demo

Roughly **one focused day of work**, same shape as the v16 ship.

---

## External dependencies

- **HIBP API key** — $3.95/month per organization. One key handles
  unlimited identities for that customer.
- **Optional face-rec integration** — defer to v17.1 if the v17
  release wants to stay narrow. The Executive Exposure Agent ships
  and works without it; face-rec becomes one more pluggable feed.
- **No new database, no new server, no new infrastructure.**

---

## Why these two together

Both v17 agents inherit v16's primitives:

| v16 primitive | v17 reuse |
|---|---|
| Nudge inbox | Both agents file into it |
| Memory layer with signature dedup | Both use it to avoid repeat alarms |
| Regulatory watcher pattern | Both follow the same module shape |
| SSE live dashboard | Both surface in the existing live view |
| Audit-chain attribution | Both log per-nudge provenance |

The narrative the v17 release sells: **SafeCadence moves from
"network/firewall risk" → "everything-that-could-hurt-you risk."**
Same architecture, expanded scope.

---

## Why not v18 first?

The OSINT Recon Agent and the Canary Pack are interesting, but they
each require more new surface than v17 does — recon needs external-
scan rate-limit handling and reputation backoffs; canaries need
careful UX around token expiration and false-positive routing.

v17 by contrast slots cleanly into v16. The watchers are the most
direct extension of the agents framework, the lowest implementation
risk, and the cleanest funnel pairing with the consumer awareness
tools live at https://safecadence.com/tools/ today.

---

## Out of scope for v17

- **Pricing changes.** v17 stays free under MIT. The HIBP API key
  cost is the customer's, not ours.
- **Enterprise tier.** No "v17 Pro" or "v17 Enterprise." The product
  stays single-tier, single-license.
- **SaaS hosting.** Local-first remains the deployment model. The
  watchers run on the customer's own SafeCadence install, polling
  HIBP + breach feeds outbound, never accepting inbound webhooks
  from third parties.

---

## When v17 ships

**Earliest:** 2026-06-09 (two weeks after v16.0.0).
**Trigger:** at least one inbound ask from a v16 user for continuous
exposure monitoring. If no such ask materializes, v17 stays paused —
the framing needs to be re-validated against actual demand before
the code gets written.

Until that trigger fires, v17 is documented here and held.

---

_Last updated: 2026-05-25._
