# v16 — DIRECTIONAL PLANNING (no code shipped, intentionally)

> v15.0 has shipped. v16 work, by design, does NOT start with code.
> v16 is a planning exercise — the actual scope crystallizes only
> after 12+ months of v12/v13/v14/v15 customer feedback.

This document exists to make that explicit. **There is no v16 branch,
no v16 tag, no v16 module.** If you came here looking for v16 code,
it doesn't exist yet — and that's the right answer, not a gap.

---

## The three plausible futures

Which v16 actually ships depends entirely on which customer profile
v12–v15 attracts in production. Three coherent paths:

### Future A — "SafeCadence is the air-gap compliance default"

If the regulated buyer (defense, healthcare, classified finance) is
where the customers actually came from, v16 doubles down on that moat.
Scope would include:

- **FedRAMP Moderate authorization** (18–24 month process, started in
  v14's non-code initiatives)
- **HSM-backed key vault** for FIPS 140-2 Level 3
- **Air-gapped multi-node cluster** (full replication + failover
  inside one customer's network — extends v12.2 peer-sync to N>2)
- **ITAR-compliant build pipeline** (US-citizen-only commit signers,
  US-only build infrastructure)
- **Industry-vertical compliance packs at depth** — HITRUST, NYDFS
  Part 500, ISO 27017 / 27018, CMMC v2.5

### Future B — "SafeCadence is the MSP platform"

If v12's MSP buyer profile validated and the customer base is mostly
MSPs serving regulated SMBs, v16 doubles down on MSP scale:

- **Distributed scanning across regions** — a North American MSP
  serving European customers needs EU-resident scanning
- **Reseller billing infrastructure** — MSPs invoice their customers,
  upstream settles monthly
- **Industry-vertical packaging** — "SafeCadence for Healthcare MSPs"
  bundling HIPAA + HITRUST + SOC 2 + healthcare-vendor adapters
- **Partner enablement at depth** — solutions architects, partner
  success team, partner advisory board

### Future C — "Identity governance was the bigger market"

If v14's conversational assistant + the operational telemetry from v13
surface that identity drift is a bigger pain than network config drift
(plausible — the v11.x line already added 5 identity adapters), v16
might be a strategic pivot:

- **Identity-first repositioning** — rename, reposition; network
  adapters become a feature instead of the core
- **JIT access at scale** (v11.x foundation expanded)
- **NHI lifecycle management at depth** — service account rotation
  enforcement, secrets-detection in code
- **Compete head-on with SailPoint / Okta Workflows** for identity
  governance

---

## What would v16 NOT be regardless of direction

- **A "v16 rewrite"** — no major architectural rewrites; Pythonic +
  stdlib-heavy stays.
- **A pivot to closed-source** — MIT license stays, even if
  commercial extensions exist around it.
- **A funded enterprise sales motion** — SafeCadence stays
  independent at v16+ scale; if a funded competitor emerges, the
  response is to compete on local-first / no-data-leaves-network,
  not to chase the SaaS money.
- **eBPF runtime monitoring** — still rejected unless a hard customer
  ask materializes; kernel code ships subtle bugs for years.

---

## Why no code now

Three honest reasons:

1. **v13/v14/v15 just shipped.** The natural feedback cycle hasn't
   started yet. Building v16 features on hypothesized customer needs
   would be the textbook mistake the roadmap warns against.

2. **The three futures are mutually exclusive on capacity.** A
   solo-maintainer or small team can do A or B or C well — not all
   three. Picking before the data lands means picking wrong.

3. **The work is large.** FedRAMP Moderate alone is 18–24 months of
   compliance work for a tiny team. Distributed scanning across regions
   is a multi-month engineering project. Identity governance at depth
   is a category pivot. None of these are "ship in one session."

---

## What WILL happen between now and "v16 work begins"

- **v15 customer feedback collection** — instrumented via the existing
  v10.9 dashboards + the v13 SSE event bus
- **Quarterly roadmap review** — read this document, mark the
  future-most-aligned-with-actual-customers, demote the other two
- **Continuous v12-v15 polish** — bug fixes and small feature work
  land as `15.x.y` patch releases, not v16 work
- **Architecture decisions for the chosen future** logged in
  individual ADR docs under `docs/adr/`

---

## How to know it's time to start v16

Concrete signals (any TWO of these):

- 10+ paying customers active for 6+ months with a clear majority in
  one of the three futures
- A specific compliance / regulatory deadline (e.g. FedRAMP) that a
  customer is explicitly funding
- A competitor moves and the response requires architectural change
- The v13 Knowledge Graph or v14 intelligence layer has accumulated
  enough operational telemetry to make new ML features honestly
  feasible

Without two of those, v16 stays a planning doc.

---

Last touched: 2026-05-25 — alongside the v15.0 ecosystem release.
This document gets reviewed quarterly. If you're reading this in
Q4 2026 and the signals above haven't fired, that's not a
disappointment — it's confirmation the discipline is working.
