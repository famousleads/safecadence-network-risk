# SafeCadence Roadmap — v12.0 → v14.0

**Last updated:** 2026-05-25 · **Maintainer:** Faz Karim ([@famousleads](https://github.com/famousleads))

This document covers the next three major releases. Each version has a
clear positioning sentence, a committed scope, and explicit callouts for
what is *not* in scope. Things change — but they change *publicly*, with
a CHANGELOG entry explaining the shift, not silently.

---

## How we decide what ships in a major release

Three filters, in order:

1. **Does it convert?** A feature only justifies a major version slot if
   it directly closes a buyer-loss reason we've seen in the last 90 days.
   Cool features that don't change a single sales conversation get
   slotted to a minor release or rejected.

2. **Does it compound?** Features that make the next features easier
   (multi-tenant org system, generic provider table, encrypted config
   store) ship first. Features that are leaves of the architecture tree
   ship last.

3. **Can a single maintainer ship it without breaking the things that
   already work?** SafeCadence is a single-maintainer project until it
   isn't. Releases that require a team don't happen.

When the three filters disagree, **filter 1 wins.**

---

## Licensing & monetization principle

> **The SafeCadence software stays MIT-licensed and 100% free for anyone
> to use, modify, develop, and self-host — forever. No feature gating.
> No open core. No "enterprise edition" with paid-only features.**

This is a permanent commitment, not a phase. Every feature shipped in
v12 through v16 is in the open-source repo, available via `pip install`,
free to use commercially or personally, free to fork, free to extend.
If a competitor wants to fork SafeCadence and run it themselves, they
can — the MIT license permits it explicitly.

So how does this project sustain itself financially? **By selling time,
services, and convenience *around* the free product — never by gating
the product itself.** Seven monetization layers, each launched at a
specific version, none of which compromise the free-software commitment:

| # | Monetization layer | Launches with | Doesn't compromise OSS because... |
|---|---|---|---|
| 1 | **Support contracts** (Starter $199/mo → Mission-critical quote) | **v12.0** | You're buying SLA + human response time, not features |
| 2 | **GitHub Sponsors button** | **v12.0** | Voluntary patronage; software is still free |
| 3 | **Audit-as-a-service** (SOC 2 / PCI / HIPAA / CMMC assessments) | **v13.0** | You're buying the auditor's certified time + credentials, not the tool |
| 4 | **Training + certification** (courses + exams + badges) | **v13.0** | You're buying education + a credential, not access to the code |
| 5 | **Hosted orchestration plane SaaS** (MSP-tier $99–$1,999/mo) | **v14.0** | You're buying us running infrastructure for you; same software is downloadable free for self-host |
| 6 | **Hardware appliance partnership** (pre-loaded fanless boxes) | **v14.0** | You're buying the hardware + warranty + zero-config convenience |
| 7 | **Marketplace revenue share** (15–25% on paid 3rd-party plugins) | **v15.0** | You're buying someone else's extensions; the platform itself stays free |

**What we will never sell:**
- The core SafeCadence Python package
- Access to any feature that exists in the OSS repo
- A "Pro" / "Business" / "Enterprise" code edition that has features the OSS doesn't
- Per-seat licenses on the open-source code

**What we will always offer for free:**
- The complete SafeCadence software (MIT)
- The complete `docs/` directory + every guide we write
- The community Slack/Discord/GitHub Discussions
- Best-effort GitHub issue triage
- The live demo at `demo.safecadence.com`
- Quarterly air-gap distribution bundles

The realistic revenue model at v14 (~18 months out, assuming distribution
work catches up): roughly **$500k ARR**, with the breakdown weighted
toward support contracts (~$150k), audit services (~$200k), and hosted
SaaS (~$72k). Hardware + marketplace come in later. Full detail in the
companion `MONETIZATION_STRATEGY.md` doc.

---

## The three-release narrative

| Version | Tagline | Single sentence |
|---|---|---|
| **v12.0** | Platform | *From tool to platform — multi-tenant, customer-facing, audit-grade, revenue-ready.* |
| **v13.0** | Operational excellence | *From snapshot to live — continuous monitoring, real-time alerts, integrated ITSM.* |
| **v14.0** | Intelligence | *From reactive to predictive — ML trained on real customer data, conversational interface, AI-driven remediation.* |

Each version builds on the previous. v13's real-time monitoring needs
v12's multi-tenant org system to know which customer's drift to alert
on. v14's ML needs v13's operational telemetry as training data. Cuts
to v12 force corresponding cuts downstream.

---

# v12.0 — Platform

**Target ship date:** Q3 2026 (8–12 weeks of focused work)
**Status:** Committed scope, in active design

### The single-sentence positioning

**SafeCadence becomes an MSP-grade multi-tenant audit platform that
your customer's customer can log into — branded, paid for, audit-ready.**

### Why this is the v12 priority

The v11 line shipped 12 LLM providers, encrypted config, UI Settings
panel, native HF / Ollama / Gemini / Groq / Cohere / etc. — but the
product still assumes one operator on one laptop scanning their own
gear. For an MSP serving 10–50 customers (the primary buyer profile),
that doesn't scale. Multi-tenancy is the single architectural change
that turns SafeCadence from "tool you install" to "platform you build
a business on."

### Themes in scope

**1. Multi-tenant org system + per-org isolation.** The config store
(`reports/llm_config.py`), report templates, branding (logos, colors,
signature blocks), webhooks, audit logs, retention policies, scan
history, AND the LLM key vault all become per-org. One MSP install
serves 50 customers cleanly with no data crossover. Includes a real
org-management UI: create org, invite members, switch active org,
roll org keys, export org data. Capability gates ensure an MSP user
can't see another MSP's customers.

**2. Customer-facing read-only portal.** Each MSP customer gets a
branded URL (e.g. `customer-acme.your-msp.com` or
`portal.your-msp.com/c/acme`) where they see *their* reports, *their*
drift status, *their* compliance posture — with the MSP's branding,
not SafeCadence's. Read-only by default. Optional e-sign on report
acceptance (already exists for one-off reports; this generalizes it
to the customer-portal pattern). This is the feature that lets an MSP
say "your customer can see this themselves" instead of "we email them
a PDF every quarter."

**3. Audit-grade SOC 2 + CMMC 2.0 Level 2 evidence packs.** The reports
module already maps findings to controls. v12 outputs the actual
artifact an auditor accepts: timestamped per-control attestations,
evidence chain of custody (extending the v11.3 hash-chained audit log),
control-owner sign-off workflow, exception register with rationale,
the specific output formats SOC 2 and CMMC assessors expect. Bridges
"we say we're SOC 2-ready" → "here's your audit package, signed off,
ready for the QSA."

**4. Stripe billing + Postmark signup + first-run wizard.** The seeded
plan tiers ($0 / $49 / $149 / $499) become real Stripe products with
working checkout. Magic-link signup actually delivers email via
Postmark. A first-run wizard takes a new user from `pip install` to
"first report generated on a sample config" in five minutes. This is
the unglamorous but critical theme — without it, the free → paid
funnel doesn't exist.

**5. Air-gap distribution bundle.** A single signed `.tar.gz` with
SafeCadence + offline CVE feed + offline rule packs + all dependency
wheels for Python 3.10/3.11/3.12. Customers in SCIFs can sneakernet
it in. Quarterly refresh cadence. Locks in the local-first moat for
the regulated buyer (defense, healthcare, classified).

**6. MCP Server (AI infrastructure positioning).** Native support
for Anthropic's Model Context Protocol so Claude / Cursor / Claude
Desktop / Block / any MCP-capable client can query SafeCadence
directly. Tool surface includes: `query_topology`,
`retrieve_findings`, `query_compliance`, `fetch_evidence`,
`inspect_identities`, `generate_report`, `evaluate_posture`. All
RBAC-aware (uses the operator's session capabilities), audit-logged
(every MCP call writes to the v11.3 hash-chained audit log), and
explainable (every response cites source objects). Positions
SafeCadence as **AI-native governance infrastructure that other AI
systems consume** — without buying into the "AI-native OS" buzzword
positioning. ~1 week of work; ~500 lines of Python.

**Reports module polish (within Theme 2 expansion):**

- **Multi-dimensional Safe Score** — the single 0–100 number splits
  into Compliance Health, Identity Health, Drift Stability, Patch
  Freshness, Attack Path Risk, AI Governance Readiness. Each
  dimension has its own trend and a confidence interval. Mature
  buyers think in dimensions, not a single rollup.
- **Risk Economics metrics** — every report now translates findings
  to dollars: estimated audit-failure exposure, estimated remediation
  cost, risk-reduction ROI per action, technical debt score,
  operational risk velocity. CISOs and boards budget in dollars, not
  severity counts.
- **Executive Risk Brief preset** — new named preset alongside the
  existing four (exec_brief, technical_deepdive, compliance_audit,
  quarterly_review). Targets the "upload → 5-minute board-ready
  report" demo flow. Includes risk score, compliance posture,
  weakest-link analysis, attack-path summary, estimated audit
  exposure, top 5 executive actions, and remediation roadmap. This
  is the demo experience that wins MSP buyers; it's not a new
  product, just a named preset that exercises the existing reports
  pipeline.

### Non-code initiatives that ship with v12

**Live Trust Center page** at `safecadence.com/trust` — *upgraded
from static to live for v12*: cryptographic posture (Fernet vault,
HMAC tokens, hash-chained audit log), data flow diagram showing
nothing leaves customer network, security policy, bug bounty program,
planned SOC 2 timeline — PLUS real-time compliance posture pulled
from SafeCadence's own self-hosted install (we eat our own dog food
publicly). Visitors see "SafeCadence-the-company is currently 91%
SOC 2, 96% NIST, 88% PCI" with refresh timestamps. Auditors and
enterprise procurement see this as concrete evidence the product
works in production. ~3 days of work.

**Public changelog page** at `safecadence.com/changelog` — every
release becomes a marketing moment. Linear/Vercel/Resend/Stripe all
have this; the absence of one signals "small project." Auto-generated
from `CHANGELOG.md` so updates land without manual work. RSS feed
included. ~2 days.

**Case study scaffolding** — interview template, permission-release
form, anonymization workflow, publication checklist, three pre-drafted
case-study skeletons (MSP / Internal IT / Air-gap buyer) ready to
populate the moment the first design partner agrees. When the first
customer succeeds, we publish in 48 hours instead of 3 weeks. ~2 days.

**First-customer onboarding playbook** — exact sequence the moment
the first paying support contract lands: kickoff agenda, week-1 /
week-2 / week-4 / week-12 check-in cadence, success metrics, escalation
paths, expansion triggers, renewal handoff. Currently undefined.
~2 days.

**Reference architecture diagrams** for three deployment scales:
- **Single operator** (one machine, one customer, free tier)
- **Mid-size MSP** (5–50 customer fleets, Starter / Business support tier)
- **Large MSP / Enterprise** (200+ customer fleets, Enterprise tier + hosted SaaS)

Each diagram includes hardware sizing, cost model, latency targets,
backup/recovery posture. Enterprise procurement asks "how does this
scale?" — this is the documented answer. ~3 days.

**Sigstore-signed releases + reproducible-build attestations.**
Every PyPI release and air-gap bundle gets Sigstore-signed via
GitHub Actions OIDC. SLSA Level 3 provenance attestation
published alongside. Trust center page links the verification
process. Standard practice for security-critical OSS in 2026;
absence signals "small project." ~2 days for v12 launch.

**OSS health badges on `README.md`** — PyPI downloads, GitHub stars,
license, Python version compatibility, CI status, CodeQL scan,
test count. Standard practice; absence sends "this is a hobby
project" signal. ~1 hour.

**Internal usage-metrics dashboard** (private to maintainer, not
public): weekly PyPI downloads (filtered for likely-human traffic),
GitHub star velocity, demo.safecadence.com unique visitors,
demo→signup conversion rate, support contract count, MRR. Without
this, the conversion funnel is invisible. ~1 day.

**Competitor migration playbooks** — published as docs / blog posts
during Q3 2026:
- `docs/migration-from-algosec.md` — "Moving from AlgoSec to SafeCadence"
- `docs/migration-from-tufin.md` — "Moving from Tufin to SafeCadence"
- `docs/migration-from-drata.md` — "Moving from Drata to SafeCadence"
- `docs/migration-from-vanta.md` — "Moving from Vanta to SafeCadence"

Each ~1 day to draft. These are SEO assets that target buying-intent
queries ("AlgoSec alternative") that paid ads can't profitably
target. Compound over 60–120 days.


**SOC 2 Type II auditor engagement starts.** 6–9 month process. If
v12 ships in Q3 2026 with the evidence-pack code, the SOC 2 audit
itself lands around Q1–Q2 2027. Start the auditor selection NOW.

**Public penetration test report.** Commission a credible third-party
firm. Budget: $10k–$25k. Report becomes part of the trust center.
Schedule for Q3 2026.

**Bug bounty program activation.** SECURITY.md is already in place
from v11.3. v12 launches the actual program — HackerOne or Bugcrowd
or self-hosted, depending on budget.

### OSS hygiene + enterprise procurement readiness (new in v12)

Enterprise buyers ask four questions in every procurement evaluation
that current SafeCadence docs don't answer. v12 closes that gap by
shipping four new policy commitments + five supporting documents.
None of this is code; all of it is required for the kind of buyer
that signs a $5,000/month support contract.

**Governance model** (new doc: `GOVERNANCE.md`). Currently SafeCadence
is single-maintainer (Faz Karim). v12 documents this honestly: how
decisions are made today, what triggers the evolution to a
maintainer council (5+ active contributors, 3+ paying companies,
formal decision-process documented), and how community members can
escalate disagreements. Says the quiet part out loud: this is a
single-maintainer project, with a documented path to wider
governance as it grows.

**Version support policy** (new doc: `SUPPORT_POLICY.md`). Defines
the support window for every major version. v11.x receives security
patches until v14 GA. v12.x receives security patches until v15 GA.
v13.x receives security patches until v16 GA. Patch-only minor
releases (vX.Y.Z) are guaranteed to be backwards-compatible within
a major. Breaking changes only happen at major version boundaries
with 6 months of pre-announcement. This is what enterprise asks for
when they evaluate "is it safe to stay on v11 for another year?"

**Continuity / bus-factor plan** (new section in `GOVERNANCE.md`).
If the primary maintainer becomes unavailable, what happens:
PyPI account access is documented + stored with a designated
successor; GitHub org commit rights are held by 2+ trusted
individuals; the build/release keys are escrowed with the same
group; the SafeCadence trademark + safecadence.com domain are
held by a legal entity with a documented succession plan; the
project license (MIT) ensures anyone can fork and continue the
work regardless. Enterprise procurement asks this question
literally; v12 has the answer ready.

**Pricing transparency commitments** (new doc: `PRICING_POLICY.md`).
The promises buyers screenshot and put in their procurement file:
- We will not raise prices on existing customers without 90 days
  written notice
- Annual prepay locks the rate for 12 months regardless of list
  price changes
- Existing customers grandfathered into pricing tiers when new
  tiers launch (no forced upgrades)
- 30-day money-back guarantee on first payment for any paid tier
- All pricing is publicly listed; no hidden enterprise pricing
  (even Enterprise tier has a published starting price)
- No "negotiable" pricing — same rate for everyone at the same
  tier
- 30-day notice on plan cancellation (no surprise lock-ins)

### Companion documents shipping with v12 launch

| File | Purpose |
|---|---|
| `GOVERNANCE.md` | Decision-making process, contributor ladder, succession plan |
| `SUPPORT_POLICY.md` | Version support windows, security-patch policy, breaking-change pre-announcement |
| `PRIVACY.md` | Data handling commitments beyond "local-first" — telemetry, training data, GDPR/CCPA stance, subprocessor list |
| `PRICING_POLICY.md` | Price-raise notice, grandfathering, refund policy, transparency commitments |
| `CONTRIBUTING.md` | PR process, code style, testing requirements, adapter contribution model |
| `CODE_OF_CONDUCT.md` | Standard Contributor Covenant — community behavior expectations |
| `.github/ISSUE_TEMPLATE/bug_report.md` | Structured bug report template |
| `.github/ISSUE_TEMPLATE/feature_request.md` | Structured feature request template |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist for contributors |

All eight files are written, reviewed, and committed to the repo
before v12 GA. They don't require engineering work — just clear
writing — but missing any of them sends serious enterprise
contributors and procurement teams away. Shipping them with v12
is the line between "interesting open-source project" and
"serious project we can build a business around."

### Monetization layers that launch with v12

**1. Support contracts go live.** Stripe + Postmark + first-run wizard
from Theme 3 make this possible — without checkout infrastructure,
support contracts can't be sold. Tier structure:

| Tier | Price | What you get |
|---|---|---|
| Community | $0 | GitHub issues, community Slack/Discord, best-effort response |
| Starter | $199/mo | Email support, 1-business-day response, monthly office hours |
| Business | $999/mo | Slack channel, 4-hour weekday response, quarterly review call |
| Enterprise | $4,999/mo | 24/7 phone + Slack, 1-hour critical-incident SLA, named contact |
| Mission-critical | Quote | Dedicated engineer, on-site when feasible, regulatory-spec SLA writing |

Goal at v12 launch: land the first 3–5 Starter / Business customers
within 90 days of v12.0 GA. The first paying support contract is the
single most important business validation point.

**2. GitHub Sponsors button on the repo.** Zero setup cost; signals
"we accept patronage." Realistic at this stage: individual sponsors
($5–$50/month each), a handful of small-company sponsors ($500/month
for "logo on README"). Total contribution: $1k–$5k MRR. Small in
absolute terms but compounds the "this project is real" signal.

**3. Audit-firm partnership conversations begin (no launch yet).** The
audit-as-a-service revenue line is v13. But the conversations to land
a QSA or CPA-firm partner take 6–12 months. Start them now so v13
launches with a partner already lined up.

### The "free for anyone" guarantee at v12

Every Theme 1–4 feature is in the open-source repo. An MSP can self-host
SafeCadence v12 with multi-tenant orgs, customer portals, the SOC 2
evidence pack, all 12 LLM providers, and the air-gap bundle, paying
SafeCadence $0 forever, and we will support that in the docs. They only
pay if they want a human SLA, the audit firm relationship, or a hosted
orchestration plane (in v14).

### Out of scope for v12 (and why)

- **Real-time / continuous monitoring** — moved to v13. v12 is
  ambitious enough; the watcher/daemon model deserves its own release
  with proper telemetry plumbing.
- **Conversational AI assistant** — moved to v14. Fun to build, weak
  conversion lever until we have customers giving us the prompts
  they actually need answered.
- **ML / predictive analytics** — moved to v14. The current v11.0
  stubs stay stubs; meaningful ML needs training data we'll have
  after a year of customer telemetry.
- **Native mobile app** — rejected. The PWA from v11.1 is enough.
  No customer has asked.
- **GraphQL alongside REST** — rejected. REST hasn't constrained
  anyone.
- **More LLM providers** — rejected. Twelve is enough. v11.6 closed
  this thread.
- **More vendor adapters** — minor versions only. The 35+ that ship
  cover the long tail; specific customer asks become minor-version
  adapter additions.

**Explicit rejections from external strategy input** (positioning
moves we considered and chose not to make):

- **"AI-native security governance operating system" as primary
  positioning** — rejected. Buzzword-heavy; loses SEO. Buyers search
  for concrete things ("SOC 2 tool," "Vanta alternative," "free
  network compliance scanner"), not abstract category language. May
  appear as a *supporting* tagline in some materials; never as the
  lead phrase.
- **8-agent "AI Core" architecture** (separate Compliance / Identity /
  Risk / Reporting / Topology / Remediation / Narrative / Audit
  Evidence agents) — rejected as overengineering for
  single-maintainer scale. Current single-model + task-specific
  prompts works fine. The user-visible "AI coordinates findings"
  outcome is delivered by the v14 conversational assistant with
  90% less code.
- **Comparison to "Drata + Vanta + Wiz + SailPoint hybrid"** —
  rejected. Invites direct comparison on every dimension against
  ~$8B of incumbents; we lose every individual comparison. Pick ONE
  anchor competitor per buyer profile and lead with it.
- **Full design language overhaul to OpenAI / Vercel / Linear
  aesthetic** — deferred. Doesn't move conversion. May land as a
  v12.5 polish item; not a strategic priority.

### v12.0 success criteria

The release ships when:

1. All **6 themes** are merged (multi-tenant org system, audit-grade
   SOC 2 + CMMC, Stripe + Postmark + first-run wizard, air-gap
   distribution bundle, **MCP Server**, plus reports-module polish:
   multi-dim Safe Score + Risk Economics + Executive Risk Brief
   preset).
2. Tests pass at **400+** (up from 350+ in earlier plan to reflect
   MCP + polish coverage), no regressions in v11.x functionality.
3. Demo at `demo.safecadence.com/settings/org` shows multi-tenant
   isolation across three sample organizations.
4. **MCP Server** responds to all advertised tool calls from at least
   one MCP client (Claude Desktop or Cursor) successfully.
5. **Live Trust Center** at `safecadence.com/trust` shows SafeCadence's
   own real-time compliance posture (we eat our own dog food publicly).
6. **Public changelog** at `safecadence.com/changelog` is live with
   v11.0 → v12.0 history auto-rendered from `CHANGELOG.md`.
7. All four **competitor migration playbooks** are published
   (AlgoSec, Tufin, Drata, Vanta).
8. **Sigstore-signed** v12.0 release published with SLSA Level 3
   attestation, verification process documented on trust center.
9. **CHANGELOG entry** written honestly distinguishing what shipped
   from what's still in progress.
10. **First paying support contract** signed (Starter tier or above)
    within 90 days of v12 GA. This is the business success criterion
    — without it, the v12 release is technically shipped but
    commercially unproven.

---

# v13.0 — Operational excellence

**Target ship date:** Q1 2027 (after the v12 dust settles, 8–10 weeks)
**Status:** Planned scope, subject to v12 customer feedback

### The single-sentence positioning

**SafeCadence becomes the platform that runs continuously between
audits — drift detected the minute it happens, alerts routed to your
ITSM, evidence collected automatically.**

### Why v13 is operational, not feature-y

By v12 the product has the right shape; v13 makes it the right shape
*running 24/7*. Vanta and Drata charge $30k+/year primarily for
continuous monitoring. Without it, SafeCadence is "the tool you run
before an audit." With it, SafeCadence is "the tool you keep running
between audits" — a 10x larger revenue surface.

### Themes in scope (planned)

**1. Continuous drift monitoring with delta alerts.** Daemon mode:
filesystem watcher on declared config directories, OR scheduled
polling against device APIs (SNMP, NETCONF, REST), OR git-watch for
infra-as-code repos. Computes a delta against last-known-good baseline.
Fires webhooks when anything regresses against policy. Tunable
sensitivity (severity threshold, change-velocity threshold,
maintenance-window suppression).

**2. Native ITSM bi-directional sync.** Today the v11.x ticketing
module creates tickets in Jira / ServiceNow / GitHub / Linear. v13
makes it bi-directional: ticket status flows back into SafeCadence,
auto-closes finding when the ticket is closed, re-opens if the
underlying drift returns. Extends to ServiceDesk Plus, Freshservice,
Zendesk.

**3. Approval workflow v2.** The current Tier-3 SSH execution
triple-gate (approval chain, blast-radius preview, HMAC confirm
token) is solid. v13 adds: multi-approver chains with required
quorums, delegate-approval rules (when X is OOO, approval routes
to Y), per-asset-class approval policies (firewalls require 2
approvers, switches require 1), full audit of *who* approved *what*
when, evidence-grade approval logs for SOC 2.

**4. Performance at scale.** Distributed scanning workers (Celery or
RQ on top of the existing Redis queue from v10.7). Horizontal scale
of report rendering (currently single-process). Cache layer for
expensive policy compilations. Tested at 5,000-host fleets.

**5. Live dashboards.** Today's dashboard pages are server-rendered
on each load. v13 adds WebSocket push so changes appear in real-time
(SOC analyst use case). Optional polling fallback for environments
where WebSockets are blocked.

**6. Customer success surface.** In-app contextual help (tooltips
explaining what each compliance control means), guided first-policy
authoring, onboarding analytics that show which steps users get
stuck on. Powered by Postgres telemetry (already in v10.7).

**7. Security Knowledge Graph (internal architecture).** Formalize
the implicit graph that already lives across attack-path code +
identity adapters + finding-to-control mappings into an explicit,
queryable internal model. Nodes: assets, identities, findings,
controls, frameworks, cloud resources, vendors, risks, attack paths,
tickets, evidence. Edges: `exposes`, `depends_on`, `mapped_to`,
`inherited_from`, `remediates`, `violates`, `grants_access_to`.

This is **the technical foundation that enables v14's predictive
forecasting + conversational assistant + AI-driven remediation**.
Without an explicit graph, those v14 features would each have to
build ad-hoc traversal logic; with the graph, they're queries.

Backing storage stays relational (existing Postgres + SQLite); the
graph abstraction sits on top as a query layer (`safecadence.graph`).
Optional NetworkX backend for in-memory analysis on smaller fleets;
optional Neo4j or Memgraph backend for fleets that need traversal
at scale (rare today; an operator decision in v15+).

Real technical moat — this is what Wiz uses under the hood, and what
makes "predictive governance" possible rather than buzzword.

### Non-code initiatives that ship with v13

**SOC 2 Type II report received** (if Q3 2026 audit start lands on
schedule). Posted to trust center.

**First-tier ITSM partnerships announced.** Jira Marketplace listing,
ServiceNow Store listing, GitHub Marketplace listing.

**Reference architecture published** for MSP deployments at 50, 200,
1000-customer scale (with cost model + hardware sizing).

### Monetization layers that launch with v13

**3. Audit-as-a-service goes live.** This is the highest-revenue-per-customer
line. Partner with (or hire) a licensed QSA + a CPA firm that does
SOC 2 attestations. Charge customers $15k–$50k per audit engagement
(market rate). SafeCadence does 70% of the evidence collection
automatically; the human auditor reviews, signs, and stamps.

Why this can only launch at v13 (not v12):
- The v12 audit-grade evidence pack must have been in production at
  real customers for 6+ months to credibly say "we use this tool
  ourselves for audit work"
- The QSA / CPA partner conversation takes 6–12 months to ripen
- The first 3–5 customer references from v12 support contracts give
  the audit-firm partner confidence in the platform

Revenue split typical for the audit-firm-partnership model: 50–60%
to the firm with the credential, 40–50% to SafeCadence. Per-engagement
range: $6,000–$25,000 to SafeCadence. Recurring annual.

**4. Training + certification catalog launches.** By v13 the product
surface is stable enough that course content has a 2-year shelf life.
Initial catalog:

| Offering | Price |
|---|---|
| Self-paced online course (8–12 hours video + labs) | $299 |
| Live cohort training (2-day intensive, monthly) | $1,499/seat |
| **Certified SafeCadence Implementer** exam | $399 |
| **Certified SafeCadence Architect** exam | $599 |
| Custom enterprise training (on-site) | $15k–$50k |
| Train-the-trainer for partners | $2,500/seat |

Drives community adoption (every certified person is an advocate),
creates recurring revenue as MSPs add team members, and opens the
"authorized training partner" channel.

**5. Hosted orchestration plane alpha.** Hand-picked 3–5 MSP design
partners get early access to the SaaS orchestration plane (full GA
in v14). Architecture: only metadata flows to the SaaS — no actual
customer config data leaves the customer's network. Honors local-first
strictly.

Alpha pricing: $0 (early access). Goal is feedback, not revenue. The
v14 GA pricing model crystallizes from what alpha customers actually
use.

### The "free for anyone" guarantee at v13

Same as v12. The new monetization at v13 — audit services + training
+ alpha SaaS — is all *additional services* around the free product.
Continuous monitoring, ITSM bi-directional sync, approval workflows
v2, performance scale, and live dashboards from Themes 1–6 are all
shipped in the open-source repo. Self-hosters get the same monitoring,
ITSM, approvals, scale, and dashboards as paying customers.

### Out of scope for v13

- ML / predictive (still v14)
- Plugin marketplace (still v15+)
- FedRAMP Moderate (huge effort, requires a year of dedicated work
  + a contracted FedRAMP sponsor)
- Native mobile (still rejected)
- A second API surface like GraphQL (still rejected)

### v13.0 success criteria

A customer can install SafeCadence v13, leave it running for 30 days
unattended, and have it autonomously detect drift, file ITSM tickets,
collect SOC 2 evidence per-control, and route alerts based on the
customer's defined policy — with zero operator intervention beyond
the initial setup.

---

# v14.0 — Intelligence

**Target ship date:** Q3 2027 (after v13 has been running in
customer fleets for two quarters of telemetry collection)
**Status:** Directional only; specifics depend on what telemetry
reveals

### The single-sentence positioning

**SafeCadence learns from how its customers' fleets actually behave
and starts predicting failures, drafting remediation, and answering
questions in plain language — the audit tool that gets smarter the
more you use it.**

### Why v14 is the AI release

The v11.0 ML modules are stubs. We left them as stubs deliberately —
meaningful ML needs training data, and training data needs customers
running the product long enough to generate it. By v14 (assuming v13
has been in production for two quarters), there's enough
operational data to make ML claims that aren't hallucinations.

### Themes in scope (directional)

**1. Predictive risk forecasting with confidence intervals.** "Your
fleet is 78% likely to fail PCI DSS 11.x quarterly review in 21 days
based on current drift velocity." Uses time-series models trained on
the v13-collected drift / patch / scan history. Surfaces in
dashboards, reports, and webhook alerts.

**2. Conversational risk assistant.** Chat interface — bound to the
operator's authenticated session and capability set. *"Show me PCI
11.x gaps on my finance VLAN."* *"What changed on edge-fw-01 since
last quarter?"* *"Why is risk score 78 instead of 72?"* Generates
SQL against the platform store, runs it, summarizes in plain
English. Honors all the existing RBAC + audit log rules.

**3. AI-driven remediation PR generation.** Detect drift → AI drafts
the vendor-specific config change as a git PR (or a pre-staged
change in the SafeCadence execution queue) with: full context in
PR description, rollback inverse pre-attached, blast-radius preview,
and a link to the operator's approval-chain workflow. The operator
clicks merge instead of writing the fix. (All Tier-3 execution
gates still apply.)

**4. Active learning from operator feedback.** When an operator
dismisses a finding as "false positive" or "intentional exception,"
the model learns. Per-customer-tenant model fine-tuning so the
"acceptable" baseline drifts with the customer's specific policies.

**5. Anomaly detection on operational data.** Not the stub from v11.0
— a real anomaly detector trained on customers' aggregated (and
anonymized) traffic / config / identity event streams. Flags "this
host is behaving differently than other hosts of its class."

**6. AI & Machine Identity Governance.** A new category that extends
the existing v11.x identity work (which already covers human
identities across Okta / Entra / ISE / ClearPass / AD) into the
machine + AI identity surface:

- **Service-account lifecycle** — discovery, ownership tagging,
  rotation policy enforcement, automatic deprecation of abandoned
  accounts
- **API key inventory** — surface every API key in scope (cloud
  IAM, SaaS apps, secrets managers), age them, flag the ones older
  than policy
- **AI agent identity tracking** — first-class support for AI agents
  that hold credentials (LangChain agents, Anthropic Computer Use,
  agentic workflows) — what scopes they have, what they're
  authorized to do, who approved them
- **Ephemeral credential auditing** — JIT credentials, vault-issued
  short-lived tokens, OIDC federation tokens — verify they're being
  used as intended
- **Workload identity governance** — Kubernetes service accounts,
  AWS IAM roles assumed by EC2, Azure managed identities
- **Trust scoring** — every machine identity gets a trust score
  based on age, rotation cadence, scope, blast radius
- **Privilege creep analysis** — flag service accounts whose scope
  has grown over time without re-approval
- **Agent-to-agent trust mapping** — when AI agent A invokes AI
  agent B with credentials, that trust edge becomes a first-class
  graph relationship (v13 Knowledge Graph extension)

Why v14 (not v12): this is a real growing market in 2026–2028
(AI agents proliferating, NHIs outnumbering humans 17:1 per current
industry data), but the foundational graph + identity work that
makes it credible lands in v11.x and v13. Trying to ship it earlier
would be feature theatre. With the v13 graph in place, this is
~2 weeks of focused work.

### Non-code initiatives that ship with v14

**FedRAMP Moderate authorization process begins.** 18–24 month
process. If v14 ships in Q3 2027 with the audit-grade evidence
plumbing matured, FedRAMP authorization lands ~Q1–Q3 2029.

**Industry-vertical packs published** based on which verticals v13
customers actually concentrated in: healthcare HIPAA SRA automation,
finance PCI quarterly attestation generator, defense CMMC v2.5
(by then).

**ISO 27001 + ISO 27017 + ISO 27018 readiness packs.**

### Out of scope for v14

- Plugin marketplace (still v15+)
- Native mobile (still rejected; consider revisiting if customer
  data says otherwise)
- Multi-region distributed scanning (covered partially in v13's
  Theme 4; v14 doesn't extend it)
- Bare-metal Linux remediation beyond config files (kernel parameters,
  systemd units) — out of scope; SafeCadence stays config-only

### Monetization layers that launch with v14

**5. Hosted orchestration plane SaaS goes GA.** The v13 alpha graduates
to public availability. Critical architectural discipline: **only
metadata flows to the SaaS — never actual customer config data.**
That promise is what keeps the local-first moat intact.

Pricing structure:

| Tier | Price | Best for |
|---|---|---|
| Self-hosted | $0 | Anyone who wants to run the orchestration plane themselves; same code as the SaaS |
| MSP Starter | $99/mo | MSPs managing 1–10 customer fleets |
| MSP Growth | $499/mo | MSPs managing 11–50 customer fleets |
| MSP Scale | $1,999/mo | MSPs managing 50+ customer fleets |
| Enterprise | Quote | Custom SLA, data residency, dedicated infrastructure |

Goal at v14 launch: 10–15 paying MSPs at MSP Starter / Growth in the
first 90 days. The "free for anyone" guarantee stays intact because
the orchestration plane SOFTWARE is in the OSS repo — the customer
is paying for us running it, not for the right to run it.

**6. First hardware appliance partnership announced.** Partner with
a fanless mini-PC vendor (Protectli, MiniForum, Netgate-class) to
ship pre-configured SafeCadence appliances. Hardware retail
$800–$3,500 depending on spec; SafeCadence revenue share 10–25%
of hardware margin. Especially attractive to: regulated buyers who
can't install Python on their own gear; MSPs who want to drop-ship
a "SafeCadence box" to their customer.

Why v14 (not earlier): the hardware-OEM relationship takes 6+ months
to negotiate, and the OEM won't sign until SafeCadence has named
production customers (which v12/v13 give us).

**7. Foundation grant applications begin.** With v14, SafeCadence
has been in production at named customers for 12+ months. Foundation
grants for security-critical OSS become realistic:

- Sovereign Tech Fund (German government — funds critical OSS)
- OpenSSF Alpha-Omega (Linux Foundation — security-focused projects)
- NLnet (privacy/security/internet-freedom OSS)
- Open Technology Fund (security/privacy for at-risk users)

Realistic grant size: $50k–$250k per year per source. Total grant
revenue ceiling: $500k/year if multiple sources fund concurrently.
No code compromise — grant money funds maintenance of the existing
OSS, not proprietary features.

### The "free for anyone" guarantee at v14

Continuous monitoring, ITSM bi-directional sync, conversational AI
assistant, predictive forecasting, AI-driven remediation PRs — every
v14 feature is in the open-source repo, free to use, free to modify.
The SaaS orchestration plane is a *deployment convenience* sold around
the free product; the same orchestration code is available for
self-host.

### v14.0 success criteria

A customer can ask the conversational assistant *"why did our SOC 2
posture drop this week?"* and get a coherent answer in under 5
seconds that maps to specific findings, specific assets, and
specific remediation actions with confidence intervals — all
sourced from data the platform has collected in the customer's
own environment.

---

# v15.0 — Ecosystem (DIRECTIONAL)

**Target ship date:** Q1 2028 (after v14 has been in production for
two quarters)
**Status:** Directional only. The actual v15 scope depends entirely on
what v12–v14 customers ask for. Read this as "if the obvious trajectory
holds, here's what v15 looks like."

### The single-sentence positioning (directional)

**SafeCadence stops being just one team's product and starts being a
platform other people build on — third-party adapters, community rule
packs, partner-built compliance templates.**

### Why ecosystem is the natural v15

By v14, SafeCadence has multi-tenant orgs (v12), continuous monitoring
(v13), and AI-native intelligence (v14). The next compounding move is
opening the platform so others extend it instead of asking the SafeCadence
maintainer to ship every adapter and every rule pack. This is the
release that turns "free tool" into "free tool + commercial extensions
+ community contributions" — the model that makes Postgres, Nginx, and
Grafana sustainable.

### Themes that would be in scope (if directional holds)

**1. Public adapter SDK + plugin system.** Today every vendor adapter
ships in the core repo. v15 adds a plugin loading system so anyone can
publish `safecadence-adapter-cisco-meraki` (or whatever) as a separate
PyPI package, and `safecadence` discovers + loads it at runtime.
Includes signing (only signed plugins run by default), capability
gates (a plugin can't execute Tier-3 SSH unless explicitly granted),
and a community marketplace at `safecadence.com/marketplace`.

**2. Community rule pack repository.** The 42 rule packs in `data/rules`
become the "official" packs; a community pack repository ships
side-by-side so anyone can publish HIPAA-specific Cisco-IOS rules,
or PCI-specific Fortinet rules, etc. PR-based contribution model with
maintainer review.

**3. White-label SDK for resellers.** A documented, supported way for
a partner to fork the UI to their own brand and resell SafeCadence
under their name — with billing flowing through their Stripe instead
of ours (which is fine because the underlying product is MIT-licensed
and they're paying for support, not for code).

**4. Partner certification program.** A practical assessment + small
fee for "Certified SafeCadence MSP" and "Certified SafeCadence
Implementer" badges. Drives credibility for partners and creates a
discovery surface for customers who want to hire help.

**5. eBPF-based runtime monitoring (optional Linux deep dive).** Adds
kernel-level visibility into what processes actually run on monitored
Linux hosts. Major architectural shift; ships as an optional component,
not a core dep. Only relevant if v13/v14 customer demand actually
materializes for this.

### Out of scope for v15 (even directionally)

- **Native mobile app** (still rejected unless customer data flips this)
- **Crypto / blockchain anything**
- **Generic agent framework** (the v14 conversational assistant is
  enough)

### Monetization layers that launch with v15

**8. Marketplace revenue share.** The v15 ecosystem (plugin SDK +
community rule pack repository) creates the natural surface for a
revenue-sharing marketplace.

How it works:
- A boutique consulting firm sells their proprietary HIPAA Cisco-IOS
  rule pack for $99/year per install
- A community contributor sells their NIST 800-171 evidence pack
  for $199/year
- A Cisco partner sells a Cisco-specific compliance template for
  $499/year
- A SafeCadence-trained agency sells their custom executive-summary
  prompt library for $49 one-time

SafeCadence's cut: **15–25%** of paid listings (industry-standard
marketplace rate). Free listings stay free; nothing is forced into
the paid model. Quality control via lightweight review process
before publication.

Why this doesn't compromise the OSS: the marketplace is *additive*
to the free product. The plugin SDK itself is in the OSS repo;
anyone can build and distribute plugins independently of the
marketplace. The marketplace is just a discovery + payments layer
for those who want to monetize their work via SafeCadence's
distribution.

**Mature monetization stack at v15 (illustrative):** Support contracts
+ audit services + training + hosted SaaS + hardware appliances +
marketplace cut + sponsorships/grants. Seven layers running in
parallel, each tied to a specific buyer pain.

### The "free for anyone" guarantee at v15

The plugin SDK + community rule pack repository + white-label SDK +
partner certification + eBPF monitoring are all in the open-source
repo. A self-hoster can install any of them at no cost. Paid
marketplace listings are *third-party extensions*, never gating of
SafeCadence itself.

### Honest meta-comment on v15

This entire section is a guess. If v12–v14 ship to a market that wants
something different — say, hyper-vertical SaaS instead of platform —
v15 will look completely different. The "ecosystem" framing is the
*default* trajectory; explicit customer pull can override it.

---

# v16.0 — DIRECTIONAL ONLY (a guess at a guess)

**Target ship date:** Q3 2028 (best case)
**Status:** Speculative. v16 is 30+ months from today. Anything written
here is a hypothesis, not a plan.

### The framing rather than the features

By v16, the product is 18+ months past v12's "platform" inflection. The
question isn't really "what features ship in v16" — it's "what does
SafeCadence look like in 2028?" Three plausible futures, each with a
different v16 shape:

### Future A — "SafeCadence is the air-gap compliance default"

If the regulated buyer (defense, healthcare, classified finance) is
where the customers actually came from, v16 doubles down on that moat.
Themes would be:

- **FedRAMP Moderate authorization** lands (started in v14's non-code
  initiatives, takes 18–24 months)
- **HSM-backed key vault** for FIPS 140-2 Level 3
- **Air-gapped multi-node cluster** (replication + failover entirely
  inside one customer's network)
- **ITAR-compliant build pipeline** (US-citizen-only commit signers,
  US-only build infrastructure)
- **Industry-vertical compliance packs at depth** — HITRUST, NYDFS
  Part 500, ISO 27017 / 27018, CMMC v2.5 (whatever the spec is by then)

### Future B — "SafeCadence is the MSP platform"

If v12's MSP buyer profile validated and the customer base is mostly
MSPs serving regulated SMBs, v16 doubles down on MSP scale:

- **Distributed scanning across regions** (a North American MSP
  serving European customers needs EU-resident scanning)
- **Reseller billing infrastructure** (MSPs invoice their customers,
  SafeCadence settles up monthly)
- **Industry-vertical packaging** — "SafeCadence for Healthcare MSPs"
  with HIPAA + HITRUST + SOC 2 + healthcare-vendor adapters in one
  bundle
- **Partner enablement at depth** — solutions architects, dedicated
  partner success, partner advisory board

### Future C — "Identity governance was the bigger market"

If v14's conversational assistant and the operational telemetry from
v13 surface that identity drift is a bigger pain than network config
drift (which is plausible — the v11.x line already added 5 identity
adapters), v16 might be a strategic pivot:

- **Identity-first repositioning** — rename, reposition, the network
  adapters become a feature instead of the core
- **JIT access at scale** (the v11.x foundation expanded)
- **NHI lifecycle management at depth** — service account rotation
  policy enforcement, secrets-detection in code
- **Compete head-on with SailPoint / Okta Workflows** for the
  identity governance market

### What I'd commit to even at this distance

**Nothing.** That's the honest answer. v16 should be a quarterly
planning exercise informed by 12+ months of v12/v13/v14 customer
feedback, not a doc written in 2026.

The point of writing this section is to confirm that v12–v14 lead
somewhere coherent for *all three* of the plausible futures above:

- Future A (air-gap compliance): v12's audit-grade evidence + v13's
  continuous monitoring + v14's AI-driven explanations are the
  exact substrate auditors want
- Future B (MSP platform): v12's multi-tenant + v13's operational
  scale + v14's predictive analytics are the substrate an MSP needs
  to serve 200 customers from one operator console
- Future C (identity-first): v11.x identity work + v13's bi-directional
  ITSM + v14's conversational assistant give the substrate for a
  modern identity-governance product

So whichever direction the customer signal points, the work in v12–v14
is not wasted.

### What v16 will NOT be, regardless of direction

- **A "v16 rewrite"** — no major architectural rewrites, Pythonic and
  stdlib-heavy stays
- **A pivot to closed-source** — MIT license stays, even if commercial
  extensions exist around it
- **A funded enterprise sales motion** — SafeCadence stays independent
  even at v16+ scale; if a funded competitor emerges, the response is
  to compete on local-first / no-data-leaves-network, not to chase
  the SaaS money

### Monetization at v16 (maturation, not new launches)

**No new monetization layers launch in v16.** By v16 the seven layers
from v12–v15 are all running in parallel; the v16 work is about
*maturing* them, not adding more.

Specifically:

- **Support contracts** — by v16 the customer base supports a real
  on-call team. Tier expansion: per-region SLAs, dedicated TSEs
  (Technical Service Engineers) for Mission-critical tier.
- **Audit services** — by v16 SafeCadence has its own SOC 2 / PCI
  certifications (from v12 audit + v13 ongoing) plus the partner
  firm relationship is mature. Add CMMC C3PAO partnership, ISO 27001
  auditor partnership, FedRAMP 3PAO partnership.
- **Training + certification** — add specialist tracks (Healthcare
  Specialist, Defense Specialist, Finance Specialist) per the
  Future-A vertical packs.
- **Hosted SaaS** — by v16 the orchestration plane should be running
  at MSP scale (100+ paying MSPs). Add multi-region data residency
  options (US/EU/AU) per Future B.
- **Hardware appliances** — by v16 there are 2–3 OEM partners across
  fanless mini-PC, rack server, and edge-router form factors.
  Expand to ARM-based appliances for edge deployments.
- **Marketplace** — by v16 the marketplace should have 100+ listings
  with 30+ paid. Add curated "Featured" tier with co-marketing.
- **Sponsorships + grants** — by v16 SafeCadence is a real foundation
  candidate; the project may join CNCF or similar as a sandbox/
  incubating project, which unlocks larger foundational funding.

**Realistic ARR at v16 (~36 months out):** $2M–$5M, depending heavily
on which of Future A/B/C the customer signal points toward. Most
likely composition: support contracts $500k, audit services $1M+,
hosted SaaS $500k+, training $200k+, marketplace $100k+, hardware
$200k+, sponsorships/grants $300k+.

If revenue hits $5M at v16, the business has crossed the threshold
where a small full-time team (3–5 people) becomes feasible without
external funding. That's the inflection point, not v16 itself.

### The "free for anyone" guarantee at v16

Still in force. Same MIT license. Same "no feature gating in the OSS"
commitment. By v16 the project will be a decade-old strategic asset
and the commitment will be tested by funded competitors offering to
buy it — and the answer should still be no. The local-first /
free-for-anyone identity *is* the moat that funded competitors can't
replicate without burning their VC math.

---

# Speculative further-out themes (no version assigned)

Things tracked, not committed to any release:

- **Plugin / marketplace ecosystem** (likely v15 per above)
- **eBPF-based runtime monitoring** (likely v15 if Linux demand
  materializes)
- **HSM-backed key vault** (likely v16 Future A)
- **Multi-region distributed scanning at planetary scale** (likely
  v16 Future B)
- **Bare-metal Linux drift detection** beyond config — kernel
  parameters, systemd unit drift, package version drift (adjacent
  to scope, possibly a separate product)
- **Industry-vertical SaaS** — healthcare-only / finance-only
  SafeCadence (v16 Future B)
- **Identity-governance product line** (v16 Future C)
- **Mobile native app** — still rejected; revisit only on real
  customer data
- **Blockchain / Web3 anything** — never
- **A "social" layer** (community discussion inside the product,
  shared rule libraries with social ranking) — interesting but
  probably its own product

---

# What is intentionally NOT in any planned release

This list is as important as what IS planned:

| Not in roadmap | Why |
|---|---|
| Native iOS / Android app | PWA is enough; no customer demand |
| GraphQL alongside REST | REST hasn't constrained anyone |
| Industry benchmarking ("you vs the median") | Aggregating data across customers has serious privacy implications; doesn't scale until 100+ customers anyway |
| Crypto / blockchain anything | No use case |
| Generic "AI agent" framework | Conversational assistant in v14 is enough; building a generic agent platform is its own product |
| Auto-remediation without approval | Triple-gate stays. Auto-execute opens liability surface we don't want |
| White-label SDK | If a real partner asks, revisit. Not building speculatively |

---

# How to influence this roadmap

If you're a customer, design partner, or open-source contributor and
something is missing — or something is in scope that you think
shouldn't be — open a GitHub Discussion at
[github.com/famousleads/safecadence-network-risk/discussions](https://github.com/famousleads/safecadence-network-risk/discussions)
with the tag `roadmap-feedback`. Specifics matter: "I'm an MSP
running 30 customers and feature X would unblock me onboarding 5
more" carries more weight than "feature X would be cool."

Direct DM to [@famousleads](https://github.com/famousleads) also
works for sensitive customer-specific feedback that shouldn't be
public.

---

# Honest meta-commentary

A roadmap is a promise to the community AND a constraint on the
maintainer. Posting this publicly means future-Faz can't quietly
abandon v12 Theme 3 (audit-grade evidence pack) without admitting
it in the v12 changelog. That's the point.

This roadmap will be wrong in places — features will slip, scope
will shift, customer feedback will reorder priorities. When that
happens, the document gets updated and the change is announced.
Silent removal is a worse breach of trust than acknowledging a
miss.

The "out of scope" sections are also a commitment: they're saying
no to easy features so the team (currently one person) can finish
the hard ones. The temptation to add "and also v12 will ship
distributed scanning, blockchain audit, mobile app" is real and
constant; resisting it is the only way the four committed themes
actually ship.

If you read this whole document and your reaction is *"too narrow
for a major release"* — that's the right tension. The alternative
is a roadmap that says "v12 will ship everything you've ever wanted"
and ships nothing.

---

# A note on the "free for anyone" commitment

The roadmap above ships seven monetization layers over four years.
That's deliberate — sustaining an OSS project requires revenue.
But every layer is structured to **sell time, services, or convenience
around the free product, never the product itself.**

If any future maintainer (including future-Faz) is tempted to:

- Move a feature from OSS to a "Pro / Enterprise" tier
- Add a license check inside the OSS code
- Charge per-seat for the open-source software
- Stop releasing source code for new features

— this document is a public commitment that those moves break the
SafeCadence covenant. The community can hold us to it. The MIT
license itself makes hard backsliding legally impossible (anyone
can fork the last open version), and posting this commitment
publicly makes soft backsliding socially expensive.

**The deal, plainly:**

> *SafeCadence the software is yours, forever, MIT-licensed. You can
> use it commercially, fork it, modify it, redistribute it. We sell
> support, audits, training, hosted convenience, hardware, and a
> marketplace cut — none of which gates access to the code. If you
> never pay us a cent, you still get every feature in every release.
> That's the deal in v12. That's the deal in v16. That's the deal
> when the company has 1 employee and when it has 50.*

The roadmap is a promise about features. This section is a promise
about what won't change about the promise itself.

---

*Last meaningful update: 2026-05-25 (added monetization integration
across all version sections).*
