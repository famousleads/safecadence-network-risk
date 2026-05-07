# SafeCadence Network Risk — Complete How-To Guide

> **The local-first, audit-first security policy platform that talks
> to your IdP, your firewalls, your switches, and your auditors —
> without ever leaving your network.**

Welcome. This guide will take you from `pip install safecadence-netrisk`
to a fully populated security operations console — discovering
assets, gating execution, auto-revoking JIT grants, generating
compliance evidence, and answering your auditor's questions in
plain English. It's everything you need to run SafeCadence
confidently in production.

---

## Table of contents

1. [What SafeCadence does (in one minute)](#what-safecadence-does)
2. [Quick start (5 minutes)](#quick-start)
3. [The big idea: read first, write rarely, log always](#the-big-idea)
4. [Killer features — what makes SafeCadence different](#killer-features)
5. [Workflows for real life](#workflows)
   - [Day 1: Connect a fleet you don't yet know](#day-1)
   - [Daily: The morning briefing](#daily-briefing)
   - [Weekly: The compliance ritual](#weekly-compliance)
   - [Incident: A capability changed at 3 AM](#incident-cap-change)
   - [Auditor visit: Producing evidence on demand](#auditor-visit)
6. [Capability-based RBAC](#capabilities)
7. [Identity write-back (read-only by default)](#identity)
8. [Tier-3 SSH execution (the most-locked-down surface)](#tier-3)
9. [Automation engine](#automation)
10. [AI assistant — what it is, what it isn't](#ai-assistant)
11. [Activity log + /audit](#activity)
12. [Notifications + webhooks](#notifications)
13. [Demo dataset (for evaluation)](#demo)
14. [CLI reference](#cli-reference)
15. [REST API reference](#api-reference)
16. [Hardening tunables (env vars)](#tunables)
17. [Frequently asked questions](#faq)
18. [Where to go next](#where-next)

---

<a id="what-safecadence-does"></a>
## What SafeCadence does — in one minute

SafeCadence is a **security policy platform for hybrid networks**.
It does five things, every one of them designed for organizations
that can't ship their fleet data to a SaaS:

1. **Discovers** assets across LAN, SNMP, AD/Entra, DHCP, and the
   three major clouds (AWS / Azure / GCP). Real LLDP/CDP harvest
   for L2 topology. AI-driven dedup. Shadow-IT finder.
2. **Authors policy** in plain English (BYO-AI optional) and
   compiles to Cisco / Arista / Juniper / Palo Alto / FortiGate /
   Okta / Entra / ISE / ClearPass / AD config — with vendor preview
   side-by-side as you edit.
3. **Detects drift** across 17 cross-system detectors. Per-device
   diff viewer. Daemon evaluates every saved policy on a schedule.
4. **Executes** real config changes through a 3-tier gate
   (sandbox → approval → SSH commit) with HMAC-bound confirm
   tokens, deterministic rollback plans, and TOTP MFA on the
   highest tier.
5. **Talks to your auditors** — control-mapping pack covers
   NIST 800-53 r5, CIS v8, PCI-DSS 4.0, HIPAA, ISO 27001:2022,
   SOC 2 TSC. Tamper-evident evidence packs. Scope-tagged
   auditor portal. Append-only activity log with CSV export.

You install it, you run it, your data stays in your estate. There
is no SaaS dial-home. There is no telemetry. There is no licence
server. The wheel runs from `pip install` and the daemon runs
from `systemctl`.

---

<a id="quick-start"></a>
## Quick start (5 minutes)

```bash
# 1. Install (Python 3.9+)
pip install safecadence-netrisk

# 2. Load the demo fleet (34 realistic assets, all subsystems seeded)
safecadence demo

# 3. Launch the local web UI
safecadence ui     # opens http://127.0.0.1:8766
```

That's it. You're now looking at a fully populated console:
inventory, findings, attack paths, identity systems, NHIs, JIT
grants, automation rules, capability grants, IdP groups —
everything's there.

**The demo box is intentionally three-tier (good / medium /
broken)** so you can see what every connector state looks like
without wiring real credentials. The automation rules are
DISABLED by default so you don't accidentally fire actions
against a real IdP.

When you're ready to point at real systems:

```bash
# Production: Postgres + OIDC
DATABASE_URL=postgres://localhost/safecadence \
SC_OIDC_ISSUER=https://acme.okta.com/oauth2/default \
SC_JWT_SECRET=$(openssl rand -hex 32) \
safecadence api
```

See [`docs/DEPLOY.md`](DEPLOY.md) for the full production guide —
local laptop, small server, Docker, or audit-grade production
deployment.

---

<a id="the-big-idea"></a>
## The big idea: read first, write rarely, log always

SafeCadence's design philosophy is three rules:

**1. Read first.** Every operation defaults to read-only.
Every adapter has a `test_only` mode. Every policy applies
in `report-only` before it enforces. The /ask AI assistant is
read-only with a write-intent screen on its output. Tier-3 SSH
execution requires an explicit capability grant — even admins
can't fire it without it.

**2. Write rarely.** Write paths are gated three ways: capability
check, approval workflow (for execute jobs), and confirm-token
HMAC binding (for identity write-back). Rollback plans are
generated *before* execution, not after. The "preview" button
is on every page that mutates.

**3. Log always.** Every authenticated mutation lands in
`$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl` via the ASGI middleware.
Capability changes, identity write-backs, JIT grants, automation
fires, OIDC reconciles, /ask calls — everything. The log is
append-only by convention and queryable from `/audit` with
substring actor, date range, `extra` filter, tenant scoping,
CSV export, and browser-local time on hover.

These three rules are not slogans. They're enforced in code by
the v9.x audit-then-fix cycle. Read the
[`CHANGELOG.md`](../CHANGELOG.md) — every release closes specific
trust gaps with file:line references.

---

<a id="killer-features"></a>
## Killer features — what makes SafeCadence different

### 🎯 Every dangerous surface is capability-gated

26 fine-grained capabilities (`read.*`, `write.*`, `execute.*`,
`identity.apply.*`, `admin.*`) layered over 6-tier role floors.
Per-user explicit grants and denies persisted in YAML, every
change audit-logged, every change fires a `capability_changed`
notification so security-team channels hear about privilege
escalations in real time.

```bash
safecadence capabilities grant alice execute.real \
    --reason "incident-42 oncall"
```

The grant writes a row to `/audit` AND fires a Slack/Teams alert.
A revoke (or a clear-deny) does the same. The `/users#caps`
matrix shows the live state. `/capabilities/all-tenants` is the
MSP-style cross-tenant view.

### 🎯 OIDC group → capability auto-grant

Connect your IdP via OIDC. Map IdP groups to capability lists
in `~/.safecadence/sso.json` (or `/settings#sso`):

```json
{
  "capability_map": {
    "okta-secops":   ["read.audit", "admin.capabilities"],
    "okta-platform": ["execute.real", "execute.approve"],
    "okta-readonly": []
  }
}
```

On every login, SafeCadence reconciles: grants what's needed,
revokes what's gone, and never touches manual grants. Misconfig
fails loud — unknown capability names raise immediately so a
typo can't silently grant nothing.

### 🎯 Tier-3 SSH execution that doesn't lie

The highest-stakes surface is Tier-3 (real SSH commit to a
device). It's gated four ways:

1. `SC_TIER3_ENABLED=1` env flag
2. `EXECUTE_REAL` capability — admin role short-circuit BYPASSED
3. TOTP MFA per-job challenge (each job gets its own challenge)
4. Approval workflow with HMAC-bound confirm token

The rollback plan is generated *at approval time*, ~45 inversion
patterns covering Cisco IOS / NX-OS, Arista EOS, Junos
(`set` ↔ `delete`), Palo Alto, FortiGate. Patterns that can't
be safely auto-inverted (interface blocks) are flagged for
manual review with a banner.

### 🎯 The activity log auditors actually love

Every mutation. JSONL one-per-day, chmod 600. `/audit` page
filters by date / actor (substring) / method / path / tenant /
`extra_filter` (e.g. `action=grant`) / arbitrary date range
(`from_ts` / `to_ts`). Browser-local time on hover. CSV export
audit-logged so the export itself shows in the next refresh.
Filename embeds filter context so three slices on the same day
are distinguishable.

```bash
safecadence activity prune --retention 90    # one-shot
# or daemon hook (default 90, 0 disables):
SC_ACTIVITY_RETENTION_DAYS=90 safecadence daemon
```

### 🎯 Multi-channel notifications, every event

One `dispatch_event(kind, severity, …)` router fans out to 11
webhook providers (Slack, Teams, Discord, Mattermost, Rocket.Chat,
PagerDuty, Opsgenie, ServiceNow, Google Chat, Webex, generic
HMAC) plus customer SMTP for email DMs. 8 NOTIFY_CATEGORIES
each have at least one in-tree emitter (CI test enforces this).
Per-user notify-prefs override tenant defaults. Webhook URLs are
Fernet-encrypted at rest.

### 🎯 Compliance the auditor walks out happy

`data/control_mappings.yaml` maps every SafeCadence control to
NIST 800-53 r5, CIS v8, PCI-DSS 4.0, HIPAA, ISO 27001:2022, SOC
2 TSC. `/compliance` coverage matrix shows you where you stand.
Control history is Type-2-grade. Exception lifecycle has
expiry, re-review, daemon alerts. Risk register at `/risks`.
Auditor portal generates scope-tagged share tokens so an external
auditor can read a slice without a SafeCadence account. Evidence
hash chain detects tampering.

### 🎯 Read-only AI assistant with write-intent screen

`/ask` answers natural-language questions over your fleet
snapshot (BYO-AI: OpenAI, Anthropic, or local Ollama). Honors
`SC_AI_DISABLED` for air-gap. Capability-gated by `read.asset` +
`read.finding`. Question length capped. Per-user/IP rate limited.
Citations cross-checked against real asset/finding IDs (no
regex theatre). Audit row stores SHA-256 hash of the question,
not plaintext.

The kicker: a **write-intent screen** on the model's response.
If the LLM emits destructive CLI patterns (Cisco `no shutdown`,
`reload`, `rm -rf`, SQL drop, imperative-execute language)
despite the read-only system prompt, SafeCadence prepends a
visible "⚠️ WRITE-INTENT DETECTED" warning. The model's actual
answer is preserved unchanged so you see exactly what was
suggested, just clearly flagged.

### 🎯 Automation engine that actually runs

IF/THEN rules persisted in `~/.safecadence/intel/automation.json`.
The daemon evaluates every cycle (`SC_AUTOMATION_DISABLED=1` to
disable). 8 actions: `auto_fix` (honors IR.targets, dry-run by
default, `commit=true` opt-in), `assign`, `notify_log`,
`notify_slack`, `add_to_watchlist`, `add_comment`,
`notify_pagerduty` (deterministic dedup_key), `notify_webhook`
(generic multi-provider).

```bash
safecadence automation create --name "auto-flag stale NHIs" \
    --when-kind stale_nhi --when-severity-at-least medium \
    --then-action add_to_watchlist
```

---

<a id="workflows"></a>
## Workflows for real life

<a id="day-1"></a>
### Day 1: Connect a fleet you don't yet know

You just installed SafeCadence. You have no asset inventory. The
quick path:

```bash
# 1. Discovery: scan the LAN
safecadence discover --cidr 10.0.0.0/16 --snmp \
    --community public --save

# 2. Identity: connect Okta (test first, save second)
safecadence identity connect okta \
    --domain acme.okta.com --token $OKTA_API_TOKEN \
    --test-only       # no persist
safecadence identity connect okta \
    --domain acme.okta.com --token $OKTA_API_TOKEN \
    --save            # commit to vault

# 3. Sync the connected systems
safecadence identity sync okta

# 4. Open the UI and review
safecadence ui
```

The /home page now shows a populated Safe Score, weak-link card,
and the next 3 actions panel. /inventory has every device.
/identity shows your identity systems with `groups_probe` results
inline. /paths shows internet → crown-jewel chains.

<a id="daily-briefing"></a>
### Daily: The morning briefing

```bash
safecadence api &       # if not already running
# Open the UI, click "Briefing" in the sidebar
```

The morning briefing is auto-generated and shows you:
- Overnight changes (what's new since yesterday)
- Top 3 actions to take today
- Watchlist alerts (entities you pinned)
- Stale NHIs / rotation overdue
- Failing controls
- Pending approvals

Or via API:

```bash
curl -H "Authorization: Bearer $JWT" \
    https://safecadence.acme.com/api/intel/briefing
```

<a id="weekly-compliance"></a>
### Weekly: The compliance ritual

Every Friday afternoon you generate the evidence pack:

```bash
safecadence policy evidence-pack \
    --frameworks "NIST,CIS,SOC2" \
    --output ~/Documents/evidence-2026-W19.pdf
```

The pack is signed and hash-chained. Verify any time:

```bash
safecadence policy verify-evidence \
    --pack ~/Documents/evidence-2026-W19.pdf
```

Or schedule it:

```bash
safecadence policy schedule-evidence \
    --frequency weekly --day friday --hour 17
```

The daemon runs the schedule, drops the pack in
`$SC_DATA_DIR/evidence/`, and fires an email + webhook with the
download link.

<a id="incident-cap-change"></a>
### Incident: A capability changed at 3 AM

3:14 AM. PagerDuty fires. Subject: "Capability grant: execute.real
on alice." Severity: HIGH.

You wake up. You hit /audit:

```
Filter: extra_filter=action=grant;capability=execute.real
Window: last 24h
```

You see the row. Actor: cto. Reason: "incident-42 oncall."
Request ID: `cap_1715047234128`. Source `cli` (extra.source
absent → direct-write, not middleware).

You cross-check `/timeline` for the same request_id. You verify
the on-call rotation. You go back to sleep.

<a id="auditor-visit"></a>
### Auditor visit: Producing evidence on demand

Auditor asks: "Show me every capability change between March 1
and April 30."

```bash
curl -H "Authorization: Bearer $JWT" \
    "https://safecadence.acme.com/api/activity?\
format=csv&from_ts=2026-03-01&to_ts=2026-04-30&\
extra_filter=action=grant,action=revoke&\
path=/api/capabilities/" \
    -o capability-changes-Q1-2026.csv
```

The CSV filename is now
`safecadence-activity-20260507-143012-actor-_-path-api_capabilities_-range-2026-03-01..2026-04-30.csv`.
Auditor opens in Excel. Done.

The CSV export itself wrote a row to the activity log. Next
quarter when the auditor asks "did anyone export this slice?"
the answer is "yes, you, on May 7th at 14:30 UTC."

---

<a id="capabilities"></a>
## Capability-based RBAC

26 capabilities, 6 roles (viewer, analyst, approver, operator,
admin, plus `auditor` for compliance read-only). Role floor +
per-user grants and denies. Resolution order:

1. Per-user explicit deny → never returned
2. Per-user explicit grant → always returned
3. Role floor → baseline

Admin role short-circuits to the full set EXCEPT for
`execute.real` (Tier-3) which uses `has_explicit_grant()` —
even admins must be explicitly granted Tier-3 SSH execution.

```bash
safecadence capabilities list-types     # all 26
safecadence capabilities list           # current grants
safecadence capabilities show alice
safecadence capabilities grant alice execute.real \
    --reason "<change-management-ticket>"
safecadence capabilities revoke alice execute.real \
    --reason "rotation-ended"
safecadence capabilities clear-deny alice read.asset
```

Every change writes to `/audit` and fires a `capability_changed`
event. High-value capabilities (`execute.real`, `admin.users`,
`admin.capabilities`, `admin.webhooks`, `admin.settings`,
`identity.apply.commit`) get severity=high; the rest are info.

---

<a id="identity"></a>
## Identity write-back (read-only by default)

Five identity adapters: Okta, Entra ID, Cisco ISE, HPE
ClearPass, Active Directory. Each has:

- `list_principals()`, `list_groups()`, `list_authz_rules()` —
  read paths (always work)
- `apply_policy(ir, dry_run=True)` — write path
  (dry_run is default; real apply requires confirm-token gate
   plus `identity.apply.commit` capability)

The translator pipeline is:

```
English description
  → AIPolicyTranslator (BYO-AI)
  → Unified Policy IR (validated)
  → Per-system change preview (every adapter renders its diff)
  → Operator approves with confirm token
  → Transactional apply with auto-rollback on partial failure
```

CLI:

```bash
safecadence identity translate \
    "deny inactive contractors from prod databases"
# → IR JSON + per-system preview

safecadence identity apply --target okta --dry-run    # always safe
safecadence identity apply --target okta \
    --commit \
    --confirm-token <token-from-preview-output>
```

The confirm-token is HMAC-bound to the IR hash, scope, actor,
600-second TTL, and the adapter version. A token minted for one
IR cannot be replayed against a different one.

---

<a id="tier-3"></a>
## Tier-3 SSH execution (the most-locked-down surface)

Tier-3 is the only place SafeCadence opens an SSH session and
sends a config command to a real device. It's the only feature
that needs paramiko. It's the only feature that uses TOTP.

Pre-flight gates:

```bash
SC_TIER3_ENABLED=1                    # env flag
safecadence capabilities grant alice execute.real \
    --reason "<ticket>"               # explicit grant (admin BYPASS doesn't apply)
```

Per-job gates:

1. Submit (status=draft) — anyone with `submit.job`
2. Review (status=ready_for_approval) — preflight runs (lockout
   detection, blocked-command guardrail, risk classifier)
3. Approve — `approve.job` capability + TOTP challenge
4. Execute — `execute.real` capability (no admin shortcut) +
   confirm token
5. Auto-snapshot pre + post running-config for /per-device-diff
6. Rollback plan generated at approve-time, viewable before
   commit

```bash
safecadence execute submit --target rt-edge-01 \
    --command "interface Gi0/1\n shutdown"
safecadence execute review <job-id>
safecadence execute approve <job-id> --totp <code>
safecadence execute commit <job-id> --confirm-token <token>
safecadence execute rollback <job-id>     # if needed
```

---

<a id="automation"></a>
## Automation engine

IF/THEN rules. Persisted in `~/.safecadence/intel/automation.json`.
The daemon evaluates every cycle.

```bash
safecadence automation list
safecadence automation create \
    --name "auto-flag stale NHIs" \
    --when-kind stale_nhi \
    --when-severity-at-least medium \
    --then-action add_to_watchlist
safecadence automation preview        # side-effect-free dry run
safecadence automation fires --limit 20
safecadence automation delete r_abc123def
```

8 actions:
- `auto_fix` — runs the suggested IR through the matching
  adapter. Honors IR.targets. Dry-run by default; opt in to real
  execution with `--then-arg commit=true`.
- `assign` — creates an Assignment for the named user
- `notify_log` — appends to `automation.log`
- `notify_slack` — fans out via dispatch_event registry
- `add_to_watchlist` — pins the finding (idempotent)
- `add_comment` — drops a comment with rationale
- `notify_pagerduty` — fires PD with deterministic
  `dedup_key=safecadence:automation:{finding_id}`
- `notify_webhook` — generic multi-provider fan-out

---

<a id="ai-assistant"></a>
## AI assistant — what it is, what it isn't

`/ask` answers natural-language questions over your fleet
snapshot. **Read-only by design.** The system prompt forbids
write actions. The output goes through a write-intent screen
that prepends a visible warning if the model emits destructive
CLI despite the prompt.

What it can do:
- Count things ("how many crown-jewel assets?")
- Summarize ("describe my identity risk in plain English")
- Spot patterns ("which contractors are over-privileged?")
- Cite real IDs (cross-checked against the snapshot)

What it can't do:
- Propose write actions (system prompt + write-intent screen)
- Read data outside the snapshot (no tool calls, no DB access)
- Bypass air-gap (`SC_AI_DISABLED=1` is unconditional)
- Burn your API budget (per-user/IP rate limited; question length
  capped at 2 KB)

What it costs:
- Nothing if you set `SC_AI_DISABLED=1` (deterministic fallback
  for common questions)
- One OpenAI / Anthropic / Ollama call per question otherwise
- Question hash (SHA-256 first 16 hex chars) lands in `/audit`
  — plaintext is NEVER logged

```bash
# Air-gap mode
SC_AI_DISABLED=1

# Tunables
SC_ASK_RATE_LIMIT=10               # calls per window
SC_ASK_RATE_WINDOW_SEC=60          # window seconds
```

---

<a id="activity"></a>
## Activity log + /audit

Every authenticated mutation lands in
`$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl` via the ASGI middleware.
`/audit` page surfaces it with deep filters:

```bash
# Substring actor — alice@example.com matches "alice"
GET /api/activity?days=7&actor=alice

# Date range (overrides days)
GET /api/activity?from_ts=2026-03-01&to_ts=2026-03-15

# Extra-dict filter (comma- or semicolon-separated)
GET /api/activity?extra_filter=action=grant
GET /api/activity?extra_filter=used_ai=True;source=http
GET /api/activity?extra_filter=export=csv

# Tenant scope (admin can pass tenant=*)
GET /api/activity?tenant=acme

# CSV export with filter context in the filename
GET /api/activity?format=csv&actor=alice&path=/api/capabilities/
# → safecadence-activity-{stamp}-actor-alice-path-api_capabilities-days-7.csv
```

CSV exports themselves write a row to the activity log so they
show up in the next refresh.

Hardening tunables:

```bash
SC_AUDIT_RATE_LIMIT=60             # calls per window
SC_AUDIT_RATE_WINDOW_SEC=60
SC_ACTIVITY_LOG_READS=1            # forensic mode (logs GETs too)
SC_ACTIVITY_SKIP_PREFIXES=/api/internal/,/_metrics
SC_ACTIVITY_RETENTION_DAYS=90      # daemon-hook prune (0 = disable)
```

Retention runs three ways. Pick whichever fits:

```bash
# Option 1 — logrotate (preferred for traditional Linux)
sudo cp docs/examples/safecadence-activity.logrotate \
    /etc/logrotate.d/safecadence-activity

# Option 2 — systemd .service + .timer (containers, minimal distros)
sudo cp docs/examples/safecadence-activity-prune.{service,timer} \
    /etc/systemd/system/
sudo systemctl enable --now safecadence-activity-prune.timer

# Option 3 — daemon hook (already running)
SC_ACTIVITY_RETENTION_DAYS=90

# One-shot manual prune any time
safecadence activity prune --retention 90
safecadence activity prune --retention 7 --dry-run
```

---

<a id="notifications"></a>
## Notifications + webhooks

```bash
# Customer SMTP for email DMs
safecadence settings smtp \
    --host smtp.acme.local --port 587 \
    --tls --user noreply@acme.com \
    --from "SafeCadence <noreply@acme.com>"
safecadence settings smtp test --to alice@acme.com

# Per-user notify-prefs (category × channel matrix)
safecadence notify-prefs get alice
safecadence notify-prefs set alice \
    --category finding_critical --channel email,slack

# Outbound webhooks (11 providers + generic HMAC)
safecadence webhooks add slack \
    --url $SLACK_WEBHOOK_URL \
    --categories finding_critical,capability_changed
safecadence webhooks list
safecadence webhooks test <id>
safecadence webhooks delete <id>
```

8 NOTIFY_CATEGORIES (every one has an in-tree emitter; CI test
enforces this):

| Category               | When it fires |
|------------------------|---------------|
| `approval_requested`   | Execute job submitted for approval |
| `finding_critical`     | New finding at severity ≥ critical |
| `watchlist_change`     | Pinned entity changed state |
| `drift_detected`       | Cross-system drift detected |
| `automation_fired`     | Automation rule fired an action |
| `jit_granted`          | JIT grant issued |
| `digest_daily`         | Morning briefing |
| `capability_changed`   | Grant / revoke / clear-deny |

---

<a id="demo"></a>
## Demo dataset (for evaluation)

```bash
safecadence demo
```

Loads:
- 34 realistic assets (Cisco/Arista/Juniper/Palo/Forti routers
  + switches + firewalls; AWS/Azure/GCP cloud workloads;
  Okta/Entra/AD identity systems; backup targets)
- 6 NHIs spanning the lifecycle (well-attested, IAM role,
  rotation overdue, no owner, stale 220 days, deprecated)
- 3 example users (alice, bob, carol) with realistic role mix
- 3 example webhooks (Slack, PagerDuty, Teams — disabled, with
  example URLs)
- Capability grants illustrating the 3-layer resolution
- 3 IdP groups (eng-leads, secops, auditors — synthetic
  fixtures, not real Okta data)
- 3 example automation rules (all DISABLED so a fresh demo box
  doesn't accidentally fire actions)
- Compliance artifacts (risk register, exceptions, control
  history, baselines, evidence packs)

Identity demo is intentionally **three-tier (good / medium /
broken)** so a buyer evaluating SafeCadence immediately sees
what each connector state looks like instead of empty cards on
first run.

---

<a id="cli-reference"></a>
## CLI reference

```bash
# Core
safecadence demo              # load demo fleet (34 assets + everything)
safecadence ui                # local UI on 127.0.0.1:8766
safecadence api               # production REST API
safecadence daemon            # continuous mode (every 30 min)
safecadence daemon --once     # single cycle then exit
safecadence selfcheck --server http://127.0.0.1:8766

# Discovery
safecadence discover          # LAN scan + SNMP + AD + cloud
safecadence list-vendors      # supported adapters
safecadence list-adapters     # truthful adapter manifest

# Policy + execute
safecadence policy            # author / evaluate / export
safecadence execute           # job approval + Tier-3 SSH
safecadence collect           # SSH-collect running configs

# Identity
safecadence identity translate     # English → IR
safecadence identity connect       # connect Okta/Entra/ISE/ClearPass/AD
safecadence identity sync          # collect + normalize + save
safecadence identity disconnect    # remove from vault
safecadence identity nhi           # NHI lifecycle

# Admin
safecadence users             # add / list / delete
safecadence webhooks          # add / list / test / delete
safecadence notify-prefs      # get / set per-user
safecadence capabilities      # list-types / list / show / grant / revoke / clear-deny
safecadence groups            # list / show / refresh IdP cache
safecadence automation        # list / create / delete / preview / fires
safecadence activity prune    # one-shot retention prune

# Helpers
safecadence vault             # encrypted credential store
safecadence onboard           # CSV import / discovery / cloud / manual
safecadence dashboard         # generate static HTML dashboard
safecadence export            # JSON → CSV
safecadence ai-explain        # BYO-AI executive summary
safecadence msp               # MSP control-plane agent
```

`safecadence --help` enumerates the rest.

---

<a id="api-reference"></a>
## REST API reference

### Authentication

```bash
# Local UI: cookie-session via password gate
# Multi-user API: JWT bearer
curl -H "Authorization: Bearer $JWT" \
    https://safecadence.acme.com/api/me
```

### Top-level surfaces

```
GET    /api/me                          — current user
GET    /api/platform/asset              — list assets
POST   /api/platform/asset              — add asset
GET    /api/platform/topology/{view}    — Cytoscape payload
GET    /api/platform/attack-paths-to/{asset_id}
GET    /api/platform/top-attack-paths

GET    /api/identity/access             — effective permissions
POST   /api/identity/translate          — English → IR
POST   /api/identity/preview            — per-system change preview
POST   /api/identity/apply              — commit (with confirm token)
POST   /api/identity/sync/{system}      — pull from connected IdP
GET    /api/identity/jit                — list JIT grants

GET    /api/policy                      — list policies
POST   /api/policy                      — create
POST   /api/policy/preview              — vendor-native preview
POST   /api/policy/exceptions           — grant exception

GET    /api/execute/jobs                — list jobs
POST   /api/execute/jobs                — submit
POST   /api/execute/jobs/{id}/approve   — approve (TOTP required)
POST   /api/execute/jobs/{id}/commit    — execute (Tier-3)
GET    /api/execute/jobs/{id}/rollback-plan

GET    /api/activity                    — audit log (JSON or CSV)
GET    /api/capabilities                — list grants (per tenant)
GET    /api/capabilities/all-tenants    — cross-tenant view (admin)
POST   /api/capabilities/{user}/grant
POST   /api/capabilities/{user}/revoke

POST   /api/intel/ask                   — AI assistant (read-only)
POST   /api/intel/automation/rules
GET    /api/intel/automation/preview
GET    /api/intel/automation/fires

GET    /api/compliance/coverage         — control matrix
POST   /api/compliance/evidence-pack    — generate evidence pack
GET    /api/risks                       — risk register
```

Full OpenAPI spec available at `/openapi.json` when the API is
running.

---

<a id="tunables"></a>
## Hardening tunables (env vars)

```bash
# Storage
SC_DATA_DIR=/var/safecadence            # data directory
DATABASE_URL=postgres://...             # production multi-user mode

# Auth
SC_JWT_SECRET=$(openssl rand -hex 32)
SC_OIDC_ISSUER=https://acme.okta.com/oauth2/default
SC_OIDC_CLIENT_ID=...
SC_OIDC_CLIENT_SECRET=...

# Activity log
SC_ACTIVITY_RETENTION_DAYS=90
SC_ACTIVITY_LOG_READS=0                 # 1 = forensic mode
SC_ACTIVITY_SKIP_PREFIXES=/api/internal/
SC_AUDIT_RATE_LIMIT=60
SC_AUDIT_RATE_WINDOW_SEC=60

# AI assistant
SC_AI_DISABLED=0                        # 1 = air-gap
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
OLLAMA_HOST=http://localhost:11434
SC_ASK_RATE_LIMIT=10
SC_ASK_RATE_WINDOW_SEC=60

# Automation
SC_AUTOMATION_DISABLED=0                # 1 = disable daemon hook

# Tier-3 execution
SC_TIER3_ENABLED=0                      # 1 = enable real SSH
SC_TIER3_RATE_LIMIT_SEC=300

# Compliance
SC_COMPLIANCE_MODE=on                   # off = hide /compliance, /risks, /evidence

# PagerDuty escalation
SC_APPROVAL_ESCALATION_PD_KEY=<integration-key>
SC_APPROVAL_ESCALATION_MINUTES=30       # 0 = disable
```

---

<a id="faq"></a>
## Frequently asked questions

### Does SafeCadence dial home?

No. There is no telemetry. There is no licence server. There is
no SaaS endpoint SafeCadence calls. Every adapter is configured
explicitly by you, every API key is yours, every webhook
endpoint is yours.

### Can I run it air-gapped?

Yes. Set `SC_AI_DISABLED=1` to disable AI calls (deterministic
fallback handles common questions). Pre-stage the wheel and its
deps. The daemon, scoring, drift detection, and policy evaluation
all work offline.

### What languages does the UI support?

English only at v10.0.0. UI strings are colocated with the
templates so localization is a future feature, not a v10.0.0
guarantee.

### How do I migrate from file-backed to Postgres?

Set `DATABASE_URL`. The platform_api detects it and switches.
Existing JSONL data isn't auto-migrated — file-backed data lives
on for read access; new writes go to Postgres. A migration
helper is on the v10.x roadmap.

### Does Tier-3 SSH work without paramiko?

No. Tier-3 is the only feature that requires paramiko. It's an
optional extra: `pip install safecadence-netrisk[ssh]`. Without
it, `SC_TIER3_ENABLED=1` will fail loud with an import error so
you don't get a half-working state.

### What if the model proposes a destructive command?

The /ask system prompt forbids it. The output goes through a
write-intent screen that scans for destructive CLI patterns
(Cisco `no shutdown`, `reload`, `rm -rf`, SQL drop, imperative-
execute language). Any match prepends a visible warning. The
model's actual answer is preserved unchanged so you see exactly
what was suggested.

### How do I rotate the JWT secret?

```bash
# 1. Generate new secret
openssl rand -hex 32 > ~/.safecadence/jwt_secret.new

# 2. Stop the API
sudo systemctl stop safecadence

# 3. Swap the file
mv ~/.safecadence/jwt_secret.new ~/.safecadence/jwt_secret

# 4. Start the API (forces all sessions to re-login)
sudo systemctl start safecadence
```

### What's the activity log retention default?

90 days. Set `SC_ACTIVITY_RETENTION_DAYS=N` to change. Three
mechanisms can prune (logrotate / systemd timer / daemon hook
/ CLI one-shot) — pick whichever fits. Set to 0 to disable
the daemon hook (when you're using logrotate / timer).

### Does it work on Windows?

The CLI runs on Windows for development. The daemon and SSH
features are Linux-first. Production deployment is documented
for Linux only.

### How do I ship to PyPI?

The wheels exist (`dist/old/`) and the `auto-publish-*.sh`
scripts wrap the `git tag` + `twine upload` pattern. The flow
needs re-validation before next push — that's a v10.x release
candidate.

### Is there a SaaS version?

No. SafeCadence is local-first by design. Every customer
installs their own copy. There is no shared SaaS instance.

### Where do I report bugs / request features?

GitHub issues: https://github.com/safecadence/network-risk
(when public). Until then: hello@safecadence.com

---

<a id="where-next"></a>
## Where to go next

- **Architecture:** [`docs/DEPLOY.md`](DEPLOY.md) — production
  deployment guide (local laptop → audit-grade)
- **Per-version history:** [`CHANGELOG.md`](../CHANGELOG.md) —
  every release with file:line references for the v9.x
  audit-then-fix cycle
- **Source:** https://github.com/safecadence/network-risk
- **Email:** hello@safecadence.com

SafeCadence is built by people who've been on the wrong end of
"I think the firewall change went out, but I'm not sure" too
many times. Every feature exists because something went sideways
and we wanted a way to be honest about what happened.

If you find a gap, tell us. The audit-then-fix cycle is the
product's actual roadmap.

— The SafeCadence team
