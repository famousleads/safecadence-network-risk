<div align="center">

# SafeCadence

**Free, open-source, local-first security posture management for hybrid networks and identity.**

Forty-five adapters across network gear, servers, identity, cloud, and backup. Twenty-two atomic security controls authored as policy. Sixteen multi-vendor translators that turn one declared intent into per-vendor configs. Attack-path graph, KEV+EPSS-prioritized CVEs, cross-system drift detection, posture scoring, full compliance suite, identity write-back with HMAC-bound confirm tokens, real per-vendor rollback plans, and Tier-3 SSH execution behind a triple-gate. Runs on a laptop, a small server, or in Docker. BYO-AI keys never leave your machine. Nothing is ever auto-executed without explicit approval.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

</div>

```bash
pip install 'safecadence-netrisk[server]'
safecadence demo                          # seed a 34-asset demo fleet
safecadence ui                            # open http://127.0.0.1:8766/home
```

That's it — about a minute end-to-end. The demo seed includes a three-tier identity scenario (a "good" tenant with a connected Okta + healthy NHIs, a "medium" tenant with an unsynced ClearPass, and a "broken" tenant with an LDAP misconfig) so every surface — Identity, NHI, Execute jobs, rollback plans, compliance — has populated content on first run.

Prefer to clone the repo? `git clone https://github.com/famousleads/safecadence-network-risk && cd safecadence-network-risk && ./bootstrap.sh` does the same dance against an editable install.

---

## What you'll see

`/home` opens with a single number — the **fleet Safe Score (0–100)**, computed from open findings, KEV-prioritized CVEs, attack-path membership, drift, missing controls, posture credit, and software currency. Below it, a **Weak Link** card that says "Fix `edge-fw-01` and 7 attack paths collapse — fleet score climbs 64 → 78." That's the value proposition in one sentence.

The sidebar groups everything else into seven sections:

- **Discover** — `/inventory`, `/groups`, `/topology` (physical L2 from LLDP/CDP, Meraki-style and geographic views), `/shadow-it`, `/coverage`, `/changes`, `/discovery-jobs`, `/tags`, `/scope`, `/vendors`.
- **Compliance** — `/policies`, `/policies/new` (YAML editor with live preview + dry-run + per-asset sandbox), `/findings`, `/drift`, `/evidence`, `/compliance` (six-framework coverage matrix), `/risks` (formal risk register).
- **Identity** — `/identity` (effective permissions across ISE/AD/Entra/Okta/ClearPass with real Connect form + sync workflow + vault-backed credential store), `/identity/nhi` (non-human identity lifecycle: register → attest → rotate → deprecate), `/jit`, `/paths` (attack paths), `/simulate`.
- **Execute** — `/execute`, `/builder` (AI command authoring with offline pack table + BYO-AI fallback), `/approvals`, `/queue`, `/rollback` (per-vendor inverted command preview before commit), `/per-device-diff` (pre/post config snapshots, line-level unified diff), `/blast-radius`, `/scores` (Safe Score leaderboard with 30-day fleet trend).
- **Automation** — `/automation`, `/watchlists`, `/briefing`.
- **Audit** — `/timeline`, `/share`.
- **Settings** — `/onboarding`, `/hub`, `/help`, `/users` (admin user directory + role + per-user notify-prefs), `/settings` (email SMTP, tenant-default routing, multi-provider webhooks).

---

## How it's different

Most of this market sits in one of three buckets. SafeCadence intentionally crosses all three:

| Tool category | Examples | What they do | What they don't do |
|---|---|---|---|
| Vulnerability scanning | Tenable, Qualys, Rapid7 | Find CVEs on hosts | No multi-vendor config remediation; no identity correlation; no air-gap |
| Network policy | AlgoSec, Tufin, FireMon | Manage firewall rules | One vendor at a time; no identity; no air-gap |
| Compliance automation | Drata, Vanta, Secureframe | Collect evidence for SOC 2 / ISO | SaaS-only; no firewall configs; no air-gap |
| **SafeCadence** | this repo | All three, locally | — |

Three things SafeCadence does that none of the above do well together:

1. **One declared policy → many vendors.** "Block SMB inbound from anything outside the `/24` mgmt subnet" becomes correct configuration for Cisco IOS, NX-OS, ASA, Arista EOS, Juniper Junos, Fortinet, Palo Alto PAN-OS, Aruba — and AWS IAM, Azure CA, GCP IAM, Okta, ISE, ClearPass when the same policy needs an identity equivalent.

2. **Attack-path-aware risk.** The score on each asset reflects whether it sits on a path to a crown-jewel — not just whether it has a CVE in isolation. The Weak Link card finds the asset whose remediation collapses the most paths.

3. **Local-first / air-gap-ready.** Pure-stdlib SNMP, file-backed JSON storage by default, optional Postgres for scale, optional BYO-AI for the LLM bits — **local Ollama, OpenAI, Anthropic, or any OpenAI-compatible local endpoint (LM Studio / vLLM / text-generation-inference / Hugging Face)**. Nothing phones home. The whole thing runs on a laptop you took into a customer SCIF.

---

## Local LLM setup (v11.3.1+)

The reports module's AI features — executive summaries, plain-language CVE explainers, quick-win ranking, stakeholder narratives — work entirely against a local model. No vendor cloud, no upload. Four providers, all first-class:

```bash
# Option 1 — Ollama (simplest local setup)
brew install ollama && ollama pull llama3.1 && ollama serve
export OLLAMA_HOST="http://127.0.0.1:11434"

# Option 2 — Hugging Face Serverless Inference
export HF_TOKEN="hf_xxxxxxxxxxxxxxxxxxxxxxxxx"               # from huggingface.co/settings/tokens
export SAFECADENCE_HF_MODEL="meta-llama/Meta-Llama-3.1-8B-Instruct"

# Option 3 — LM Studio / vLLM / TGI / llama.cpp (any OpenAI-compatible local runner)
export OPENAI_API_KEY="any-string"                           # local runners ignore it
export SAFECADENCE_AI_BASE_URL="http://localhost:1234"       # your runner's URL
export SAFECADENCE_OPENAI_MODEL="your-model-id"

# Option 4 — OpenAI or Anthropic (cloud)
export OPENAI_API_KEY="sk-..."          # or ANTHROPIC_API_KEY
```

Precedence: Ollama > Hugging Face > OpenAI > Anthropic > deterministic stub. Override with `SC_AI_PROVIDER`. Full guide: [`docs/LOCAL-LLM.md`](docs/LOCAL-LLM.md).

---

## Trust posture

The hardest problem with a tool that *can* push config to firewalls and identity systems is making sure it never does so by accident, never lies to the operator about what it's about to do, and always leaves a way back. The v9.32 → v9.35 line of work has been a deliberate audit-then-fix exercise across every surface that touches a real system:

- **Dry-run is the default at every layer.** Identity write-back, Tier-3 SSH execution, and policy translation all return a diff first. The operator has to flip an explicit flag to commit.
- **HMAC-bound confirm tokens.** Identity policy commits require a confirm token that's bound to the IR hash, scope, actor, a 600-second TTL, and the adapter version. A token minted for one IR cannot be replayed against a different one. (See `src/safecadence/identity/confirm_token.py`.)
- **Encrypted credential vault.** Identity connector credentials are stored Fernet-encrypted (AES-128 + HMAC-SHA256) under a master key auto-bootstrapped to `~/.safecadence/.identity_vault.key` (chmod 600). `save_creds` refuses to persist unless `test_connection` passed first. (See `src/safecadence/identity/vault.py`.)
- **Real per-vendor rollback plans.** Approving a CONFIG-mode job generates a real rollback plan with ~45 inversion patterns covering Cisco IOS / NX-OS, Arista EOS, Junos (set↔delete), Palo Alto, FortiGate. Operators see the inverted commands per-vendor in the `/rollback` slide-over *before* clicking. Patterns that can't be safely auto-inverted (interface blocks) are flagged for manual review with a banner.
- **Pre/post config snapshots.** Tier-3 SSH execution captures running-config before and after each command. `/per-device-diff` renders a unified diff with vendor pill, dry-run badge, and +/- line counts.
- **Tier-3 triple-gate.** Real SSH execution requires `SC_TIER3_ENABLED=1`, the `EXECUTE_REAL` capability on the role, an explicit `acknowledge` + `i_mean_it` payload, and TOTP MFA. Vendor-specific output scanning catches "Invalid input" / "Ambiguous command" patterns and marks the execution failed.
- **6-tier RBAC + no self-approve.** `VIEWER → AUDITOR → OPERATOR → ENGINEER → SECURITY_ADMIN → SUPER_ADMIN`. Medium-risk approvals require `SUPER_ADMIN`. A submitter cannot approve their own job. Critical jobs require multiple approvers.
- **Approval notifications.** Approval requests dispatch to Slack / Teams / PagerDuty / generic HMAC webhooks with a structured payload (job, risk, target count, link, requester).
- **Continuous best-effort hooks.** The daemon runs identity sync, NHI staleness checks, and snapshot generation on a 30-min cycle. One failed hook never aborts the cycle.
- **NHI lifecycle.** Non-human identities (service accounts, IAM roles, bot tokens) are tracked through register → attest → rotate → mark_used → deprecate. The store emits `nhi_stale` and `nhi_rotation_overdue` findings for what falls behind policy.
- **Audit docs ship with the product.** Each audit-then-fix cycle leaves a doc in `docs/`: [`v9.33-write-back-audit.md`](docs/v9.33-write-back-audit.md) (identity write-back), [`v9.35-execute-audit.md`](docs/v9.35-execute-audit.md) (execute section). Findings, file:line refs, what was wrong, what was fixed.

The v9.35.1 end-to-end smoke test (`tests/test_e2e_v9_35_1.py`) walks the full chain — connect → sync → access → NHI lifecycle → builder → submit → review → approve → rollback plan content — in one test, so a regression in any link of the chain fails before users notice.

---

## Architecture

```
discovery → unified asset schema → policy/control evaluator → findings
                                          ↓
                               attack paths + posture + CVE+KEV+EPSS
                                          ↓
                                      Safe Score
                                 (fleet + per-asset)
                                          ↓
                                 /home, /scores, /findings,
                                 /compliance, /risks, /evidence
```

Storage auto-upgrades from file-backed JSON to Postgres when `DATABASE_URL` is set. The same code path runs both. Nothing in the UI changes.

---

## Killer features at a glance

- **Safe Score 2.0** — 0-100 per asset (and criticality-weighted fleet aggregate) composed from posture credit (+up to 20 for protective controls) plus risk deductions (findings/CVEs/paths/drift) plus a confidence axis. Confidence below 0.3 renders `—` instead of a misleading 100.
- **Weak Link** — the single asset whose remediation kills the most attack paths weighted by target criticality.
- **Posture pack** — 17 declarative posture controls in `data/posture_controls.yaml`, evaluator runs them per asset.
- **Vendor hardening pack** — 15 Cisco IOS / IOS-XE checks aligned to CIS Benchmarks. Drop in YAML for other vendors.
- **Software currency** — running OS/firmware vs. recommended; `current` / `supported` / `behind` / `eol` / `kev_vulnerable` for 8 vendor families.
- **Compliance suite** — `data/control_mappings.yaml` maps every SafeCadence control to NIST 800-53 r5, CIS v8, PCI-DSS 4.0, HIPAA, ISO 27001:2022, SOC 2 TSC. `/compliance` coverage matrix, control-history (Type 2 evidence), exception lifecycle with expiry/re-review, risk register, config-baseline drift, auditor portal with scope-tagged tokens, evidence hash chain (verifiable tamper-detection).
- **Splunk-out** — push every finding, score change, weak-link alert via HEC. Settings panel for URL/token/index. Test-event button.
- **Per-device diff** — A/B picker, fetches both running configs, line-level diff with green-add / red-delete highlight. After a real Tier-3 execution, the same view shows pre vs. post config snapshots captured by the executor.
- **Continuous discovery + identity sync** — daemon mode (`safecadence daemon`) runs every 30 min by default, fires scheduled discovery jobs (LAN scan / SNMP / AD / Entra / DHCP / AWS / Azure / GCP), refreshes vault-backed identity connectors, scans NHIs for staleness/rotation overdue, writes Safe Score snapshots so the trend line on `/home` is real. Each hook is best-effort — one failure never aborts the cycle.
- **Identity vault + Connect form** — five identity adapters (Okta, Entra ID, Cisco ISE, HPE ClearPass, Active Directory). Connect form with `test_only` (validates without persisting) and `save` (persists only after test passes). Browser autofill defenses (honeypot fields, randomized name attrs, post-render cleanup, target-help text). Vault encrypts credentials at rest; status panel reports `source=vault` and `last_synced_at` per system.
- **Real rollback plan generator** — ~45 inversion patterns across major vendors. Remainder-preserving (`ip route 10/8 1.1.1.1` → `no ip route 10/8 1.1.1.1`, not a truncated stub). Symmetric Junos `set` ↔ `delete`. Interface blocks flagged for manual review. `/rollback` slide-over shows inverted commands per-vendor before commit. `GET /api/execute/jobs/{id}/rollback-plan` exposes the persisted plan.
- **NHI lifecycle** — register → attest → rotate → mark_used → deprecate, JSON-backed with `nhi_stale` and `nhi_rotation_overdue` finding emitters. Demo seeds 6 NHIs spanning the full lifecycle (well-attested, IAM role, rotation overdue, no owner, stale 220 days, deprecated).
- **Builder AI fallback** — pack-driven plan resolution first; for intents that don't match a pack, an opt-in BYO-AI fallback (OpenAI / Anthropic / local Ollama) generates a candidate plan that's then run through the same preflight guardrails. `SC_AI_DISABLED=1` keeps the whole subsystem off; the system prompt explicitly forbids destructive commands.
- **Quick policy + dry-run + per-asset sandbox + live vendor preview** — author a policy in three clicks, run it report-only for a soak period, simulate it on a single asset before fleet-wide rollout, see the rendered vendor config side-by-side as you edit.
- **Selfcheck** — `safecadence selfcheck` crawls a running deployment and reports broken nav links / JSON-on-nav-link regressions. Runs in CI via `tests/test_link_audit.py` (56 tests guarding every page including `/users` + `/settings`).
- **Three-tier demo data** — `safecadence demo` seeds the fleet, identity vault, NHIs, execution jobs, rollback plans, compliance artifacts, plus three example users (alice/bob/carol) and three example webhooks (Slack/PagerDuty/Teams, all disabled with example URLs) so `/users` and `/settings#webhooks` aren't empty pages on first visit. Identity demo is intentionally three-tier (good / medium / broken) so a buyer evaluating the product immediately sees what each connector state looks like instead of empty cards on first run.
- **Multi-channel notifications** — every event flows through one `dispatch_event(kind, severity, …)` router. Eight NOTIFY_CATEGORIES (`approval_requested`, `finding_critical`, `watchlist_change`, `drift_detected`, `automation_fired`, `jit_granted`, `digest_daily`, `capability_changed`) each have at least one in-tree emitter (a CI test enforces this). Eleven webhook providers ship: Slack, Teams, Discord, Mattermost, Rocket.Chat, PagerDuty, Opsgenie, Webex, ServiceNow, Google Chat, generic_hmac (with HMAC-SHA256 signing) — plus customer SMTP for email DMs. Per-user notify-prefs override tenant defaults (category × channel matrix). Webhook URLs and tokens are Fernet-encrypted at rest; the registry list shows only redacted previews.

- **Activity log + audit page** — every authenticated mutation lands as a JSONL line under `$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl` via an ASGI middleware. `/audit` filters by date / actor (substring) / method / path / tenant / `extra_filter` (e.g. `action=grant`) / arbitrary date range (`from_ts` / `to_ts`), exports CSV (`?format=csv`) with the export itself audit-logged, and shows browser-local time on hover. The middleware skip-list excludes `/api/v9/search` palette keystrokes plus health probes by default and is `SC_ACTIVITY_SKIP_PREFIXES`-extensible. The endpoint is rate-limited (60/60s default, env-overridable) and tenant-scoped — non-admins can't read other tenants' activity. Retention runs three ways: drop-in `docs/examples/safecadence-activity.logrotate`, the matching systemd `.service` + `.timer` units for container deployments, or — for `pip install` boxes that don't have either — the daemon hook that prunes files older than `SC_ACTIVITY_RETENTION_DAYS` (default 90), with `safecadence activity prune --retention N` for one-shot manual runs.

- **AI assistant** — `/ask` answers natural-language questions over the fleet snapshot. Hardened in v9.56: honors `SC_AI_DISABLED` for air-gap mode, gated by `read.asset` + `read.finding`, question length capped at 2 KB, per-(user, IP) rate-limited (10/60s default), snapshot truncation reported to the LLM rather than silently sliced, citations cross-checked against real asset/finding IDs (not regex theatre), audit row stores SHA-256 hash of the question (not plaintext), HTTP error reasons surface body excerpt + label. v9.56.1 added a write-intent screen that prepends a visible warning when the model emits destructive CLI patterns despite the read-only system prompt — bypass-resistant tripwire, not a CLI safety parser.

- **Capability-based RBAC** — 26 fine-grained capabilities (`read.*`, `write.*`, `execute.*`, `identity.apply.*`, `admin.*`) layered over the 6-tier role floor. Per-user explicit grants/denies persisted in YAML, every change audit-logged, every change fires a `capability_changed` event so security-team channels hear about privilege escalations in real time. `/users#caps` matrix UI plus `safecadence capabilities {grant,revoke,list-types}` CLI. Cross-tenant view at `/api/capabilities/all-tenants` for MSP-style deployments.

- **OIDC SSO with capability auto-grant** — Auth Code + PKCE flow against any RFC-compliant IdP (Okta, Entra, Auth0, Keycloak, Google). `capability_map` field on `SSOConfig` maps IdP group claims to capability lists; on every login `reconcile_sso_grants()` idempotently grants what's needed and revokes what's gone (manual grants are tracked separately and never touched). Failure-loud on misconfig — unknown capability names raise instead of silently granting nothing.

- **Automation engine** — IF/THEN rules persisted in `~/.safecadence/intel/automation.json`. Daemon evaluates every cycle (`SC_AUTOMATION_DISABLED=1` to disable). Eight actions: `auto_fix` (honors IR.targets, dry-run by default, `commit=true` opt-in), `assign`, `notify_log`, `notify_slack`, `add_to_watchlist`, `add_comment`, `notify_pagerduty` (deterministic dedup_key), `notify_webhook` (multi-provider fan-out). Gated by the `write.automation` capability. `safecadence automation {list,create,delete,preview,fires}` CLI parity.

---

## Without compliance

The compliance suite is **opt-in by visual weight**. Set `SC_COMPLIANCE_MODE=off` (or `POST /api/settings/compliance-mode {"enabled": false}`) and `/compliance`, `/risks`, `/evidence` disappear from the sidebar. The policy engine, controls, translators, drift, attack paths, Safe Score — all of it — stay live. SafeCadence is a security-policy tool that *can* talk to auditors, not a compliance product that pretends to do security.

---

## Installing

Four supported paths in [`docs/DEPLOY.md`](docs/DEPLOY.md):

| Path | Use when | Time |
|---|---|---|
| Local laptop | One operator, demo, evaluating | 5 min |
| Small server | One team, internal use | 30 min |
| Docker | You prefer containers | 15 min |
| Production | Multi-team, audit-grade | 2–4 hr |

All four share the same codebase. Production differs only in `DATABASE_URL=postgres://...` + an OIDC IdP via `SC_OIDC_*` env vars.

---

## CLI

```bash
safecadence demo                  # load 34-asset demo fleet + identity (good/medium/broken) + NHIs + execution + compliance
safecadence ui                    # local UI on 127.0.0.1:8766
safecadence daemon                # continuous mode (every 30 min) — discovery + identity sync + NHI staleness + scoring
safecadence daemon --once         # single cycle then exit
safecadence selfcheck --server http://127.0.0.1:8766
safecadence scan <config-file>    # one-shot audit of a config file
safecadence list-vendors          # supported vendor adapters
safecadence list-adapters         # adapter manifest with status
safecadence identity translate    # English → unified identity policy IR
safecadence identity connect      # connect an identity system (Okta/Entra/ISE/ClearPass/AD)
safecadence identity sync         # collect + normalize + save assets from a connected system
safecadence identity disconnect   # remove a connector from the vault
safecadence identity nhi          # NHI register / attest / rotate / list / deprecate
safecadence execute               # job approval + execution group
safecadence vault                 # credential store
safecadence onboard               # CSV import / discovery / cloud / manual
safecadence users                 # add / list / delete entries in the user directory
safecadence webhooks              # add / list / test / delete outbound webhooks
safecadence notify-prefs          # get / set per-user category × channel routing
safecadence capabilities          # list-types / list / show / grant / revoke / clear-deny
safecadence groups                # list / show / refresh IdP-sourced approver groups
safecadence automation            # list / create / delete / preview / fires
safecadence activity prune        # one-shot prune of activity logs older than --retention N days
```

`safecadence --help` enumerates the rest.

---

## Tests

```bash
pytest tests/ -q
```

1271 tests across the suite, all green. Highlights:

- `tests/capabilities/` (67) — capability constants + store + role-floor + gate decorator + history + cross-tenant view + OIDC group → capability auto-grant reconcile.
- `tests/activity/` (44) — JSONL store + ASGI middleware + CSV export + daemon-driven prune retention + /audit endpoint (cross-day pagination, date-range, extra_filter, tenant scoping, rate limit, filename context).
- `tests/intel/` (35) — AI assistant hardening (SC_AI_DISABLED honor, capability gate, length cap, snapshot truncation, citation cross-check, write-intent screen).
- `tests/identity/test_v9_55_automation.py` (16) — daemon hook + capability gate + IR-target routing + commit opt-in + four new actions + demo seed.
- `tests/identity/test_v9_53.py` (9) — capability GET gate + CSV export + capability_changed dispatch fan-out.

- `test_link_audit.py` (60) — boots the FastAPI app, crawls every sidebar page (incl. /users + /settings + /audit + /idp-groups + /capabilities), asserts no 404s or JSON-on-nav-link regressions.
- `test_compliance.py` (29) + `test_compliance_api.py` (24) — module + HTTP-level coverage of the compliance suite.
- `test_safe_score.py` (16) + `test_safe_score_v9_26.py` (14) — Safe Score 1.0 + 2.0 (posture, best-practice, software currency, confidence).
- `test_score_history.py` (6) — snapshot history + trend math.
- `test_splunk_hec.py` (4) — HEC notifier with httpx mock transport.
- `test_settings.py` (6) — file-backed settings + token masking + env-var override.
- `test_v9_intel_modules.py` (15) — coverage / fleet-changes / discovery-jobs.
- `test_v9_33_identity_writeback.py` + `test_v9_33_confirm_token.py` — identity write-back audit fixes (confirm-token gate, real `_rollback`, dry-run defaults).
- `test_v9_34_identity_connect.py` + `test_v9_34_identity_sync.py` + `test_v9_34_nhi.py` — Connect form, vault, sync workflow, NHI lifecycle.
- `test_v9_35_rollback.py` (13) — rollback plan inversion patterns + builder AI fallback + approval notification.
- `test_e2e_v9_35_1.py` (2) — full product loop smoke (connect → sync → access → NHI → builder → approve → rollback) and demo seed populates every surface.
- Plus the older base suite (multi-vendor adapters, parser, topology, identity, policy).

---

## Status

**v10.0.1 — shipped to PyPI.** The v9.x line was a sustained
audit-then-fix cycle across every customer-visible surface
(Execute, Discover, Compliance, Identity write-back, Automation,
AI assistant, /audit). Each section got a deep audit doc, a
punch list of honest gaps, and a dedicated release closing them
out — most often followed by a `.1` cleanup release for the items
the audit flagged but didn't fix. The result: every load-bearing
surface is capability-gated, rate-limited where it could be
abused, audit-logged, and tested at the HTTP level.

Install with `pip install safecadence-netrisk` (or
`pip install 'safecadence-netrisk[server]'` for the FastAPI UI).
Latest release: [v10.0.1 on PyPI](https://pypi.org/project/safecadence-netrisk/10.0.1/).
See [`CHANGELOG.md`](./CHANGELOG.md) for per-version history,
[`docs/HOWTO.md`](./docs/HOWTO.md) for the five-minute quick
start, and [`docs/DEPLOY.md`](./docs/DEPLOY.md) for laptop /
server / Docker / production deployment paths.

License: MIT. See `LICENSE`.
