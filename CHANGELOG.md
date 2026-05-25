# Changelog

## [12.0.0a6] — 2026-05-25 — Discoverability + audit fixes

Polishes the v12 release so every new capability is reachable from the
README, the sidebar nav, and the public site — and fixes one real bug
+ three doc inaccuracies the audit caught.

**Discoverability:**
- README rewritten with a `Documentation` section grouping all 30 docs
  by audience (Getting started / Deployment / Per-feature / Migrations
  / Policies / Roadmap / Internal runbooks).
- Sidebar nav gains a new "Cluster & AI" group exposing the v12+
  surfaces (Cluster status / Customer portal / AI agents /
  API key inventory).
- Three new operator UI pages: `/cluster-status`, `/ai-agents`,
  `/api-keys` — thin server-rendered wrappers over the existing
  v12.1, v14 APIs.
- Public marketing site (`safecadence.com` / `SecurityAlgo` repo)
  hero updated with a v12 alpha callout listing the eight new
  capabilities; `pip install --pre` instructions inline.

**Bug fixes from the audit:**
- `scores/multi_dim_score.py` — fixed broken import of
  non-existent `safecadence.platform.platform_assets`; now uses the
  correct `safecadence.reports.sections._load_platform_assets`.
  Effect: `patch_freshness` dimension actually reads asset data
  instead of silently returning None.
- `docs/FIRST_CUSTOMER_ONBOARDING.md` — three CLI commands that
  don't exist (`safecadence org create`, `safecadence inventory`,
  `safecadence reports compose`) replaced with the real Python
  helper / HTTP API equivalents that actually ship today.

**Tests:**
- `tests/test_v12_0a6_ui_pages.py` — 7 tests covering the three
  new operator UI pages including defensive-degradation when
  underlying APIs raise.
- All 1,868 v9.x–v14 tests still passing.

Version bump 12.0.0a5 → 12.0.0a6. No breaking changes.

## [12.0.0a5] — 2026-05-25 — Peer-to-peer continuous sync (Architecture B)

Ships the second HA architecture alongside v12.1's shared-stores
architecture. Customers can now pick the model that fits their
infrastructure:

| Mode | Backing infra | Pick when |
|------|---------------|-----------|
| `SC_HA_MODE=` (unset) | none | single-node default |
| `SC_HA_MODE=shared-stores` | Postgres + Redis + S3 | enterprise |
| `SC_HA_MODE=peer-sync` | nothing — direct TCP | MSP / SMB / air-gapped |

**`safecadence.cluster.peer_sync` (NEW package, 5 submodules)**
- `writer.py` — `peer_events` table with monotonic seq + per-row
  HMAC; `record_event`, `list_events_since`, `trim_events_below`.
- `transport.py` — length-prefixed JSON frames over TCP; stdlib
  socket + struct only; `send_frame`/`recv_frame` with
  `MAX_FRAME_BYTES` ceiling.
- `applier.py` — receive loop; HMAC verify → idempotent dedupe
  on seq → dispatch to registered handler → ACK back with new
  `last_applied_seq`. `register_handler(kind, fn)` is the wiring
  point.
- `streamer.py` — active node's sender; persistent TCP connection
  to peer; reconnect with exponential backoff + catch-up from
  `last_applied_seq + 1`; per-event ack tracking; idle heartbeats.
- `heartbeat.py` — `LivenessMonitor` decides when to auto-promote
  on peer silence (30s default); split-brain guard via
  "no events AND no heartbeat" combined check;
  `request_demotion()` flag for graceful drain.

**Wired into the running app:**
- `start_peer_sync(conn)` called from `ui/app.py` boot when
  `SC_HA_MODE=peer-sync`; spawns applier + streamer + monitor as
  daemon threads.
- `GET /api/v1/cluster/peer/status` — full peer-sync state.
- `POST /api/v1/cluster/peer/promote` — force self to active.
- `POST /api/v1/cluster/peer/demote` — force self to standby.
- `record_replicated_event(kind, payload)` called from the four
  v12.1-guarded mutation paths (webhook fire / email send /
  scheduled reports / evidence schedules) — best-effort, no-op
  when peer-sync is disabled.

**Tests:**
- `tests/test_v12_2_peer_sync.py` — 18 tests covering writer
  ordering + HMAC + trim, transport loopback + oversized rejection,
  applier dedupe + bad-HMAC rejection + unknown-kind handling,
  heartbeat role transitions + monitor decisions, and a full
  end-to-end live-socket test (active writes → streamer ships
  → applier verifies + dispatches + ACKs).

**Docs:**
- `docs/HA_DEPLOYMENT.md` extended with Architecture B section:
  topology, env-var configuration, wire format spec, failover
  behavior table, operational endpoints, catch-up mechanics,
  failover test procedure, explicit non-goals, and a
  "which architecture should you pick" decision matrix.

Version bump 12.0.0a4 → 12.0.0a5. No breaking changes; single-node
behavior identical to v11.x.

## [12.0.0a4] — 2026-05-25 — High availability (active/standby)

Turns the v10.7 cluster scaffold into a working, tested HA story.
Single-node behavior is preserved exactly — no Redis = no cluster =
"always active" forever, same as v11.x.

**`safecadence.cluster.guards` (NEW)**
- `@active_only(default_return=None, raise_on_standby=False)` decorator.
- `require_active()` imperative helper raising `IsStandbyError`.
- `is_standby()` defensive check (returns False on any failure).
- Single guard pattern used across every mutation path.

**`safecadence.cluster.replication_lag` (NEW)**
- `probe_lag()` queries Postgres for primary/standby role + replay lag
  in seconds + bytes.
- Degrades to `{"status": "unknown"}` on SQLite / missing psycopg /
  unreachable database.
- `is_safe_to_failover(max_lag_s=5.0)` convenience for automatic
  promotion logic.

**Wired into the running app:**
- `GET /api/v1/cluster/status` — full cluster view (this node + peers
  + replication lag).
- `POST /api/v1/cluster/transfer` — voluntary lease release for
  manual failover.
- Failover lease loop auto-starts on `safecadence ui` boot when
  `SC_REDIS_URL` is set.

**Mutation paths guarded:**
- `notifier.providers.send_webhook` — standby returns
  `(False, "skipped: standby cluster node")`.
- `notifier.email_notifier.send_email` — same pattern.
- `reports.scheduler.run_due` — standby returns `[{"skipped": ...}]`.
- `compliance.evidence_schedule.run_due_schedules` — same pattern.
- Result: two SafeCadence nodes pointed at the same Postgres never
  double-write findings, double-fire webhooks, or double-deliver
  scheduled reports.

**UI:**
- Cluster status badge in topbar chrome — green `ACTIVE` / amber
  `STANDBY` / hidden when single-node. Tooltip shows peer
  reachability + replication lag. Polls every 30s.

**Docs:**
- `docs/HA_DEPLOYMENT.md` — full recipe covering Postgres streaming
  replication setup, S3/MinIO shared bucket, Redis sizing, Caddy
  load balancer config, failover test procedure, manual transfer
  procedure, sizing guidance, what we deliberately do NOT automate.

**Tests:**
- `tests/test_v12_1_ha.py` — 18 tests covering guards (decorator +
  imperative + defensive), replication_lag fallbacks, route shape +
  behavior (single-node + simulated standby), and mutation guard
  integration for all four guarded paths.

Version bump 12.0.0a3 → 12.0.0a4. No breaking changes.

## [12.0.0a3] — 2026-05-25 — Intelligence layer

Adds the v14 intelligence layer that produces honest, useful AI-driven
output without requiring any global training corpus. Every output
carries a `data_source_breakdown` field so the customer and any
auditor see exactly what fed the answer.

**`safecadence.intelligence.corpus`**
- `ReferenceCorpus(vertical, local_store=None)` — blends the customer's
  own local history with per-vertical published industry baselines.
- Six verticals (healthcare / finance / msp-smb / retail / defense /
  generic) with citations to NVD, CISA KEV, Verizon DBIR 2025, IBM
  Cost of a Data Breach 2025, Mandiant M-Trends 2025, Microsoft
  Digital Defense Report 2025, CyberArk Identity Security Threat
  Report 2025, Qualys TruRisk 2025.
- Nine metrics per vertical: safe_score, open_critical, open_high,
  drift_events_per_week, mean_time_to_remediate_days, mfa_coverage_pct,
  stale_account_pct, patch_lag_days, nhi_growth_rate_pct.
- Blending rule: 0–7 days = 100% baseline; 7–90 days = linear blend;
  90+ days = 100% local.

**`safecadence.intelligence.forecasting`**
- OLS regression on the customer's own series with honest 90% PI bands
  that widen with horizon. Stdlib-only.
- `forecast_metric()` returns trajectory ("improving"/"worsening"/
  "stable"), interpretation, and the data-source breakdown.
- Higher-is-better metrics (safe_score, mfa_coverage_pct) interpret
  positive slope as "improving"; lower-is-better metrics
  (open_critical, patch_lag_days) interpret positive slope as
  "worsening" — never mis-reports the direction.

**`safecadence.intelligence.anomaly`**
- EWMA + z-score per entity, with `min_n` threshold to prevent thin-
  sample false positives.
- `corpus_seed` parameter for cold-start scoring against the right
  baseline.
- `batch_detect_per_entity()` for per-host fleet-wide detection.

**`safecadence.intelligence.assistant`**
- NL question router → MCP tools (compliance / posture / topology /
  findings / identity / report).
- Calls v12 MCP tools, summarizes via BYO-AI client (OpenAI / Anthropic
  / Gemini / etc.); deterministic structured fallback when no key
  configured. Returns the full call trail for audit.

**`safecadence.intelligence.remediation_pr`**
- Known recipes for (cisco_ios + ssh_open), (cisco_ios +
  snmp_default_community), (fortigate + ssh_open),
  (okta + user_missing_mfa). LLM fallback for other vendor + family
  combinations. Refuses to hallucinate when neither produces a
  result — returns `needs_operator_input` instead.
- Always pre-attaches the inverse rollback so the PR description is
  safety-net complete.

**Testing**
- 38 new tests in `tests/test_v14_1_intelligence.py`.
- All v12 + v13 + v14 + v14.1 tests passing.

## [12.0.0a2] — 2026-05-25 — v13/v14 skeletons

Promotes the v13 + v14 scaffolds from "raise NotImplementedError"
placeholders to real, working alpha skeletons. No breaking changes.

**v13 — Security Knowledge Graph (`safecadence.graph`)**
- `schema.py` — 11 node types, 11 edge types, schema-validated `Node`/`Edge` dataclasses.
- `store.py` — SQLite-backed `GraphStore` with `add_node`/`add_edge`/`get_node`/`neighbors`/`count`/`clear`.
- `build.py` — `build_graph_from_assets()` populates from existing v11.x sqlite_store; `rebuild()` reads + wipes + repopulates.
- `query.py` — high-level wrappers: `what_touches`, `assets_exposing_finding`, `frameworks_affected`, `violations_for_framework`, `crown_jewel_reachers`.
- `traverse.py` — BFS `shortest_path` + bounded `walk` with optional edge_filter.

**v14 — AI & Machine Identity Governance (`safecadence.ai_governance`)**
- `agents.py` — AI agent registry: register / list / deprecate, status transitions, per-org isolation, invocation logging for cross-tool attribution.
- `api_keys.py` — API key inventory tracking last-four-only (never the secret), with age, rotation timestamps, last-seen tracking, deprecation flag.
- `trust_score.py` — 0–100 trust score per key + per agent across age, rotation cadence, scope breadth, active use, owner attribution; with per-factor breakdown + recommendation.

**Testing**
- 24 new tests in `tests/test_v13_0_graph.py`.
- 21 new tests in `tests/test_v14_0_ai_governance.py`.
- All passing; full v11.x + v12 regression suite still passing.

## [12.0.0a1] — 2026-05-25 — Alpha

First v12 alpha. Four shipping themes plus OSS-health polish. No
breaking changes versus v11.6.0 — every v11.x integration keeps working.

**Theme 5: MCP Server (`safecadence mcp-server`)**
- Anthropic Model Context Protocol implementation over stdio.
- JSON-RPC 2.0, protocol version `2024-11-05`.
- Seven tools: `query_topology`, `retrieve_findings`, `query_compliance`,
  `fetch_evidence`, `inspect_identities`, `generate_report`, `evaluate_posture`.
- RBAC via `SC_MCP_ORG_ID` / `SC_MCP_USER` env vars (defaults: `local` / `mcp-stdio`).
- Best-effort audit-log integration via the v11.3 hash-chained log.
- Defensive: every tool degrades to empty + note rather than raising,
  so a fresh install never crashes a connected MCP client.

**Theme 6: Multi-dimensional Safe Score (`safecadence.scores.multi_dim_score`)**
- Six dimensions: Compliance Health, Identity Health, Drift Stability,
  Patch Freshness, Attack Path Risk, AI Governance Readiness.
- Each dimension reports `value`, `trend_7d`, `confidence_band`, `top_factors`.
- Weighted-mean overall score (compliance + attack-path each 1.5,
  patch 1.3, identity 1.2, drift 1.0, ai-gov 0.5 placeholder).
- `compute_safe_score_flat()` returns a single number for any v11.x
  callsite that hasn't been updated to consume the dict.

**Theme 7: Risk Economics (`safecadence.reports.risk_economics`)**
- Translates findings into business-language metrics:
  - Estimated audit-failure exposure (USD, per-framework + SOC 2 deal-block).
  - Estimated remediation cost (USD + engineer-hours, by severity).
  - Risk-reduction ROI ranking (top N actions by points-removed / hours).
  - Technical debt score (cumulative weight of stale findings > 90/180d).
  - Operational risk velocity (4-week trailing rolling rate).
  - Compliance burn-down (weeks to 95% compliance at current rate).
- Every output includes a `disclaimer` field noting the figures are
  order-of-magnitude estimates from public IBM / Verizon / regulator data.

**Theme 8: Executive Risk Brief preset**
- New v12 flagship preset at index 0: 5-minute board-ready report.
- Composes KPI summary, executive narrative, multi-dim Safe Score radar,
  weakest-link analysis, attack-path summary, compliance roll-up,
  risk economics ($), top-5 executive actions, and remediation roadmap.
- Legacy `exec_brief` preset preserved for backwards compatibility.

**OSS-health polish**
- README badges for license, Python version, PyPI, test count,
  local-first commitment, no-telemetry, MCP protocol, and CoC.
- GitHub issue templates (bug, feature) + PR template + issue config
  routing security reports to private advisories.
- `multitenant.py` org-schema scaffold, Stripe products scaffold,
  Postmark notify scaffold, SOC 2 evidence pack scaffold, customer
  portal UI scaffold (all opt-in, no behavior change for existing users).
- Scaffolded `safecadence/graph/` (v13 Security Knowledge Graph) and
  `safecadence/ai_governance/` (v14 AI & Machine Identity Governance)
  as architectural placeholders.

**Testing**
- 36 new tests in `tests/test_v12_0_mcp_and_polish.py`, all green.
- Full v11.x regression suite re-run: 1749 tests passing, zero failures.

## [11.6.0] — 2026-05-25

### Five more LLM providers — Cloudflare, DeepSeek, GitHub Models, Mistral, Cohere

Companion to v11.5.0. Closes the BYO-AI provider list at twelve options
across local, free cloud, and paid. The Settings dropdown now reads
like a "what LLM do you use?" survey.

**1. Cloudflare Workers AI — 10,000 neurons/day free**

- `_call_cloudflare()` via the OpenAI-compatible endpoint at
  `api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1`.
- Requires BOTH `CLOUDFLARE_API_TOKEN` AND `CLOUDFLARE_ACCOUNT_ID`
  (account ID embeds in the URL).
- Default model `@cf/meta/llama-3.1-8b-instruct`.
- UI form has an extra "Account ID" field for this provider.

**2. DeepSeek — strong reasoning, generous free tier**

- `_call_deepseek()` via `api.deepseek.com/v1` (OpenAI-compatible).
- Activates via `DEEPSEEK_API_KEY`.
- Default model `deepseek-chat`; switch to `deepseek-reasoner` for
  thinking-class outputs.

**3. GitHub Models — free with any GitHub token**

- `_call_github_models()` via `models.inference.ai.azure.com`
  (Microsoft hosts the inference under Azure).
- Activates via `GITHUB_TOKEN` OR `GH_TOKEN` (gh CLI vs PAT
  convention; both honored).
- Default model `gpt-4o-mini`; full catalog includes Phi-3.5,
  Mistral, Llama, and others.
- **The politically interesting one** — every developer already has
  a GitHub token in their environment, so this is zero-friction
  signup.

**4. Mistral La Plateforme — free credits + OpenAI-compatible**

- `_call_mistral()` via `api.mistral.ai/v1`.
- Activates via `MISTRAL_API_KEY`.
- Default model `mistral-small-latest`.

**5. Cohere — 1,000 calls/month free (non-OpenAI shape)**

- `_call_cohere()` — the only v11.6 provider that's NOT
  OpenAI-compatible. Cohere posts to `/v1/chat` with `{message,
  preamble, max_tokens}` and reads top-level `text` from the
  response.
- Activates via `COHERE_API_KEY`.
- Default model `command-r`.
- Adds the first real diversity to the provider implementation
  pattern, which keeps the abstraction honest.

**6. Updated precedence + UI dropdown**

Full chain: **Ollama > HF > Gemini > Groq > OpenRouter > Cloudflare
> DeepSeek > GitHub > Mistral > Cohere > OpenAI > Anthropic**. UI
dropdown's "Free cloud tier" optgroup now lists nine free providers
above the "Paid cloud" group with OpenAI / Anthropic.

**7. Schema, API endpoint, and form updates**

- `llm_config.py` schema includes five new provider blocks. All
  API keys encrypted on save; Cloudflare `account_id` stays plain
  (per Cloudflare's docs, account IDs are not secret).
- `/api/settings/llm/test` routes to all five new providers.
- `/settings/llm` form has per-provider field groups with show/hide
  JS — total of twelve providers selectable from one dropdown.

### Tests

- New `tests/test_v11_6_0_more_providers.py` — 19 tests covering
  detection (Cloudflare needs both env vars, GitHub honors both
  `GITHUB_TOKEN` and `GH_TOKEN`), call shape for each (verifying
  URLs, auth headers, and Cohere's non-OpenAI request/response
  format), full 12-provider precedence chain, store schema
  integration with encrypted-vs-plain field handling, and
  `_try_ai` routing through stored credentials.
- All 19 pass. Full suite: **269 / 269 green** across all
  v11.3/v11.4/v11.5/v11.6 + reports + compliance + v10.6.

### Migration notes

Fully additive. Existing users see no behavior change. Twelve new
env vars opt-in (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
`DEEPSEEK_API_KEY`, `GITHUB_TOKEN`/`GH_TOKEN`, `MISTRAL_API_KEY`,
`COHERE_API_KEY`, plus five `SAFECADENCE_*_MODEL` / `_BASE_URL`
overrides).

### Architecture note

This release fills out the provider catalog without adding any new
abstraction beyond what v11.5 already introduced. Four of the five
new providers (Cloudflare, DeepSeek, GitHub Models, Mistral) are
thin wrappers around the existing `_call_openai_compatible` helper.
Cohere is the only one with its own implementation. Adding a 13th
provider is now a sub-30-minute task.

---

## [11.5.0] — 2026-05-25

### Three free-tier LLM providers as first-class options

Following the v11.4.x BYO-AI story (Ollama + Hugging Face + UI Settings
panel), v11.5.0 adds three more providers with generous free tiers, all
selectable from the same `/settings/llm` dropdown. The architecture is
table-driven now — adding a tenth provider becomes one table row plus
a thin wrapper, not a new code path.

**1. Google Gemini — 1M tokens/day free indefinitely**

- `_call_gemini()` posts to Google's OpenAI-compatible endpoint at
  `generativelanguage.googleapis.com/v1beta/openai`.
- Activates via `GEMINI_API_KEY` or `GOOGLE_API_KEY` (both names
  honored per Google's docs).
- Default model `gemini-2.0-flash`; override with
  `SAFECADENCE_GEMINI_MODEL`.
- Most-requested provider after the v11.4 launch — closes the
  "Gemini isn't on the dropdown" gap.

**2. Groq — fast inference, free tier no card**

- `_call_groq()` hits `api.groq.com/openai/v1`.
- Activates via `GROQ_API_KEY`.
- Default model `llama-3.1-70b-versatile`.
- Speed differentiator: Groq runs at 300-500 tokens/sec, which means
  the AI exec-summary lands in under 2 seconds. Real visible demo
  moment vs. the 8-15 seconds OpenAI typically takes.

**3. OpenRouter — 200+ models in one integration**

- `_call_openrouter()` hits `openrouter.ai/api/v1`.
- Activates via `OPENROUTER_API_KEY`.
- Default model `meta-llama/llama-3.1-8b-instruct:free` (the `:free`
  suffix is OpenRouter's convention for zero-cost variants).
- Sends `HTTP-Referer: safecadence.com` + `X-Title: SafeCadence NetRisk`
  to participate in OpenRouter's leaderboard.
- Force-multiplier: one config exposes Llama, Mistral, Gemma, Claude,
  GPT, Gemini, and dozens more through one key.

**4. Updated provider precedence**

When multiple env vars are set, auto-detection now goes:
**Ollama > Hugging Face > Gemini > Groq > OpenRouter > OpenAI > Anthropic**.
Free local first, then free cloud, then paid. Rationale: if the
operator set up a free option, they probably want it used over paid.

**5. UI dropdown grouping**

The `/settings/llm` provider dropdown now uses `<optgroup>` to visually
separate **Local (free, air-gap)** / **Free cloud tier** / **Paid cloud**.
Helps buyers see the three tiers at a glance instead of one flat list.

**6. Architectural refactor: `_call_openai_compatible`**

Gemini, Groq, OpenRouter (and OpenAI's own code path with a custom base
URL) all share a single generic OpenAI-Chat-Completions caller now.
Adding the seven providers planned for v11.6 (Cloudflare Workers AI,
DeepSeek, GitHub Models, Mistral La Plateforme + Cohere) becomes mostly
config-table additions.

**7. Test endpoint + UI form updates**

- `/api/settings/llm/test` routes to the three new providers
  correctly when called with a body override.
- `/settings/llm` form has per-provider field groups (API key, model,
  base URL) for each, with show/hide JS toggling on selection.

### Tests

- New `tests/test_v11_5_0_free_cloud.py` — 18 tests covering provider
  detection precedence (with new providers slotted in correctly),
  `SC_AI_PROVIDER` override accepting `gemini`/`groq`/`openrouter`,
  HTTP call shape for each (verifying URL, auth header, model in
  payload), OpenRouter's `HTTP-Referer`/`X-Title` headers, store
  schema integration (encryption + masked previews), and `_try_ai`
  routing through stored credentials for each.
- All 18 pass. Full suite: **185 / 185 green.**
- Fixed a pre-existing bug in `load_config()` where new provider
  blocks were dropped on round-trip (the merge loop had a hardcoded
  provider list that needed extending).

### Migration notes

Fully additive. Existing OpenAI / Anthropic / Ollama / HF users see
no behavior change. The three new env vars (`GEMINI_API_KEY` /
`GOOGLE_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`) and the four
new `SAFECADENCE_*_MODEL` / `SAFECADENCE_*_BASE_URL` overrides are
all opt-in.

### What v11.5.0 does NOT include (slated for v11.6)

- Cloudflare Workers AI (free 10k neurons/day)
- DeepSeek (free, strong reasoning models)
- GitHub Models (free with any GitHub token)
- Mistral La Plateforme (free credits)
- Cohere (free 1k calls/month) — needs its own non-OpenAI shape

---

## [11.4.2] — 2026-05-25

### Navigation polish

Tiny patch on top of v11.4.0. The `/settings/llm` page was reachable
by direct URL but had no link from the main `/settings` hub, so most
users would never find it. Closes that discoverability gap.

- `/settings` tab strip now ends with an **"AI / LLM →"** link that
  navigates to `/settings/llm`.
- `/settings/llm` now shows a **"← Back to Settings"** breadcrumb at
  the top so navigation flows both ways.

### Why v11.4.2 instead of v11.4.1

v11.4.1 was tagged + pushed with the navigation fix but without
bumping the package version (operator forgot to edit `__init__.py` +
`pyproject.toml`). PyPI rejected the upload because v11.4.0 was
already taken. v11.4.2 is the same nav fix shipped with a clean
version bump. v11.4.1 remains as a tag on GitHub but never reached
PyPI — `pip install safecadence-netrisk==11.4.1` will fail; use
v11.4.2 instead.

---

## [11.4.0] — 2026-05-25

### UI Settings panel for LLM provider configuration

Closes the "must I edit env vars and restart the service?" UX gap from
v11.3.x. Operators can now point the reports module at Ollama,
Hugging Face, OpenAI, an OpenAI-compatible local endpoint (LM Studio /
vLLM / TGI), or Anthropic from a web form — no shell, no restart,
no env-var fiddling. Provider switch takes effect on the next report
generation call.

**1. Encrypted config store (`reports/llm_config.py`)**

- Persists to `~/.safecadence/llm_config.json` (chmod 600).
- API keys and HF tokens are Fernet-encrypted (AES-128 + HMAC-SHA256)
  via a master key auto-bootstrapped to `~/.safecadence/.llm_vault.key`
  on first save.
- Falls back to base64 obfuscation when the `cryptography` package
  isn't installed — operators wanting real encryption should
  `pip install safecadence-netrisk[vault]`.
- `public_view()` returns a UI-safe dict with secrets replaced by
  `has_token`/`has_api_key` booleans and 4-character suffix previews.

**2. Three new API endpoints (`server/platform_api.py`)**

- `GET  /api/settings/llm` — current config + live `llm_status()`
- `POST /api/settings/llm` — save provider + per-provider fields
  (capability-gated, requires `MANAGE_SETTINGS`)
- `POST /api/settings/llm/test` — send a tiny test prompt to the
  active or body-supplied config; returns
  `{ok, sample_response, error?}`. Works on the read-only demo too
  (it doesn't persist anything — just probes the chosen endpoint).

**3. Read-only demo guard**

- `POST /api/settings/llm` returns 403 with structured JSON
  `{error: "read_only_demo", message: "..."}` when `SC_READONLY=1`.
- `POST /api/settings/llm/test` stays open in demo mode so visitors
  can validate their own Ollama URL or HF model reachability before
  committing to a local install.

**4. Dedicated `/settings/llm` page**

- Self-contained HTML form with provider dropdown (None / Use env /
  Ollama / Hugging Face / OpenAI / Anthropic), per-provider fields
  that show/hide on selection, "Test Connection" button (shows the
  sample response inline), and "Save" button.
- Linked to from the existing /settings hub.
- Live status line shows the currently-active provider, model,
  endpoint, and whether it came from the UI store or env vars.

**5. Resolver integration in `reports/ai_helpers.py`**

- `_try_ai` consults `llm_config.get_active_provider()` first; when
  the UI explicitly selected a provider, those credentials win and
  the env-var fallback is skipped (operator made an explicit choice
  — honor it).
- When the store is set to `"env"` (default), behavior is identical
  to v11.3.x — env-var auto-detection with full Ollama → HF → OpenAI
  → Anthropic precedence.
- `llm_status()` now returns `source: "ui"` or `source: "env"` so
  the UI can show where the active config came from.

**6. Non-breaking refactor of `_call_*` functions**

- Each call function now accepts optional kwargs (`host`, `model`,
  `api_key`, `token`, `base_url`) that override env-var detection.
  When kwargs are `None`, behavior is unchanged.
- This is what lets the UI store pass resolved credentials through
  without monkey-patching environment variables at runtime
  (cleaner, thread-safer).

### Tests

- New `tests/test_v11_4_0_llm_config.py` — 20 tests covering store
  round-trip, encryption round-trip (Fernet + base64 fallback),
  blank-field preservation (UI convention: blank = unchanged),
  double-encryption prevention, `public_view()` masking, resolver
  precedence (store > env), `none` mode short-circuit, `_try_ai`
  routing through stored credentials, and `llm_status()` source
  tagging. All 20 pass.
- Full reports + v11.3.1 + v11.4.0 suite: **167 / 167 green.**

### Migration notes

Fully additive. v11.3.x users see no behavior change until they visit
`/settings/llm` and save a provider. The default config is
`{provider: "env"}` which means "consult env vars exactly like
v11.3.x." Container deployments using env vars for config don't need
to do anything.

### What v11.4.0 does NOT include (slated for later)

- Multi-tenant per-org config (current store is process-wide).
- API key rotation reminders.
- Per-section LLM config (different model for exec summary vs CVE
  explainer).
- "Add custom provider" for arbitrary REST endpoints beyond the
  four supported.

---

## [11.3.2] — 2026-05-24

### Hugging Face Serverless Inference completes the v11.3.1 BYO-AI story

Companion to v11.3.1. The earlier release added Ollama and an
OpenAI-compatible base URL (which technically covered Hugging Face
via vLLM / LM Studio / TGI), but did not include a dedicated
first-class Hugging Face provider. v11.3.2 closes that gap.

**1. Hugging Face as a labeled provider in the reports module**

- New `_call_huggingface()` posts to HF's OpenAI-compatible chat
  endpoint (`api-inference.huggingface.co/v1/chat/completions`).
- Activates via `HF_TOKEN` or `HUGGINGFACE_API_TOKEN` — HF docs use
  both names; we honor both.
- Default model `meta-llama/Meta-Llama-3.1-8B-Instruct`. Override
  with `SAFECADENCE_HF_MODEL`. HF Inference Endpoints (the paid
  product) supported via `SAFECADENCE_HF_BASE_URL`.
- `SC_AI_PROVIDER=hf` short alias accepted.

**2. Updated provider precedence**

- Ollama > **Hugging Face** > OpenAI > Anthropic > deterministic stub.
- HF wins over OpenAI by default because if the operator brought an
  HF token, they probably want it used over a cloud default.

**3. Graceful cross-provider fallback**

- If HF is configured but the inference call times out, the module
  falls through to whatever other key is set (OpenAI, Anthropic)
  rather than returning `None`. Better partial AI output than none.

**4. `llm_status()` reports HF as a first-class provider**

- Returns `{provider: "huggingface", model: "...", endpoint: "..."}`
  with the actual model and endpoint URL, so the (forthcoming) UI
  Settings panel can show "Hugging Face: meta-llama/...-8B-Instruct
  at api-inference.huggingface.co" rather than guessing.

**5. Documentation: `docs/LOCAL-LLM.md` Path 3 rewritten**

- Hugging Face section now described as a first-class path with
  three sub-flavors (Serverless / Inference Endpoints / self-hosted)
  and a "when to use which" guidance table.

### Tests

- New `tests/test_v11_3_1_local_llm.py` grew from 21 to 31 tests
  covering HF detection, the `hf` alias, custom HF endpoint + model
  overrides, the HTTP call shape, and graceful fallback from HF to
  OpenAI. All 31 pass; full reports suite remains 212 / 212 green.

### Why two releases in 12 hours

v11.3.1 went out via Trusted Publishing on a tag that was created
before the HF additions landed, due to an in-session split commit.
PyPI doesn't allow re-uploading the same version, so the complete
release ships as v11.3.2. Both are functionally compatible — v11.3.1
users will see "Hugging Face" appear as a labeled option after
upgrading.

---

## [11.3.1] — 2026-05-24

### Local LLM support in the reports module

Patch release driven by real user feedback within hours of v11.3.0
going public. A LinkedIn commenter pointed out that they use Ollama
and Hugging Face for their LLM work when customer DPAs forbid SaaS
uploads — and discovered (correctly) that the reports module was only
wired for OpenAI and Anthropic clouds, despite the headline "BYO-AI"
claim. This release fixes that gap.

**1. Ollama is now a first-class provider in `reports/ai_helpers.py`**

- New `_call_ollama()` posts to a local Ollama `/api/chat` endpoint
  (default `http://127.0.0.1:11434`, default model `llama3.1`).
- Activates automatically when `OLLAMA_HOST` or
  `SAFECADENCE_LOCAL_LLM` is set.
- Was already supported in the CLI (`safecadence.ai.client`) and the
  discovery chat — the reports module was the gap.

**2. Hugging Face Serverless Inference API as a first-class provider**

- New `_call_huggingface()` posts to HF's OpenAI-compatible chat
  endpoint (`api-inference.huggingface.co/v1/chat/completions`).
- Activates via `HF_TOKEN` or `HUGGINGFACE_API_TOKEN` — HF docs use
  both, so we honor both.
- Default model `meta-llama/Meta-Llama-3.1-8B-Instruct`; override
  with `SAFECADENCE_HF_MODEL`. Custom endpoints (HF Inference
  Endpoints, the paid product) supported via `SAFECADENCE_HF_BASE_URL`.
- `SC_AI_PROVIDER=hf` short alias accepted.

**3. OpenAI-compatible local endpoint support via `SAFECADENCE_AI_BASE_URL`**

- The existing OpenAI code path now honors a custom base URL.
- Unlocks LM Studio, vLLM, text-generation-inference, llama.cpp
  server, Together.ai, Groq, Fireworks in a single line of config.
- HF models served via any of those local runners (the "self-host
  the HF model" path) work through this code path; HF's hosted
  serverless API uses the dedicated `_call_huggingface()` path above.

**4. Explicit provider override (`SC_AI_PROVIDER`)**

- Matches the CLI's existing override. Forces `ollama`, `huggingface`
  (alias `hf`), `openai`, or `anthropic` regardless of which other
  env vars are set.

**5. Local-first precedence by default**

- When multiple providers are configured: Ollama > Hugging Face >
  OpenAI > Anthropic. Rationale: if someone installed Ollama or
  brought an HF token, they probably want it used over a cloud
  default.

**6. `llm_status()` now reports the active endpoint**

- When `SAFECADENCE_AI_BASE_URL` is set, the status response includes
  the actual URL the reports module is hitting — so the UI can show
  "OpenAI API at http://localhost:1234" instead of misleadingly
  implying OpenAI cloud.

**7. Graceful provider fallback**

- If Ollama is configured but the daemon is unreachable at request
  time, the module now falls through to whatever cloud key happens
  to be set rather than returning `None`.

**8. New documentation: `docs/LOCAL-LLM.md`**

- Step-by-step setup for Ollama, Hugging Face Serverless + Inference
  Endpoints, LM Studio / vLLM / TGI / llama.cpp server (OpenAI-compatible
  runners), and OpenAI / Anthropic cloud. Provider precedence table,
  env var reference, troubleshooting, air-gap notes.

### Tests

- New `tests/test_v11_3_1_local_llm.py` — 31 tests covering provider
  detection precedence (Ollama > HF > OpenAI > Anthropic),
  `SC_AI_PROVIDER` override (including `hf` alias), Ollama HTTP call
  shape, Hugging Face HTTP call shape, custom base URL routing,
  `llm_status` reporting, and graceful cross-provider fallback.
  All 31 pass; full reports suite is 212 / 212 green.

### Migration notes

Zero. Fully additive. Existing OpenAI / Anthropic users are
unaffected. The four new env vars (`OLLAMA_HOST`,
`SAFECADENCE_LOCAL_LLM`, `SAFECADENCE_AI_BASE_URL`, `SC_AI_PROVIDER`)
are all opt-in.

---

## [11.3.0] — 2026-05-11

### Operations + governance

The last code release before the v12.0 compliance-certification push
(SOC 2 / ISO 27001 / FedRAMP). Six deliverables, all stdlib, all
opt-in.

**1. Backup / verify / restore (`src/safecadence/ops/backup.py`)**

- `create_backup(out_dir, include_orgs=None)` produces one
  `.tar.gz` containing every org's data dir, the schedules + risk
  acceptance files, the SQLite portal DB (when present), the legacy
  audit log + the v11.3 chained audit log, and a `MANIFEST.json`
  listing every member's SHA-256.
- `verify_backup(path)` recomputes hashes from the tar without
  extracting — catches truncation, single-bit flips, and missing
  members.
- `restore_backup(path, target_dir=None, dry_run=False)` extracts
  into the live SafeCadence home (or a given target). `dry_run=True`
  short-circuits before any disk write.
- CLI: `safecadence ops backup --out`, `ops verify --from`,
  `ops restore --from [--target-dir] [--dry-run]`.

**2. Per-org GDPR-style data export (`ops/export_org.py`)**

- `export_org(org_id, out_path, include_blobs=False)` writes one
  schema-versioned JSON file with everything the platform stores for
  one org: members, templates, audit trail (both flavors), risk
  acceptances, pentest history, change log, scan history, evidence
  index. `include_blobs=True` inlines evidence bytes as base64.
- CLI: `safecadence ops export-org --org-id X --out org.json [--include-blobs]`.
- HTTP: `GET /api/v1/orgs/{org_id}/export?include_blobs=false` (admin-only)
  — returns JSON or a ZIP containing it when blobs are inlined.

**3. Disaster recovery runbook (`docs/runbooks/disaster-recovery.md`)**

- Five scenarios: primary droplet down, database corruption, lost SSH
  access (the actual DO Recovery ISO procedure we've rehearsed twice),
  Postgres replication lag > 5 min, Stripe webhook missed events.
- Each scenario lists trigger conditions, prerequisites, the exact
  commands to run, success criteria, and points to the post-mortem
  template at the bottom of the file.

**4. Hash-chained audit log (`audit/log.py`)**

- New `log_event_chained(org_id, ...)` writes to a separate
  `audit_chain.jsonl`. Each row carries `prev_hash` (SHA-256 of the
  previous row's `hash`) and `hash` (SHA-256 of its own canonical JSON,
  excluding the `hash` field). Tampering breaks the chain at the
  affected line and every line after it.
- `verify_chain(org_id) -> {ok, broken_at_line, line_count}` walks
  the chain and reports the first break. Empty chain ⇒ ok.
- The legacy `log_event` API (used by ~6 callers) is unchanged.
- CLI: `safecadence ops verify-audit --org-id X`.

**5. Data retention controls (`ops/retention.py`)**

- `RetentionPolicy(kind, keep_days, keep_min_count)` per kind:
  `scans` / `audit` / `reports` / `errors`. Defaults: 365 / 730 / 180 /
  90 days, min 50 per kind.
- `get_retention(org_id)` / `set_retention(org_id, policy)` /
  `apply_retention(org_id)` — returns purge counts per kind.
- Persisted at `~/.safecadence/orgs/<id>/retention.json`.
- CLI: `safecadence ops retention show / set / apply`.
- Scheduler hook: the existing `safecadence report schedule daemon`
  fires a built-in retention pass at 03:00 UTC daily for every org.

**6. Bug bounty / responsible disclosure (`SECURITY.md`)**

- Tiered SLA table (Critical 24h ack / 7-day fix → Low 10-day ack).
- Reward bands $50 – $5,000 USD by severity, with explicit
  "we don't pay for" exclusions.
- Hall of fame section reserved.
- Existing trust-posture, cryptographic-posture, and PGP-key
  scaffolding from v10.5 is kept intact.

### Test additions

- `tests/test_v11_3.py` — 14 tests covering backup round-trip,
  manifest tamper detection, export schema shape, chain append +
  tamper detection, retention purge with floor preservation, and
  docs/SECURITY.md presence checks.
- All 311 prior tests remain green; this version targets ≥ 325 total.

## [11.2.0] — 2026-05-11

### Developer experience — SDKs, IaC, container packaging

A platform-developer-experience release. No new analytical capabilities
— instead, NetRisk gains the surrounding ecosystem that lets teams
embed, automate, and ship the platform.

**1. Python SDK (`sdk/python/`)**
- Publishable as `safecadence-sdk` (0.1.0). Single runtime dep: `requests`.
- `Client(base_url, api_key)` with `list_inventory`, `get_asset`,
  `list_reports`, `compose_report`, `generate_report` (async),
  `get_findings`, `get_compliance_status`, `list_templates`,
  `save_template`.
- Typed exception hierarchy: `SafeCadenceError` / `AuthError` /
  `RateLimitError` (carries `.retry_after`) / `NotFound`.
- Mocked-`requests` test suite covers each method + every error code path.

**2. JavaScript/TypeScript SDK (`sdk/js/`)**
- Publishable as `@safecadence/sdk` (0.1.0). Zero runtime deps — uses
  the native global `fetch` (Node ≥ 18, browsers, Deno, Bun).
- TypeScript types in `src/types.ts` for `Asset`, `Finding`, `Report`,
  `Template`, etc.
- Same method shape as the Python SDK, plus a Vitest test suite with
  mocked `fetch`.

**3. Go SDK (`sdk/go/`)**
- Module path `github.com/famousleads/safecadence-go`, Go 1.21,
  stdlib-only (no third-party deps).
- `Client` with the full method set; typed `AuthError`,
  `NotFoundError`, `RateLimitError` (with `RetryAfter time.Duration`).
- `httptest`-mocked test suite.

**4. Terraform provider scaffold (`terraform/provider-safecadence/`)**
- Plugin-SDK v2 entrypoint, two resources (`safecadence_org`,
  `safecadence_report_template`) and one data source
  (`safecadence_inventory`).
- `go mod tidy` is required to fetch `terraform-plugin-sdk/v2` the
  first time (intentionally left out of `go.mod` so the scaffold lands
  without a dep fetch).

**5. Docker Compose local-dev stack (`docker-compose.yml`)**
- Expanded from the single-service file to a full four-service stack:
  `safecadence` (port 8003), `redis` (6379), `postgres` (5432),
  `minio` (9000 + 9001 console).
- New `docker-compose.override.example.yml` documents every env var
  you'd want to set in dev.
- Root `Dockerfile` rebased on `python:3.12-slim` (was Alpine), exposes
  8003, default CMD now runs `safecadence ui --host 0.0.0.0 --port 8003`.

**6. Helm chart (`helm/safecadence-netrisk/`)**
- `Chart.yaml` (version 0.1.0, appVersion 11.2.0).
- `values.yaml` with replicaCount, image, ingress.host (+ TLS),
  persistence, plus toggles for bundled Postgres + Redis sub-services.
- Templates: `deployment.yaml` (with liveness + readiness probes
  pointing at `/healthz/detail`), `service.yaml`, `ingress.yaml`,
  `secret.yaml`, and a `_helpers.tpl` for shared labels.

**7. OpenAPI 3.1 schema export**
- New CLI: `safecadence openapi export --out openapi.json`.
- Imports the FastAPI app, calls `app.openapi()`, stamps the package
  version into `info.version`, writes pretty-printed JSON.
- Used by SDK code generation in CI.

**8. Tests**
- `tests/test_v11_2.py` (16 cases) covers SDK package layout (Python +
  JS + Go + Terraform), Docker Compose YAML validity + service set,
  Helm chart presence, and that `safecadence openapi export` actually
  produces a valid OpenAPI document with `info` + `paths`.
- All 294 prior tests still pass — bringing the total to 310 green.

### File map

```
sdk/python/                         # safecadence-sdk Python package
sdk/js/                             # @safecadence/sdk TypeScript SDK
sdk/go/                             # github.com/famousleads/safecadence-go
terraform/provider-safecadence/     # Terraform provider scaffold
helm/safecadence-netrisk/           # Helm chart
docker-compose.yml                  # 4-service local-dev stack
docker-compose.override.example.yml # Env-override starter
Dockerfile                          # rebased on python:3.12-slim, port 8003
src/safecadence/cli.py              # new `safecadence openapi export` cmd
tests/test_v11_2.py                 # new integration tests
```

## [11.1.0] — 2026-05-11

### Mobile-responsive + PWA + accessibility + i18n framework

Mostly a UI-quality release. No new analytical capabilities — instead, the
existing UI gets a responsive sweep so it works on tablets and phones, a
PWA layer so it can be installed to the home screen, a WCAG 2.2 AA pass
across every chrome-wrapped page, and a tiny stdlib-only i18n framework
ready for real localization later.

**1. Responsive UI (`src/safecadence/ui/responsive.css`)**
- New CSS sheet served at `/static/responsive.css`, injected into every
  chrome-wrapped page via the `<link rel="stylesheet">` in `_chrome.py`'s
  `<head>`.
- Tablet breakpoint (`max-width: 768px`): step pills stack, inventory
  table hides low-priority columns (keeps hostname, criticality, risk,
  KEV), forms go full-width, dashboard cards collapse to 2 columns,
  reports wizard download buttons go full-width.
- Mobile breakpoint (`max-width: 480px`): cards collapse to 1 column,
  preset cards stack, headline sizes shrink, customer portal grids
  collapse to a single column.
- Tap targets: every clickable element gets `min-height: 44px` on
  touch-sized viewports.
- New hamburger button (`.sc-hamburger`) in the chrome topbar with
  `aria-controls`/`aria-expanded` plumbing.

**2. PWA support (`src/safecadence/ui/pwa/`)**
- New subpackage with `manifest.json`, `service_worker.js`, and an
  `__init__.py` that registers FastAPI routes.
- `GET /manifest.webmanifest` — app manifest with theme `#1F6F6A`,
  background `#0b1020`, two SVG-data-URL icons (192×192 + 512×512), and
  three home-screen shortcuts (Dashboard, Reports, Inventory).
- `GET /sw.js` — service worker: cache-first for static, network-first
  for `/api/*` with stale-cache fallback. Cache name versioned with the
  release so bumps auto-invalidate.
- `_chrome.py` `<head>` now ships `<link rel="manifest">`, the
  `<meta name="theme-color">`, and a tiny `if ('serviceWorker' in
  navigator)` boot script.

**3. WCAG 2.2 AA pass (`src/safecadence/ui/accessibility.md`)**
- Skip-to-content link (`.skip-to-content`) is the first focusable
  element on every page; visible only on focus.
- `<main role="main" id="sc-main-content">` and `<aside aria-label="Primary
  navigation">` landmarks in `_chrome.py`.
- Icon-only topbar buttons got `aria-label` (palette, Ask AI, bell,
  hamburger).
- Global `aria-live="polite"` region (`#sc-live`) + new `scAnnounce(msg)`
  helper for dynamic status messages.
- Reports wizard tabs got `role="tablist"`/`role="tab"`/`aria-selected`,
  preview wrapped in `role="region"` + `aria-live="polite"`.
- `:focus-visible { outline: 2px solid #5fc6bc; outline-offset: 2px }`
  applies globally.
- Color contrast audited — every body-text foreground passes 4.5:1 on
  both dark and light themes (cheatsheet in `accessibility.md`).
- `accessibility.md` lists what's left for v11.2 (Cytoscape keyboard nav,
  NVDA/VoiceOver smoke, reduced-motion, redundant icons on severity pills).

**4. i18n framework (`src/safecadence/i18n/`)**
- Stdlib-only — no `gettext`, no `babel`, no external deps.
- `t(key, lang=None, **vars)` — looks up `key` in the active language's
  JSON catalog, falls back to English when missing. Supports
  `str.format()`-style substitution.
- `set_lang(lang)` / `get_lang()` / `current_lang()` — thread-local
  active language.
- `resolve_lang(query_lang, cookie_lang, accept_language)` — query param
  wins, then cookie, then `Accept-Language`, then `en`.
- Catalogs shipped: `en.json` (~50 keys), plus `es.json` / `fr.json` /
  `de.json` / `ja.json` (~25 stub keys each, prefixed `[TODO-XX]` so
  translators can grep).
- Wired into the reports wizard as proof of concept: `_wizard_body()`
  substitutes `%T:key%` placeholders at render time. Step headings, tab
  labels, action buttons, read-only banner, and the preview empty-state
  flow through `t()`. `GET /reports?lang=fr` switches to the French stub.

**5. Mobile app scaffold (no submission)**
- `mobile/README.md` documents the React Native init recipe
  (`npx react-native@latest init SafeCadence --version 0.74`), the
  recommended packages, how to point at the demo/production API, and
  the first four screens to build. Native scaffold stays uninitialized
  until App Store + Play Console accounts are set up.

**6. Tests (`tests/test_v11_1.py`)**
- 15 new tests covering i18n fallback, language resolution priority,
  catalog discovery, accessibility.md presence, mobile README presence,
  `/static/responsive.css` content, manifest JSON validity, service
  worker headers, wizard skip-link + landmark + live region, wizard
  i18n substitution, query-param language switch, version + CHANGELOG
  bumps.

**7. Version + housekeeping**
- `safecadence` 11.0.0 → 11.1.0 in `pyproject.toml` + `__init__.py`.
- `TODO_MORNING.md` gets a `# 2026-05-11 — v11.1 follow-ups` block with
  the punch list (real translations, RN init, real PNG icons, AT smoke).

## [11.0.0] — 2026-05-11

### ML + intelligence depth: anomaly detection, predictive risk, clustering, drift forecasting, NLQ, threat-hunting playbooks

New top-level package `safecadence.ml`. Stdlib + `math` only — no `sklearn`, no `numpy`, no `scipy`. The point of this release is that the platform behaves intelligently on real data *today*, before any trained model ships. Real supervised classifiers (trained on customer-supplied labels + drift events) ride in subsequent v11.0.x point releases.

**1. Anomaly detection (`safecadence.ml.anomaly`)**
- `detect_anomalies(timeseries, window=20, threshold=3.0)` — sliding-window z-score against the *trailing* window. Skips constant windows (zero stdev). Returns `{index, value, z, mean, stdev, severity}` per flagged point.
- `detect_seasonal_anomaly(series, period_days=7)` — compares each `(ts, value)` to the median of same-weekday peers from the last ~8 cycles. Flags points outside `2 × IQR`.
- `detect_finding_anomaly(org_id, window=14, threshold=3.0)` — runs the sliding z-score over the daily finding-count series; reads from `finding_history.jsonl`, `scan_history/*.json`, or `platform_assets/*.json` in that order.

**2. Predictive risk scoring (`safecadence.ml.predict_risk`)**
- `predict_risk_30d(asset, history=None)` — EWMA over the trailing 60 observations + linear-trend slope, projected 30 days forward. Confidence is a function of history length + variance. Returns interpretable `drivers` (KEV count, EOL, public exposure, MFA missing, trend direction).
- `assets_trending_critical(org_id, horizon_days=30)` — sweeps every asset and surfaces the ones forecast to cross `risk_score >= 70` inside the horizon. Reports `days_to_critical` per asset.

**3. Finding pattern clustering (`safecadence.ml.cluster_findings`)**
- `cluster_similar(findings, k=None)` — k-medoids over a small categorical feature vector (`rule_id`, severity, `controls`, category) with a Jaccard-on-controls + step-distance metric. `k` defaults to silhouette-picked over 2..6 — silhouette score implemented from scratch (~30 lines, no SciPy). `Cluster` dataclass exposes `representative_finding`, `members`, `count`, `common_remediation`.
- Used by the v10.x report builder to surface "these N findings share the same root cause."

**4. Drift forecasting (`safecadence.ml.drift_forecast`)**
- `forecast_drift(asset_id, history=None, org_id=None)` — inter-arrival-time estimator over the v10.8 change log. Shortens the window when recent events are high/critical or when the asset is already overdue. Returns `{days_until_drift, confidence, key_indicators, events_seen, mean_gap_days, days_since_last}`.
- `assets_at_drift_risk(org_id, days=14)` — every asset forecast to drift inside `days`, sorted ascending by ETA.

**5. Natural-language query (`safecadence.ml.nlq`)**
- `parse_query(text)` — rule-based parser covering the six required examples plus severity thresholds, hostname-contains, tag, vendor, criticality, asset-type, site. Returns `ParsedQuery(text, filter, matched_patterns, source, note)`.
- LLM fallback: when `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is set and no rule matches, we call `safecadence.ai.client` and parse the LLM's JSON response into the same filter shape. With no key + no rule match, `source="parse_failed"` and `note` explains why.
- `execute_query(parsed, store=None, org_id=None)` runs the filter against an in-memory list or the org's `platform_assets/*.json`.

**6. Threat-hunting playbooks (`safecadence.ml.playbooks`)**
- `kev_response` — identify affected assets → check patch availability → score exposure (public/crown counts) → isolate + compensating controls → notify + log decision. Deterministic. Reads `platform_assets` to count affected hosts.
- `lateral_movement` — scope the foothold → trace reachable paths to crown jewels → contain east-west → hunt for additional footholds → write postmortem stub.
- `credential_compromise` — identify the account → revoke active sessions + force rotation → audit recent actions → contain blast radius → report.
- `list_playbooks()` + `run_playbook(id, context)` make every playbook a callable workflow. Step severity escalates automatically when the context says the account is privileged or the asset is crown-jewel.

**7. API (`safecadence.ml.api`)**
FastAPI router auto-mounted from `safecadence.ui.app.create_app`:
- `POST /api/v1/ml/anomalies` — body `{timeseries?, org_id?, window?, threshold?}`
- `POST /api/v1/ml/predict-risk` — body `{asset?, asset_id+org_id?, org_id+horizon_days?, history?}`
- `POST /api/v1/ml/cluster-findings` — body `{findings?, org_id?}`
- `POST /api/v1/ml/drift-forecast` — body `{asset_id?, history?, org_id?, days?}`
- `POST /api/v1/ml/nlq` — body `{query, org_id?}` → returns `parsed` + `matches`
- `GET /api/v1/ml/playbooks` — list
- `POST /api/v1/ml/playbook/{id}/run` — body is the context dict

**8. Tests (`tests/test_v11_0.py`)**
- Anomaly: planted spike found; constant series + short series flagged empty; seasonal anomaly catches off-weekday outlier; finding-anomaly reads `finding_history.jsonl`.
- Predict: monotonic upward history predicts higher than current; flat history stays stable; `assets_trending_critical` separates climbers from quiet hosts.
- Cluster: three planted groups → 2..4 clusters (silhouette is fuzzy); single + empty input safe.
- Drift: noisy history → shorter window + higher confidence than quiet; empty → 365 days, conf 0.0.
- NLQ: six parametrized known queries, `parse_failed` when no rule + no LLM key, `execute_query` filters.
- Playbooks: list contains baseline three; `kev_response` returns ≥3 steps with at least one `critical`; unknown ID raises; credential playbook escalates session-revoke to `critical` on privileged path.
- API: TestClient round-trip for every endpoint, including the 404 on unknown playbook.

**9. Wiring**
- `safecadence.ui.app.create_app` includes `safecadence.ml.api.router` in a try/except so the demo never breaks on partial mounts.
- `safecadence` 10.9.0 → 11.0.0 in `pyproject.toml` + `__init__.py`.

## [10.9.0] — 2026-05-10

### Commercialization: Stripe billing, plan tiers + metering, self-service signup, customer portal, pricing page

Everything is env-gated. With no `STRIPE_SECRET_KEY` configured, billing endpoints return `503 {"error":"billing_not_configured"}` and the rest of the platform keeps working — the public read-only demo is unchanged.

**1. Stripe billing module (`safecadence.billing`)**
- `stripe_client.py` — stdlib `urllib` REST client. No `stripe` package dep. Public surface: `create_checkout_session(plan, customer_email, success_url, cancel_url)`, `create_customer(email, name=None)`, `create_subscription(customer_id, price_id, trial_days=14)`, `cancel_subscription(subscription_id, at_period_end=True)`, `create_billing_portal_session(customer_id, return_url)`, `get_invoice(invoice_id)`, `list_invoices(customer_id, limit=20)`, `is_configured()`, `price_id_for_plan(plan_id)`. Missing key raises `BillingNotConfigured`; HTTP errors raise `StripeError(status, body, code)`.
- `webhook.py` — `verify_webhook_signature(payload, sig_header, secret, tolerance=300)` does the standard Stripe HMAC-SHA256 protocol (timestamp + `v1=` digests + replay tolerance window). `handle_event(event, org_id=None)` dispatches on `event.type` for `checkout.session.completed`, `customer.subscription.created/updated/deleted`, `invoice.payment_failed`, `invoice.paid`. Persists state to `~/.safecadence/orgs/<org_id>/billing.json`; appends paid invoices to `payments.jsonl`.
- `routes.py` — FastAPI router exposing `POST /api/billing/webhook`, `POST /api/v1/billing/checkout`, `POST /api/v1/billing/portal`, `GET /api/v1/billing/plan`, `GET /api/v1/billing/plans`. The webhook receiver verifies the signature when `STRIPE_WEBHOOK_SECRET` is set, dev-mode accepts otherwise (with a warning).

**2. Plan tiers + metering (`safecadence.billing.plans` + `usage`)**
- Three hardcoded plans: `Free` ($0, 25 assets, 5 reports/mo, API disabled), `Pro` ($49/mo, 250 assets, unlimited reports, 100k API calls/mo, all integrations), `Enterprise` ($499/mo, unlimited everything, SAML SSO, dedicated support).
- `get_plan(plan_id)`, `list_plans()`, `get_org_plan(org_id)`, `set_org_plan(org_id, plan_id, source=, status=, stripe_*=)`. Plan record persisted to `billing.json` per org.
- `check_quota(org_id, resource)` → `{ok, used, limit, plan, resource}` for `"assets"`, `"reports"`, `"api_calls"`. Limit of `-1` means unlimited, `0` means disabled.
- `usage.record_usage(org_id, resource, count=1, meta=None)` appends to `~/.safecadence/orgs/<org_id>/usage.jsonl`. `get_usage(org_id, period="month")` aggregates the current month; `get_usage_history(org_id, resource, months=6)` returns per-month buckets.
- `billing.middleware.UsageMeteringMiddleware` counts every `/api/v1/*` hit as one `api_calls` event for the requesting org and short-circuits the response with HTTP 402 + `quota_error_payload()` when the org's quota is already over. Exempts `/api/v1/billing/*`, `/api/v1/me`, `/api/v1/plans`, `/api/billing/webhook`. Disable via `SC_USAGE_METERING_DISABLED=1`.

**3. Self-service signup (`safecadence.auth.signup` + `signup_routes`)**
- `request_signup(email, org_name, plan="Free", return_url=None)` creates a pending verification record (`~/.safecadence/signups.json`), emails a magic link via the existing SMTP helper, returns `{sent, token, verify_url, plan}`. 24-hour TTL.
- `verify_signup(token)` provisions the Org via `org_store.create_org`, assigns ADMIN role, sets the initial plan via `set_org_plan`, creates a session, and (for paid plans with Stripe configured) creates a Checkout session and returns `checkout_url`. Records a `signup_completed` change event for audit.
- Routes: `GET /signup` (HTML form, plan-prefilled via `?plan=Pro`), `POST /signup` (submit), `GET /signup/verify?token=...` (consume + set session cookie + redirect to portal or Stripe).

**4. Customer portal (`safecadence.portal.customer`)**
- Server-rendered HTML at `/portal/*` — consistent with the rest of the codebase, no React build step. Routes:
  - `GET /portal` — overview dashboard: current plan card, three KPI cards (assets / reports / API calls used this month with progress bars), action items (trial ending, past-due, near-quota).
  - `GET /portal/billing` — current subscription card, plan cards (Free/Pro/Enterprise) with switch buttons, invoice table from Stripe.
  - `POST /portal/billing/change` — switches Free in-process; paid plans redirect to a Checkout Session.
  - `POST /portal/billing/manage` — returns Stripe Customer Portal URL via `create_billing_portal_session`.
  - `GET /portal/team` — RBAC roster table; admins see invite + remove forms.
  - `POST /portal/team/invite` — assigns role + emails magic-link sign-in. Admin-only.
  - `POST /portal/team/remove` + `DELETE /portal/team/{user_id}` — drops member from RBAC. Admin-only.
  - `GET /portal/usage` — 6-month per-resource bar charts via `get_usage_history`.
  - `GET /portal/support` + `POST /portal/support` — ticket form + table backed by `portal.support_tickets` (JSONL store at `<org_dir>/support_tickets.jsonl`).

**5. Pricing page on safecadence.com**
- New static file at `/srv/safecadence/sites/safecadence.com/pricing/index.html` (mirrored in repo at `outputs/safecadence-site/pricing/index.html`). Three-tier comparison table, feature matrix, 6-item FAQ. CTAs link to `https://app.safecadence.com/signup?plan=<Free|Pro>` and `mailto:sales@safecadence.com` for Enterprise. Prominent "14-day free Pro trial — no credit card required" pill.
- Main `index.html` (mirror at `outputs/safecadence-site/index.html`) gains a "Pricing" link in the top nav (between Live Demo + Studio) and a featured Pricing card in the right rail of the hero. v10.9.0 version chip in the footer.

**6. Tests (`tests/test_v10_9.py`)**
- Stripe client: BillingNotConfigured when key unset; price_id env lookup; create_customer mocked request shape.
- Webhook: HMAC signature verify good + bad + replay-rejected; checkout.session.completed activates plan; invoice.payment_failed flags `past_due`.
- Plans + quota: registry sanity; set/get org plan; Free 402 shape after exceeding 25 assets; API disabled on Free; unlimited on Enterprise.
- Usage: aggregate; 6-month history; readonly no-op; unknown resource rejected.
- Signup: Free round-trip creates Org + ADMIN role; Pro produces checkout URL with Stripe mocked; bad email rejected; expired token rejected; readonly refused.
- Portal: dashboard renders all sections + plan; billing lists all three plans; `/api/v1/billing/plans` is public; checkout returns 503 when unconfigured.
- Pricing page: file exists in outputs dir + contains "Free", "Pro", "Enterprise", and the droplet path comment.

**7. Wiring**
- `safecadence.ui.app.create_app` now mounts (in try/except blocks): `auth.signup_routes`, `billing.routes`, `portal.customer`, and adds `billing.middleware.UsageMeteringMiddleware`. Every mount is best-effort so the demo never breaks on a missing dependency.
- `safecadence` 10.8.0 → 10.9.0 in `pyproject.toml` + `__init__.py`.

## [10.8.0] — 2026-05-10

### Workflow + governance: approval chains, SOC 2 evidence, change hooks, pentest, SAML, AWS Security Hub

All persistent, env-gated, no new dependencies. Read-only demos (`SC_READONLY=1`) refuse mutations with a clear `PermissionError` → HTTP 403.

**1. Approval chains for risk acceptance (`safecadence.workflow.approval_chains`)**
- `ApprovalChain` dataclass with per-step role + signer + signed-at.
- `define_chain(org_id, name, role_steps)` saves a chain template.
- `start_approval(org_id, finding_id, chain_name)` instantiates a pending approval.
- `sign_step(approval_id, user_email, role)` verifies the signer holds the step's role via `safecadence.auth.rbac` (or a custom roles file for non-builtin labels like `CISO`), advances the chain, and on the final step applies the risk acceptance via `reports.risk_acceptance.add_acceptance`.
- `list_approvals(org_id, status=None)` + `cancel_approval(approval_id, reason)`.
- Persisted as append-only JSONL at `~/.safecadence/orgs/<org_id>/approvals.jsonl`.

**2. SOC 2 evidence collection (`safecadence.workflow.soc2_evidence`)**
- `EvidenceItem` (id / control_id / framework / kind / file_ref / captured_at / captured_by / note).
- `attach_evidence(org_id, control_id, framework, kind, file_data, filename, note, user)` writes the blob under `~/.safecadence/orgs/<org_id>/evidence/<framework>/<control_id>/` and indexes it.
- `list_evidence(org_id, framework=, control_id=)`.
- `export_evidence_pack(org_id, framework) -> bytes` returns a ZIP with `MANIFEST.csv` listing every control + evidence file plus every file.
- Auto-capture: `reports.builder.compose_report` calls `record_report_as_evidence` whenever the scope carries `framework` + `controls` so generating a compliance report leaves a per-control receipt automatically.

**3. Change-management hooks (`safecadence.workflow.change_mgmt`)**
- `ChangeEvent` dataclass + `register_hook(name, callback) / unregister_hook / list_hooks`.
- `record_change(org_id, kind, before, after, actor, asset_id, extra)` appends a JSONL event to `~/.safecadence/orgs/<org_id>/change_log.jsonl` and fires every registered hook.
- Built-in `jira` + `servicenow` hooks call into the v10.6 / v10.7 integration modules and auto-create tickets for `risk_accepted`, `acceptance_expired`, `finding_transition`, `pentest_signoff` events. No-op when the integration's `is_configured()` returns False.
- Wired into `risk_acceptance.add_acceptance` (`risk_accepted`), `risk_acceptance.expire` (`acceptance_expired`), `reports.templates.save_template` (`template_saved`), and `reports.audit_trail.log_event` (`finding_transition`).

**4. Pen-test workflow (`safecadence.workflow.pentest`)**
- `PenTest` + `PenTestFinding` dataclasses.
- `create_pentest / start_pentest / complete_pentest / add_finding / update_finding_status / signoff` lifecycle (planned → running → completed → signed_off).
- `gap_to_remediation(pentest_id)` returns rows with `days_open` + `overdue` flag against a 30-day target.
- Persisted as one JSON per pentest under `~/.safecadence/orgs/<org_id>/pentests/`, with a `pentests.json` index refreshed atomically on every write.

**5. SAML SSO + AWS Security Hub**
- SAML SP at `safecadence.auth.saml`: SP-initiated flow with `metadata_xml() / handle_acs_response(saml_response)`. Signature verification uses HMAC-SHA256 over a stub canonicalisation of the assertion (documented limit — for production IdPs with RSA-SHA256 + exclusive XML-DSig, a follow-up will need `python3-saml` or `signxml`). Env-gated on `SC_SAML_IDP_METADATA_URL` + `SC_SAML_SP_ENTITY_ID`. Routes `GET /auth/saml/metadata` + `POST /auth/saml/acs`.
- AWS Security Hub at `safecadence.integrations.aws_security_hub`: stdlib HTTP + SigV4 (reused from `storage.s3_store`). `ingest_findings(profile, region, max)` calls Security Hub `/findings` with `x-amz-target=SecurityHub.GetFindings` and returns SafeCadence-shaped findings (severity normalised, CVE pulled from `Vulnerabilities[]` or title). Env: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (optional), `AWS_REGION`. CLI: `safecadence ingest aws-security-hub --region us-east-1`.

**6. REST API**
- `POST/GET /api/v1/approvals` (+ `/chains`) — start / sign / cancel / list.
- `POST /api/v1/evidence` (multipart) + `GET /api/v1/evidence` + `GET /api/v1/evidence/export?framework=...` (returns ZIP).
- `GET /api/v1/changes?org=...` — list change events.
- `/api/v1/pentests` CRUD + `/start /complete /findings /signoff /gap`.
- All routes are org-scoped via `X-SafeCadence-Org` header or `?org_id=` query.

**7. Tests**
- `tests/test_v10_8.py` — approval chains happy path + wrong-role rejection; evidence attach/list/export-zip shape; change_mgmt hook firing; pentest lifecycle; SAML metadata + ACS rejection of unsigned response; AWS Security Hub mocked HTTP returning normalised shape.
- Every prior test (5 + 6 + 7 + reports + identity + intel + policy) continues to pass.

## [10.7.0] — 2026-05-10

### Scale + failover code: Redis, Postgres, S3, cluster + 3 new integrations

All env-gated. No `SC_REDIS_URL` / `SC_POSTGRES_URL` / `SC_S3_BUCKET` = identical behaviour to v10.6 (in-memory queue + SQLite + local disk).

**1. Redis-backed job queue (`safecadence.queue`)**
- New stdlib-only RESP client at `safecadence.queue.redis_queue` — no `redis` package required.
- Public surface: `enqueue(queue, payload) -> job_id`, `dequeue(queue, timeout)`, `set_status(job_id, status, result)`, `get_status(job_id)`.
- `__init__.py` proxies to Redis when `SC_REDIS_URL` is set; falls through to an in-process dict otherwise.
- `reports.api_v1._REPORT_JOBS` now mirrors every state transition to Redis (`_mirror_status`) so multi-worker deployments share the job table. Mirroring is best-effort and silently no-ops if Redis is down — never crashes the wizard.

**2. Postgres adapter (`safecadence.storage.postgres_store`)**
- Stdlib + `psycopg` (v3) when available. Schema mirrors SQLite column-for-column.
- `safecadence.storage.open_store()` now resolves in order: `SC_POSTGRES_URL` → PostgresStore, SQLAlchemy URL → SqlStore, else SqliteStore.
- New `safecadence migrate --from sqlite --to postgres` CLI: streams every scan in 500-row batches via `executemany`.

**3. S3 / DO Spaces object store (`safecadence.storage.s3_store`)**
- Stdlib AWS Signature V4 — no boto3 dependency. Works with real S3, DigitalOcean Spaces, Backblaze B2, MinIO.
- `S3Store.put_object / get_object / delete_object / list_objects`.
- `reports.templates.put_rendered_report(filename, body, content_type)` writes to S3 when `SC_S3_BUCKET` is configured, falls back to `<data_dir>/reports/rendered/` otherwise. Silently degrades on any S3 failure.

**4. Cluster + failover code (`safecadence.cluster`)**
- `cluster.health.node_health()` — cpu/mem/disk, last-scan age, db/redis/s3 status, is-active flag.
- `cluster.health.cluster_state()` — aggregates `node_health` from every peer in `SC_CLUSTER_PEERS`. Injectable fetcher for tests.
- `cluster.failover.{am_i_active, try_take_lease, renew_lease, release_lease}` — SETNX-backed 60s lease at `safecadence:cluster:active_node`. Background renewer at 15s via `start_lease_loop()`. Single-node mode (no Redis) reports active forever — demo unaffected.
- `deploy/postgres-replication-setup.sh` — Postgres 16 streaming replication primary/standby installer.
- `deploy/load-balancer.md` — DO Load Balancer + DNS playbook for active-passive.

**5. ServiceNow / Teams / Splunk (`safecadence.integrations`)**
- `servicenow.create_servicenow_incident(finding)` — Table API basic auth, severity→impact/urgency mapping, returns `{sys_id, number, url}`. Env: `SC_SERVICENOW_INSTANCE/USER/PASS`.
- `teams.post_message(text)` + `teams.post_finding(finding)` — MessageCard via channel webhook. Env: `SC_TEAMS_WEBHOOK_URL`.
- `splunk.forward_event(event)` + `splunk.forward_finding(finding)` — HEC token auth, configurable index + sourcetype. Env: `SC_SPLUNK_HEC_URL/HEC_TOKEN`.

**6. Tests**
- `tests/test_v10_7.py` covers Redis queue (memory + mocked-socket fallback), Postgres adapter (mocked psycopg), S3 (mocked HTTP + SigV4 shape + XML LIST), cluster health/failover (lease lifecycle), and all three integrations (mocked HTTP). All existing 206 tests still pass.

## [10.6.0] — 2026-05-10

### Real AI, Slack + Jira integrations, configurable dashboard widgets

**1. Real LLM integration (`safecadence.reports.ai_helpers`)**
- Deterministic stub path replaced with a stdlib-only LLM client (no SDK dependency).
- **OpenAI Chat Completions** (`gpt-4o-mini`) when `OPENAI_API_KEY` is set; **Anthropic Messages API** (`claude-haiku-4-5-20251001`) when `ANTHROPIC_API_KEY` is set. 30-second timeout, one retry on 5xx.
- `generate_executive_summary()` now sends structured KPI JSON plus a tone hint so the LLM rephrases without inventing numbers; falls back to the deterministic three-part summary on any failure.
- New `explain_cve(cve_id, severity, kev=False, host=None) -> {explanation, source}` — `source` is `"llm"` or `"stub"` so the UI can badge the result.
- New `detect_quick_wins(actions, top_n=3) -> list[dict]` — LLM-ranked when keys are set; deterministic `risk_reduction/effort_minutes` heuristic otherwise.
- `llm_status()` reports the active provider/model.
- Env-gated everywhere: with zero keys configured, every helper degrades to the v10.5 deterministic path. The demo keeps working.

**2. Slack OAuth bot (`safecadence.integrations.slack`)**
- OAuth 2.0 install flow: `GET /oauth/slack/install` → consent → `GET /oauth/slack/callback` exchanges code, persists to `~/.safecadence/orgs/<org_id>/slack_install.json`.
- Slash command handler at `POST /slack/commands` verifies HMAC-SHA256 signature over `v0:{timestamp}:{body}` with `SLACK_SIGNING_SECRET`, rejects requests older than 5 minutes.
- Supports `/safecadence report <preset>`, `/safecadence status`, `/safecadence findings <severity>`.
- `post_message(channel, text, token=…)` sends `chat.postMessage` (uses `SLACK_BOT_TOKEN` env if no token passed).
- Env-gated on `SLACK_CLIENT_ID`; install returns 503 with `{"error":"not_configured"}` when missing.

**3. Jira integration (`safecadence.integrations.jira`)**
- Atlassian 3LO OAuth: `GET /oauth/jira/install` → consent → `GET /oauth/jira/callback` trades code, looks up cloud-id via `/oauth/token/accessible-resources`, persists token + cloud-id to `~/.safecadence/orgs/<org_id>/jira_install.json`.
- `create_jira_ticket(finding, *, org_id=None, project_key=None) -> {issue_key, url}` — POSTs `/rest/api/3/issue` with an ADF description and severity-to-priority mapping. Returns `None` when no token is available.
- `poll_status_updates(org_id)` — read-only sync stub that searches `labels = safecadence` and returns `{issue_key, status, resolution}` rows the caller can use to close out findings.
- Env-gated on `JIRA_CLIENT_ID`.

**4. Configurable dashboard widgets (`safecadence.dashboard.widgets`)**
- `Widget` dataclass: `{id, type, title, config, position}`. Seven types ship: `kpi_card`, `severity_donut`, `compliance_radar`, `top_findings_list`, `recent_changes`, `vendor_concentration`, `risk_trend_sparkline`.
- `list_widgets(org_id)` returns 6 sensible defaults when no per-org file exists.
- `save_widgets(org_id, widgets)` validates type, normalises positions, persists to `~/.safecadence/orgs/<org_id>/widgets.json`.
- `render_widget(widget, store) -> dict` returns `{id, type, title, data, empty}` — store may be a dict (`hosts`, `severity`, `vendors`, ...) or `None` for an empty card.
- Endpoints: `GET /api/v1/dashboard/widgets`, `PUT /api/v1/dashboard/widgets` (admin-gated via `require_role(ADMIN)`), `GET /api/v1/dashboard/widget/{id}`.

**5. Wizard hooks**
- `POST /api/reports/ai/explain-cve` → `{explanation, source}` from `explain_cve()`.
- `POST /api/reports/ai/quick-wins` → `{top: [...]}` from `detect_quick_wins()`.

**6. Tests**
- New `tests/test_v10_6.py` — 36 tests covering AI stub/LLM paths, signature verification, install round-trip, slash-command dispatch routing, Jira issue create (mocked HTTP), and widget defaults + render + save/load round-trip.
- All existing reports/v10.4/v10.5/identity/cli/intel/policy tests continue to pass.

**No new external dependencies.** Every LLM call and integration uses stdlib `urllib` + `json` + `hmac` + `hashlib`.

## [10.5.0] — 2026-05-10

### Multi-tenant foundation: auth, isolation, RBAC, observability

**1. Magic-link email auth (`safecadence.auth.magic_link`)**
- `request_login(email, return_url=None)` issues a 32-byte token, persists it to `~/.safecadence/auth_tokens.json` with 15-minute expiry, emails the sign-in link via `safecadence.reports.email_delivery.send_email_raw()`.
- `verify_token(token)` — one-shot consume → returns `(user_id, email)` or `None`.
- `create_session(user_id, email)` → 30-day session token persisted to `~/.safecadence/sessions.json`.
- `get_session(token)` / `revoke_session(token)` round out the lifecycle.
- **Demo bypass**: `SC_AUTH_DISABLED=1` short-circuits every helper to a deterministic `demo@safecadence.com` pseudo-session — keeps `demo.safecadence.com` open with zero config.
- New FastAPI routes: `GET /login`, `POST /login/request`, `GET /auth/callback?token=…`, `POST /logout`, `GET /me`. HttpOnly + Secure (when HTTPS) + SameSite=Lax cookie management.

**2. Per-org data isolation (`safecadence.storage.org_store`)**
- `Org` dataclass + `create_org / get_org / list_orgs / delete_org` CRUD persisted to `~/.safecadence/orgs.json`.
- `org_data_dir(org_id) -> Path` returns `~/.safecadence/orgs/<org_id>/` with `platform_assets/`, `scans/`, `reports/`, `members.json`, `audit.jsonl` provisioned on demand.
- `compose_report(..., org_id=None)` is now org-aware via a `contextvars`-scoped shim — section composers reading `_load_platform_assets()` automatically pick up the org's directory. `org_id=None` keeps the legacy global-data behavior.

**3. RBAC (`safecadence.auth.rbac`)**
- `UserRole` enum: `VIEWER < EDITOR < ADMIN`.
- `assign_role / get_role / remove_role / list_members` persisted to `~/.safecadence/orgs/<org_id>/members.json`.
- `require_role(min_role)` FastAPI dependency factory — reads org id from `X-SafeCadence-Org` header or `org_id` query; 403s on insufficient role. Bypassed under `SC_AUTH_DISABLED=1`.

**4. Audit log (`safecadence.audit.log`)**
- `log_event(org_id, user_email, action, target=None, metadata=None)` appends one JSON object per line to `~/.safecadence/orgs/<org_id>/audit.jsonl`.
- `read_events(org_id, limit=100, since=None)` returns newest-first list.
- Wired into the report wizard write endpoints: `report.template.save`, `report.template.delete`, `report.share_token.issue`, `report.render` are all recorded.

**5. Observability (`safecadence.observability`)**
- **Stdlib-only Prometheus exposition** at `GET /metrics` — counters, histograms, gauges hand-rendered to text. No `prometheus_client` dependency.
  - `safecadence_requests_total{path,method,status}` counter.
  - `safecadence_request_duration_seconds_bucket{path,method,le}` histogram (+ `_sum`/`_count`).
  - `safecadence_active_sessions` gauge.
  - `safecadence_reports_generated_total{format,preset}` counter.
- `GET /healthz/detail` JSON dashboard — `{status, version, uptime_seconds, disk_free_mb, recent_errors_count, scheduled_jobs_age_seconds}`. Status: healthy / degraded / unhealthy thresholds.
- Error log at `~/.safecadence/errors.jsonl` — `record_error(exc, context)`. `MetricsMiddleware` auto-records uncaught exceptions. Last 100 viewable at `GET /api/v1/admin/errors`.

**6. Test-fix carryover**
- Fixed `tests/test_link_audit.py::test_chrome_sidebar_links_resolve` and `test_asset_detail_links_resolve` — the `/reports` route wasn't registered on the `safecadence.server.create_app()` factory (only on the standalone UI app). Both factories now include the reports router.

**Wiring**
- `server.app.create_app()` and `ui.app.create_app()` both mount: reports router, auth router, observability router + `MetricsMiddleware`. All wrapped in try/except so an install without `[server]` extras still imports cleanly.
- `email_delivery.send_email_raw(to, subject, body)` added for transactional email (magic links).

**New modules**
- `src/safecadence/auth/__init__.py`
- `src/safecadence/auth/magic_link.py`
- `src/safecadence/auth/rbac.py`
- `src/safecadence/auth/deps.py`
- `src/safecadence/auth/routes.py`
- `src/safecadence/storage/org_store.py`
- `src/safecadence/audit/__init__.py`
- `src/safecadence/audit/log.py`
- `src/safecadence/observability/__init__.py`
- `src/safecadence/observability/metrics.py`
- `src/safecadence/observability/errors.py`
- `src/safecadence/reports/_scope_ctx.py`
- `tests/test_v10_5.py` (17 tests)

**Tests**: 1433 collected, all passing. `tests/test_v10_5.py` adds 17.

---

## [10.4.0] — 2026-05-10

### Three themes: scheduled & scriptable / compliance depth / inventory polish

**Theme A — Scheduled & scriptable reports**
- New CLI `report` command group: `compose`, `send`, `list-presets`, `list-sections`, `schedule {list,add,remove,run-due,daemon}`
- SMTP email delivery — `safecadence report send --preset X --to a@b.com` (uses `SC_SMTP_*` env vars, STARTTLS)
- Persistent scheduler — `~/.safecadence/schedules.yaml` with cron syntax (`* / , - MON TUE …`), `safecadence report schedule daemon` runs the loop
- REST API — `POST /api/v1/reports/generate` returns a job_id; background thread renders; `GET /api/v1/reports/{id}` for status; `GET /api/v1/reports/{id}/download` for the file. Optional `deliver_via=email`. Fires `report.ready` webhook event on success.

**Theme B — Compliance depth**
- Three new canonical framework libraries: **NIS2** (EU 2022/2555, Article 21 measures), **FedRAMP Rev. 5** (Low/Moderate/High), **CMMC 2.0** (Levels 1/2/3 with 800-171 mapping). ~42 new controls total.
- Custom framework support via `~/.safecadence/custom_frameworks.yaml` — define your own control library; auto-merged into the compliance sections at composition time.
- SLA-aware risk register — P0=14d, P1=30d, P2=60d, P3=90d (configurable via `~/.safecadence/sla_policy.yaml`). KEV findings uplift to immediate-priority SLA. New "Due date" and "SLA status" columns in DOCX / XLSX / HTML control matrix and gap analysis tables. ON_TRACK / DUE_SOON / BREACHED status pills.
- Risk acceptance log — persists to `~/.safecadence/risk_acceptance.json`. Findings the org has signed off on accepting are decorated with a "RISK ACCEPTED" pill in the evidence pack. New `risk_acceptance_log` section (default OFF, opt-in for auditor reports).
- Per-finding audit trail — `~/.safecadence/audit_trail.jsonl` tracks discovered → triaged → remediated transitions. `summary_for(finding_id)` returns TTT (time-to-triage) and TTR (time-to-remediate) for surfacing in the evidence pack.

**Theme C — Inventory polish**
- Full-width live search box on `/inventory` (300ms debounce) — matches across hostname, asset_id, vendor, site, owner, interface IPs, and tags. Stacks with the category filter.
- **Saved filter views** — capture filter + search + columns + widths + density under a name; persists in `localStorage["SC_INV_VIEWS"]`. Seeds three defaults on first run: Crown jewels / Critical risk score / Network gear only.
- **Inline edit** — double-click owner, site, or criticality cells to swap in an input/select. Optimistic update with rollback on failure. POSTs to `/api/platform/asset/{id}/field` (server-side whitelist of 9 fields, blocked in read-only mode).
- **CSV / XLSX export** from the inventory page — CSV is client-side, XLSX POSTs to `/api/platform/inventory/xlsx` which streams a real .xlsx via the reports XLSX engine.
- **Column profile quick-picks** — Compact / Security focus / Compliance focus / Lifecycle / EOL buttons instantly switch visible columns.

**Tests**: 153 passing (was 116; +19 Theme A + 18 Theme B).

**New modules**:
- `safecadence.reports.email_delivery`
- `safecadence.reports.scheduler`
- `safecadence.reports.api_v1`
- `safecadence.reports.custom_frameworks`
- `safecadence.reports.sla_policy`
- `safecadence.reports.risk_acceptance`
- `safecadence.reports.audit_trail`

---

## [10.3.0] — 2026-05-10

### Polished Office-grade deliverables + inventory ergonomics

**5-format export with embedded charts**
- New `POST /api/reports/render-download` endpoint accepts `format=html|pdf|json|docx|pptx` — one-shot composed download, works in read-only mode without saving a template
- Ephemeral share links via `POST /api/reports/share-link` → `GET /r-live/{token}` (base64-encoded payload, no template save required)
- Real PNG charts embedded in DOCX and PPTX (PIL-based engine): severity donut, compliance radar, vendor-concentration bar, sparkline trend, risk gauge, logo mark, cover hero

**DOCX overhaul — proper Word document**
- Cover page with logo mark, eyebrow, big title, italic subtitle, confidence pill, branded metadata table, "Confidential" footnote
- Header + footer applied to every page (Page X of N via field codes, classification line)
- Branded numbered headings with `keepNext` so headings never sit orphaned
- Drop-cap executive summary (36pt teal first letter) + auto-generated pull quote from the most striking KPI
- Risk dashboard: real severity donut chart + 5 KPI tiles with colored top accents + 30-day critical-CVE sparkline trend
- Compliance scorecard: real radar chart above the framework table
- Industry-benchmark page (peer medians: NIST 71, CIS 76, PCI 83, HIPAA 70, SOC 2 79)
- Risk register table (RR-001…) with owner, target date by priority, status, mitigation
- Vendor concentration analysis with hbar chart + commentary
- Site heatmap (sites × severity, intensity-shaded cells)
- What-if delta tile (before → after posture lift from completing P0 actions)
- Quarter-over-quarter comparison via `delta.compute_delta()` with baseline fallback
- Glossary appendix (CVE, CVSS, EPSS, KEV, EOL, EOS, MFA, CDE, ePHI, ATT&CK, NVD)
- Sign-off page with three signature lines (Prepared / Reviewed / Approved)
- Revision history table

**PPTX overhaul — proper 16:9 presentation**
- Cover slide with full-bleed PIL-rendered hero image (abstract network mesh) and big risk-index number
- Speaker notes on every slide via dedicated `notesSlide` parts (linked to a notesMaster)
- Section divider slides (Part I / II / III) between major topic groups
- Risk-dashboard slide: 5 colored KPI tiles + embedded severity donut chart
- Compliance scorecard slide: embedded radar chart + per-framework rows
- Visual table slides for CVE exposure, host inventory, EOL hardware, control matrix (no more bullet dumps)
- Top-findings slide with severity badges
- Prioritized action plan slide with P0/P1/P2/P3 color badges
- Closing slide

**Compliance promoted to flagship feature** (within reports)
- Four new sections beyond `compliance_posture`:
  - `compliance_executive_summary`: board-ready narrative + roll-up
  - `compliance_control_matrix`: per-control PASS/PARTIAL/FAIL with evidence note
  - `compliance_gap_analysis`: per-framework gaps with score lift + remediation
  - `compliance_evidence_pack`: per-finding evidence trail with mapped controls
- New `_COMPLIANCE_LIBRARY` with canonical control mappings for NIST 800-53 Rev 5, CIS v8, PCI DSS v4.0, HIPAA Security Rule, SOC 2 — ~70 controls
- `compliance_audit` preset rebuilt to include all four new compliance sections in audit-friendly order

**Reports wizard UX**
- Picking a preset/industry template lands on Step 1 (Sections) so you can review and tweak before previewing — no longer jumps to Preview
- Preset / industry cards toggle `.rep-preset-card.active` for immediate visual feedback
- Step 4 (Export) gains Word + PowerPoint download buttons next to HTML/PDF/JSON
- Read-only-mode-aware share link button (uses ephemeral path)

**Inventory page**
- Fixed header/data column mis-alignment (no more nested `<td colspan="0">` invalid HTML)
- **Resizable columns** — drag the right edge of any header to widen/narrow; widths persist per-user via localStorage
- **Row density toggle** — Compact / Normal / Comfortable, also persists per-user
- "↺ Widths" reset button

**Tests**: 116 passing, 0 XML leaks across all Office outputs, all XML well-formed.

---

## [10.2.0] — 2026-05-10

### A+++ Reports flagship — turns NetRisk into the only network-risk platform with a first-class report builder.

**Visual + content overhaul**
- Branded cover page with 240px risk-gauge SVG
- Numbered TOC, AI-written executive summary with "Top action this week" callout
- 5-card KPI band with sparklines + delta indicators (↑/↓)
- Inline SVG charts: severity donut, compliance radar, control heat-map, severity bars, attack-path graph, sparklines
- CVE badges with KEV / exploit-available pills
- Prioritized P0–P3 action plan with owner / effort / risk-reduction-per-action / compliance impact
- Print-ready A4 CSS, polished typography, accessible markup

**4 stakeholder presets** — exec_brief / technical_deepdive / compliance_audit / quarterly_review

**4 industry templates** — Healthcare HIPAA + HITECH, Finance PCI DSS 4.0 + SOX, Defense CMMC 2.0 + FedRAMP, SaaS SOC 2 + ISO 27001/27017

**AI layer** (real OpenAI when key set, deterministic templates otherwise)
- Executive summary in 5 tones
- Plain-language CVE explainer
- Quick-wins detector (sorts by risk_reduction / effort_minutes)
- Patch sequencer (identity → edge → server → backup → app)

**Delta reports** — daily snapshots, KPI delta indicators, sparklines, "what changed" lists

**Webhooks** — Slack/Teams/generic with HMAC-SHA256 signed delivery

**Ticketing integration** — Jira / ServiceNow / GitHub Issues / Linear, deduped by external_id

**Wizard UI** — 6-step builder (preset → sections → scope → preview → notify → tickets)

**Tests**: 116 passing (was 32). New modules: visuals.py, ai_helpers.py, presets.py, delta.py, webhooks.py, industry.py, ticketing.py.

**API additions**: 30+ new endpoints under /api/reports/* including /presets, /industry-templates, /webhooks, /ticketing, /delta, /trend, /snapshots.

**Read-only safety**: SC_READONLY=1 env var blocks all write endpoints with 403 + JSON error.



All notable changes to **safecadence-netrisk** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [10.1.0] — 2026-05-10

### Reports module — build any report from real system data

A first-class wizard-driven reports module. Customers running NetRisk
locally now get a 4-step UI at `/reports` that reads real fleet state
(no canned data) and renders into HTML, JSON, or PDF.

- **New package** `safecadence.reports` (extends the existing legacy
  per-scan renderers without breaking them):
  - `sections.py` — 10 composers reading the live store: `kpi_summary`,
    `host_inventory`, `cve_exposure`, `compliance_posture`, `eol_hardware`,
    `attack_paths`, `identity_drift`, `recommended_actions`,
    `recent_changes`, `executive_summary`. Each handles empty data
    gracefully (returns `empty: True`, never panics).
  - `builder.py` — `compose_report(sections=, scope=, store=)` plus
    `list_section_keys()` / `list_scope_keys()`.
  - `templates.py` — JSON-on-disk template persistence with
    `save/load/list/delete` + share-token helpers, all gated by
    `SC_READONLY=1`.
  - `renderers.py` — `render_html` (cover, TOC, print-friendly CSS),
    `render_json`, `render_pdf` (uses `weasyprint` if available, falls
    back to HTML bytes — never a hard dep).
  - `ui_routes.py` — FastAPI router auto-mounted by `safecadence ui`.
- **Wizard UI** at `/reports`: 4 steps (sections / scope / live preview
  iframe / export). Save-as-template, share link, HTML/PDF/JSON
  download. Real values for sites and vendors pulled from the store.
  Vanilla JS, no external CDNs, fully self-contained.
- **Scope filters**: `site`, `criticality`, `asset_type`, `vendor`,
  `date_range` — AND-combined.
- **Public share** at `/r/<token>` for read-only sharing.
- **Read-only safety**: every save/delete/share endpoint returns 403
  `{"error":"read_only"}` when `SC_READONLY=1` is set (also enforced at
  the Caddy `@write` layer on demo.safecadence.com).
- **Sidebar**: new "Reports" group with a "Builder" link in
  `safecadence/ui/_chrome.py`.
- **Tests**: `tests/test_reports.py` covers all 10 composers (empty +
  populated), template round-trip, read-only enforcement, share-token
  flow, and the builder → render-html round-trip.
- **No new hard deps**. `weasyprint` is opt-in; everything else is pure
  stdlib + existing safecadence deps.

## [10.0.2] — 2026-05-07

### Metadata-only patch — fix broken PyPI project URLs

- `pyproject.toml`: corrected `[project.urls]` Repository / Documentation /
  Issues / Changelog from `github.com/safecadence/network-risk` (which does
  not exist) to `github.com/famousleads/safecadence-network-risk` (the actual
  public repo). Without this, every "Repository" / "Issues" / "Changelog"
  link on the PyPI 10.0.1 page returns a 404.
- `pyproject.toml`: fixed the `[project.optional-dependencies] all` reference
  from `safecadence-network-risk[...]` to the correct package name
  `safecadence-netrisk[...]`. The old name would resolve to a non-existent
  PyPI package.

No code changes. Same wheel layout, same dependencies, same tests.

## [10.0.1] — 2026-05-07

### Pre-ship validation pass + epic HOWTO rewrite

Final pre-ship validation before public release. Nothing
functional changed — this release is the verification + docs
that the v10.0.0 milestone deserves.

#### Validation pass

- **Full test suite — 1263/1263 passing.** Every directory, no
  skips. Six-batch run to fit pytest discovery + execution
  inside the wall-clock budget.
- **325 module import smoke — 0 failures.** `pkgutil.walk_packages`
  walked every `safecadence.*` module and imported it cleanly.
  Catches typos, missing deps, circular imports.
- **CLI smoke — every command + subcommand renders `--help`.**
  32 top-level commands tested (activity, automation,
  capabilities, groups, identity, execute, users, webhooks,
  notify-prefs, vault, demo, daemon, ui, selfcheck, etc.). All
  good.
- **UI walkthrough — 41 sidebar pages confirmed by link audit
  (61 tests passing).** Every advertised page renders 200, no
  404s, no JSON-on-nav-link regressions.
- **Demo smoke — 34 assets + identity vault + NHIs + execution
  jobs + rollback plans + compliance artifacts + capability
  grants + IdP groups + automation rules** all populate on
  `safecadence demo`.

#### HOWTO.md — complete rewrite

Pre-v10.0.1 the HOWTO was 970+ lines of reference material —
useful but unfriendly to a buyer / new operator coming in cold.
v10.0.1 ships a from-scratch rewrite designed for Google +
new-user onboarding:

- **One-minute pitch** — what SafeCadence does, in five
  bullet points
- **5-minute quick start** — `pip install` → `safecadence demo`
  → `safecadence ui`
- **The big idea: read first, write rarely, log always** —
  the design philosophy in three rules
- **Killer features** — eight illustrated paragraphs covering
  capability gating, OIDC auto-grant, Tier-3 SSH, activity log,
  notifications, compliance, AI assistant, automation
- **Real-life workflows** — Day 1, Daily briefing, Weekly
  compliance, Incident response, Auditor visit (each with
  the actual commands an operator would run)
- **Per-section deep dives** — Capabilities, Identity,
  Tier-3, Automation, AI assistant, Activity log,
  Notifications, Demo dataset
- **CLI reference + REST API reference + env-var tunables**
- **FAQ** — 12 questions buyers and operators actually ask
  (dial-home, air-gap, SaaS, JWT rotation, Windows support,
  PyPI flow, etc.)

The doc is built for SEO: clear H2/H3 headings, table of
contents with deep links, descriptive section titles
(`/audit deep filter set` not just `/audit`), CSS-class-free
Markdown that GitHub + GitBook + Pandoc all render the same.

#### UI friendliness assessment (no fixes needed)

Honest review of every sidebar page. The friendliness story is
already strong:

- Every page has a hero band explaining what it is
- Empty states across discovery / drift / per-device-diff /
  changes / tags / scope have explainer cards (v9.20.2)
- /audit has 5 quick-filter chips, browser-local time on hover,
  "My actions only" toggle, deep filter set
- /capabilities matrix shows G/R/D/— glyphs with tooltip
- Universal nav, command palette (Ctrl-K), keyboard shortcuts
  + ? help overlay, dark mode

Known-rough but not v10.0.1 blockers (these are in the v10.x
backlog):
- `v9_pages.py` is 9700+ lines (architectural debt, no
  user-facing impact)
- No screenshot library in docs (we ship a UI, not a
  marketing site)
- UTC-only timestamps in chrome's "last updated" stamps
  (only /audit got the local-time hover)

#### Known follow-ups (intentional, documented)

These were called out in the v10.0.0 milestone CHANGELOG and
are unchanged for v10.0.1 — none customer-blocking:

- PyPI publishing (flow needs re-validation; wheels exist)
- SAML 2.0 response validation (xmlsec hard-dep concern)
- Activity log hash chain (compliance/evidence already has one)
- `v9_pages.py` split (architectural cleanup release)
- Comments/assignments capability migration (workflow surface)

#### Ship

Version 10.0.1 in `__init__.py` and `pyproject.toml`. README,
DEPLOY.md, HOWTO.md all current. CHANGELOG carries the full
v9.x → v10.0.x journey.

The project is finished.

---

## [10.0.0] — 2026-05-07

### Production milestone

The v9.x line was a sustained audit-then-fix cycle across every
customer-visible surface. v10.0.0 closes the cycle and declares
the project production-ready.

#### What v10.0.0 includes vs v9.0.0

The shape of the work, by section:

- **Execute (v9.35)** — rollback plan generator with ~45 inversion
  patterns, real /per-device-diff, approval notifications via
  Slack/Teams/PagerDuty, builder AI fallback, Tier-3 SSH output
  capture, rate-limit enforcement.
- **Discover (v9.36)** — /discovery-jobs Run Now real execution,
  param validation at create-time, /coverage recommendation
  reasons, sources list endpoint.
- **Compliance (v9.37)** — control mapping pack, /compliance
  matrix, control metadata, SLA tracking, exception lifecycle,
  control test records, risk register, auditor portal, evidence
  hash chain.
- **Identity write-back (v9.33-v9.34.2)** — confirm-token gate on
  apply, per-system change-diff, transactional rollback, real
  Connect form, identity vault, sync workflow, NHI lifecycle,
  daemon NHI stale-finder, daemon auto-resync, CLI parity.
- **Notifications (v9.42-v9.45)** — generalized dispatch_event
  routing, per-user prefs, customer SMTP, 11 webhook providers,
  multi-provider fan-out, dispatch_event wired into every event.
- **Activity log (v9.47-v9.57.2)** — ASGI middleware, JSONL
  store, /audit page with deep filter set (date range,
  extra_filter, contains-actor, my-actions, browser-local,
  tenant-scoped), CSV export with audit-logged downloads,
  retention via logrotate / systemd-timer / daemon hook /
  one-shot CLI, rate limit + skip-list for noise.
- **Capability-based RBAC (v9.48-v9.55.1)** — 26 capabilities, 6
  role floors, per-user grants/denies/history, dispatch_event on
  every change, OIDC group → capability auto-grant with
  idempotent reconcile, cross-tenant admin view, capability
  migration sweep covering policy/exceptions/execute-approve,
  /settings#sso editor.
- **Automation (v9.55-v9.55.1)** — daemon hook actually runs
  rules, write.automation capability gate, IR-target routing,
  commit=true opt-in, four new actions (watchlist, comment,
  pagerduty, webhook), CLI parity, demo seed.
- **AI assistant (v9.56-v9.56.1)** — SC_AI_DISABLED honored,
  capability-gated, length-capped, rate-limited, snapshot
  truncation reported to LLM, citations cross-checked against
  real IDs, audit row stores SHA-256 hash (not plaintext), HTTP
  error reasons surface body excerpt, write-intent screen
  prepends visible warning when model emits destructive CLI.

#### What's intentionally not in v10.0.0

A few items called out in the audits as real gaps but
deliberately deferred — none are customer-blocking, all have
honest workarounds:

- **PyPI publishing** — wheels in `dist/old/` and
  `auto-publish-*.sh` scripts wrap the `git tag` + `twine
  upload` pattern; flow needs re-validation before next push.
- **SAML 2.0 response validation** — v7.4 shipped metadata +
  AuthnRequest builders. Full xmlsec-based response validation
  needs a hard dep we don't want to add. OIDC works with every
  major IdP — operators with SAML-only IdPs can open an issue.
- **Activity log hash chain** — compliance/evidence has one
  (v9.27 #9). The activity log is append-only by convention but
  not cryptographically signed. Future v10.x feature.
- **`v9_pages.py` split** — 9700+ lines, single file. Architectural
  debt that would make future edits less risky but doesn't
  affect runtime behavior. Future cleanup release.
- **Comments/assignments capability migration** — still on the
  legacy `require_writer` role check (real auth, not capability).
  Workflow surface, not a security boundary breach.

#### v10.0.0 release polish

This version itself ships small, mechanical fixes flagged by the
final pre-release pass:

- **`/api/platform/attack-paths-to/{id}` and `/top-attack-paths`**
  now require `read.identity` capability. Aligns with the v9.x
  capability sweep — both endpoints expose identity-graph
  internals.
- **`/api/platform/topology*` endpoints** (4 of them) now require
  `read.asset` via a shared `_require_read_asset` Depends.
  Topology data is "view assets" so the capability already in the
  viewer floor is the right one.

#### Tests + ship

1271 tests across the suite. Final regression:
- `tests/activity` + `tests/capabilities` + `tests/notifier` +
  `tests/identity` + `tests/intel` — 430 passing.
- `tests/test_link_audit.py` — 61 passing (every sidebar page
  renders, no 404s, no JSON-on-nav-link regressions).
- `tests/policy` + `tests/cli` + `tests/test_settings.py` +
  `tests/test_audit_engine.py` — 326 passing.
- `safecadence demo` end-to-end populates 34 assets, identity
  vault, NHIs, execution jobs, rollback plans, compliance
  artifacts, capability grants, IdP groups, automation rules.

Version 10.0.0 in `__init__.py` and `pyproject.toml`. README
status section reflects production-milestone language.

---

## [9.57.2] — 2026-05-07

### Four /audit cleanup items before moving to the next section

The honest "anything else?" pass after the v9.57 + v9.57.1 work
surfaced four real issues. Closing them out before moving to the
next audit section.

#### #1 — Per-tenant scoping on `/api/activity`

Pre-v9.57.2 the endpoint accepted no tenant arg. The activity
store HAD tenant filtering since v9.47, but the HTTP route never
passed it through. In MSP-style multi-tenant deploys, an auditor
for tenant A could see tenant B's activity by hitting the
endpoint directly. Real cross-tenant data leak — same shape as
the v9.54 #1 OIDC capability gap.

v9.57.2: callers are auto-scoped to their own tenant. Admins
(`role=admin` short-circuit) can pass `tenant=*` to read across
tenants explicitly, or `tenant=acme` to scope to a specific one.
Non-admins asking for a different tenant get 403 with a clear
detail.

The synth-admin in single-user mode keeps working — local
deployments aren't affected.

#### #2 — Token-bucket rate limit on `/api/activity`

v9.56 #3 added a rate limit to /ask. /audit was the next obvious
target — a viewer-tier user with `read.activity` could hammer
the endpoint in a tight loop to exfiltrate the whole log without
tripping any alarm.

v9.57.2: token-bucket per (username, client_ip), default 60
calls / 60s. Override via `SC_AUDIT_RATE_LIMIT` and
`SC_AUDIT_RATE_WINDOW_SEC`. SIEM puller installs that legitimately
need to poll faster can raise the limit.

429 response includes a retry-after hint in the detail so a
well-behaved client backs off.

#### #3 — CSV filename reflects filter context

Pre-v9.57.2 every CSV download was named
`safecadence-activity-{stamp}.csv` — three slices on the same day
ended up indistinguishable. An auditor downloading three
different filter views had to open them to tell which was which.

v9.57.2: filename embeds the filter args:

```
safecadence-activity-20260507-143012-actor-alice-path-api_capabilities-method-POST-days-7.csv
safecadence-activity-20260507-143400-tenant-acme-range-2026-03-01..2026-03-15.csv
```

Each segment is sanitized to `[a-zA-Z0-9._-]` and capped at ~32
chars so a deep path filter like `/api/capabilities/{username}/`
doesn't blow the filename length budget. Date-range mode replaces
the `days-N` segment with `range-FROM..TO`.

#### #4 — README / DEPLOY / HOWTO refresh for v9.56–v9.57

Six releases of doc drift since the last refresh in v9.55.1:

- **README.md**: test count `1196 → 1268`. New /audit feature
  paragraph now mentions tenant scoping, rate limit, browser-local
  hover, my-actions chip, date-range, extra_filter. New AI
  assistant paragraph covers v9.56 hardening (air-gap, capability
  gate, length cap, citation cross-check, audit row) plus v9.56.1
  write-intent screen.
- **DEPLOY.md**: new section B.3d-bis covers `SC_AUDIT_RATE_LIMIT`,
  `SC_AUDIT_RATE_WINDOW_SEC`, `SC_ACTIVITY_SKIP_PREFIXES`, and the
  multi-tenant scoping contract.
- **HOWTO.md**: new section Z covers /audit's deep filter set
  (date range, extra_filter syntax, tenant=`*` admin path, CSV
  filename shape). New section AA covers /ask hardening
  (`SC_AI_DISABLED`, rate limit envs, audit row shape,
  write-intent screen).

#### Tests + ship

5 new tests in `tests/activity/test_v9_57_audit_endpoint.py`:
- Endpoint auto-scopes to caller tenant (acme can't see globex)
- Admin with `tenant=*` reads across tenants
- Non-admin with mismatched tenant → 403
- Rate limit returns 429 with retry hint
- CSV filename carries filter segments
- CSV filename uses `range-FROM..TO` when date range supplied

Test count moves from 1266 → 1271. Version 9.57.2.

That closes out the /audit deep-audit cycle cleanly.

---

## [9.57.1] — 2026-05-07

### Three /audit polish items dropped from the v9.57 punch list

The v9.57 audit found 12 things; v9.57.0 shipped 8. The remaining
three were rated low-priority but each had a real "this is what
operators actually want" shape, so closing them out.

#### #1 — Middleware-written rows now carry shape signal

Pre-v9.57.1: direct `append()` callers (capability store, /ask,
automation fires, OIDC reconcile) populated `extra` with rich
payloads. The ASGI middleware wrote `extra={}`. So /audit showed
mixed-richness data with no way to tell which kind a row was.

v9.57.1: middleware rows carry `extra.source = "http"` plus
`extra.query` (URL query string, capped at 500 chars to prevent
hostile-input log bloat) and `extra.ua` (User-Agent, capped at
200 chars). Direct-write rows still don't carry `source` so
filtering on `extra_filter=source=http` cleanly separates the
two populations.

We deliberately don't log the request body — append-only logs
are the wrong place for credentials, /ask question plaintext,
or anything else sensitive that bodies can carry. The query
string is borderline (could contain a token) but it's already
in the path/access logs, capped, and useful enough for the
trade.

#### #2 — Browser-local time on hover

Pre-v9.57.1 the When column showed ISO UTC. An auditor in PST
reading "2026-05-07T14:23:11Z" had to do mental tz math.

v9.57.1: each timestamp wraps in a `<span title="...">` whose
title is the browser-local string formatted via
`Intl.DateTimeFormat`. Hover any row → tooltip shows local time
+ timezone abbrev. A footer note (`Timestamps stored as UTC.
Hover any row to see your local time (America/Los_Angeles).`)
populates from `Intl.DateTimeFormat().resolvedOptions().timeZone`
so the operator can sanity-check.

Falls back to the raw UTC string on browsers too old for
`Intl` (graceful, no broken HTML).

#### #3 — "My actions only" toggle

Common workflow ("what did I do this week?") required typing
your own username into the Actor Contains field. v9.57.1: a
new "My actions only" chip in the Quick filter row.

On click:
1. Clears the actor box (so we don't double-filter).
2. Fetches `/api/me` — multi-user mode returns the JWT user;
   single-user mode 404s.
3. Populates Actor Contains with `me.username` or
   `local-admin` (synth-admin fallback).
4. Reloads.

Because actor matching is substring (v9.57 #4), populating with
`alice` correctly matches `alice@example.com` too — the chip
doesn't need to know the IdP-emitted form.

#### Tests + ship

Two new tests in `test_v9_57_audit_endpoint.py`:
- Middleware populates `source: "http"`, `query`, `ua`.
- Query string is capped at 500 chars (hostile-input defense).

The browser-local hover and "My actions" chip are JS-side and
manually verified — both depend on `Intl` and `/api/me`, neither
of which mocks cleanly in pytest. The link-audit test still
covers that the page renders.

Test count moves from 1264 → 1266. Version 9.57.1.

---

## [9.57.0] — 2026-05-07

### /audit deep audit + hardening

The /audit page is the most-used compliance surface — auditors and
operators hit it weekly, often daily. The deep audit before this
release found ten things, ranked by what actually matters:

#### Critical-ish (load-bearing trust)

**#1 — `read_range` cross-day pagination bug.** Pre-v9.57 the
function applied `limit` per-day, then sorted the union and sliced.
For a busy day 1 plus a quiet day 7 with `limit=500`, day 1 alone
could fill the buffer and day 2-7 records were silently dropped.
Visible to anyone running a busy tenant: "show me the last 500
events in 7 days" could miss yesterday entirely.

The fix: read each day with a per-day cap >= `limit`, then sort
+ slice once. The cost (a few extra in-memory records) is dwarfed
by the correctness win. Two regression tests lock the new
behavior down: a busy-day-vs-quiet-day scenario and a balanced
two-day distribution.

**#2 — CSV exports were unrecorded.** `format=csv` shipped the
whole log offline with no record of who pulled it. Anyone with
`READ_ACTIVITY` could dump everything. Compliance auditors will
ask "who exported this slice last March" and the answer was
"the log doesn't know."

v9.57: writes an audit row to the same log being exported,
BEFORE responding. Row's `extra` carries the filter args
(`filter_actor`, `filter_path`, `filter_days`, `filter_from_ts`,
`filter_to_ts`, `filter_extra`) plus `row_count` and
`export: "csv"`. The next /audit refresh shows the export inline
with whatever else happened that minute.

#### Medium

**#3 — Trust-note refresh.** Said retention was enforced via
`find ... -mtime +90 -delete`. Stale — v9.53 shipped logrotate +
systemd-timer examples, v9.54 added the daemon hook, v9.55.1
added `safecadence activity prune`. Now points at the right
mechanisms.

**#4 — Actor filter is now substring.** Pre-v9.57 the actor
filter was exact-match (`rec.actor != actor`) but the UI input
shape suggested substring (Path field IS substring). Typing
"alice" when the actor is "alice@example.com" returned nothing.
v9.57: substring + case-insensitive. Label updated to "Actor
contains" with `alice or @example.com` placeholder.

**#5 — Date-range filter (`from_ts` / `to_ts`).** Pre-v9.57 the
only window controls were `last_24h / 7d / 30d / 90d`. Compliance
auditors typically want "everything between March 1 and March 15."
Both `from_ts` and `to_ts` accept ISO8601; bounds are inclusive.
When supplied, they override the `days` window.

**#6 — `extra_filter` query param.** The quick chip filtered by
path. You couldn't filter by `extra.action="grant"` (vs revoke),
`extra.used_ai=true` (find /ask calls that hit the model),
`extra.commit=true` (find Tier-3 real executions). Now there's
a server-side `extra_filter` accepting `key=value` pairs
(comma- or semicolon-separated). Malformed entries are silently
skipped — a typo in one key shouldn't lose the whole filter.

**#7 — Middleware skip-list expansion.** Pre-v9.57 the only
skipped paths were `/static/` and `/api/activity` (self-loop
prevention). `/api/v9/search` was hit on every keystroke in the
command palette and blasted the log under
`SC_ACTIVITY_LOG_READS=1`. `/favicon.ico`, `/healthz`, `/readyz`,
`/livez`, `/_status`, `/api/_ping`, `/robots.txt` — all noise.
v9.57 ships a sane default skip list AND adds
`SC_ACTIVITY_SKIP_PREFIXES` (comma-separated) for operator
extension. Env values append to the default list, not override —
so an operator can ADD prefixes without losing the noise floor
we ship.

#### #8 — HTTP-level test backfill

Pre-v9.57 there were ~14 tests for the activity store + middleware
+ prune (unit-level). Zero coverage of the actual `/api/activity`
HTTP path the auditor hits in the browser, or the CSV export
flow.

`tests/activity/test_v9_57_audit_endpoint.py` adds 16 tests
covering:
- Cross-day pagination correctness (busy-vs-quiet + balanced)
- `actor_contains` substring + case-insensitivity
- `from_ts` / `to_ts` inclusive bounds
- `extra_filter` dict matching including bool coercion
- CSV export writes its own audit row with full filter args
- JSON endpoint shape
- Substring actor via query
- `extra_filter` via query (with malformed-skipped behavior)
- Capability gate blocks revoked users
- Middleware skips palette keystrokes (default skip list)
- Middleware honors `SC_ACTIVITY_SKIP_PREFIXES` env extension

#### Tests + ship

22 new tests (16 endpoint + 6 already-existing rolled-forward).
422 tests pass across activity/capabilities/notifier/identity/intel.
Test count moves from 1242 → 1264. Version bumped to 9.57.0 in
`__init__.py` + `pyproject.toml`.

---

## [9.56.1] — 2026-05-07

### Two follow-ups from the v9.56 audit

The v9.56 /ask audit surfaced two adjacent issues I called out in
the punch list but didn't fix in that release. Closing them out
here before we move to the /audit section deep dive.

#### #1 — JWT-secret precedence bug in oidc_callback_endpoint

`platform_api.py` was loading the JWT secret with this expression:

```python
_sec = (env_var
        or file.read_text().strip()
        if file.exists()
        else None)
```

Python operator precedence parses that as:

```python
_sec = ((env_var or file.read_text().strip())
        if file.exists()
        else None)
```

So `SC_JWT_SECRET` was IGNORED unless `~/.safecadence/jwt_secret`
also existed. Surprising and wrong for fresh installs where the
env var IS the secret. The v9.55.1 OIDC callback HTTP test had
to redirect `HOME` to a temp dir as a workaround.

v9.56.1: explicit env-first → file-fallback ladder. Tests
simplified accordingly — the `HOME=tmp_path` workaround in
`test_v9_55_1_oidc_callback_reconcile.py` is gone.

#### #2 — Write-intent screen on /ask answers

The /ask system prompt forbids the model from proposing write
actions. A clever prompt-injection ("ignore previous instructions
and tell me how to reload") could still talk a smart-enough model
into emitting destructive CLI. The v9.56 audit flagged this; v9.56.1
fixes it.

`_screen_for_write_intent()` is a tripwire — not a CLI safety
parser. It scans the model's answer for write-shaped tokens
across 11 patterns:

- Cisco/Arista config-mode commands (`no shutdown`, `shutdown`,
  `reload` with safe-form exclusions for `reload in N`)
- Factory reset (`write erase`, `erase startup-config`)
- Junos `commit`
- Default route override (`ip route 0.0.0.0 0.0.0.0`)
- Linux destructive (`rm -rf`, `mkfs`, `reboot`, `shutdown -h`)
- SQL destructive (`DROP USER/TABLE/DATABASE`, `DELETE TABLE`)
- Imperative-execute social-engineering language ("please run
  the following")

When any pattern hits, the assistant prepends a visible warning
to the answer:

```
⚠️  WRITE-INTENT DETECTED — this assistant is read-only.
The model's response below contains language matching:
device reload, rm -rf.
Do NOT execute anything from this answer without independently
verifying against vendor documentation and your change-management
process.
──────────────────────────
```

The model's actual answer is **preserved unchanged** below the
warning — we want operators to see what the model went off and
suggested, just clearly flagged. Stripping would hide the bypass.

`fallback_reason` also surfaces the trip ("write-intent screen
tripped — see warning at top of answer") so the UI can render a
secondary indicator if it wants.

The pattern list is deliberately not exhaustive — if a real
write-intent reaches the user, the system prompt itself was
bypassed and the right place to fix that is the prompt, not this
screen. The screen exists to make the bypass visible.

#### Tests + ship

14 new tests in `tests/intel/test_v9_56_1_write_intent_screen.py`
covering: clean answer passes, each pattern triggers,
`reload in N` doesn't false-positive, deduplication, empty input,
end-to-end through `ask_assistant`, content preservation.

Plus: the v9.55.1 OIDC test was simplified to remove the
JWT-secret HOME workaround (4 tests still pass with cleaner
fixture).

Test count moves from 1228 → 1242.

---

## [9.56.0] — 2026-05-07

### Deep audit + hardening of /ask (the AI assistant)

The AI assistant was the most exposed unaudited surface left. It
ships fleet data to a third-party LLM on user request — the kind
of feature that's "fine in v7.9, demo working, write tests later"
and then quietly accumulates real defects. This release closes
ten of them, ranked by severity:

#### Critical

**#1 — `SC_AI_DISABLED` honored.** Every other AI surface
(`builder`, `explain_finding`, `executive_briefing`) checks the
master kill switch. `ai_assistant.py` did not. An air-gapped
install with `SC_AI_DISABLED=1` set would still hit
OpenAI/Anthropic if a stale key was in env. v9.56 honors it
unconditionally — even the `ai_call` test seam is blocked, on
the principle that anything weaker would let a future PR
accidentally bypass air-gap.

**#2 — Capability gate on `/api/intel/ask`.** Pre-v9.56 the
endpoint was authenticated but capability-free. Any viewer-tier
user could dump the fleet snapshot to a third-party LLM. Now
requires `read.asset` + `read.finding` (both in the viewer floor
— backwards compatible, but tenants that revoked these per-user
now correctly block /ask).

#### High

**#3 — Question length cap + per-user rate limit.** Pre-v9.56
the endpoint accepted arbitrarily long questions. A 50KB question
plus a 6KB snapshot is non-trivial at a million calls. v9.56:
- `MAX_QUESTION_CHARS = 2000` enforced both in `ask_assistant()`
  and in the HTTP route (413 on oversize).
- Token-bucket rate limiter keyed on `(username, client_ip)`,
  default 10 calls per 60s. `SC_ASK_RATE_LIMIT` and
  `SC_ASK_RATE_WINDOW_SEC` override.

**#5 — Snapshot truncation no longer lies.** Pre-v9.56 `_ask_via_ai`
did `json.dumps(snapshot, indent=2)[:6000]` — a 200-asset fleet
got silently truncated mid-record and the LLM confidently answered
as if that was the whole fleet. Now:
- Per-entity caps in `_build_snapshot` (max_findings, max_paths,
  max_crown_jewels) with `truncated_*` and `total_*` keys the
  model can read.
- A `MAX_SNAPSHOT_CHARS` length cap is applied AFTER the entity
  caps, with an inline warning ("snapshot truncated… caveat
  answers with 'based on partial data'") so the model knows.

#### Medium

**#6 — Citations cross-checked against real IDs.**
`_extract_citations` was pure regex theatre — anything in parens
with 4+ chars came back as a citation. "(see RFC 1234)" became
id "see RFC 1234". v9.56 keeps only IDs that appear in the
snapshot's `_internal_asset_ids` / `_internal_finding_ids` sets
(stripped from the JSON before sending to the LLM, so the model
doesn't see raw ID lists outside structured records). Each cited
ID now carries `kind: "asset" | "finding"`.

**#7 — Audit row for /ask.** Activity log captured the request
but not the question or provider. v9.56 writes a row with:
- `question_sha256_16` — first 16 hex chars of SHA256 (NOT the
  plaintext — questions may contain sensitive operational
  context the operator typed in)
- `question_len`, `used_ai`, `fallback_reason`, `cited_count`

A year from now an auditor can ask "show me every /ask call alice
made in March" and the timeline is real.

**#8 — Asset-detail "Generate runbook" stops lying.** The action
called `/api/intel/ask` (a read-only Q&A endpoint whose system
prompt forbids write actions) and called the result a "runbook."
That's a write-shaped output through a read-only surface. v9.56:
- Renamed the action from "Generate runbook" to "AI operational
  notes."
- Slide-over now has a yellow warning: "Verify before executing.
  These are suggestions the model produced from your fleet
  snapshot plus its training data, not a vendor-validated
  runbook."
- Prompt explicitly asks the model to mark every command
  read-only or write, and not to issue `reload` itself.
- Surfaces `fallback_reason` to the user so they can tell when
  the deterministic path ran instead of AI.

#### Low

**#4 — `detect_provider()` test seam clarified.** The pre-v9.56
logic was `chosen=detect_provider() if ai_call is None else
AIProvider.OPENAI`, which masked the test seam behind a fake
provider assignment and silently returned `('', False)` with no
fallback_reason when no provider was detected. v9.56 honors
ai_call cleanly (returns immediately without consulting
`detect_provider()`) and surfaces a clear "no AI provider
configured (set OPENAI_API_KEY / ANTHROPIC_API_KEY /
OLLAMA_HOST)" reason when nothing's available.

**#9 — HTTP error reasons surface body excerpt + label.** Was
`AIError("openai 429")` — useless. Now:
- 429 → "openai 429 — rate limit: \<body excerpt\>"
- 401 → "anthropic 401 — auth (check API key): \<body excerpt\>"
- 503 → "openai 503 — model overloaded"
- 5xx generic → "server error"
- 4xx generic → "client error"

#### #10 — Test backfill

Pre-v9.56: 3 tests in `tests/identity/test_v7_9.py` (empty
question, NHI count, crown-jewel count). For a load-bearing
feature that ships data to a third party, that's not enough.

`tests/intel/test_v9_56_ask_assistant.py` adds 21 tests covering:
- SC_AI_DISABLED unconditional honor + truthy variants
- Question length cap (function + endpoint 413)
- ai_call test seam without provider faking
- No-provider helpful fallback reason
- Snapshot per-entity caps with truncation flags
- Internal indexes stripped from LLM payload
- Truncation warning appended
- Citation cross-check (real IDs cited, hallucinated parens
  filtered, asset vs finding kind)
- HTTP error reason labelling (429 / 401 / 503)
- HTTP-level capability gate (403 when read.asset revoked)
- HTTP-level rate limit (429 with retry-after hint)
- HTTP-level audit row written with correct shape
- HTTP-level audit row stores hash NOT plaintext

The pre-existing v7.9 citation test was updated to the v9.56
contract (used to assert `(build-bot)` came back as a citation;
now uses an asset_id that's actually in the snapshot).

#### Tests + ship

24 new tests (21 new file + 3 updated). Test count moves from
1204 → 1228. Version bumped to 9.56.0 in `__init__.py` and
`pyproject.toml`.

---

## [9.55.1] — 2026-05-07

### Honesty + cleanup pass on v9.51-v9.55

Six gaps the v9.51-v9.55 wave left behind. None of them blocked
v9.55 from shipping, but together they were quietly drifting the
docs and leaving v9.54-v9.55 features half-finished from a UX
perspective.

#### #1 — Docs refresh

README, DEPLOY.md, HOWTO.md were last refreshed in v9.50.1 — six
releases of drift covering the entire automation makeover, OIDC
capability auto-grant, cross-tenant view, activity-log retention,
and capability_changed dispatch_event.

- **README.md**: notify-categories count corrected from 7 to 8;
  test count from 1131 to 1196; CLI list extended with
  `automation`, `capabilities`, `groups`, and `activity prune`;
  three new feature paragraphs (Activity log + audit page,
  Capability-based RBAC, OIDC SSO with capability auto-grant,
  Automation engine).
- **DEPLOY.md**: new sections B.3d (activity-log retention with
  three configurations: logrotate / systemd timer / daemon hook),
  B.3e (capability_changed notifications), B.3f (OIDC SSO +
  capability auto-grant), B.3g (cross-tenant capability admin),
  B.3h (automation engine). Also fixed "27 canonical keys" → 26.
- **HOWTO.md**: new sections S–Y covering capability migration
  sweeps, CSV export of activity log, capability_changed
  notifications, activity log retention, OIDC SSO with capability
  auto-grant, cross-tenant capability admin, automation engine.

#### #2 — `/capabilities/all-tenants` UI page

v9.54 #2 shipped the API but not the UI. You could `curl` the
JSON; you couldn't see it as a screen.

The new page consumes the `/api/capabilities/all-tenants` endpoint
and renders one card per tenant with the user list, explicit
grants (green pills), and explicit denies (red pills). Stats
header reports tenant count, user count, total grants, total
denies. Server-side gate stays the same — the page just shows the
error inline if the caller doesn't have access.

#### #3 — `/settings#sso` tab for OIDC capability_map

v9.54 added the `capability_map` field on `SSOConfig`. The only
way to edit it was hand-editing `~/.safecadence/sso.json`. The
new SSO tab in /settings:

- Shows read-only summary of the SSO config (issuer, client ID,
  default role, flow). Edits still go through the JSON file by
  design — secrets shouldn't be touchable from a browser tab.
- Shows the `capability_map` as an editable two-column table
  (group claim → comma-separated capability names) with add-row
  / remove-row controls.
- Save validates every capability name against `ALL_CAPABILITIES`
  before persisting, so a typo (e.g., `read.audity`) raises 400
  instead of silently saving a no-op mapping.

Two new endpoints back the tab:
- `GET /api/settings/sso` — returns redacted config (no
  client_secret) for display.
- `POST /api/settings/sso/capability-map` — validates + persists
  the new mapping. Both gated by `admin.capabilities` or the
  synthetic admin role.

#### #4 — `safecadence activity prune` CLI

v9.53 shipped logrotate + systemd timer examples, v9.54 added the
daemon hook, but no one-shot CLI for "I want to prune *right now*
without waiting for the next 30-min cycle, and I don't have
logrotate set up yet." Now there is:

```bash
safecadence activity prune --retention 90
safecadence activity prune --retention 7 --dry-run    # preview only
```

Filename-based (parses `YYYY-MM-DD` from the stem) so logrotate's
copytruncate doesn't confuse it. Reuses the same
`safecadence.activity.prune()` function the daemon hook calls so
the behavior stays identical.

#### #5 — `capability_changed` regression test

v9.53 added the 8th `NOTIFY_CATEGORIES` key for capability
changes. The `/settings` notify-prefs matrix is auto-rendered
from the registry — but no test enforced that the row actually
shows up. A future PR that drops the entry from
`NOTIFY_CATEGORIES` would silently lose the row.

`tests/notifier/test_v9_55_1_capability_changed_visible.py`
locks it down with four checks:
- The entry exists in `NOTIFY_CATEGORIES` with all UI-required
  fields (key, label, description, defaults).
- `category_keys()` returns it (used by prefs validators).
- The `/api/notify/categories` endpoint surfaces it end-to-end.
- The description mentions "privilege" or "capability" so the
  tooltip is meaningful (catches a future PR that nukes the text).

#### #6 — HTTP test for OIDC callback → reconcile

`reconcile_sso_grants` had unit tests in
`test_v9_54_sso_caps.py`, but the actual `/api/auth/oidc/callback`
endpoint that calls it didn't have an HTTP-level test. A
refactor that dropped the reconcile call from the endpoint would
not have been caught.

`tests/capabilities/test_v9_55_1_oidc_callback_reconcile.py`
patches `safecadence.sso.oidc_callback` to skip the real OIDC
discovery + token exchange, then exercises the full HTTP path:

- **Happy path** — okta-secops user lands at /callback, response
  carries `granted: ["admin.capabilities", "read.audit"]`, and the
  YAML store actually has the grants.
- **Group revocation** — first login with okta-secops, second
  without; reconcile reports `revoked: ["admin.capabilities"]`.
- **SSO disabled** — returns 404, not 500 with a stack trace.
- **Empty capability_map** — basic SSO login still mints a JWT;
  the capability feature must not break the auth path.

The fixture had to redirect `HOME` to a temp dir so the existing
JWT-secret loader (which has a quirky precedence bug — it only
honors `SC_JWT_SECRET` if `~/.safecadence/jwt_secret` exists)
doesn't poison the developer's home directory.

#### Tests + ship

8 new tests across two files (4 notify-prefs visibility + 4 OIDC
callback HTTP). Test count moves from 1196 → 1204.

---

## [9.55.0] — 2026-05-07

### Automation actually automates now

The v7.9 automation engine had been quietly broken for months. The
audit before this release found four real defects, three missing
features, and a documentation gap that all combined into "rules
sit on disk doing nothing". v9.55 fixes the lot.

#### #1 — Daemon hook (the load-bearing fix)

Pre-v9.55, ``evaluate_rules()`` was only called from
``/api/intel/automation/preview``. That meant rules ran exactly
when a human clicked the preview button, never on the
daemon's recurring cycle. The "stickiness lever" docstring at the
top of automation.py was aspirational, not real.

``run_cycle()`` now calls ``evaluate_rules(scan_findings(assets),
apply_actions=True)`` after the v9.49 escalation hook. The fire
count lands in ``compliance_hooks["automation_fires"]`` so the
per-cycle daemon log captures impact.

Audit-only deployments can disable the hook with
``SC_AUTOMATION_DISABLED=1`` so the daemon doesn't surprise an
operator who's still figuring out what their rules will do.

#### #2 — ``notify_slack`` broken import fix

``_act_notify_slack`` imported from ``safecadence.notifiers.slack``
(plural). That module never existed — the singular
``safecadence.notifier`` package is what we actually have.
The action silently returned "slack notifier not available" on
every call.

It now routes through the v9.43 ``dispatch_event`` registry:

- Critical/high severity → ``kind="finding_critical"``, hits the
  notify-prefs matrix the same way real findings do.
- Lower severity → ``kind="automation_fired"``.
- The ``channel`` arg is preserved as an extra so per-channel
  routing rules in the webhook registry can branch on it.

This means the four other v9.44 webhook providers (Teams, Discord,
Mattermost, Rocket.Chat) all work for "notify_slack" now too, by
virtue of category routing. The action name is preserved for
backwards compat.

#### #3 — Capability gate

The endpoints in ``server/intel_api.py`` were on the legacy v7.x
``require_writer`` role check. The v9.48 capability migration
sweep missed them. ``WRITE_AUTOMATION`` already existed in
ROLE_FLOOR (analyst-tier), so the migration was clean: a new
inline ``_require_write_automation`` Depends gates POST and
DELETE on the rules endpoint.

Backwards compatible — analysts and above still get the floor
grant by default. High-trust tenants can revoke per-user via
/users#caps.

#### #4 — ``auto_fix`` honors IR targets

Pre-v9.55: hardcoded ``OktaAdapter`` and "stub.okta.local". An IR
targeting ``ad`` or ``ise`` silently dry-ran against Okta. The
result message lied — "dry-ran auto_fix on ise" was technically
the IR's intent but the actual run hit Okta.

Now the action reads ``ir.targets[0]`` and routes to the matching
adapter (``okta``, ``ise``, ``ad``, ``entra``, ``clearpass``). IR
``targets=["all"]`` falls through to okta + a fan-out note so the
rule author knows to split into per-target rules if they want true
fan-out. Unknown targets return a clear "no adapter for IR target
{x}" instead of routing to the wrong one.

#### #5 — ``commit=true`` opt-in

The action schema's documented ``commit=true`` opt-in (in the
docstring at the top of automation.py) wasn't actually wired —
``_act_auto_fix`` always passed ``dry_run=True`` regardless. So
"automation never auto-commits" was correct but "rule author can
opt in" was aspirational.

Now ``_do_action`` passes the action dict to ``_act_auto_fix``,
which checks ``action.get("commit")``. Default stays False so a
rule typed in /automation can't accidentally mutate a real IdP.

#### #6 — Four new actions

The v7.9 action library was thin: ``auto_fix``, ``assign``,
``notify_log``, ``notify_slack``. Customers writing real rules
hit the wall fast. v9.55 adds:

- ``add_to_watchlist`` — pin the finding to a watchlist
  (idempotent, reuses v7.9 watchlists module)
- ``add_comment`` — drop a comment on the finding so the team
  workflow surface carries the automation's rationale
- ``notify_pagerduty`` — fire a PD event with deterministic
  ``dedup_key`` ``safecadence:automation:{finding_id}``
- ``notify_webhook`` — generic fan-out via the v9.44 multi-
  provider webhook registry; rule author specifies category +
  optional ``webhook_id``

#### #7 — CLI parity

Every other v9.x admin surface had a CLI command group. Automation
didn't. New ``safecadence automation`` group ships with:

- ``list`` — show every rule, enabled flag, last fired
- ``create --name X --when-kind Y --then-action Z [--then-arg k=v...]``
- ``delete RULE_ID``
- ``preview`` — show what would fire, side-effect-free
- ``fires --limit N`` — recent rule-fire history

#### #8 — Demo seed + new ``/api/intel/automation/fires`` endpoint

``safecadence demo`` now seeds three example automation rules
covering the most common patterns (notify-on-critical, assign-and-
watch on stale NHIs, dry-run auto_fix on no_mfa). All three are
created **disabled** so a fresh demo box doesn't surprise the
operator. New ``GET /api/intel/automation/fires?limit=N`` endpoint
exposes recent fire history alongside the live rules list.

#### Tests + ship

16 new tests in ``tests/identity/test_v9_55_automation.py`` cover:

- daemon hook fires + the SC_AUTOMATION_DISABLED escape hatch
- notify_slack severity-based kind routing
- auto_fix dry-run/commit behavior + IR target routing + invalid IR
- four new actions (watchlist idempotency, comment, pagerduty
  dedup_key, webhook with category override)
- unknown action graceful failure
- demo seed creates three disabled rules + idempotency check

Test count moves from 1180 → 1196.

---

## [9.54.0] — 2026-05-07

### SSO group-claim → capability auto-grant + cross-tenant view + daemon retention

Three real-world capabilities follow-ups. v9.48-v9.53 built the
capability layer and the per-user grant/revoke surfaces; v9.54
makes the layer scale to (a) IdP-driven privilege management,
(b) MSP-style multi-tenant deployments, and (c) pip-install
boxes that don't have logrotate.

#### #1 — OIDC group-claim → capability auto-grant

Manually granting capabilities through the /users page is fine
for a 5-person SOC. For a real customer with 50+ users behind
Okta or Entra, "give the secops team admin.capabilities" becomes
an SSO concern, not a SafeCadence concern.

The new ``capability_map`` field on ``SSOConfig`` (persisted in
``~/.safecadence/sso.json``) maps IdP group-claim values to
capability lists:

```json
{
  "capability_map": {
    "okta-secops":     ["read.audit", "admin.capabilities"],
    "okta-platform":   ["execute.real", "approve.job"],
    "okta-readonly":   []
  }
}
```

On every successful OIDC login, ``oidc_callback()`` enumerates
the user's groups (``groups`` / ``roles`` / ``memberOf`` claims —
flattened by the existing ``_flatten_group_claims`` helper) and
returns the union of matching capability lists in the result
dict's ``capabilities`` key.

The OIDC callback endpoint then calls a new
``reconcile_sso_grants()`` in the capability store. The reconcile
is the load-bearing safety property:

- Capabilities the user *should* have but doesn't yet → granted.
- Capabilities tracked as SSO-managed but no longer in the
  computed set → revoked (the user left the matching group).
- Capabilities granted by other paths (CLI, /users UI) →
  **untouched**. The store tracks the SSO-managed set in a
  separate field (``sso_managed``) on the user record so manual
  grants stay outside the reconcile loop.

This matters because the alternative — "every login mirrors the
groups verbatim" — would silently revoke the temporary admin
capability the on-call lead got via CLI five minutes earlier.
The split-tracking design preserves that.

Each grant/revoke fires the v9.53 ``capability_changed``
dispatch_event, so security-team Slack/Teams hears about
SSO-driven privilege changes in real time alongside manual ones.

Misconfiguration fails loudly: ``reconcile_sso_grants`` raises
``ValueError`` on unknown capability names, so a typo in
``capability_map`` shows up immediately instead of silently
granting nothing.

#### #2 — Cross-tenant capability admin view

MSPs and multi-customer deployments hit the same problem from
the other side: "who has admin.capabilities anywhere on this
install?" used to require N round trips, one per tenant.

New endpoint ``/api/capabilities/all-tenants`` returns the full
set of grants across every tenant in one response, grouped by
tenant. Two new helpers in the store —
``list_tenants()`` and ``list_all_grants()`` — power it.

The gate is admin.capabilities on **at least one** tenant, OR
``role=admin`` (the synth-admin in single-user mode). MSP
operators with one customer can see grants for that customer
plus visibility into the cross-tenant audit trail.

The response carries the same metadata bundle (
``all_capabilities``, ``descriptions``, ``role_floor``) the
single-tenant matrix returns, so a future ``/capabilities/
all-tenants`` UI page won't need a second round trip to render.
History is capped at 10 entries per user to keep payloads sane
on 200-tenant installs.

#### #3 — Daemon-driven activity log retention

v9.53 shipped logrotate + systemd-timer examples for activity
retention. Both are great in production. Neither helps the
``pip install safecadence-netrisk && safecadence daemon`` case,
which is a meaningful slice of real users.

A new ``prune()`` function in ``safecadence.activity`` deletes
JSONL files older than N days (default 90). It pulls the date
from the filename — ``YYYY-MM-DD.jsonl`` — so logrotate's
copytruncate touching mtime doesn't confuse it. Non-date-named
files in the activity dir (a stray README, etc.) are left alone.

The daemon's ``run_cycle()`` calls it after the v9.49 approval
escalation. Retention is configured via
``SC_ACTIVITY_RETENTION_DAYS=N``. Set to 0 to disable (the
preferred path when logrotate or the systemd timer is already
configured — this is a safety net, not the canonical mechanism).

Returns a summary the daemon's per-cycle log captures:

```json
{"retention_days": 90, "deleted": 3, "kept": 60,
 "freed_bytes": 1234567, "errors": []}
```

Per-file failures (read-only mount, permissions) are caught
inside the loop so one bad file doesn't abort the prune; the
errors list shows the offenders.

#### Tests + ship

29 new tests across three files:
- ``tests/capabilities/test_v9_54_sso_caps.py`` — 14 tests
  covering ``resolve_capabilities`` (group flatten, dedup,
  no-match, comma-string, memberOf) + ``reconcile_sso_grants``
  (grant new, revoke removed, manual untouched, swap, unknown,
  dispatch fire, idempotent).
- ``tests/capabilities/test_v9_54_cross_tenant.py`` — 7 tests
  covering ``list_tenants`` / ``list_all_grants`` + the HTTP
  endpoint (synth admin pass, metadata, empty store, history
  truncation).
- ``tests/activity/test_v9_54_prune.py`` — 8 tests covering
  empty dir, recent kept, old deleted, non-date ignored,
  retention arg, freed_bytes, daemon-hook positive, daemon-hook
  zero.

Test count moves from 1151 → 1180.

---

## [9.53.0] — 2026-05-07

### Capability gates everywhere + activity-log CSV + privilege-change notifications

Five real follow-ups from the v9.52 review. The shape of v9.48's
capability layer hasn't changed — but the surfaces around it now
fit the rest of the platform.

#### #1 — `GET /api/capabilities/{username}` is now gated

v9.48 protected POST /grant /revoke /clear-deny but left the GET
unprotected. Anyone with a session could enumerate every user's
grants (an info-disclosure bug — useful reconnaissance for an
internal attacker).

The new gate is:

- **Self-read** — caller looking at their own grants always
  succeeds. Doesn't burn a capability and matches user intuition.
- **Other-user read** — requires `READ_AUDIT` *or*
  `MANAGE_CAPABILITIES`. SOC reviewers + admins see everything.
- **Anyone else** → 403 with the standard `Missing capability`
  detail.

Single-user mode short-circuits via the synthetic admin
(`local-admin` role list `["admin"]`) so local UI workflows don't
break.

The implementation lives in `_caps_self_or_admin_check()` and runs
inline at the top of the route. We deliberately don't reuse
`_require_caps()` because the self-read case has different logic.

There's a subtle PEP 563 footgun here that took two iterations to
fix: `from __future__ import annotations` defers all annotations
to strings, and FastAPI's `get_type_hints()` evaluates them in the
function's `__globals__`. Importing `Request` inside `register()`
made it a *local* — invisible to FastAPI — and the framework
silently fell back to treating `request` as a query parameter
(hence 422 errors in tests). Pinned the import at module scope.

#### #2 — `/api/activity?format=csv` for the auditor's offline workflow

The activity log was JSON-only. Auditors live in spreadsheets, so
the GUI button + CSV endpoint were both missing.

The new endpoint streams a CSV with the same gate as JSON
(`READ_ACTIVITY`) — CSV does not expose anything the JSON path
didn't, so the security boundary is unchanged.

```
GET /api/activity?days=30&format=csv
Content-Type: text/csv
Content-Disposition: attachment; filename="safecadence-activity-20260507-194523.csv"
```

Columns: `ts, actor, tenant, method, path, status, ip,
duration_ms, request_id, extra` (extra is JSON-encoded so each row
stays one line).

The /audit page got a "Download CSV" button next to the existing
filter controls. Click → browser saves the file. Auditor opens in
Excel / Google Sheets / their tool of choice. No new API surface
to learn.

#### #3 — Capability migration wave 2

v9.50 migrated Tier-3 EXECUTE_REAL to capability checks but left a
half-dozen routes still on the legacy admin role check. Wave 2
covers everything that mutates policy or approves jobs:

- `POST /api/policy/` → `WRITE_POLICY`
- `PUT /api/policy/{id}` → `WRITE_POLICY`
- `DELETE /api/policy/{id}` → `WRITE_POLICY`
- `POST /api/policy/exceptions` → `WRITE_EXCEPTION`
- `POST /api/execute/jobs/{id}/approve` → `APPROVE_JOB`

Now five routes that used to require role=admin can be granted
to a specific user via `safecadence capabilities grant`. The
admin role still gets them through the role floor — backward
compatible for existing deployments.

#### #4 — `capability_changed` notification kind

Granting `EXECUTE_REAL` or `MANAGE_CAPABILITIES` is a
privilege-escalation event. The activity log already recorded it,
but `dispatch_event` wasn't firing — meaning Slack / Teams /
PagerDuty channels didn't hear about it in real time.

Every `grant()` / `revoke()` / `clear_deny()` now emits a
`capability_changed` event in addition to the activity row. The
new event:

- `kind="capability_changed"`
- `severity="high"` for `EXECUTE_REAL`, `MANAGE_USERS`,
  `MANAGE_CAPABILITIES`, `MANAGE_WEBHOOKS`, `MANAGE_SETTINGS`,
  `IDENTITY_APPLY_COMMIT` — anything that grants real-world
  power. `severity="info"` otherwise.
- `extra.action` carries the short verb (`grant` / `revoke` /
  `clear_deny`) so consumers can branch without parsing the title.
- `link="/audit?path=/api/capabilities/"` deep-links to the
  matching audit rows.

This is `NOTIFY_CATEGORIES`'s 8th key. The /settings notify-prefs
matrix grew a row automatically — no schema change needed because
the registry is the source of truth.

The dispatch fires from `_emit_activity` in
`safecadence/capabilities/store.py`. It's wrapped in
try/except so notifier failures can never break a capability
change — auditing > alerting in this layer.

#### #5 — Activity-log retention examples (logrotate + systemd)

The activity directory grows linearly forever (one JSONL file per
day). v9.47 documented "rotate this with logrotate" but didn't
ship a config. Now there are three example files in
`docs/examples/`:

- `safecadence-activity.logrotate` — 90-day daily rotation,
  copytruncate + compress + missingok. Drop into
  `/etc/logrotate.d/`.
- `safecadence-activity-prune.service` — systemd alternative for
  containers / minimal distros where logrotate isn't available.
  `find ... -mtime +90 -delete`.
- `safecadence-activity-prune.timer` — daily 03:30 UTC trigger
  with `Persistent=true`.

`docs/DEPLOY.md` now references all three from the activity-log
section.

#### Tests + ship

`tests/capabilities/test_v9_53.py` is new — 9 tests covering:

- Self-read passes without any capability (2 tests)
- CSV export returns correct content-type + headers + rows
- Default format is JSON (`format=csv` is opt-in)
- `grant()` fires `dispatch_event(kind="capability_changed")`
- `revoke()` fires the same with `extra.action="revoke"`
- High-value capabilities get `severity="high"`
- Low-value capabilities get `severity="info"`
- `capability_changed` is enumerable in `NOTIFY_CATEGORIES`

Test count moves from 1142 → 1151.

---

## [9.52.1] — 2026-05-07

### Cleanup pass — five honest gaps from the v9.52 review

#### #1 — CHANGELOG capability count fix

v9.48 entry said "27 capability constants". Real count from
`ALL_CAPABILITIES` is 26. One-character fix.

#### #2 — Tests for `groups_probe`

v9.51 added `groups_probe` to all 5 adapters' `test_connection()`
returns but no test asserted the field's presence. New
`tests/identity/test_v9_52_1_groups_probe.py` (7 tests) pins the
shape: probe-present-when-tested, count when probe succeeds, reason
when probe fails, AD's early-return when ldap3 absent.

#### #3 — Integration smoke for `/capabilities` matrix

v9.50.1's existing test verified the page rendered HTML; this one
exercises the full data flow. Seeds users + grants + denies, fetches
`/api/capabilities`, asserts every field the matrix script reads
(all_capabilities, descriptions, role_floor, grants) is present and
that descriptions cover every capability key (4 tests).

#### #4 — `groups_probe` surfaced in /identity Connect form

The probe was on the wire but invisible. The Connect-form result
panel now renders inline:

- **`Groups: 14 found`** with a link to `/idp-groups` when the probe
  succeeds.
- **`Groups: 403 — missing scope`** with an amber explanation
  ("auth + sync still works, but `@group:NAME` invitee expansion will
  resolve to nothing for this system") when the probe fails.

Operator sees at connect time whether the IdP-groups cache will
populate, instead of discovering days later.

#### #5 — Honesty comment on demo seed

`_seed_idp_groups_demo` docstring now explicitly says the
`eng-leads` / `secops` / `auditors` rows are SYNTHETIC fixtures —
no real Okta or AD tenant is connected. They're there so
`/idp-groups` and `@group:NAME` invitee expansion can be exercised
on a fresh demo box without wiring real credentials.

#### Tests + ship

Combined v9.52.1 adds 11 new tests (7 groups_probe + 4 caps matrix).
Test count moves from 1131 → 1142.

---

## [9.52.0] — 2026-05-07

### Group probe at connect time + capability migration sweep

Combined v9.51 + v9.52 since both are scoped tightly.

#### v9.51 — `test_connection()` probes `list_groups()`

Each identity adapter's `test_connection()` now also runs the v9.50
`list_groups()` capability and surfaces the result in the response
under `groups_probe`:

```json
{
  "ok": true,
  "groups_probe": {"count": 14, "ok": true}
}
```

Or on failure:

```json
{
  "ok": true,
  "groups_probe": {"count": 0, "ok": false,
                   "reason": "HTTPError: 403 — service account
                              missing group-read scope"}
}
```

Operators see at connect time whether the IdP-groups cache will
populate, instead of discovering days later that `@group:NAME`
expansion silently resolves to nothing. The probe is best-effort
— it never raises, never blocks the connect-test verdict, and
always returns a structured dict.

Wired into all five adapters: Okta, Entra, AD, ISE, ClearPass.

#### v9.52 — Capability migration sweep

The v9.49.1 cleanup migrated `/api/users`, `/api/webhooks`, and
`/api/capabilities/*` from `"admin role"` raw checks. v9.52
finishes the sweep on the remaining write endpoints in
`server/platform_api.py`:

- `POST /api/settings/email` → `Capability.MANAGE_SETTINGS`
- `POST /api/settings/email/test` → `Capability.MANAGE_SETTINGS`
- `POST /api/settings/notify-defaults` → `Capability.MANAGE_SETTINGS`
- `GET /api/users/{username}/notify-prefs` → `MANAGE_USERS` (or
  caller is the user themselves)
- `POST /api/users/{username}/notify-prefs` → `MANAGE_USERS`

Every gated route still inherits `Depends(get_current_user)` for
auth; the capability check runs after the bearer-token decode.
Admin role short-circuits up — admins keep working unchanged.
Non-admins with explicit grants now have the right surfaces
they were granted access to.

#### Trust posture preserved

- All migrated routes preserve the existing 403 status; the only
  change is the detail message now names the missing capability.
- The "self vs. other user" distinction in `/api/users/{user}/
  notify-prefs` is preserved — caller can always view/edit their
  own prefs without `MANAGE_USERS`. Only viewing or editing
  ANOTHER user's prefs needs the capability.

---

## [9.50.1] — 2026-05-07

### Cleanup pass — six gaps from the v9.50 punch list

#### #1 — Audit dedup on capability changes

v9.48's store-side emitter and v9.47's middleware were both
logging capability grant/revoke events. Two rows per change —
forensically misleading. Added a `mark_http_in_flight()`
contextvar that the HTTP route handlers set before calling
`grant`/`revoke`/`clear_deny`. The store-side `_emit_activity`
helper checks the flag and skips its synthetic write when the
middleware is already in flight. CLI / direct-Python paths still
emit (the middleware never sees them), so audit coverage stays
complete.

#### #2 — DEPLOY.md + HOWTO.md catch up to v9.47–v9.50

Added env vars for activity log (`SC_ACTIVITY_LOG_READS`,
`SC_ACTIVITY_DISABLED`) and PagerDuty escalation
(`SC_APPROVAL_ESCALATION_*`). New B.3b section walks through
capability-based RBAC including the Tier-3 dual-gate caveat.
New B.3c section documents the IdP-groups CLI + which
adapters return real members vs empty.

HOWTO gained sections O (activity log + jq examples), P
(capability RBAC + Tier-3 dual-gate), Q (IdP groups), R
(PagerDuty escalation).

#### #3 — Demo seeds for capabilities + IdP groups

`safecadence demo` now also seeds:

- 4 example capability grants (alice gets `manage.capabilities` +
  `manage.webhooks`; bob gets `execute.rollback` + `grant_jit`)
- 1 example explicit deny (carol denied `execute.real`)
- 3 example IdP groups (eng-leads, secops via Okta; auditors via
  AD)

So `/users#caps`, `/idp-groups`, and the new `/capabilities`
matrix all show real rows on first visit instead of empty
states.

#### #4 — `safecadence capabilities list-types`

New CLI subcommand prints all 26 canonical capability keys with
descriptions and the role-floor mapping. Operators no longer have
to grep source code to find the right key for `grant`.

#### #5 — `/capabilities` org-wide grant matrix

New page (sidebar entry under Settings, key icon) renders a
read-only matrix:

- Rows: every user (from directory + anyone with grants).
- Columns: all 26 capabilities (rotated headers, hover tooltip
  shows the description).
- Cells: `G` (explicit grant), `R` (via role floor), `D` (explicit
  deny), `—` (not granted).

Reuses the existing `/api/capabilities` endpoint. Edits still
happen via `/users#caps` (linked from each row); this page is the
"everyone, at a glance" view.

#### #6 — `auDetail()` noise filter on /audit

The Detail column on `/audit` was rendering noise keys like
`request_id`, `duration_ms`, `ip`, `tenant`, `status` that
already have their own columns. Filtered them out so the column
shows only meaningful fields.

#### Tests + ship

7 new tests in `tests/capabilities/test_v9_50_1_cleanup.py`:
- CLI grant emits the synthetic row (direct path)
- HTTP grant skips the synthetic row (middleware path)
- Demo seeds populate capabilities (≥4 grants)
- Demo seeds populate IdP groups (≥3 groups)
- `capabilities list-types` lists at least 25 keys
- `/capabilities` page renders with `cmLoad` wiring
- `/api/capabilities` returns the expected shape

Link-audit grew from 59 → 60 (added `/capabilities`).

---

## [9.50.0] — 2026-05-07

### Real adapter list_groups + /idp-groups page + Tier-3 capability migration

The v9.49 IdP-group cache was real but every call was returning `[]`
because none of the five identity adapters actually implemented
`list_groups()`. v9.50 closes that gap, adds the admin surface to
manage the cache, and migrates Tier-3 SSH execution from the legacy
role-only gate to a dual-system check.

#### #1 — `list_groups()` in five identity adapters

- **OktaAdapter**: GET `/api/v1/groups` then per-group
  `/groups/{id}/users`. Members returned as Okta `login` (e.g.
  `alice@acme.com`).
- **EntraIDAdapter**: Microsoft Graph `/v1.0/groups` then
  `/groups/{id}/members`. Members returned as `userPrincipalName`
  so they match what Entra emits in JWT `preferred_username`.
- **ActiveDirectoryAdapter**: LDAP search for `(objectClass=group)`
  with paged results. Member DNs resolved to `sAMAccountName`
  (capped at 200/group to keep daemon refresh fast).
- **CiscoISEAdapter** + **HPEClearPassAdapter**: enumerate group
  list; `members: []` because both vendors only expose membership
  via per-user iteration. Documented in adapter docstring; the
  v9.49 consumer in `identity/groups.py` already degrades
  gracefully when members is empty.

Every adapter returns `[]` when credentials are missing or the
underlying call fails — never raises, so the daemon refresh never
aborts.

#### #2 — Capability-changes filter chip on /audit

The v9.47 activity log surface gains a "Capability changes only"
quick-filter chip + a Detail column that pretty-prints the `extra`
dict. Capability grant/revoke rows now show `grant execute.real —
incident-42` inline instead of forcing the auditor to dig into the
JSONL file. Generic rows render the first three keys of `extra`
compactly.

#### #3 — /idp-groups admin page + CLI

New page at `/idp-groups` (sidebar entry under Audit) renders the
cached snapshot:

- One row per group with system, name, member count, sample
  members (first 3 + "+N more"), last sync time, and a stale
  badge for groups not refreshed in 24 h.
- "Force refresh now" button → `POST /api/idp-groups/refresh`
  iterates connected IdPs, runs `list_groups()` on each, returns a
  per-system summary.
- Read endpoint requires `READ_IDENTITY`; refresh requires
  `MANAGE_IDENTITY_VAULT`. Single-user installs short-circuit
  through the synthetic-admin caller helper.

CLI parity:
```
safecadence groups list [--system <name>]
safecadence groups show <name-or-id>
safecadence groups refresh
```

The asset-groups page keeps its existing path `/groups`; the
IdP-groups page lives at `/idp-groups` to avoid collision.

#### #4 — Tier-3 dual-system gate

The v9.48 punch list noted that `Capability.EXECUTE_REAL` from the
legacy `execution/rbac.py` and the same-named constant in the new
`safecadence/capabilities/` were independent code paths. v9.50
makes Tier-3 require BOTH:

1. Legacy: `execution.rbac.can(role, EXECUTE_REAL)` — the existing
   "even Super Admin doesn't get this without explicit
   role config" gate stays in place.
2. New: `capabilities.has_explicit_grant(username,
   Capability.EXECUTE_REAL)` — and this is `has_explicit_grant`,
   NOT `has_capability`. The admin-role short-circuit is
   intentionally bypassed for this surface; admins still need
   `safecadence capabilities grant <user> execute.real` per-user.

The dual check fails closed. Existing legacy callers that don't
pass a username keep working (the v9.48 check is skipped when
`username=""`).

New helper `safecadence.capabilities.has_explicit_grant()` —
returns True only if the capability is in the user's explicit
`grant` list AND not in their `deny` list. Bypasses the admin
short-circuit. Use this for highly destructive surfaces where
"even admins don't get this without an explicit, audit-logged
grant" is the rule.

#### #5 — 23 new tests

- `tests/identity/test_v9_50_list_groups.py` (10) — empty when
  no creds (×5), real shape with mocked transport for Okta and
  Entra, http-failure handling for Okta, ISE/ClearPass groups
  with empty members.
- `tests/identity/test_v9_50_idp_groups_page.py` (6) — page
  renders, /api/idp-groups empty + seeded, CLI list/show/abort.
- `tests/capabilities/test_v9_50_explicit_grant.py` (7) — admin
  short-circuit doesn't apply, grant returns true, deny blocks,
  unknown capability false, Tier-3 blocks without explicit grant,
  Tier-3 passes with grant, Tier-3 legacy callers skip the v9.48
  check.

Link-audit grew from 58 → 59 (added `/idp-groups` entry).

#### Trust posture preserved

- The /idp-groups refresh button calls each adapter's
  `list_groups()` synchronously. Per-system isolation (each
  adapter is in its own try/except) means a slow Okta call
  doesn't block AD's refresh.
- Tier-3 is now strictly OPT-IN per-user even for admins. This
  is the correct posture for "rm -rf as a service" — the admin
  role is the org's highest authority, not its standing
  authorization.
- ISE and ClearPass groups appear in the cache (and on
  /idp-groups) WITHOUT membership data. The trust note on the
  page tells the operator to use AD or Okta for human approver
  groups.

---

## [9.49.1] — 2026-05-07

### Cleanup pass — wire the v9.48 capability gates that were sketched but unenforced

v9.48 shipped the capability infrastructure (constants, store, decorator,
UI). v9.49 stacked Phase B/C on top. But several routes still relied on
raw `if "admin" not in user.roles` checks or had no gate at all. This
release closes those gaps.

#### #1 — `/api/activity` is now capability-gated

The activity log endpoint required no capability — anyone with a session
could read it. Now requires `Capability.READ_ACTIVITY`. Single-user UI
mode short-circuits via the synthetic-admin fallback in
`safecadence.ui._caller`; multi-user JWT installs check the real user.

#### #2 — Caller resolution helper

New `safecadence.ui._caller.caller_user(request)` — resolves a user
object usable by `has_capability()` from JWT bearer token, then
`request.state.user`, finally a synthetic admin (single-user mode where
the password cookie has already authenticated). Always returns
something; never raises 401 (that's the auth middleware's job). Lets the
same `register()` mount on both `ui/app.py` (single-user) and
`server/app.py` (multi-user) without duplicating gate logic.

#### #3 — Write endpoints migrated from "admin role" to capabilities

In `server/platform_api.py`:
- `POST /api/users` and `DELETE /api/users/{username}` →
  `Capability.MANAGE_USERS`.
- `POST /api/webhooks`, `DELETE /api/webhooks/{id}`, and
  `POST /api/webhooks/{id}/test` → `Capability.MANAGE_WEBHOOKS`.

In `ui/v9_pages.py`:
- `POST /api/capabilities/{user}/grant`, `/revoke`, `/clear-deny` →
  `Capability.MANAGE_CAPABILITIES`. The `actor` field is now derived
  from the resolved caller (not the request body) so audit-trail
  attribution is trustworthy.

The admin role short-circuits up — admins keep working unchanged.
Non-admins with explicit capability grants now have a real route to
managing the surface they were granted access to.

#### #4 — Honest test count + 7 new tests

- README updated: 1051 → 1091 (counted via `pytest --collect-only`).
- `test_link_audit.py` count corrected: 56 → 58 entries.
- `tests/capabilities/test_v9_49_1_gates.py` (7 tests): activity
  endpoint passes in single-user mode, capability grant/revoke
  round-trip via HTTP, unknown capability returns 400, caller helper
  returns synthetic admin without JWT, decodes real JWT when present,
  and falls back gracefully on tampered tokens.

#### Trust posture preserved

- The synthetic-admin fallback isn't a security bypass — the local-UI
  password cookie still gates the entire app at the middleware layer
  before any route is hit. Once you're past the password gate in
  single-user mode, you ARE the admin. Capabilities matter in
  multi-user installs where multiple JWT users share the same
  deployment.
- Actor attribution is now caller-derived. The body's `actor` field is
  honored only as an override; if absent, we use the resolved
  username from the JWT/caller helper. Either way, the audit log row
  reflects who actually made the change, not who claimed to.

---

## [9.49.0] — 2026-05-07

### Phase B + Phase C — IdP-sourced approver groups + PagerDuty escalation

The two follow-on items the v9.42–v9.48 plan parked: approval flows
that scale past hard-coded usernames, and a no-one-noticed-this
backstop for stale CRITICAL approvals.

#### Phase B — IdP-sourced approver groups

New module `safecadence.identity.groups` with a JSON cache at
`$SC_DATA_DIR/identity/groups.json`. The daemon refreshes the cache
once per cycle from each connected IdP (Okta, Entra, AD, ISE,
ClearPass) by calling each adapter's `list_groups()` capability.

The notification registry's `dispatch_event` now expands any
`@group:NAME` entry in the `invitees` list against the cached
snapshot before fan-out:

```python
dispatch_event(
    kind="approval_requested",
    title="Approve config push", summary="...",
    invitees=["@group:eng-leads", "alice"],   # <-- group expansion
)
# resolves to ["bob", "carol", "dan", "alice"] at dispatch time
```

Resolution is best-effort: an unknown group degrades into "no DM
goes out" rather than breaking the approval flow. Groups not
refreshed in 24 h are flagged `stale` so the UI can warn approvers
the resolution might be out of date.

Cross-system collision rule: when the same group name exists in
multiple IdPs, the most-recently-synced one wins. Plain usernames
in the invitee list pass through unchanged; duplicates are
de-duped while preserving first-seen order.

#### Phase C — PagerDuty escalation on stale CRITICAL approvals

New module `safecadence.execution.escalation` with a daemon hook
that walks CRITICAL execution jobs sitting in `review` longer than
`SC_APPROVAL_ESCALATION_MINUTES` (default 30) and fires a single
PagerDuty event per never-yet-escalated job.

```bash
# Configuration (all opt-in — disabled when PD key absent)
SC_APPROVAL_ESCALATION_PD_KEY=<integration-key>
SC_APPROVAL_ESCALATION_PD_URL=https://events.pagerduty.com/v2/enqueue
SC_APPROVAL_ESCALATION_MINUTES=30      # 0 disables
```

The PagerDuty `dedup_key` is deterministic
(`safecadence:approval:{job_id}`) so PD de-dupes server-side too if
the daemon re-fires through a transient state-file loss. Each fire
is recorded in `$SC_DATA_DIR/execution/escalation_state.json` so a
restarted daemon doesn't re-page jobs it already escalated.

**Idempotency rule**: a job_id seen in the state file's `fires`
list never fires again, even if PD reports failure. Re-firing on a
transient HTTP error would be *more* alarming to the on-call human
than missing the alert (two pages for the same job is the worst
outcome). Operators wanting a retry can clear the state file entry
manually.

The escalation also dispatches an `approval_requested` event with
`severity=critical` through the standard registry, so the org's
other channels (Slack, email DM, configured webhooks) hear about
it through their existing routing.

#### Trust posture

- **Group cache is read-only at dispatch time.** The fan-out path
  never blocks on a network round trip — if the cache is empty,
  `@group:NAME` resolves to nothing and a plain user list is the
  only thing that gets DM'd.
- **PagerDuty is opt-in.** Phase C does nothing without
  `SC_APPROVAL_ESCALATION_PD_KEY` set. There's no global default
  PD endpoint baked into the code.
- **Stdlib HTTP only.** The PD POST uses `urllib.request` so
  air-gapped installs that haven't installed `httpx` still work
  when escalation is configured.
- **Per-system isolation.** A slow Okta `list_groups()` doesn't
  block AD's refresh on the same cycle — each adapter is wrapped
  in its own try/except.

#### 16 new tests

- `tests/identity/test_v9_49_groups.py` (8) — upsert/list,
  by-name-then-id lookup, `members_of` empty for unknown,
  `resolve_invitees` expansion + dedup + unknown-group-silent,
  `stale_groups` flagging, and end-to-end `dispatch_event`
  expansion test.
- `tests/identity/test_v9_49_escalation.py` (8) — disabled when
  no PD key, disabled when threshold=0, default threshold,
  invalid threshold falls back, deterministic dedup_key,
  idempotent already-fired, `run_cycle` fires only new jobs,
  failure still records fire (anti-retry rule).

---

## [9.48.0] — 2026-05-07

### Capability-based RBAC — fine-grained permissions on top of role floor

Roles answered "what kind of user are you" (admin / analyst /
viewer). v9.48 adds capabilities — fine-grained permissions an
admin can hand out individually without promoting someone to a
higher role. Every grant/revoke is logged through the v9.47
activity log, so /audit shows the full provenance chain.

#### #1 — `safecadence.capabilities` module

26 capability constants split into six groups: read paths, write
paths, approval/execute, identity write-back, admin. Examples:
`Capability.READ_ASSET`, `Capability.WRITE_POLICY`,
`Capability.EXECUTE_REAL`, `Capability.GRANT_JIT`,
`Capability.MANAGE_USERS`, `Capability.MANAGE_WEBHOOKS`.

A YAML-backed store at `$SC_DATA_DIR/capabilities.yaml` holds
per-user `grant` and `deny` lists plus a `history` array recording
every change (ts, actor, action, capability, reason).

Three-layer resolution:
1. Per-user explicit deny → never granted, regardless of role.
2. Per-user explicit grant → always granted.
3. Role floor union of every role the user holds.

The `admin` role short-circuits to the full set (the role IS the
authority floor). The `viewer/analyst/approver/operator` floors
are hard-coded in `constants.py:ROLE_FLOOR` so a misconfigured
YAML can never silently strip a viewer of `READ_ASSET`.

#### #2 — `require_capability` FastAPI dependency

```python
from safecadence.capabilities import require_capability, Capability

@app.post("/api/users")
def create_user(
    body: dict,
    user: CurrentUser = Depends(
        require_capability(Capability.MANAGE_USERS)),
):
    ...
```

Returns 403 with the missing capability name when the resolved
user can't pass the check. The detail message tells the operator
exactly which capability they need so an admin can grant it.

#### #3 — REST endpoints + CLI parity

`/api/capabilities` — list every grant in the tenant, plus the
canonical capability descriptions and role floor.
`/api/capabilities/{username}` — per-user effective set, grants,
denies, and last 50 history entries.
`/api/capabilities/{username}/grant`, `/revoke`, `/clear-deny` —
mutations.

Matching CLI:
```bash
safecadence capabilities list
safecadence capabilities show alice
safecadence capabilities grant alice execute.real --reason oncall
safecadence capabilities revoke alice execute.real --reason rotation-ended
safecadence capabilities clear-deny alice execute.real
```

Every command takes `--actor` for audit-trail attribution and
`--reason` for free-text justification (logged).

#### #4 — UI: per-user "Caps" slide-over on /users

Each user row on `/users` now has a "Caps" button that opens a
slide-over showing the full capability matrix:

- Each capability has a state badge (`granted`, `via role`,
  `denied`, or `—`) and a one-click button to grant / revoke /
  clear-deny.
- The slide-over also surfaces the most recent 50 history entries
  per user (when, by whom, what action, why).
- Trust note links to /audit so admins see the same change in the
  activity log.

#### #5 — Trust posture

- **Audit trail is the whole point.** Every grant/revoke writes
  YAML history *and* a v9.47 activity row. A capability without
  provenance is just a security promise nobody can verify.
- **Revoke also denies.** Revoking a role-floor capability writes
  an explicit deny so the floor doesn't silently restore it. The
  UI labels "via role" vs "granted" vs "denied" so admins know
  what state they're moving from.
- **Grant clears deny.** Granting auto-clears any prior explicit
  deny so the operator doesn't have to flip both fields.
- **No admin override.** Admin role short-circuits up; nothing
  short-circuits down. Even an admin can't deny themselves a
  capability via this surface — they have to demote themselves
  out of `admin` first, which is intentional friction.

#### #6 — 12 new tests

`tests/capabilities/`:
- `test_v9_48_capabilities.py` (10) — admin short-circuit, role
  floor for viewer, grant overrides floor, deny overrides grant +
  floor, clear-deny restores floor, unknown capability raises,
  history append round-trip, grant writes to activity log,
  decorator blocks without capability, decorator passes with
  grant.
- `test_v9_48_cli.py` (2) — full CLI round-trip
  (grant→list→show→revoke→clear-deny) and unknown-capability
  abort.

---

## [9.47.0] — 2026-05-07

### Activity tracking — every authenticated mutation, on disk, queryable

A common ask from anyone planning to deploy SafeCadence on shared
infrastructure: *"who did what, when?"*. The existing
`store.audit()` covered execution-job audit trail, but other
mutations (user CRUD, webhook CRUD, JIT grants, settings changes)
landed nowhere. v9.47 closes that gap.

#### #1 — `safecadence.activity` module

New top-level module: append-only JSONL log of every authenticated
mutation. One file per UTC day under
`$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl`. Each line is a JSON
record:

```json
{
  "ts": "2026-05-07T13:42:11Z",
  "actor": "alice",
  "tenant": "default",
  "method": "POST",
  "path": "/api/users",
  "status": 200,
  "ip": "127.0.0.1",
  "duration_ms": 23,
  "request_id": "req_abc123def456"
}
```

The `ActivityRecord` dataclass is the canonical shape; `append()`
writes one line, `read_day()` and `read_range()` filter by actor /
method / path-substring.

#### #2 — ASGI middleware

`ActivityMiddleware` plugs into the FastAPI app via
`app.add_middleware`. It:

- Mints a `req_…` request ID per request, exposes it as
  `request.state.request_id` and as the `X-SC-Request-Id` response
  header so client logs can correlate.
- Decodes the bearer JWT (when configured) to learn the actor;
  falls back to the cookie session, then `request.state.user`,
  finally `"anonymous"`.
- Logs **mutations only** by default
  (POST/PUT/PATCH/DELETE). `SC_ACTIVITY_LOG_READS=1` flips on
  forensic mode for GETs.
- Skips its own paths (`/api/activity*`, `/static/*`) so the audit
  view doesn't generate audit noise on every page load.
- Is best-effort: a disk-full append never breaks the wrapped
  request (covered by `test_disk_full_does_not_break_request`).

Wired into both FastAPI apps: `server/app.py` (the multi-user JWT
API) and `ui/app.py` (the single-user local UI). Set
`SC_ACTIVITY_DISABLED=1` to skip the middleware entirely.

#### #3 — `/audit` page + `/api/activity` endpoint

A new sidebar entry under Audit ("Activity log") opens a filterable
table of the last 7 days. Filters: window (24h/7d/30d/90d), actor,
HTTP method, path-contains. Each row shows when, actor, method,
path, status (color-coded by 2xx/4xx/5xx), duration in ms, IP, and
request ID.

The `/api/activity` endpoint is the JSON backing for the page —
same filters, capped at 5000 rows per call so a noisy day doesn't
DoS the browser.

The `tests/test_link_audit.py` link-audit gained a wiring guard for
`/audit` (now 57 tests, was 56).

#### #4 — Trust posture

- **Append-only.** No "delete row" button on purpose. The retention
  story is `find $SC_DATA_DIR/activity -mtime +90 -delete` run from
  ops, not application code.
- **chmod 600.** Files are written with 0600 permissions so the
  log can't leak via accidental shared read.
- **Reads not logged by default.** A daemon polling `/api/devices`
  every minute would otherwise drown out the actual signal.
- **Self-log skipped.** Loading `/audit` doesn't write a row about
  loading `/audit`.
- **Best-effort.** Activity log is forensic, not load-bearing.
  Every disk path swallows OSError; the request always completes.

#### #5 — Tests

10 new tests across `tests/activity/`:

- `test_v9_47_activity_store.py` (4) — append/read round-trip,
  filter API, range query newest-first, disk-full robustness, and
  corrupt-line tolerance on read.
- `test_v9_47_middleware.py` (6) — POST logged, GET skipped, GET
  logged when forensic, DELETE with path-param, disk-full doesn't
  break the request, and self-log on `/api/activity` is ignored.

`tests/test_link_audit.py` gained an entry for `/audit` (56 → 57).

---

## [9.46.0] — 2026-05-07

### Docs refresh: README + DEPLOY + HOWTO catch up to v9.42–v9.45

No code changes. Three docs drifted behind the v9.42–v9.45 work:

- **README.md**: Sidebar listing now mentions `/users` + `/settings`
  in the Settings group. Added a multi-channel-notifications bullet
  to the "Killer features" section explaining the seven
  NOTIFY_CATEGORIES, eleven webhook providers, the Fernet-at-rest
  posture, and the per-user notify-prefs override model. CLI
  listing now includes the v9.45 `users` / `webhooks` /
  `notify-prefs` command groups. Demo seeds note the example
  users + webhooks.
- **DEPLOY.md**: New B.3a section ("Configuring multi-channel
  notifications") with copy-paste CLI commands operators run after
  systemd is up. Env vars for SMTP, user directory file path, and
  webhook registry path are now documented. Legacy
  `SC_NOTIFIER_*` env vars are kept but tagged "legacy
  single-channel" — modern installs should use the registry under
  `/settings#webhooks` instead.
- **HOWTO.md**: New section N walks through the full notification
  setup loop — configure SMTP → add users → set notify-prefs →
  wire webhooks → verify with synthetic events. Includes the seven
  NOTIFY_CATEGORIES and how to inspect routing in `/timeline`.

This release is purely a documentation honesty pass — same code, no
test count change. The user-facing docs now match the product.

---

## [9.45.0] — 2026-05-07

### Notifications fan out from every emitter; CLI parity for v9.42–44

v9.44 wired the multi-provider webhook registry. v9.44.1 closed the
nav + link-audit gaps. This release closes the remaining honest
gap: not every emitter was actually calling `dispatch_event`. The
operator could configure a Teams webhook for `watchlist_change` and
get nothing, because the watchlist module never told the registry
about its changes. Same for JIT grants, automation fires, and the
daily digest. Five emitters are now fully wired.

#### #1 — `dispatch_event` wired into every emitter

Each call site is best-effort (`try/except pass`) so a misconfigured
webhook never breaks the underlying flow:

- `intel/watchlists.py:watch_changes` → `kind="watchlist_change"`,
  one event per detected delta, scoped to the watch owner via
  `invitees=[user]` so personal watchlists DM the owner.
- `identity/jit.py:grant` / `expire_due` / `revoke` →
  `kind="jit_granted"` with `extra.lifecycle ∈ {granted, expired,
  revoked}` so a single Slack channel can show the full grant
  lifecycle.
- `intel/automation.py:evaluate_rules` → `kind="automation_fired"`,
  one event per fired action, only when `apply_actions=True`
  (preview mode skipped).
- `digest.py:send` → `kind="digest_daily"` after a successful SMTP
  send, with summary line built from briefing/drift/approval counts.
- `daemon.py:run_daemon` → `kind="drift_detected"` aggregated per
  cycle (one event per cycle, not per finding) so a noisy detector
  run doesn't spam the channel.

The seven NOTIFY_CATEGORIES (`approval_requested`,
`finding_critical`, `watchlist_change`, `drift_detected`,
`automation_fired`, `jit_granted`, `digest_daily`) now all have at
least one in-tree emitter. A new test
(`test_all_categories_have_emitter`) walks the source tree and fails
CI if anything regresses.

#### #2 — CLI parity for users / webhooks / notify-prefs

Anything you can do from `/users` or `/settings#webhooks` you can
now do from `safecadence` headlessly. Three new command groups:

```
safecadence users add alice --email alice@x.com --role admin
safecadence users list
safecadence users delete alice

safecadence webhooks add team-slack --url https://… --provider slack \
            --category finding_critical --min-severity high
safecadence webhooks list
safecadence webhooks test team-slack         # fires a synthetic event
safecadence webhooks delete team-slack

safecadence notify-prefs set bob finding_critical \
            --channel email --channel slack
safecadence notify-prefs get bob
```

All three groups round-trip through the same upsert/list/delete
calls the HTTP endpoints use — no new storage paths, no parallel
truth.

#### #3 — Small UX fixes

- `/timeline` kind datalist refreshed with the seven NOTIFY_CATEGORIES
  alongside the legacy `audit/jit/comment/automation` kinds, so
  filtering matches what dispatch_event actually emits.
- `/settings#webhooks` form now hides the API token + HMAC secret
  rows for providers that don't use them (only opsgenie / pagerduty
  / webex / servicenow show the token row; only `generic_hmac` shows
  the signing-secret row). Cleaner form, fewer "what does this mean"
  questions.
- `safecadence demo` now seeds three example users
  (alice/bob/carol) and three example webhooks (Slack / PagerDuty /
  Teams, all disabled with example URLs) so `/users` and
  `/settings#webhooks` aren't empty pages on first visit.

#### #4 — 14 new tests

- `tests/notifier/test_v9_45_dispatch_wiring.py` (9 tests) —
  per-emitter mock of `dispatch_event` to prove each call site
  actually fires with the right `(kind, severity)` pair, plus a
  source-walk test that catches future drift between
  NOTIFY_CATEGORIES and emitters.
- `tests/cli/test_v9_45_users_webhooks_cli.py` (5 tests) —
  click-runner round-trip for every new command, including bad-URL
  rejection on the webhook adder.

#### Trust posture preserved

- All dispatch_event calls are best-effort — a webhook timeout never
  breaks the daemon cycle, a JIT grant, or a digest send.
- Drift fan-out is **aggregated per cycle**, not per finding, so a
  brownfield import that surfaces 200 drift findings sends one Slack
  message saying "200 new drift finding(s) — critical: 3, high: 12,
  medium: 185", not 200 separate notifications.
- Demo webhooks ship with `enabled: false`. The operator must
  explicitly enable each one before any real delivery is attempted.

---

## [9.44.1] — 2026-05-07

### Cleanup pass: verify suite, hook new pages into nav + link audit

Three honest gaps from v9.44 closed:

#### #1 — Real test count

I claimed "1033 tests, all green" at the end of v9.44 from
`pytest --collect-only` because the full run kept timing out my
shell. This release actually ran every chunk:

- `tests/identity` + `tests/policy`: 518 (one regression fixed —
  `test_approval_notification_payload_shape` was pinning the old
  `kind: "execution_approval_requested"` string; my v9.44 rename to
  the NOTIFY_CATEGORIES-aligned `approval_requested` made it fail.
  Updated the test to match the new contract.)
- `tests/test_v9_36_*` … `test_v9_44_*` + `test_e2e_v9_35_1.py`: 143
- `tests/test_link_audit.py`: 56 (new entries for `/users` +
  `/settings` brought it from 49 → 56)
- All other root tests: 320

**Real total: 1037 tests, all green.** No silent regressions —
honest pass.

#### #2 — `/users` + `/settings` in the sidebar

v9.42–v9.43 added the `/users` admin page and `/settings` hub but I
forgot to wire them into the chrome's left sidebar. Operators had to
type the URL. Fixed in `ui/_chrome.py` — both pages now appear under
the Settings group with active-pill highlight when selected.

#### #3 — Link-audit guards for the new pages

`tests/test_link_audit.py` now lists `/users` + `/settings` in
`_NAV_PAGES` so the "every nav page must render 200 text/html" check
catches accidental breakage. Wiring-token rows added so a future
refactor can't silently regress to a stub:

- `/users` → must contain `uxLoad`, `ux-tbl`, `uxOpenAdd`
- `/settings` → must contain `stLoadEmail`, `stLoadDefaults`,
  `stLoadPrefs`, `whLoad` (one per tab)

#### #4 — Channel webhook smoke (already covered)

v9.44's `test_dispatch_fans_out_to_matching_webhooks` already
monkey-patches `urllib.request.urlopen` and verifies the right URLs
get POSTed for the right (kind × severity) combination. No new test
needed — the smoke was already part of the v9.44 test file.

## [9.44.0] — 2026-05-07

### Multi-provider webhooks + dispatch_event wired everywhere

The v9.43 notification registry was a foundation; it wasn't used yet
by every place SafeCadence pings the operator. And the channel webhook
was still single-URL, hard-coded to a Slack-or-Teams shape. This
release turns webhooks into a first-class registry of customer-side
messaging integrations and routes every category-bearing event through
the same fan-out machinery.

#### 11 provider adapters + auto URL detection

```
slack            hooks.slack.com/services/...
mattermost       (Slack-API-compatible — uses slack renderer)
rocketchat       (Slack-API-compatible — uses slack renderer)
teams            outlook.office.com/webhook | webhook.office.com
discord          discord.com/api/webhooks/...
pagerduty        events.pagerduty.com/v2/enqueue
opsgenie         api.opsgenie.com/v2/alerts (+ API key)
servicenow       <instance>.service-now.com/api/now/table/incident
google_chat      chat.googleapis.com/v1/spaces/...
webex            webexapis.com/v1/messages (+ Bearer token)
generic_hmac     any URL, body HMAC-signed by SC_WEBHOOK_SIGNING_SECRET
generic_webhook  any URL, unsigned JSON
```

Each adapter renders the same generic event dict
(`{kind, title, summary, severity, link, ...}`) into the JSON shape
that provider's incoming webhook accepts: Slack Block Kit attachments
with severity-coloured sidebars, Teams MessageCards with theme colours,
Discord embeds with `color` int + footer, PagerDuty Events v2 with
mapped severity, Opsgenie alerts with `P1-P5` priority, ServiceNow
incidents with mapped impact/urgency, Google Chat cardsV2, Webex
markdown, etc.

Provider auto-detected from URL pattern; operators can override per
webhook for self-hosted Mattermost/Rocket.Chat instances. All
adapters use stdlib `urllib` so the notifier works in air-gap installs
without `httpx`.

#### Webhook registry — Fernet-encrypted at rest, filterable

```
$SC_DATA_DIR/settings/webhooks.json   # one row per webhook
[
  {
    "id": "secops-slack",
    "provider": "slack",
    "url_encrypted": "FERNET:gAAAAA…",
    "categories": ["approval_requested", "finding_critical",
                   "drift_detected", "jit_granted"],
    "min_severity": "medium",
    "enabled": true
  },
  {
    "id": "ops-discord",
    "provider": "discord",
    "url_encrypted": "FERNET:…",
    "categories": ["automation_fired", "watchlist_change"],
    "min_severity": ""
  },
  {
    "id": "all-incidents-pagerduty",
    "provider": "pagerduty",
    "url_encrypted": "FERNET:…",
    "categories": [],
    "min_severity": "high"
  }
]
```

**Filters are AND'd**: a webhook fires only when both the category
matches (or is empty = any) AND the severity ≥ floor (or floor is
empty = any). Same env var (`SAFECADENCE_VAULT_KEY`) covers identity
vault (v9.39), email config (v9.42), and now webhook URLs.

#### Trust posture

- Webhook URLs are bearer secrets → Fernet-encrypted at rest.
  Leak-canary test confirms plaintext never lands on disk.
- `GET /api/webhooks` returns `url_preview` (e.g.
  `hooks.slack.com/services/T0AAA/B0BBB/****`) so admins can
  recognise the row without exposing the secret.
- Admin role required to write or test.
- Per-webhook `Test` endpoint sends an `_test` event so admins can
  verify wiring before relying on it for real alerts.
- Each webhook fires independently — one dead Discord doesn't block
  the Slack one. Per-webhook `ok / error` recorded in the audit log.
- Disabled webhooks never match (off-switch without deletion).

#### dispatch_event wired into real notification points

The v9.43 registry now actually serves the events SafeCadence emits:

- **Approval requests** (`workflow.py`) — replaces the inline
  channel-webhook + email-DM split with a single
  `dispatch_event(kind="approval_requested", invitees=...)` call.
  Legacy `SC_SLACK_WEBHOOK` env var still honoured as fallback for
  pre-v9.44 deployments.
- **Daemon CRITICAL findings** — every new CRITICAL finding the
  daemon spots fires `kind="finding_critical"`, fanning out to all
  matching webhooks AND any user who opted in via
  `/settings#prefs`.

Other surfaces (drift, watchlist, automation, digest, JIT) emit
events that the dispatch fan-out automatically picks up via the
v9.43 categories — no code change required at each call site once
they migrate from `notify(webhook, ...)` to
`dispatch_event(kind=..., ...)`.

#### New endpoints

```
GET    /api/webhooks                  list (URLs redacted)
POST   /api/webhooks                  create or update (admin)
DELETE /api/webhooks/{id}             remove (admin)
POST   /api/webhooks/{id}/test        send an _test event (admin)
```

#### `/settings#webhooks` UI tab

Fourth tab on the settings hub. Admin-only writes. Add a webhook by
pasting the URL — provider auto-detected; override available for
Mattermost/Rocket.Chat self-hosted. Pick categories with checkboxes
(populated from `NOTIFY_CATEGORIES`), pick min severity from the
dropdown, save. The table shows the redacted URL preview with the
provider name, current filters, enabled state, plus per-row Test /
Edit / Delete buttons.

#### Tests

`tests/test_v9_44_multi_provider_webhooks.py` (26 new):
- URL-pattern detection across 10 known platforms
- Per-provider payload shape: Slack Block Kit, Teams MessageCard,
  Discord embed (with `color` int), PagerDuty Events v2, Opsgenie
  P1-P5 priority mapping, ServiceNow impact mapping, Google Chat
  cardsV2, Webex markdown
- Fernet-encrypted-at-rest leak canary
- `to_public_dict()` never leaks the URL — separate canary test
- URL scheme + min_severity validation
- Blank URL on edit preserves existing (parity with email config)
- Filter rules: categories AND severity AND'd; disabled never matches;
  no-filters matches anything
- `dispatch_event` fan-out hits exactly the matching webhooks (kind +
  severity filters)
- One failing webhook doesn't block the others (isolated dispatch)
- HTTP API: admin-only writes, list never returns URLs
  (leak-canary canary at the wire), test endpoint admin-gated
- UI surface: settings has the Webhooks tab + redacted preview +
  Fernet trust note
- Workflow integration: approval notifier calls `dispatch_event`
  (verified via monkey-patch capture)

## [9.43.0] — 2026-05-07

### Generalized notification routing — any event kind, any user

v9.42 plumbed email-DM routing through the customer's SMTP, but only
the approval workflow knew how to use it. Every other notification
point (findings, drift, watchlist hits, the daemon, automation rules,
the morning digest) still hit the channel webhook directly with no
way to deliver to a *specific* operator.

This release generalizes the v9.42 email-DM machinery into a
notification registry that any event kind can use, with per-user
opt-in preferences, a tenant-default routing matrix, and Slack/Teams
DM @-mentions woven into the existing channel webhook payload.

#### `notifier/registry.py` — `dispatch_event(...)`

One function call, many places to plug it in:

```python
dispatch_event(
    kind="finding_critical",
    title="New CRITICAL finding on prod-db-01",
    summary="…",
    severity="critical",
    invitees=["alice", "bob"],
    tenant="acme",
    channel_webhook=os.environ["SC_SLACK_WEBHOOK"],
    link="/findings#abc",
)
```

Every dispatch:

1. **Always fires the channel webhook** (Slack / Teams / PagerDuty /
   HMAC) — backups still see the event regardless of per-user prefs.
2. **Per-invitee email DM** when SMTP is configured AND the user opted
   in to that category on that channel.
3. **Slack/Teams DM via @-mention** — the existing channel payload is
   enriched with `slack_user_ids`, `slack_mentions`, and
   `teams_user_ids` when invitees have those ids on file. No second
   webhook call, no per-user Slack token.
4. **Audit trail** — returns a `DispatchResult` recording which
   channels fired and per-recipient `ok / reason` for SOX evidence.

#### Three-layer configuration

| Layer | Where it lives | Who can set it |
|---|---|---|
| **Code defaults** | `NOTIFY_CATEGORIES` table | locked — `approval_requested` always fires for invitees |
| **Tenant defaults** | `$SC_DATA_DIR/settings/notify_defaults.json` | admin via `/settings#defaults` |
| **Per-user overrides** | `notify_prefs` field on user record | self-service via `/settings#prefs` |

Resolution order for "should we email Alice about this finding?":
**user override → tenant default → silent (no DM)**, then intersected
with the channels Alice actually has contact info for. A pref enabling
`email` is silently dropped if Alice has no email on file (defense in
depth on top of `validate_prefs`).

#### Trust property: invitation ≠ authorization (still enforced)

Per-user prefs control *delivery*, not *authority*. An operator can't:

- Enable a channel they don't have contact info for (`validate_prefs`
  returns 400).
- Opt out of `approval_requested` invites — direct ask, always-on
  for the named invitees.
- View or edit another user's prefs unless they have the admin role
  (the `/api/users/{u}/notify-prefs` endpoints check this).
- Hide an event from the team channel — the channel webhook fires
  regardless of any user toggling.

#### Categories shipped

```
approval_requested    Always-on for invitees (direct ask)
finding_critical      CRITICAL findings on the operator's fleet
watchlist_change      An asset / NHI / principal you watch changed
drift_detected        Cross-system drift between AD/Entra/Okta/etc.
digest_daily          Morning briefing — overnight changes + actions
automation_fired      An automation rule you authored fired
jit_granted           A JIT grant was issued or revoked
```

Adding a new category is a one-line edit in `NOTIFY_CATEGORIES` —
the matrix UI, the prefs API, and `dispatch_event` all pick it up
automatically.

#### Channels shipped

| Channel key | Required user field | How it delivers |
|---|---|---|
| `email` | `email` | Direct email DM via the v9.42 SMTP client |
| `slack_dm` | `notify.slack_user_id` | `<@U03ABCDEF>` mention in the existing Slack channel webhook payload |
| `teams_dm` | `notify.teams_user_id` | `teams_user_ids` array on the existing Teams payload |

PagerDuty escalation (`pagerduty_user_id`) is reserved for v9.44 —
the field is in the schema so users can pre-populate it.

#### New endpoints

```
GET  /api/notify/categories              list available categories + channels
GET  /api/settings/notify-defaults       tenant-default matrix
POST /api/settings/notify-defaults       admin-only — update tenant defaults
GET  /api/users/me/notify-prefs          self — overrides + available channels
POST /api/users/me/notify-prefs          self — update own overrides
GET  /api/users/{u}/notify-prefs         admin (or self) — view another user
POST /api/users/{u}/notify-prefs         admin — update another user
```

#### New UI surfaces

- **`/users`** — directory admin page. List users with badges for
  configured channels (email / slack / teams / pagerduty); inline add
  / edit / delete with all v9.42 contact fields surfaced.
- **`/settings`** — three-tab hub:
  - **Email (SMTP)** — customer SMTP config + Send test email button
    (the v9.42 endpoints, now in a real UI).
  - **Tenant defaults** — admin-only category × channel matrix.
  - **My notifications** — every user's self-service matrix.
    Channels they don't have contact info for render as disabled
    cells with a tooltip explaining what's missing.

#### Tests

`tests/test_v9_43_notification_routing.py` (26 new) pins:
- `validate_prefs` rejects email when the user has no email on file
  (trust gate)
- User overrides beat tenant defaults; empty override = explicit opt-out
- Tenant defaults round-trip to disk; unknown categories/channels
  silently dropped
- Directory round-trips `notify_prefs` through YAML
- Air-gap: SMTP off = no email DMs, no exception, deliveries record
  `smtp_not_configured` reason
- Opted-in user with SMTP on = `send_email` called once with their
  primary email
- Opted-out user (empty prefs list) = no email
- `approval_requested` ignores prefs (always-on for invitees)
- Channel webhook payload enriched with `slack_user_ids` +
  `slack_mentions` when invitees have Slack ids
- HTTP API gate tests: admin-only writes for tenant defaults; users
  can't view/edit other users' prefs without admin role; users can
  view their own through the admin route
- UI surface tests: `/users` calls the directory API and has CRUD
  handlers; `/settings` has all three tabs and renders the trust
  note about the channel webhook always firing

## [9.42.0] — 2026-05-07

### Approver directory + customer SMTP + targeted email notifications

Pre-v9.42 the approval flow was open-queue and channel-blast: a job
in REVIEW pinged a Slack/Teams/PagerDuty channel and the right
approver had to happen to be watching. There was no way to invite a
specific person, and the user record didn't even have an email.

This release closes that gap with **Phase A** of the design doc —
explicit invite-by-name, email DM through the customer's own SMTP
server, channel webhook still firing as a fallback. Phase B
(IdP-sourced groups via the v9.34 vault) and Phase C (PagerDuty
escalation) keep the door open without locking us in.

#### Schema (additive, backward-compatible)

`users.yaml` gains four optional fields per user. Old YAML loads
unchanged.

```yaml
- username: alice
  password_hash: $2b$...
  roles: [admin]
  email: alice@acme.com           # NEW
  display_name: Alice Chen        # NEW
  notify:                          # NEW
    email: alice@acme.com         #   override email for DM routing
    slack_user_id: U03ABCDEF      #   future @-mention in Slack DM
    teams_user_id: 8:orgid:guid   #   future @-mention in Teams DM
    pagerduty_user_id: PD0123     #   future PagerDuty escalation
  external_id: okta:00u3xyz        # NEW — phase B IdP resolution
```

`CommandJob` gains `approvers_invited: list[str]` — the explicit
invite list, distinct from `approvers` (the list of people who said
yes). Empty `approvers_invited` preserves v9.41 open-queue behaviour.

#### Trust property: invitation ≠ authorization

The role gate in `workflow.approve()` is unchanged. Inviting alice@acme
to a job she lacks the role to approve is a no-op — she gets the email
and sees the queue page; clicking Approve returns 403. The v9.42
invite is a hint to reduce noise, not an authorization. Tests pin this
explicitly.

#### Customer SMTP — never our infrastructure

New `safecadence/notifier/email_notifier.py` wraps stdlib `smtplib`.
SafeCadence is an **SMTP client**, never a server: the customer
points us at their own Exchange / Postfix / corporate relay /
SendGrid / Gmail SMTP and we send through it. Every byte of message
content stays in their mail estate's logs, nothing routes through
SafeCadence's infrastructure or any third-party email service.

Air-gap: empty config = email DMs disabled, audit log records the
skip with `reason=smtp_not_configured`, channel webhook still fires.
No exception raised.

#### SMTP password Fernet-encrypted at rest

Plaintext SMTP password from the API → `FERNET:<ciphertext>` in
`$SC_DATA_DIR/settings/email.json`. Reuses the existing
`SAFECADENCE_VAULT_KEY` env var so a single key bootstrap covers
identity vault + email config. The leak-canary test confirms the
plaintext string never lands on disk.

`GET /api/settings/email` returns `{has_password: true|false}` —
never the password itself. Editing the config without re-entering
the password preserves the existing encrypted value.

#### Notifier flow on submit

When `workflow.create_job` puts a job into REVIEW:

1. **Channel webhook** (Slack / Teams / PagerDuty / HMAC) fires —
   unchanged from v9.35 #4. Backups still see the request even with
   no invitees.
2. **Per-invitee email DM** — if `approvers_invited` is set AND SMTP
   is configured, we resolve each invitee in the user directory and
   send them a structured approval email. Every delivery is
   independent: one failed DM never blocks others, and the workflow
   proceeds either way.
3. **Audit trail** — `email_dm_dispatched` / `email_dm_skipped`
   entries record exactly who got pinged on which channel, with
   per-recipient `ok / reason` for SOX evidence.

Every approval email surfaces the trust note in both plaintext and
HTML: *"This invitation does not grant approval authority — your role
still gates the actual approve action."*

#### New endpoints

```
GET    /api/users                   list directory (no hashes)
POST   /api/users                   create or update (admin)
DELETE /api/users/{username}        delete (admin, can't delete self)
GET    /api/settings/email          read SMTP config (no password)
POST   /api/settings/email          update SMTP config (admin)
POST   /api/settings/email/test     send test email (admin)
```

`/api/settings/email/test` sends a one-shot test email through the
configured SMTP so the admin can verify end-to-end before relying
on it for real approvals.

#### Builder UI: invite-approvers row

`/builder` now has an optional **Step 2.5 — Invite specific
approvers** card between target and the Preview button. Typeahead
populated from `/api/users`; pick people one at a time, they show
as removable chips. Each chip warns ⚠ if the user has no email on
file (they won't get a DM, only the channel ping). The trust note
is rendered inline.

Save-as-draft and Submit-for-approval both pass `approvers_invited`
through to the saved job.

#### Tests

`tests/test_v9_42_approver_directory.py` (26 new):
- Directory loads v9.42 fields + backward-compat with old YAML
- Directory NEVER returns `password_hash` (leak-canary check)
- Validation: bad email rejected, username/roles required
- Upsert preserves existing password hash
- `lookup_invitees` drops unknown usernames silently
- SMTP password Fernet-encrypted at rest (leak-canary check)
- `to_public_dict()` never returns password / password_encrypted
- Air-gap: `is_configured()` False without config; `send_email`
  returns `(False, reason)` instead of raising
- Approval-email template includes the trust note in both plaintext
  and HTML
- HTTP `/api/users` requires admin role for write; lists never leak
  hashes; admin can't delete themselves
- HTTP `/api/settings/email` round-trips; blank password preserves
  existing; `has_password` boolean correct
- Workflow `_notify_invited_approvers_via_email` skips cleanly when
  SMTP off
- Workflow calls `send_email` once per invitee with a primary email
- Builder UI has invite row, calls `/api/users`, passes
  `approvers_invited` on save, renders the trust note

## [9.41.0] — 2026-05-07

### Command Builder redesign

The pre-v9.41 `/builder` page was confusing in three concrete ways:
the target asset group was a free-text input (you had to *know* the
group name), the plan output was a raw JSON dump in a `<pre>`, and
the single Save button shoved every plan straight to `/approvals`
with no way to sit on a draft and refine it. Operators were leaving
the page without using it.

This release rebuilds `/builder` around the right mental model —
**intent → target → plan** — without changing the API contract.

#### Step 1: intent — example pills + textarea

Six starter pills sit above the intent textarea covering the common
operator asks: *Block service inbound, Add log destination, Disable
insecure protocol, Update NTP server, Tighten management ACL,
Rotate SNMP community*. Click a pill, the textarea fills, you edit
or hit Preview. The list lives in one constant
(`BLD_INTENT_PILLS`) so adding a new intent pack means adding a
matching pill in the same commit.

#### Step 2: target — dropdown with live device-count preview

The free-text "Target asset group" input is replaced with a
`<select>` populated from `GET /api/platform/asset-groups`. The
adjacent panel shows the resolved device list as soon as you pick
a group: *"4 devices · edge-fw-01, edge-fw-02, edge-fw-03 and 1
more"*. An explicit *(All matching assets)* option is available but
labelled in red — using it is deliberate.

#### Step 3: plan — structured cards instead of JSON

Click *Preview plan* and the result panel renders three cards:

1. **Header card** — coloured risk badge (`SAFE / LOW / MEDIUM /
   HIGH / CRITICAL`) plus the required-approver line
   (`MEDIUM → SUPER_ADMIN`, `HIGH → SUPER_ADMIN + 1 additional`),
   blast-radius numbers (vendors / commands total / target summary),
   and the matched-pack list.
2. **Per-vendor card** — one `<details>` per vendor, first one
   auto-expanded. Each shows the actual commands in a monospace
   block. No more JSON tax to read what'll run.
3. **Rollback card** — explicit indicator that the rollback plan
   will be auto-generated when the job is approved (the v9.35
   `_INVERT_PATTERNS` work), with a deep-link to `/rollback`.

When a plan is **blocked by guardrails** the header card flips red
and lists the human reasons from `block_reasons` — no more searching
inside JSON. When the intent doesn't match a pack, the operator
gets a yellow banner with the summary text instead of silence.

#### Two save buttons (was one)

- **Save as draft** → `POST /api/execute/builder/save-draft` (new
  endpoint). Job is persisted in `DRAFT` status, no approver
  pinged. Operator can come back, refine the intent, re-preview,
  re-save. The job stays in DRAFT and does NOT appear on
  `/api/execute/queue`.
- **Submit for approval** → existing `POST /api/execute/builder/
  plan-and-save`. Goes through `workflow.create_job` and lands on
  `/approvals` for the right tier of approver.

#### Tests

`tests/test_v9_41_builder_redesign.py` (13 new) pins the visible
shell so a future refactor can't silently regress to a JSON dump:
intent pills, dropdown not free-text, group→devices preview wiring,
risk badge + required-approver helper, per-vendor `<details>`
expandable groups, rollback indicator, two distinct save buttons,
blocked-plan rendering, no-pack-match coachable message. Plus three
HTTP-level tests pinning that save-draft returns `status=draft`,
that DRAFT jobs do NOT leak into `/api/execute/queue`, and that
`plan-and-save` still works.

Updated `test_link_audit.py` for the new wiring tokens
(`bldPreview` / `bld-intent` replace `builderPlan` / `builder-intent`).

## [9.40.0] — 2026-05-06

### Per-principal asset breakdown for /access

The v7.5 ``decide()`` resolver answers one (action, resource,
principal) question at a time — perfect for the detail view, wrong
shape for the question auditors actually ask:

> *"Show me everything alice@acme can reach across the fleet, and
> which systems grant each permission, so I can prove
> least-privilege at audit time."*

v9.40 adds the breakdown shape that question needs. New module
`identity/access_breakdown.py` composes per-asset chains by replaying
``decide()`` against every (asset, action) pair in the fleet for a
single principal, then groups by asset and lists the contributing
systems for each granted action.

#### New endpoint: `GET /api/identity/access`

```
GET /api/identity/access?principal=alice@acme
                        &groups=Engineering,On-call
                        &actions=ssh,console,https
                        &only_granted=true
                        &mfa=true&posture=true
```

Returns:

```json
{
  "principal": "alice@acme",
  "groups": ["Engineering", "On-call"],
  "actions_probed": ["ssh", "console", "https"],
  "summary": {
    "assets_total": 34,
    "assets_with_any_grant": 12,
    "actions_granted": 19,
    "systems_seen": ["ad", "okta"]
  },
  "grants": [
    {
      "asset_id": "prod-db-01",
      "hostname": "prod-db-01",
      "asset_type": "server",
      "environment": "prod",
      "criticality": "high",
      "site": "dc1",
      "actions_allowed": ["ssh"],
      "actions_denied": ["console", "https"],
      "actions_step_up": [],
      "granted_by_systems": ["okta", "ad"],
      "chain": [
        {"action": "ssh", "system": "okta", "rule_name":
          "okta-allow-ssh", "effect": "allow",
          "matched_on": ["user:alice@acme", "action:ssh",
                         "asset_type:server"]}
      ]
    }
  ]
}
```

The chain field surfaces the rule names + matched evidence so
auditors can trace each grant to its source rule. Capped at 24
chain entries per asset to keep the response shape sane on
fleets with thousands of assets.

#### Trust property

Read-only. The breakdown reflects what the connected systems
declare — no write-back, no elevation requests, no implicit
permission discovery. The ``decide()`` precedence order
(deny > step_up > allow > default-deny) is unchanged.

#### Tests

`tests/test_v9_40_access_breakdown.py` (11 new) pins:
- Per-asset grants surface allowed / denied / step_up actions.
- `granted_by_systems` collects every contributing system
  (Okta + AD both grant ssh → both appear).
- Deny rules block grants (precedence enforced).
- `only_granted=True` filters out no-access assets.
- Summary counts match the grants list (`assets_with_any_grant` +
  `actions_granted`).
- Group rules match when `principal_groups` is supplied (resolver
  expects bare names, not `group:` prefix).
- `asset_types` filter restricts the probe (no printer noise in
  the breakdown).
- The chain includes rule names so the auditor can read it.
- The HTTP endpoint returns the breakdown shape and accepts a
  custom action list.

## [9.39.0] — 2026-05-06

### Postgres-backed identity vault

Before v9.39, `IdentityVault` was hardcoded to the SQLite-backed
`PlatformVault` even when the rest of the platform was using
Postgres via `DATABASE_URL`. For multi-instance HA deployments this
meant the identity vault was the one piece of state that didn't sync
across nodes. v9.39 closes that gap.

#### Backend selector

`IdentityVault.__init__` now picks at construction time:

- **`DATABASE_URL` set + SQLAlchemy installed** → Postgres path via
  the new `_PgIdentityBackend` and the `sc_identity_vault` table in
  `storage_pg.py`. Same engine the rest of the platform shares.
- **Otherwise** → SQLite via `PlatformVault` (the v9.34 default,
  unchanged behaviour for laptop / single-node).

Surface the choice via `vault.backend → "postgres" | "sqlite"` so the
connector status strip can render an honest "Storage: Postgres"
badge. `force_sqlite=True` bypass added for tests + the local
bootstrap.

#### Encryption at rest in both backends

Credentials are Fernet-encrypted (AES-128-CBC + HMAC-SHA256) before
the JSON payload column. The database never sees plaintext secrets,
even on `pg_dump` / restore. Plain metadata (target, last_test_at,
last_synced_at) lives in indexed JSON keys for fast `list()` without
needing the master key.

#### Per-tenant isolation

The Postgres table's primary key is `(system, tenant)` so two
tenants on the same DB never see each other's connectors. Each
`IdentityVault(tenant="acme")` filters on its own tenant for every
read/write/delete.

#### Schema

```
sc_identity_vault (
    system     VARCHAR(32),     -- okta|entra|ise|clearpass|ad
    tenant     VARCHAR(64),     -- multi-tenant scope
    target     VARCHAR(256),    -- e.g. "acme.okta.com"
    payload    JSON,            -- {encrypted_blob, last_test_at, ...}
    updated_at TIMESTAMPTZ,
    PRIMARY KEY (system, tenant)
)
```

`MetaData.create_all` runs on first `_ensure()` so a fresh deployment
just sets `DATABASE_URL` and the table appears.

#### Tests

`tests/test_v9_39_pg_vault.py` (11 new) pins:
- Save / load round-trip preserves credentials and metadata.
- Upsert replaces prior records (no duplicates).
- `list_connected()` excludes secrets — leak-canary check.
- Disconnect is idempotent.
- `mark_synced()` updates only metadata, preserves credentials.
- `save_creds(test_passed=False)` rejected.
- Empty creds rejected.
- **Credentials are encrypted at rest** — direct DB read confirms
  the plaintext canary string is nowhere in the JSON payload.
- Per-tenant isolation — tenant A and B share a DB but can't see
  each other's connectors.
- The SQLite path still works when `DATABASE_URL` is unset.
- `force_sqlite=True` overrides `DATABASE_URL` for tests/bootstrap.

Tests use SQLAlchemy's `sqlite:///` URL so they exercise the same
ORM code path Postgres uses, without requiring a running Postgres
server.

#### Migration

There is no auto-migration from SQLite to Postgres. Operators who
have been running SQLite and want to switch:

```bash
# Existing connectors will need to be re-saved against the new
# Postgres backend. Run the connect flow again with mode=save for
# each system, OR copy via:
SAFECADENCE_VAULT_KEY=<key> python -c "
  from safecadence.identity.vault import IdentityVault
  src = IdentityVault(force_sqlite=True)
  dst = IdentityVault()  # picks Postgres from DATABASE_URL
  for c in src.list_connected():
      rec = src.load_creds(c['system'])
      dst.save_creds(system=rec.system, target=rec.target,
                     credentials=rec.credentials, test_passed=True)
"
```

This is documented in `docs/DEPLOY.md`'s upgrade notes.

## [9.38.0] — 2026-05-06

### Small pages audit: clean, two transparency tweaks

The audit (`docs/v9.38-small-pages-audit.md`) covered the seven
surfaces operators touch daily but rarely talk about: `/timeline`,
`/share`, `/automation`, `/watchlists`, `/briefing`, `/settings`,
`/audit`. **All seven came back real and wired** — the v7.9 (intel
suite) and v7.2 (audit log + settings) work shipped properly.

Two small transparency / UX items:

#### #1 — `/automation` preview banner

The preview button correctly POSTs to `evaluate_rules(apply_actions=
False)` so no actions ever fire from this surface, but the UI just
dumped raw JSON. Someone scanning quickly could misread `would_fire`
as `fired`. Now the output starts with a yellow banner: *"🔮 Preview
only — no actions taken. These are the rules that *would* fire
against current findings."*

#### #2 — `/timeline` kinds datalist

The kinds filter was a freeform text input. A typo (`automatin` vs.
`automation`) returned empty results and looked like there were no
events. Now there's a `<datalist>` with the six actual emitters
(`audit`, `jit`, `comment`, `assignment`, `watchlist`, `automation`)
so the field auto-completes.

#### Tests

`tests/test_v9_38_small_pages.py` (3 new) pins the dry-run banner,
the datalist suggestions, and that the audit doc itself ships.

## [9.37.0] — 2026-05-06

### Compliance section: clean audit, two UX gaps closed

The audit (`docs/v9.37-compliance-audit.md`) found all 7 Compliance
surfaces (`/policies`, `/policies/new`, `/findings`, `/drift`,
`/evidence`, `/compliance`, `/risks`) **real and wired** — no
fake-success endpoints, no default-to-apply paths, no abandoned
buttons. The deliberate v9.27 + v9.31 + v9.32 polish work shows.

This release closes two UX gaps where features that shipped were not
surfaced in the UI:

#### #1 — `/policies` slide-over: stale "(coming v9.2)" buttons → real wiring

The slide-over had `alert('Per-vendor preview — coming v9.2')` and
`alert('Add exception flow — coming v9.2')`. Both features actually
shipped (preview-config in v9.31 #9, policy changes/exceptions in
v9.32 #4) but the UI labels still claimed they were future work,
mocking the operator. Now:

- **Preview per-vendor** posts to `/api/policy/preview-config` and
  renders the cisco_ios shape-only preview inline in the slide-over.
- **Add exception** prompts for a one-line reason and posts to
  `/api/policy/changes` with `kind: "exception"`, surfacing the
  exception in the audit trail.

#### #2 — `/policies/new`: brownfield import button

`POST /api/policy/import-from-config` shipped in v9.32 #1 but was
only reachable via curl. The YAML editor at `/policies/new` now has
an "Import from config…" button next to "Load template". Operators
paste a running config; SafeCadence infers a starter policy YAML;
operator reviews + edits + saves.

#### Tests

`tests/test_v9_37_compliance.py` (6 new) pins:
- The slide-over no longer has the stale `coming v9.2` labels.
- Both buttons wire to the real endpoints with the expected request
  bodies.
- `/policies/new` exposes `pnImportFromConfig` and calls
  `/api/policy/import-from-config`, then loads the returned YAML
  into the editor and refreshes the preview.
- The compliance + drift + policy + risk endpoints stay registered
  in `platform_api.py` so a refactor doesn't silently drop them.

## [9.36.0] — 2026-05-06

### Discover section: kill fake-success + raise floor

Same audit-then-fix exercise we ran on Identity (v9.33-v9.34) and
Execute (v9.35.0). The audit at `docs/v9.36-discover-audit.md` found
that 8 of 10 Discover surfaces were already production-ready; the
material trust gap was a single endpoint pretending to do work.

#### #1 — `/discovery-jobs` Run Now actually runs the job

`src/safecadence/server/platform_api.py` previously stamped
`mark_run(job_id, ok=True)` and returned a hint to "open the matching
hero card on /inventory" — a fake-success that lied to the operator.
The daemon path correctly fired the job through
`daemon._fire_discovery_job`; the HTTP endpoint did not.

- Extracted the dispatcher into `intel/discovery_jobs.py:fire_job(job)`
  as the single source of truth used by **both** the daemon's
  scheduled cycle and the HTTP `run-now` endpoint.
- HTTP `run-now` now calls `fire_job` and persists the real outcome
  via `mark_run`, returning `{ok, error, source}` so the UI can show
  truth.
- Daemon's `_fire_discovery_job` is now a thin shim over the same
  function — kept as a module-level name so existing tests that
  monkey-patch the daemon shim still work.

#### #2 — Discovery job params validated at create-time

Before v9.36 you could save a job with `source=lan-scan` and no `cidr`.
The error only surfaced on the first scheduled fire — by which point
the operator had moved on. Now:

- `intel/discovery_jobs.py:validate_params(source, params)` knows the
  required keys per source (cidr for lan-scan, host for snmp,
  server+base_dn for ad, tenant_id+client_id+client_secret for entra,
  subscription for azure, project for gcp).
- `create_job` calls `validate_params` and raises `ValueError` →
  HTTP 400 with the exact missing key in the error message.
- `fire_job` re-validates as defense in depth (a job persisted before
  v9.36's check landed will still fail loudly instead of running with
  bad inputs).

#### #3 — `/coverage` recommendations explain themselves

Operators saw priority `high / medium / low` on the recommendations
panel but no explanation of why one item ranked above another. Each
recommendation now ships with a `reason` field surfacing the visibility
multiplier behind the priority bucket (e.g. "SNMP harvest is the
highest-impact missing source — each network device contributes 50–500
neighbor + MAC table entries.").

#### #4 — `GET /api/platform/discovery-jobs/sources`

Single source of truth for the UI's source dropdown. Returns each
supported source with its label, required params, and a one-line
"needs" hint, so adding a new source only requires editing
`SUPPORTED_SOURCES` + `REQUIRED_PARAMS` + `SOURCE_DESCRIPTIONS` in
one file.

#### Tests

`tests/test_v9_36_discover.py` (18 new) pins:
- `fire_job` is module-level callable and rejects unknown sources +
  missing required params.
- `validate_params` for each source's required-key set.
- `create_job` raises `ValueError` on missing params.
- `compute_coverage()` recommendations all have non-empty `reason`s
  and high-priority sources have *distinguishing* reasons.
- `SUPPORTED_SOURCES`, `REQUIRED_PARAMS`, and `SOURCE_DESCRIPTIONS`
  stay in sync.
- HTTP `run-now` calls `fire_job` and persists the real outcome.
- HTTP `/api/platform/discovery-jobs/sources` lists every supported
  source with the four expected fields.

Plus updated `tests/test_v9_intel_modules.py` to supply valid params
for the `create_job` calls that previously relied on the permissive
behavior.

## [9.35.1] — 2026-05-06

### Polish pass: demo coverage, README, end-to-end smoke

A patch release that closes three small but visible gaps in v9.35.

#### #1 — Three-tier demo data (good / medium / broken)

`safecadence demo` now seeds the identity vault, NHIs, and execution
jobs alongside the existing fleet + compliance seeds. Identity is
intentionally three-tier so a buyer evaluating the product sees what
each connector state looks like instead of empty cards on first run:

- **good** — `acme-good.okta.com` connected and synced (`source=vault`,
  `last_synced_at` set); 2 healthy NHIs (well-attested + recent IAM
  role).
- **medium** — `cp-medium.acme.demo` ClearPass connected but never
  synced (`last_synced_at` empty); 2 NHIs that need attention
  (rotation overdue 60d, no owner).
- **broken** — `ldap://ad-broken.acme.demo` AD connector with a
  deliberate misconfig; 2 NHIs in trouble (stale 220 days, deprecated).

Plus 6 `CommandJob` records spanning the full lifecycle (DRAFT → REVIEW
→ APPROVED+rollback plan → DONE+pre/post snapshots → FAILED+error
pattern → ROLLED_BACK), so the Execute section, /per-device-diff, and
/rollback all populate on first run.

`/api/identity/nhi/findings` returns at least one stale-NHI finding on
the demo, so the Identity action panel has real content out of the box.

#### #2 — README + DEPLOY refresh

README rewritten to reflect v9.32 → v9.35 work:

- Trust posture section explicitly walks through dry-run defaults,
  HMAC-bound confirm tokens, the Fernet-encrypted vault, the ~45-pattern
  rollback plan generator, pre/post config snapshots, the Tier-3
  triple-gate, the 6-tier RBAC + no-self-approve rule, approval
  notifications to Slack/Teams/PagerDuty, NHI lifecycle, and links to
  `docs/v9.33-write-back-audit.md` + `docs/v9.35-execute-audit.md`.
- Killer features list extended with the v9.32-9.35 additions
  (vendors page, /policies/new editor, identity vault + Connect form,
  rollback plan generator, NHI lifecycle, builder AI fallback,
  three-tier demo data).
- CLI section updated with the new `safecadence identity connect / sync
  / disconnect / nhi` subcommands.
- Test count refreshed (~875 tests) with new entries called out.

#### #3 — End-to-end smoke test

`tests/test_e2e_v9_35_1.py` walks the full product loop in one test:

1. Connect identity (test_only) — assert `saved=False`.
2. Connect again with `mode=save` — assert `saved=True` and credentials
   land in the vault.
3. Sync — collect + normalize + save_asset, vault status reports
   `source=vault` with `last_synced_at`.
4. `/access` — verdict against the synced data.
5. `/findings` + `/attack-paths` — surfaces respond.
6. NHI lifecycle — register + attest + rotate + list.
7. Builder — pack-driven plan resolution for a known intent.
8. Workflow — submit → review → approve (SUPER_ADMIN) → rollback plan
   persisted on the job.
9. Rollback plan content — assert remainder-preserving inversion of
   `ip route 10.99.0.0 …` AND `logging host 10.0.0.5`.

Plus `test_e2e_demo_seed_populates_every_surface` confirms every
surface has content after `demo.load_demo_fleet()` — Identity ≥ 2
configured, NHIs ≥ 6, execution jobs ≥ 6, and at least one stale-NHI
finding visible on the API.

If any link in the chain regresses, this test fails before users notice.

## [9.35.0] — 2026-05-06

### Execute section: closes the "looks real but isn't" gaps

Same audit-then-fix exercise we ran on identity in v9.33-v9.34. The
audit (`docs/v9.35-execute-audit.md`) found five real half-baked
items behind features that *looked* like they worked.

#### #1 — Audit doc

`docs/v9.35-execute-audit.md` captures the surface inventory, the
strong trust posture pieces (RBAC no-self-approve, multi-approver
for CRITICAL, blocked-commands list, Tier-3 triple-gate, emergency
stop), and the gaps fixed below.

#### #2 — Real rollback plan generator

The plan generator existed but only knew 7 invert patterns; many
real commands fell through to a `# REVIEW` TODO that the operator
never saw because the `/rollback` UI didn't show the plan before
clicking. Now:

- **`_INVERT_PATTERNS` expanded from 7 to ~45 entries** covering
  Cisco IOS / NX-OS, Arista EOS, Junos (set↔delete symmetric),
  Palo Alto, FortiGate.
- **Remainder-preserving inversion** — `ip route 10/8 1.1.1.1` now
  correctly inverts to `no ip route 10/8 1.1.1.1` (was producing a
  truncated `no ip route ` before).
- **Interface blocks** are flagged for manual review instead of
  auto-inverted to `no interface` (which would delete the interface).
- **`GET /api/execute/jobs/{id}/rollback-plan`** surfaces the
  persisted plan so operators can review.
- **`/rollback` UI** now shows the inverted commands per-vendor in
  a slide-over BEFORE the operator clicks "Submit rollback". A
  banner counts `# REVIEW` lines that need manual edits.

9 new tests pin every inversion pattern.

#### #3 — Real `/per-device-diff` viewer

`/per-device-diff` was a table of executions, not a config diff.
Now:

- New `pre_config_snapshot` + `post_config_snapshot` fields on
  `CommandExecution`.
- New **`GET /api/execute/jobs/{id}/config-diff`** endpoint —
  computes unified-diff per execution + added/removed line counts.
- `/per-device-diff?job=<id>` triggers the new mode: per-asset
  card with vendor pill, dry-run badge, +/- counts, color-coded
  unified diff. Empty-snapshot case is surfaced honestly ("Tier-3
  SSH didn't capture them").
- Asset-A vs Asset-B drift mode preserved.

#### #4 — Approval notifications

`workflow.request_approval()` wrote the `ApprovalRequest` record
but didn't notify anyone. Now wires to the existing notifier infra
(Slack / Teams / PagerDuty / generic HMAC webhook) with a
structured payload: `{kind, severity, title, summary, job_id,
risk, target_count, requested_by, link}`. Severity escalates to
`critical` for CRITICAL-risk jobs. Best-effort: failure never
breaks the workflow.

#### #5 — Builder AI fallback

`builder.py` docstring promised an AI fallback when offline packs
miss; the code path didn't exist. Now wired:

- `_try_ai_fallback()` calls `safecadence.ai.client` with
  detect-provider (OpenAI / Anthropic / Ollama).
- Honors `SC_AI_DISABLED=1` for air-gap.
- AI-translated commands go through the **same preflight
  guardrails** as pack-driven plans — no bypass.
- Marks `plan.matched_packs = ["ai_fallback"]` and the summary
  warns "Review carefully — AI output is unverified."
- System prompt explicitly disallows destructive commands.

#### #6 — Tier-3 SSH output capture

The Tier-3 paramiko executor now:

- **Captures pre/post running-config** per asset via vendor-aware
  `show running-config` (or Junos `show configuration | display
  set`, FortiGate `show full-configuration`, Palo Alto `show
  config running`). Attaches to the execution so #3's diff viewer
  lights up automatically.
- **Vendor error pattern detection** — scans output for `% Invalid
  input`, `Incomplete command`, `Authorization failed`, `Syntax
  error`, etc. — most network CLIs don't set non-zero exit codes,
  so pattern-matching is the only way to detect failed config
  pushes. Detected patterns become structured `issues` and
  escalate the effective exit code so the queue UI flags the row.

#### #7 — Rate-limiting (audit was wrong)

The audit flagged this as missing, but Tier-3's `_rate_gate()`
already enforces `Job.rate_limit_per_minute` between asset
executions via a token-bucket. No code change. Audit doc updated.

#### Tests

13 new tests cover:

- 9 rollback inversion patterns (no-prefix flip, shutdown↔, route
  remainder preservation, reverse order, interface review marker,
  Junos set↔delete, unknown→REVIEW, comment skipping, multi-vendor).
- 2 builder AI fallback (skipped when disabled, skipped when no
  provider).
- 2 approval notification (skipped when no webhook, payload shape
  + severity escalation).

Full suites unchanged: 626 tests passing across the touched
slices (policy + identity + link + compliance).

#### Trust property

Same theme as v9.33. Features that *looked* like they worked but
behaved like no-ops under load are now backed by real code paths
+ tests that pin the property. The audit doc is preserved in
`docs/` so future work has the truth, not the marketing.

---

## [9.34.2] — 2026-05-06

### Connect form UX hardening (operator-reported)

The first time someone tried the v9.34 Connect form against Okta,
three real UX bugs surfaced. All fixed:

#### 1. Browser autocomplete leaked the SafeCadence login into the target field

Chrome happily autofilled `admin` (the SafeCadence bootstrap
username) into the Okta domain field, which then failed
test_connection with a DNS resolution error. The target field had
no `autocomplete="off"` and no `name` Chrome would treat as
unfamiliar. Fix: every input in the slide-over now carries
`autocomplete="off"`, `autocorrect="off"`, `autocapitalize="off"`,
`spellcheck="false"`, plus `data-lpignore="true"` and
`data-1p-ignore` to also stop LastPass and 1Password.

#### 2. "Save & sync" button looked active when it was disabled

The button had the `disabled` attribute (so clicking did nothing)
but the CSS didn't grey it out — visually it looked identical to
an active button. New `_setSaveBtnEnabled()` helper drives both the
attribute AND `opacity` + `cursor`, so disabled clearly looks
disabled. Initial render also now ships with the visual disabled
state.

#### 3. Raw socket errors leaked to the operator

`[Errno 8] nodename nor servname provided, or not known` is
correct but useless. The `/api/identity/connect` endpoint now
inspects the underlying error string and returns a `hint` field
when it can translate:

* DNS resolution failure → "Could not resolve `<target>`. The
  Okta target should be a fully-qualified hostname like the
  placeholder example, not a username or single word."
* `401 Unauthorized` → "Credentials were rejected by the target.
  Check the API token / client secret and the scope it was
  issued with."
* `403 Forbidden` → "The target accepted the credentials but
  refused the request. The token may not have the read scope
  required for sync."
* TLS / certificate failure → hostname or verify_ssl hint.
* Timeout → firewall + reachability hint.

The UI's failure card surfaces the hint prominently above a
collapsed `<details>` with the raw error for debugging.

#### 4. Client-side target validation

Catches the autofill foot-gun before any network call. Single
words ("admin"), values without a `.`, and whitespace are
rejected with a message pointing at the expected format
(`acme.okta.com` for Okta, `ldap://host` or `ldaps://host` for AD).

#### Tests

Two new HTTP tests pin the translation:

* `test_connect_failure_returns_friendly_dns_hint` — fakes the
  `[Errno 8]` Okta error and asserts the response includes the
  "Could not resolve" hint plus the raw error.
* `test_connect_failure_translates_401_to_credentials_hint` —
  401 → credential/scope hint.

All 266 identity + link-audit tests still passing.

---

## [9.34.1] — 2026-05-06

### Closes the v9.34 loose ends

v9.34 shipped the connect → test → save → sync flow. v9.34.1 closes
three pieces that were one-shot in v9.34 and would have been
operationally fragile.

#### Daemon NHI stale-finder (#1)

`daemon.run_cycle` now calls `nhi_store.stale_findings()` each
cycle and merges the results into the main findings stream.
Compliance hooks dict gets a new `nhi_stale_findings_emitted`
counter for observability. Best-effort — a failure here never
aborts the cycle. Without this, stale findings only fired when
something hit `GET /api/identity/nhi/findings` directly.

#### Daemon auto-resync for connected identity systems (#2)

`daemon.run_cycle` now iterates `IdentityVault().list_connected()`
and runs `collect → normalize → save_asset` for each system.
Each system is isolated — one slow Okta cycle never blocks AD.
Compliance hooks dict gets `identity_systems_resynced` (count) and
`identity_resync_errors` (per-system error map). Read-only against
targets; write-back stays on the separate confirm_token-gated
path. Without this, "last synced 2s ago" became "last synced 4
hours ago" the moment the operator walked away.

#### CLI parity (#3)

New commands mirror the v9.34 HTTP endpoints so headless setups
work identically to the UI:

```
safecadence identity connect <system> --target X --cred K=V --save
safecadence identity sync <system>
safecadence identity disconnect <system>
safecadence identity nhi list [--include-deprecated]
safecadence identity nhi add --name X [--owner Y --rotation-days N]
safecadence identity nhi attest <nhi_id> [--by user]
safecadence identity nhi rotate <nhi_id>
safecadence identity nhi findings [--stale-days N]
```

Same vault, same adapter, same trust property — `connect` runs
`adapter.test_connection()` first, only persists on `--save` and
only after a passing test.

#### Tests

Three new daemon-hook tests pin the behavior:
* `test_daemon_runs_nhi_stale_finder` — stale NHIs land in the
  cycle's findings list with `kind=nhi_stale`.
* `test_daemon_resyncs_connected_identity_systems` — connected
  systems get exactly one collect+normalize+save_asset call per
  cycle and the vault's `last_synced_at` updates.
* `test_daemon_resync_isolates_per_system_failures` — Okta's
  collect raising sets `identity_resync_errors[okta]` but the
  cycle still completes. Defends the "best-effort" property.

Full suite: **875 tests passing** (212 identity + 421
policy/link/compliance/v9_32 + 242 other). No regressions.

#### Trust property of the v9.34.1 release

Same as v9.34, with one addition: the daemon's auto-resync runs
read-only adapter calls in the background. It cannot mutate any
target system — write-back is a separate code path requiring an
explicit `apply_policy` call gated by the v9.33 confirm_token.

---

## [9.34.0] — 2026-05-06

### Identity goes from "promise" to "actually does the thing"

v9.33 closed the trust holes. v9.34 closes the value-loop hole: the
identity pages had no way to actually pull data from a real Okta /
Entra / ISE / ClearPass / AD without setting env vars on the server
process. After v9.34, the operator opens `/identity` → Connect →
fills a form → Test Connection → Save & Sync — and the synced data
lights up `/access`, `/paths`, `/findings`, the connector strip, and
the NHI tab.

Designed to work against real systems. The user has nothing to test
against locally, so we tested every code path with adapter stubs that
match each vendor's real API shape, and ran the FULL Connect → Test →
Save → Sync flow as an integration test. The first time someone
points this at a real Okta, the wire is already proven.

#### Identity credential vault (#2)

- New `safecadence.identity.vault.IdentityVault` — Fernet-encrypted
  SQLite, one record per system, upsert-on-save semantics.
- Master-key auto-bootstrap. First run generates
  `~/.safecadence/.identity_vault.key` (chmod 600); operators can
  override with `SAFECADENCE_VAULT_KEY` env. **No hardcoded fallback.**
- `save_creds()` raises `ValueError` if `test_passed=False`. The vault
  *physically cannot* hold un-tested credentials.
- `list_connected()` returns metadata only — system / target /
  last_test_at / last_test_ok / last_synced_at. The actual
  credential dict never appears in this output. One of the tests
  pins the property by JSON-serializing the result and asserting the
  secret value is absent.

#### Real Connect form + Test Connection endpoint (#1)

- **`POST /api/identity/connect`** — body `{system, target,
  credentials, mode}`. `mode=test_only` instantiates the real
  adapter, calls `adapter.test_connection()` (one outbound HTTP/LDAP
  call), returns ok/error **without ever touching the vault.**
  `mode=save` runs the test first, persists only on success.
- **`POST /api/identity/disconnect/{system}`** — idempotent removal.
- `_adapter_for(target)` now reads from the vault first, falls back
  to env vars. Existing env-var-based deployments keep working.
- `/api/identity/connectors-status` now reports
  `source: "vault" | "env" | "none"` so the UI can show "connected"
  honestly when creds came from the vault, vs "missing 3/3 env" when
  nothing's set.
- UI: `openConnectSlide` rewritten as a real form picker with
  per-system field schemas (Okta domain + token, Entra tenant +
  client ID + secret, ISE host + ERS user/pass, ClearPass host +
  OAuth client, AD server + bind DN + base DN). Includes Test
  Connection button (gates Save), inline result panel for
  ok/error/stale-token cases.

#### Initial sync workflow (#3)

- **`POST /api/identity/sync/{system}`** — loads creds from vault,
  builds the adapter, calls `adapter.collect()` (real network),
  `adapter.normalize()`, `save_asset()`. The synced UnifiedAsset
  lands in `list_assets()` so every existing surface
  (`/api/identity/findings`, `/attack-paths`, `/who-can`,
  EffectivePermissionResolver) reads it without modification.
- Returns a sync receipt with per-bucket counts.
- Marks the vault record's `last_synced_at` so the connector strip
  shows "last synced 2s ago" honestly.
- 502 on adapter collect failure with no asset written — defends
  against partial-state writes.
- 409 on sync against an unconnected system.

#### NHI tab + lifecycle (#5, deferred from v9.33)

- New `safecadence.identity.nhi_store` — JSON-backed CRUD under
  `$SC_DATA_DIR/nhi/`. Per-record fields: name, subtype, provider,
  owner, last_used_at, last_rotated_at, rotation_policy_days,
  attested_at/by, deprecated.
- Lifecycle ops: `register`, `attest`, `rotate`, `mark_used`,
  `deprecate`.
- Stale-finder: `nhi_store.stale_findings()` returns finding dicts
  for NHIs unused beyond `stale_unused_days` (default 90) and
  rotation-overdue NHIs (when `last_rotated_at + rotation_policy_days
  < now`). Deprecated NHIs are excluded.
- HTTP: `GET /api/identity/nhi`, `POST /api/identity/nhi`,
  `POST /api/identity/nhi/{id}/attest`, `POST .../rotate`,
  `POST .../deprecate`, `GET /api/identity/nhi/findings`.
- UI: new "Non-human identities" section on `/identity` with list
  table (name, subtype, owner, last rotated, attested, per-row
  Attest + Rotated buttons). Manual-add slide-over with subtype
  picker, owner field, rotation cadence input.

#### Tests

- 9 vault tests (round-trip, refuses-without-test-passed,
  upsert-not-duplicate, never-leaks-secrets, master-key bootstrap).
- 8 connect-endpoint tests (test-only doesn't persist, save persists
  only after pass, **failure does not persist**, unknown system,
  empty credentials, writer-gated, disconnect, connectors-status
  promotes vault).
- 8 sync-endpoint tests (unconnected→409, calls collect+normalize
  exactly once, persists asset, marks `last_synced_at`, **collect
  failure→502 with no asset written**, error-dict→502, writer-gated).
- 2 end-to-end integration tests (full connect→sync→surfaces wiring;
  disconnect flips status correctly).
- 11 NHI tests (round-trip, lifecycle ops, stale-finder, deprecated
  excluded, rotation-overdue, HTTP CRUD, writer-gated).
- All 304+ identity tests pass; full link-audit + compliance suites
  unchanged.

#### Trust property of the v9.34 release

End-to-end:

1. Test Connection makes exactly one outbound call. No persistence
   on failure (HTTP and vault both enforce this).
2. Save only happens after a passing test. Multiple-layer defense:
   `vault.save_creds(test_passed=True)` raises if False, the HTTP
   handler runs the test before save, and the integration test
   pins the property end-to-end.
3. Sync is read-only against the target. Write-back is a separate
   path (`apply_policy`), still gated by the v9.33 confirm_token.
4. No secret ever appears in any list endpoint or status payload.
5. NHI lifecycle is opt-in: nothing auto-registers; the operator
   adds NHIs manually or via sync from a connected system.

---

## [9.33.0] — 2026-05-06

### Identity, action-first + trustworthy by default

The headline of v9.33 is the trust posture for identity write-back.
Before this release, anyone with a writer token could POST `apply: true`
against `/api/identity/apply` and commit straight to Okta/AD/Entra/ISE/
ClearPass without first running a dry-run; the audit had also wrongly
claimed transactional rollback worked across all 5 adapters when in
fact none of them implemented `_rollback`. Both holes are closed.

#### Trust foundation

- **Audit doc** (`docs/v9.33-write-back-audit.md`) — surface map of
  every write-back path (adapter, transactional, HTTP, CLI, UI) with
  default-behavior table and the gaps the rest of v9.33 closes.
- **Confirm-token gate**
  (`safecadence.identity.confirm_token`) — every dry-run mints an
  HMAC-signed token bound to (IR hash, scope, actor, TTL=10min,
  adapter version). Every commit requires that token. Mismatch on
  any field returns HTTP 409 with the specific reason. Wired through
  `IdentityWriteBackMixin.apply_policy`, `transactional.apply_all`,
  `/api/identity/apply`, `/api/identity/apply-all`,
  `/api/identity/auto-fix/{id}`. Trust property: an external
  identity system **cannot** be mutated without (a) a fresh dry-run
  by the same operator against the exact same IR + target set, and
  (b) the operator presenting the resulting token within 10 minutes.
- **Real `_rollback()` on all 5 adapters** — Okta DELETEs each
  group rule; ISE DELETEs each authz rule; ClearPass drops the
  policy first then the profile (dependency order); AD/LDAP emits a
  `MODIFY_DELETE` against the same group DN; Entra DELETEs each CA
  policy. 404 is treated as already-gone so partial rollback can
  finish what's left. Each returns a typed receipt.
- **Per-system diff card on /findings** — auto-fix flow no longer
  fires `alert("ok")`. The dry-run renders a slide-over with target
  pill, op-by-op cards (severity badge + summary + expandable
  payload), warnings, and a single "I've reviewed this — commit"
  button that posts the confirm_token. Stale-token (409) shows
  "Preview is stale" with a "Re-run dry-run" CTA.

#### Action-first /identity

- **/identity rebuilt** in v9 chrome (supersedes the old
  `identity_ui.py` translator-only page). Three-card hero band:
  Auto-detect, Connect a system, Add NHI manually. Connector status
  strip shows "0 of 5 connected" with the missing env-var count per
  adapter. "Next 3 actions" panel sorts identity findings by
  severity and surfaces the top 3 with deep-link Resolve buttons.
  Translator + JIT widgets preserved.
- **`POST /api/identity/discover`** — exposes the existing
  `safecadence.identity.discover` probe over HTTP. Read-only,
  returns confidence + env-var recipe per finding.
- **`GET /api/identity/connectors-status`** — surfaces which of the
  5 adapters has all required env vars set; honest "not yet" rather
  than fake "ready".
- **/jit** gets a 3-card hero band (active / expiring / expired-
  awaiting-revoke); **/paths** gets a hero band (total / critical /
  worst-terminal-asset); both feed off the same endpoints they
  already use.
- **New /access page** — Who-can-reach-X surface powered by the
  existing `EffectivePermissionResolver`. Type a resource + action,
  get the verdict (ALLOW/DENY), the systems consulted, the per-rule
  chain, and a Revoke CTA that funnels into the diff-card flow.

#### Tests + housekeeping

- 17 new confirm-token tests (`test_v9_33_confirm_token.py`):
  round-trip, missing/expired/forged token, IR mismatch, scope
  mismatch, actor mismatch, scope canonicalization, dry-run mints,
  commit-without-token rejected, multi-target aggregate token,
  target-set substitution attack defended.
- 9 new rollback tests (`test_v9_33_rollback.py`): per-adapter
  URL/DN shape pinning, partial-failure error handling, end-to-end
  test that proves `apply_all` invokes the real Okta `_rollback()`
  on partial failure (not the old "no rollback hook" stub).
- 7 existing identity tests updated to mint→commit pattern.
- Link-audit + selfcheck seeds extended to `/access`.

#### Deferred to v9.34 (called out so it isn't half-baked)

- Real per-system **connect** slide-overs with form-based test-
  connection + encrypted vault writes. v9.33 ships env-var recipe
  cards as the v0 form factor; the encrypted-vault test-connection
  plumbing was scoped out to keep v9.33 honest.
- **Dedicated NHI tab + lifecycle** (#10–#12) — needs a new NHI
  store, owner attestation workflow, rotation tracking, stale
  finder, and per-NHI attack-path drill-down. Each is a real chunk
  of work; rather than ship surface-level stubs, the whole NHI
  lifecycle moves to v9.34.

#### Trust property

No new outbound network calls. The confirm-token gate uses the
existing `SC_JWT_SECRET` (no new key management). The discover
endpoint runs the same probes the CLI ran in v7.8 — local
DNS/LAN/Graph; no telemetry. Rollback is best-effort with explicit
404-as-already-gone semantics so partial rollback can finish.

---

## [9.32.1] — 2026-05-06

### Fixed — `/drift` is now a real three-tab roll-up

Through 9.32.0, `/drift` only surfaced cross-system divergences (Okta
vs AD vs Entra). The two more important sources — *policy drift* and
*baseline drift* — were collected by their respective modules but
never landed on the page. This patch wires all three together.

- **New `/api/drift/all` endpoint** (`safecadence.server.platform_api`)
  — unified roll-up across the three drift sources with a single
  summary block (`{policy, baseline, cross_system, summary{total,
  by_severity}}`). The `/drift` page now reads this and renders three
  tabs with per-row remediate buttons.
- **Policy-drift wiring bug** — `/api/drift/all` was importing from
  `safecadence.policy.persistence` (which doesn't exist) and reading
  the wrong key (`drift` instead of `regressions`). Fixed: imports
  from `safecadence.policy.store` and reads the actual `regressions`
  field that `detect_drift()` returns.
- **Daemon policy-eval persist hook** — `daemon.run_cycle` now calls
  `evaluate_policy()` + `persist_evaluation()` on every cycle so
  `detect_drift()` has at least two history points to compare. Without
  this, `/drift`'s policy tab was permanently empty even when configs
  visibly drifted. Best-effort: a bad policy never aborts the cycle.
- **Demo gold-standard baseline** — `safecadence demo` now seeds a
  baseline that intentionally differs from the running configs so the
  Baseline tab populates on first run instead of looking dead.

### Added — `/vendors` UI page (back-end shipped in 9.32.0, page missed)

The vendor-risk module landed in 9.32.0 with full backend + tests but
the UI page was never built. This patch closes the loop:

- `GET /vendors` — full page with summary cards (count, attestations
  expiring soon, residual-risk distribution), vendor list with status
  pills, slide-over create form, slide-over add-attestation flow.
- Sidebar nav entry under Compliance group; respects the
  compliance-off toggle (hides when compliance is off).
- Live-wired to the existing `/api/compliance/vendors*` endpoints.

### Added — `/policies/new` raw-YAML editor (back-end shipped in 9.32.0)

Same story for the manual YAML policy editor: `quick.py` + the API
endpoint shipped in 9.32.0 but no UI page existed. Now:

- `GET /policies/new` — split-screen layout: YAML editor on the left,
  live vendor-rendered preview on the right (re-renders on every
  keystroke via `/api/policy/preview-config`).
- Save posts to `/api/policy/quick` with `mode=report_only` by
  default — never auto-enforces a hand-written policy on first save.
- Sidebar entry under Compliance.

### Added — Test coverage for the new wiring

- `test_api_drift_all_returns_three_buckets_with_summary` — asserts
  the three buckets + summary always exist (UI relies on the keys).
- `test_api_drift_all_requires_auth` — 401/403 without a bearer token.
- `test_daemon_persists_policy_evaluations_in_run_cycle` — proves
  the hook is wired and always emits the counter, even at zero.
- Link-audit + selfcheck seeds expanded to crawl `/vendors` and
  `/policies/new`.

### Trust property

No new outbound network calls. The `/drift` rebuild and the two new
pages all read from existing local stores. The daemon policy-eval
hook is best-effort; an individual bad policy never aborts the cycle.

---

## [9.32.0] — 2026-05-06

### Added — Differentiation features + trust artifacts

This release ships ten new capabilities and the trust-posture
artifacts a serious security buyer expects to see before evaluating
unknown software. Every feature was designed with an explicit trust
property; the release notes call them out per item.

#### Brownfield + cross-vendor (the "we have an existing fleet" wedge)
- **Brownfield policy import** (`safecadence.policy.import_from_configs`)
  — point at a directory of vendor configs, get back the *implicit*
  policy: which SafeCadence controls each device already enforces,
  aggregated across the fleet with a configurable quorum (default
  60%). Generates a YAML the operator reviews in `report_only` mode
  before activating. **Trust property: read-only — never modifies
  the source configs.** Endpoints `/api/policy/import-from-config`,
  `/api/policy/import-from-fleet`.
- **Cross-vendor policy migration** (`safecadence.policy.migrate`)
  — take an abstract control list from Vendor A, render the
  equivalent for Vendor B using the v9.31 preview pack. Surfaces
  what migrated cleanly, what was lost, and what notes apply.
  **Trust property: produces a draft for review — never applies
  changes.** Endpoint `/api/policy/migrate`.

#### Policy authoring (the "we want control" wedge)
- **Policy change approval workflow** (`safecadence.policy.changes`)
  — every edit logs a change record (before/after, requested_by,
  timestamp) and stays `pending` until an approver acts. SOX-like
  per-change audit trail. **Trust property: every mutation has a
  durable, signed record.** Endpoints `/api/policy/changes` (GET/POST),
  `/api/policy/changes/{id}/approve` and `.../reject`.
- **Multi-team RBAC for policies** (`safecadence.policy.rbac`) —
  scope tag per policy (network | cloud | identity | backup |
  server | storage | *), role-to-scope mapping, default roles
  shipped (policy_admin, netops_admin, cloud_admin, iam_admin,
  storage_admin, viewer). **Trust property: enforces least-
  privilege at policy edit time.** Endpoints `/api/policy/rbac`.

#### Compliance depth
- **Vendor risk module** (`safecadence.compliance.vendor_risk`)
  — track third-party vendors, their attestations (SOC 2,
  ISO 27001, PCI, HIPAA, FedRAMP, HITRUST), expiry dates, residual
  risk. Daemon flags expiring attestations as findings.
  **Trust property: SOC 2 CC9 / ISO 27001 A.5.19 first-class
  artifact.** Endpoints `/api/compliance/vendors` (GET/POST/DELETE),
  `/api/compliance/vendors/{id}/attestations` (POST).
- **Data classification** (`safecadence.compliance.data_classification`)
  — tag assets with PII / PHI / PCI / IP / CUI / Internal / Public.
  Risk multiplier feeds the Safe Score. Fleet-wide rollup endpoint.
  **Trust property: scope reduction — encrypt-sensitive-data
  controls now know what "sensitive" means.** Endpoints
  `/api/compliance/data-classification/catalog` and `.../summary`.
- **Scheduled evidence pack generation**
  (`safecadence.compliance.evidence_schedule`) — cron-style
  schedules (daily / weekly / monthly / quarterly), daemon fires
  due ones, packs auto-append to the v9.31 hash chain, optionally
  email via SMTP (only if `SC_SMTP_HOST` is set — air-gap-safe by
  default). **Trust property: continuous Type-2 evidence with
  tamper-evident chain.** Endpoints
  `/api/compliance/evidence-schedule` (GET/POST/DELETE).

#### AI-explain a finding (BYO-AI, transparent)
- **Plain-English explanations** (`safecadence.ai.explain_finding`)
  — sends the finding to the operator-configured AI provider
  (Anthropic / OpenAI / local Ollama). Returns the EXACT prompt
  that was sent, the model name, and a `network_used` flag so the
  operator can verify the air-gap claim. Honors `SC_AI_DISABLED=1`
  to force the offline rule-based path. **Trust property: BYO-AI
  with full prompt transparency. Air-gap-safe by default.**
  Endpoint `/api/findings/explain`.

#### Trust artifacts (the artifacts a security buyer asks for)
- **`SECURITY.md`** — vulnerability reporting policy, response SLA,
  scope, trust posture by design (no telemetry, no phone-home,
  no auto-update), cryptographic posture summary, build verification
  steps, PGP key placeholder. RFC-9116 aligned.
- **`docs/THREAT_MODEL.md`** — STRIDE summary across spoofing /
  tampering / repudiation / information-disclosure / DoS / EoP.
  Adversary table, trust boundaries diagram, mitigations per
  surface, explicit "things we do not protect against" section.
- **`/.well-known/security.txt`** — RFC 9116 disclosure pointer
  served by the FastAPI app.
- **`/api/trust/posture`** — live trust-posture report. Surfaces
  every property a buyer's security team would otherwise have to
  grep for: telemetry off, AI air-gap status, evidence chain
  integrity, outbound-call gating list, version. One curl, full
  posture.
- **`scripts/generate_sbom.py`** — generates a CycloneDX 1.5 SBOM
  for SafeCadence + every installed dependency. Hand-rolled (no
  cyclonedx-py runtime dep) so it works in air-gap. Output ships
  next to the wheel + sdist on every release.

#### Daemon
- New cycle hook fires `evidence_schedule.run_due_schedules()` so
  scheduled evidence packs generate automatically. `compliance_hooks`
  in the cycle report now includes `evidence_schedules_fired`.

### Tests
- `tests/test_v9_32.py` — 22 module-level tests covering brownfield
  import, cross-vendor migration, change approval, RBAC, vendor
  risk, data classification, AI explain (offline path), and
  scheduled evidence. Trust properties are tested explicitly:
  AI must return `network_used=False` when disabled; secrets must
  not appear in list responses; chain integrity holds across writes.
- Total suite: **802 passing** (753 module + 49 link-audit).

## [9.31.0] — 2026-05-06

### Added — Cleanup, "policy without compliance" UX, and demo seeding
The 9.30 cycle landed the compliance suite as eight new modules. 9.31
glues those modules into the daemon, evidence pack, and demo loader,
adds HTTP-level tests, and ships five new policy-authoring surfaces
that make the engine usable without the compliance framing.

#### Daemon + evidence integration
- **Daemon hooks for compliance lifecycle** — every cycle now calls
  `auto_expire_past_due()`, `expiring_exceptions_as_findings(within_days=14)`,
  `drift_findings_for_fleet()`, and `control_history.record(...)`. The
  synthetic findings flow through the existing notifier path — Slack,
  Teams, PagerDuty, Splunk all see them automatically. New
  `compliance_hooks` block in the cycle report.
- **Evidence pack auto-appends to the hash chain** —
  `evidence_pack.generate()` now writes a tamper-evident chain entry
  for every PDF it produces. Auditors can `verify_content(pack_id, bytes)`
  to confirm the PDF you served matches the chain.

#### Tests
- **`tests/test_compliance_api.py`** — 24 HTTP-level tests that boot the
  real FastAPI app, log in, and hit every `/api/compliance/*` and
  `/api/policy/*` endpoint. Catches wiring bugs the module tests can't.
- Fixed a subtle issue: `from __future__ import annotations` caused
  `req: Request` parameters in async POST handlers to be mis-parsed as
  required query parameters because `Request` lived in `register()`'s
  local scope. Promoted the import to module level so FastAPI's
  annotation resolver finds it.

#### Demo seeding
- **`safecadence demo`** now seeds the v9.27..v9.30 surfaces:
    * 4 risk register entries spanning network, server, identity, backup
    * 2 exception lifecycle records (one near re-review boundary)
    * 30 days × 6 controls = 180 control test history records
    * 3 baselines for the first three network assets
    * 3 evidence chain links across SOC 2 / ISO 27001 / NIST 800-53
  First-run `/compliance`, `/risks`, `/scores`, `/evidence` no longer
  show empty tables.

#### Policy without compliance
- **Compliance-off mode** — `SC_COMPLIANCE_MODE=off` env (or
  `POST /api/settings/compliance-mode {"enabled": false}`) hides
  `/compliance`, `/risks`, `/evidence` from the sidebar. Policy engine,
  Safe Score, posture, drift, attack paths all stay live. New endpoints
  `GET/POST /api/settings/compliance-mode`.
- **Quick-policy authoring** — `safecadence.policy.quick.quick_author()`
  + `POST /api/policy/quick`. Author a policy in one shot from a target
  group + control list. Defaults to `mode=report_only` so the policy
  emits findings without enforcing for a soak period before flipping
  to `enforce`. List/delete via `GET/DELETE /api/policy/quick`.
- **Policy dry-run / report-only mode** — `set_mode(policy_id, mode)`
  switches a policy between `enforce | report_only | disabled`. The
  evaluator reads the flag and skips remediation when in report-only.
  New endpoint `POST /api/policy/{id}/mode`.
- **Live vendor-native config preview** — `render_for_vendor()` ships
  preview snippets for 5 vendors (cisco-ios, juniper-junos,
  paloalto-panos, fortinet-fortios, arista-eos) covering ~8 logical
  controls each. Endpoint `POST /api/policy/preview-config` for
  split-screen authoring UIs. Real translators still kick in at
  enforce-time; this is the *shape preview*.
- **Per-asset policy sandbox** — `simulate_on_asset()` applies a
  proposed policy to ONE asset and returns
  `{would_pass, would_change, would_fail_to_render, rendered_preview}`.
  Reuses the v9.26 best-practice evaluator to detect what the asset
  is already passing, so the diff is honest. Endpoint
  `POST /api/policy/sandbox/{asset_id}`.

#### README
- Full rewrite. Replaces v5.x-era marketing with an honest current-
  state summary: what `/home` looks like, the seven sidebar groups,
  the four deploy paths, the killer-features list (Safe Score 2.0 /
  Weak Link / posture / vendor hardening / software currency /
  compliance suite / Splunk-out / per-device diff / continuous
  discovery / quick-policy / selfcheck), the comparison table vs.
  Tenable / AlgoSec / Drata, and the test summary.

### Total suite: 780+ passing
Module tests + 49 link-audit tests + 24 HTTP-level compliance API
tests. Recursive crawl of the running app reports zero broken nav
links or non-HTML responses.

## [9.30.0] — 2026-05-06

### Compliance Suite
This release rolls four planned cycles into one: v9.27 (control
mapping + coverage page), v9.28 (SLA + exceptions + control history),
v9.29 (risk register + baseline drift), v9.30 (auditor portal +
evidence tamper-evidence). Eight new modules under
`safecadence.compliance/`, two new YAML data packs, sixteen new API
endpoints, two new UI pages.

#### v9.27 — Control mappings + /compliance page
- **`data/control_mappings.yaml`** — every existing SafeCadence
  control mapped to NIST 800-53 r5, CIS Controls v8, PCI-DSS 4.0,
  HIPAA, ISO 27001:2022, and SOC 2 TSC. Each entry also carries owner
  default, severity-based SLA defaults, frequency, and evidence type.
- **`safecadence.compliance.mappings`** — loader + coverage math
  (`list_frameworks`, `coverage`, `control_detail`,
  `framework_detail`, `all_metadata_for_control`).
- **`/compliance`** page — framework picker, coverage matrix, drill
  into any SafeCadence control to see all six framework mappings +
  metadata.
- **API**: `GET /api/compliance/frameworks`,
  `/api/compliance/coverage/{framework}`,
  `/api/compliance/control/{id}`.

#### v9.28 — SLA + exception lifecycle + control test history
- **`compliance.sla`** — `annotate_finding`, `breach_summary`,
  `sla_breaches_as_findings`. Severity → SLA pulled from the control
  mapping pack (per-control overrides) with platform-default fallback.
  Resolved findings don't breach.
- **`compliance.exception_lifecycle`** — file-backed exception store
  at `$SC_DATA_DIR/exceptions.json`. Every exception carries
  justification, `accepted_by`, `expires_at`, `re_review_at`. Daemon
  can promote expiring exceptions to findings via
  `expiring_exceptions_as_findings`.
- **`compliance.control_history`** — JSON-lines append-only log of
  every control evaluation. `summary_for_evidence_pack` produces the
  per-control "tested N times, passed M" Type 2 artifact auditors
  expect.
- **API**: `/api/compliance/sla` (summary + annotated),
  `/api/compliance/exceptions` (GET/POST/DELETE),
  `/api/compliance/control-history/{id}`,
  `/api/compliance/control-history-summary`.

#### v9.29 — Risk register + config-baseline drift
- **`compliance.risk_register`** — file-backed register with
  `Risk(title, description, owner, domain, likelihood, impact,
  control_ids, mitigation, status)`. Inherent score = L × I; residual
  = inherent × (1 - control_strength) where control_strength comes
  from real pass-rates in `control_history`. Bands at 3/6/12/20
  thresholds.
- **`/risks`** page — heatmap summary, sortable table, slide-over
  create form.
- **`compliance.baseline_drift`** — declared baseline per asset at
  `$SC_DATA_DIR/baselines/<id>.txt`. Line-level diff with vendor-
  agnostic noise filter (timestamps, dynamic counters). Promotes
  drift to findings via `drift_findings_for_fleet` so it flows
  through Splunk / Slack like everything else.
- **API**: `/api/compliance/risks` (GET/POST/DELETE),
  `/api/compliance/baseline/{asset_id}` (GET/POST).

#### v9.30 — Auditor portal + evidence tamper-evidence
- **`compliance.auditor_portal`** — issue scope-tagged tokens for
  audit firms. Secret returned ONCE (only the SHA-256 hash is
  persisted). Configurable scope (default: /compliance, /evidence,
  /scores, /findings, /policies). Time-bound (1–180 days). HMAC-safe
  comparison. Auto-expire-on-verify.
- **`compliance.evidence_chain`** — append-only hash chain at
  `$SC_DATA_DIR/evidence_chain.jsonl`. Each entry stores
  `pack_id`, `framework`, `content_sha256`, `prev_hash`,
  `record_hash`. `verify_chain()` walks the file and detects any
  retroactive tampering. `verify_content(pack_id, bytes)` proves a
  served pack matches what was chained.
- **API**: `/api/compliance/auditor/tokens` (GET/POST/DELETE),
  `/api/compliance/evidence-chain` (GET),
  `/api/compliance/evidence-chain/append` (POST).

### Sidebar
- New "Compliance" + "Risk register" entries under the Compliance
  group. `/compliance` and `/risks` added to `safecadence selfcheck`
  and the link-audit test seed.

### Tests
- `tests/test_compliance.py` — 29 new tests (mappings, SLA breach
  detection, exception create/revoke/expire, control history
  append + summary, risk register score math + residual reduction,
  baseline drift add/remove + path-traversal block, auditor portal
  scope enforcement + revoke, evidence chain tamper detection +
  content round-trip).
- Total suite: **756 passing**.

## [9.26.0] — 2026-05-06

### Added — Safe Score 2.0
Three-layer formula replaces the v9.24 "100 minus deductions" model
that gave every untouched asset a 100 and rewarded nothing:

  displayed_score = clamp(posture_credit + 100 - risk_deductions, 0..100)
  confidence      = signal_completeness × recency

- **Posture credit (+up to 20)** — Microsoft Secure Score / ISE
  Posture analog. New module `safecadence.scores.posture` evaluates
  declarative checks from `data/posture_controls.yaml` (17 controls
  shipping covering endpoint, identity, network gear, cloud, backup).
  Each satisfied control adds points. Adding a new control is a YAML
  edit, not a code change. No `eval()`, no callbacks — six match
  ops only: `eq`, `ne`, `in`, `not_in`, `truthy`, `gte`, `lte`,
  `regex`.
- **Vendor hardening checks (best practice)** — new module
  `safecadence.scores.best_practice`. First pack
  (`data/best_practice_cisco_ios.yaml`) is 15 Cisco IOS / IOS-XE
  hardening checks aligned to CIS and the Cisco hardening guide
  (AAA, SSH v2, no telnet, logging, NTP, no default SNMP communities,
  enable secret, login block-for, etc.). Each pack is per-vendor;
  drop in a new YAML to support a new platform.
- **Software currency** — `safecadence.scores.software_currency`
  reads `data/software_currency.yaml` (8 vendors seeded: Cisco IOS /
  IOS-XE / NX-OS / ASA, Juniper Junos, Arista EOS, PAN-OS, FortiOS,
  Aruba AOS-CX) and classifies each asset as
  `current | supported | behind | eol | kev_vulnerable | unknown`.
  EOL uses train-aware comparison ("16.6.1 is in the 16.6 train"),
  KEV-known versions are flagged as the strongest signal.
- **Confidence (0..1)** — explicit "we know enough about this asset
  to score it" axis. Combines `last_seen` recency, presence of a
  collected running config, and availability of findings/CVE/path
  data. Below 0.3 the UI renders `—` with a tooltip listing what's
  missing instead of a misleading 100.

### New API endpoints
- `GET /api/scores/posture/{asset_id}` — posture-credit breakdown
- `GET /api/scores/best-practice/{asset_id}` — vendor hardening pass/fail
- `GET /api/scores/software-currency/{asset_id}` — version status

### UI
- Asset cockpit gains a "Safe Score breakdown" card showing posture
  credit / vendor hardening compliance / software currency status.
- The cockpit's Safe Score badge now renders `—` with a "low
  confidence" hint when confidence < 0.3 instead of a confident-
  looking 100.

### Tests
- `tests/test_safe_score_v9_26.py` — 14 tests covering posture
  evaluation across asset types, Cisco IOS best-practice pack,
  software-currency for current/EOL/KEV cases, and confidence math.
- Total suite: **725 passing**.

## [9.25.0] — 2026-05-06

### Added — Score history, real trend, Splunk settings UI, /scores page
- **Score history store** (`safecadence.scores.history`) — daemon
  writes a snapshot of fleet + per-asset Safe Score every cycle into
  `$SC_DATA_DIR/score_history.json`. 90-day retention with hard cap
  at 1,000 snapshots. New helpers: `append_snapshot`, `fleet_history`,
  `asset_history`, `trend`.
- **Real trend on /home** — replaces v9.24's band-letter pill with
  "↑ +3 this week" computed from the actual snapshot history. Falls
  back to the band letter if there's not enough history yet. Plus an
  inline 30-day SVG sparkline next to the score circle.
- **`/scores` leaderboard page** — full per-asset table sortable by
  score, fleet headline, 30-day fleet-trend chart with the 50/80
  band thresholds drawn as dashed reference lines. "Snapshot now"
  link for first-run convenience.
- **History API endpoints** — `/api/scores/safe/history`,
  `/api/scores/safe/{asset_id}/history`, and a manual
  `/api/scores/safe/snapshot` POST.
- **Splunk settings panel** — finished UX for the v9.24 HEC notifier.
  HEC URL / token / index / source / sourcetype / enabled-toggle in
  the existing Settings tab. Token field is masked on read; submitting
  the masked value preserves the real one (so editing other fields
  doesn't clobber the credential). New endpoints
  `/api/settings/splunk` (GET/POST) and `/api/settings/splunk/test`
  for sending a canary event.
- **Settings store** (`safecadence.settings`) — file-backed JSON at
  `$SAFECADENCE_HOME/settings.json`, env vars still win.

### Changed
- `safecadence selfcheck` and the link-audit test now seed `/scores`
  so the new page is guarded against future 404 regressions.

### Tests
- `tests/test_score_history.py` — 6 tests (append/read, retention,
  trend math, asset filter, clear).
- `tests/test_settings.py` — 6 tests (defaults, roundtrip, token
  masking, mask-preserve on resave, env override, explicit clear).
- Total suite: **710 passing**.

## [9.24.0] — 2026-05-06

### Added — Safe Score, Weak Link, Splunk-out
- **Safe Score** — single 0-100 number per asset (and a criticality-weighted
  fleet aggregate) that composes findings, KEV/EPSS/CVSS-prioritized CVEs,
  attack-path membership, drift, and missing controls. Lives in
  `safecadence.scores.safe`. Pure function; deterministic; every deduction
  carries a reason for the "why this number" tooltip. Surfaced at three
  places:
    * `/home` headline (replaces the old random-trended compliance number)
    * `/inventory` as a sortable column
    * Asset cockpit (`/asset/{id}`) identity strip
  Three new endpoints: `/api/scores/safe`, `/api/scores/safe/{id}`,
  `/api/scores/weak-link`.
- **Weak Link hero card** on `/home` — finds the single asset whose
  remediation collapses the most attack paths, and renders the sentence
  "Fix edge-fw-01 and 7 paths collapse — fleet Safe score climbs 64 → 78".
  Uses the projected fleet score (recomputed pretending the weak-link
  asset is clean) to make the lift concrete.
- **Splunk HEC notifier** — `notify_splunk_hec()` sits alongside the
  existing Slack / Teams / PagerDuty / generic notifiers. Newline-
  delimited JSON envelopes, `Authorization: Splunk <token>`, configurable
  source / sourcetype / index. Mock-tested with httpx.MockTransport;
  no real network in tests.

### Tests
- `tests/test_safe_score.py` — 16 unit tests (per-asset, fleet,
  criticality-weighted aggregate, weak-link math, projected score
  recomputation, JSON serialization).
- `tests/test_splunk_hec.py` — 4 tests covering envelope shape, auth
  header, non-2xx handling, network errors caught.
- Total suite: **698 passing**.

## [9.23.0] — 2026-05-06

### Added
- **`safecadence selfcheck`** — new CLI subcommand that crawls a running
  server, follows every internal link from the v9 sidebar, and reports
  any 404s or navigation links that serve JSON instead of HTML
  (the regression class we hit in v9.16.1). Supports `--json` for CI use.
- **Six graduated pages** — `/drift`, `/evidence`, `/builder`,
  `/approvals`, `/queue`, and `/rollback` are now real v9-chromed pages
  backed by their respective APIs (`/api/policy/cross-system-drift`,
  `/api/platform/evidence-pack`, `/api/execute/builder/*`,
  `/api/execute/jobs`, `/api/execute/queue`). Each has explicit empty
  states that link to the right adjacent feature instead of the
  legacy-UI fallback.
- **`/discovery-jobs`** now surfaces `last_error` as a hover tooltip on
  jobs whose last status was `error` — failures from the daemon hook
  are now visible without tailing `~/.safecadence/daemon.log`.

### Changed
- Removed the duplicate `/per-device-diff` registration that lived in
  both the real-page block and the stub list (real page won, but the
  dupe was confusing). The link-audit test now guards against
  duplicate GET-route registrations.

## [9.22.0] — 2026-05-05

### Added
- **`/per-device-diff`** graduated from stub to real page. A/B device
  picker, fetches `raw_collection.running` for both, computes an
  O(N+M) line diff with green-add / red-delete highlighting, supports
  `?a=...&b=...` deep-links plus a swap button.
- **`tests/test_link_audit.py`** — 46 link-audit tests that boot the
  real FastAPI app, crawl every sidebar-reachable page, and assert
  no 404s or JSON-on-nav links. Catches the v9.16.1 / v9.20.1
  regression class in CI.
- **15 unit tests for v9.17/v9.18/v9.19 intel modules**
  (`coverage`, `fleet_changes`, `discovery_jobs`) under
  `tests/test_v9_intel_modules.py`.

### Fixed
- **Daemon scheduling hook** — `daemon.run_cycle()` now calls
  `_run_due_discovery_jobs()` each cycle and dispatches to the right
  harvester (lan-scan / snmp / ad / entra / dhcp / aws / azure / gcp),
  with `mark_run` ok/error feedback to the job store.
- Added missing `import sys` in `daemon.py` (NameError fix).

## [5.1.0] — 2026-05-04

### Added
- **Unified local UI sidebar** — `safecadence ui` now shows three new sections:
  **Audit (v2)**, **Platform (v4) ★** (9 tabs), and **Policy (v5) ★**
  (7 tabs). Sidebar version label bumped from `v2.3.0` → `v5.1.0`. Each new
  tab iframe-mounts the matching v4/v5 dashboard and deep-links via URL hash.
- **One-command installer** — `install.sh` auto-detects pipx / pip / docker
  on macOS, Linux, and Windows-bash. `--docker`, `--pipx`, `--pip`,
  `--no-launch`, and `--help` flags. Pure bash, no curl-piped sudo.
- **Docker first-class** — Dockerfile labels refreshed to advertise v5.0
  capabilities. Image republishable as `safecadence/netrisk:5.1.0` and
  `:latest` (multi-arch amd64 + arm64).

### Changed
- Platform + Policy UIs now skip the `Authorization` header when no JWT is
  in `localStorage`, so the same code works in both server (bearer-auth)
  and local-UI (no-auth) modes.
- Local UI app mounts `/api/platform/*` (15 routes) and `/api/policy/*`
  (25 routes) with stub auth, alongside the existing v2 endpoints.
- Removed duplicate `/api/platform/ui` registration in `server/app.py`.

### Fixed
- `safecadence.policy.__init__` now re-exports `PolicyState`,
  `PolicyException`, `RemediationStep` so `policy_api` can import them
  from the top-level package.

## [5.0.0] — 2026-05-04

### Added — Policy Intelligence Engine
- 22 atomic security controls across network/server/cloud/storage/backup
- 10 starter policy templates (network hardening, firewall baseline,
  router/switch baseline, server hardening, cloud security, logging &
  monitoring, identity & access, encryption, backup security, zero trust)
- AI policy interpreter — plain English → structured `SecurityPolicy`
  (offline keyword path always works)
- 12 multi-vendor config translators (cisco_ios, cisco_nxos, cisco_asa,
  arista_eos, juniper_junos, fortinet_fortios, paloalto_panos, linux,
  windows, aws_iam, azure, gcp)
- Compliance evaluator + drift detection + remediation engine
- 7 export formats (raw, ansible, terraform, powershell, bash, markdown, pdf)
- 10 advanced features: GitOps, exception/risk-acceptance, what-if
  simulator, custom controls, CVE-driven auto-policies, attestation
  reports, multi-env variants, webhooks, shadow-IT detection, testing
- Compliance framework mappings — NIST 800-53, CIS, PCI-DSS, HIPAA, ISO 27001
- `/api/policy/*` REST surface (~25 endpoints)
- 7-tab Policy UI dashboard at `/api/policy/ui`
- `safecadence policy ...` CLI (15 subcommands)
- 64 unit tests pass

## [4.0.0] — 2026-05-04

### Added — Complete Device Intelligence Platform
- 40 vendor adapters across 6 infrastructure domains (was 25 in v3.1)
  - Network (8), Servers (6), Storage (9), Virtualization (5),
    Cloud (6), Backup (6)
- Platform REST surface at `/api/platform/*` — 15 endpoints
- Cross-domain correlation engine — VM → host → datastore → array → backup
  chains, orphan + toxic-combo detection
- 10 platform reports — lifecycle, security posture, capacity, backup
  compliance, vendor inventory, EOL/EOS, health summary, risk register,
  cloud exposure, executive overview
- 9-tab platform UI dashboard at `/api/platform/ui`

## [3.1.0] — 2026-05-03

### Added
- 19 additional vendor adapters bringing the total to 25 across all
  6 infrastructure domains.

## [3.0.0] — 2026-05-03

### Added
- Device Intelligence Platform foundation: `UnifiedAsset` schema,
  `BaseAdapter` registry, `ConnectionManager`, `PlatformVault`,
  4-dimensional health scoring, `dell_idrac` reference adapter (Redfish).

## [2.4.0] — 2026-05-03

### Added
- **CVE matching** wired into discover output. Every identified device now
  carries a `cves` array sorted KEV-first. Risk score auto-boosts when
  CISA-KEV-listed CVEs match.
- **AI deep-analyze** (`/api/discover/ai-analyze`) — per-device BYO-LLM
  analysis returning structured JSON: identification, threat assessment,
  validated CVEs (no hallucination), prioritized actions with exact CLI
  commands, compliance impact, executive summary. Click 🤖 on any row.
- **AI remediation playbook** (`/api/discover/playbook`) — generates a
  vendor-specific Markdown playbook with pre-checks, exact commands,
  verification, rollback, time estimate. Copyable to runbook/ticket.
- **Management report** (`/api/discover/management-report`) — multi-section
  exec-grade HTML with cover page, KPI grid, inline-SVG donut + bar charts,
  per-device cards for critical/high devices, top-CVEs table, top-actions
  table, NIST/CIS/PCI/HIPAA compliance auto-mapping. Print-perfect to PDF.
  Designed to match or beat output from Tenable / Qualys / Rapid7.
- **SNMP v2c sysDescr probe** — pure-stdlib BER encoder. Tries common
  community strings (public, private, etc.). When successful, extracts
  vendor, model, OS, version in one shot. Biggest single identification win.
- **Device categorization** — heuristic classifier combining MAC OUI, port
  patterns, banners, mDNS services, SNMP sysDescr → router | switch |
  firewall | wireless-ap | printer | camera | nas | iot | media | voip |
  server-linux | server-windows | workstation-mac | workstation-windows |
  mobile-ios | mobile-android | unknown.
- **Per-device risk scoring** — 0-100 + band (safe/low/medium/high/critical)
  with explicit findings list and recommended actions. 13 port-based rules,
  default-credential checks, TLS heuristics, KEV-CVE boost.
- **LAN deep-scan mode** — combines ARP cache + mDNS Bonjour + extended
  TCP ports + TLS cert subject + HTTP page-title scrape. Finds devices
  that don't open any TCP port (sleeping IoT, printers in standby).

### UI
- Subnet sweep now shows risk badges, sorted highest-risk-first
- CVE column with KEV indicator
- Click any row for full per-device detail (findings + actions + CVEs)
- 🤖 button per row for AI deep-analysis
- 📋 button for remediation playbook
- 📊 Management report button generates exec-grade HTML

### Fixed
- `/api/discover` 500 — was iterating DiscoveryResult instead of .hosts

## [2.3.0] — 2026-05-03

### Added
- **`safecadence ui` — local web UI with full CLI parity.** Single-user,
  no-auth FastAPI server bundled with the package. Multi-tab SPA covering:
  - **Dashboard** — fleet KPIs, recent devices, scoring at a glance
  - **Scan** — drag-drop config files, live results with vendor-specific
    fix snippets and severity grouping
  - **Devices** — fleet list with drill-down per device
  - **History** — recent scans with health/risk trends
  - **Discover** — subnet sweep UI (multi-threaded TCP)
  - **CVEs** — KEV-aware searchable catalog with NVD links
  - **EOL** — end-of-life trains with past-EOS highlighting
  - **AI explainer** — BYO OpenAI / Anthropic / Ollama key, executive briefings
  - **Vault** — encrypted credential management UI
  - **Rule library** — searchable rule browser grouped by vendor
  - **Vendors** — registered adapter inventory
  - **Settings** — refresh threat intel feeds, server info
- All UI routes are localhost-only by default. No telemetry. Same SQLite
  storage the CLI writes to (`~/.safecadence/ui.sqlite`), so a scan run
  from the UI shows up in `safecadence history` and vice-versa.
- Single-file HTML+JS, no CDN dependencies (works air-gapped).

### Changed
- Bumped to v2.3.0 (minor version bump for the new UI feature surface).

### Install
- `pip install safecadence-netrisk` then `safecadence ui` to launch.
- The UI requires the `[server]` extras (FastAPI + uvicorn). Install with
  `pip install 'safecadence-netrisk[server]'` if you only installed core.

## [2.2.2] — 2026-05-03

First public PyPI release. Install with `pip install safecadence-netrisk`.

### Fixed
- `pyproject.toml`: corrected `[project.scripts2]` typo to `[project.scripts]`
  so the `safecadence` CLI command is properly registered when pip-installed.

### Changed
- Renamed PyPI distribution from `safecadence-network-risk` to `safecadence-netrisk`
  (shorter, fits PyPI naming conventions). The Python import path is unchanged
  (`import safecadence`); only the package name on PyPI moves.
- README updated with live PyPI version + downloads badges.

### Notes
- Same functional code as 2.2.0; 2.2.1 was a rename-only attempt that never
  landed on PyPI due to the auth setup process.
- The package was previously installable via `pip install git+https://github.com/famousleads/safecadence-network-risk.git`;
  that still works for tracking `main`, but `pip install safecadence-netrisk`
  is now the recommended path for a stable release.

## [0.1.0] — 2026-05-02

Initial public release.

### Added
- **Network discovery engine** (`safecadence discover <cidr>`) — multi-threaded
  TCP sweep over any CIDR, banner-grab on common management ports, OUI-based
  MAC-vendor lookup, and heuristic OS / device-type identification. No raw
  sockets, no root required. Identifies Cisco IOS / IOS-XE / NX-OS / ASA,
  Aruba, Arista, Juniper, Fortinet, Palo Alto, MikroTik, Ubiquiti, Meraki,
  Mist, plus generic Linux / Windows / printers / IoT.
- Vendor adapter framework (`BaseAdapter`, `AdapterRegistry`) with auto-discovery.
- **Five vendor adapters** with pure-stdlib parsers:
  - Cisco IOS / IOS-XE
  - Cisco NX-OS (Nexus)
  - Cisco ASA Firewall
  - Aruba CX (AOS-CX)
  - Arista EOS
- **Config audit engine** that loads YAML rule packs and runs three rule types:
  `match_regex`, `absent_regex`, and sandboxed `custom` Python expressions.
- **77 audit rules** total, shipping out of the box:
  - 34 Cisco IOS rules
  - 11 Cisco NX-OS rules
  - 11 Cisco ASA rules
  - 10 Aruba CX rules
  - 11 Arista EOS rules
- Deterministic **Health (0–100)** and **Risk (0–100)** scoring with bands and
  business-criticality multipliers.
- **Four report formats**:
  - Rich-formatted CLI table (color, summary panel)
  - Portable Markdown (`--output`)
  - Machine-readable JSON (`--json`)
  - Self-contained, brand-able HTML (`--html`)
  - Microsoft Word .docx (`--docx`) — pure stdlib, no external deps
- **Bring-Your-Own-Key AI** module — talks directly to OpenAI or Anthropic
  from the user's machine. Keys never touch SafeCadence servers. Supports
  `--output` to save the briefing as Markdown.
- CLI: `safecadence scan | discover | list-vendors | list-rules | rule-info | ai-explain | history`.
- Optional local SQLite scan history (`--save-history`).
- Sample configs for every vendor in `examples/sample_configs/`.
- 66-test pytest suite covering parsers, registry auto-discovery, rule
  loading, scan-to-score pipeline, every renderer, characteristic-rule
  spot checks for each vendor, and the network discovery engine
  (OUI lookup, banner heuristics, sweep with mock TCP listener).
- Convenience `Makefile` (`make install | scan | ai | report | test | shell`).
- GitHub Actions CI matrix (Python 3.10/3.11/3.12) with smoke tests.

### Privacy promises
- The CLI never makes network calls except to the BYOK AI provider you
  explicitly opt into.
- API keys are read from environment variables or `--api-key` only, with
  whitespace trimmed defensively.
- All findings stay on disk unless you run `--save-history`.
