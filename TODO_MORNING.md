# Morning TODO — needs your input before going live

Things I built tonight that are **code-complete but need a human decision
or external action** before they're actually usable in production. None of
these block the demo — they're for when you're ready to onboard real users.

## Critical-path decisions

### 1. Auth (v10.5)
- I built **magic-link email auth** as the only sign-in path.
- It requires a working SMTP provider. Set these env vars on the droplet:
  - `SC_SMTP_HOST` — e.g. `smtp.postmarkapp.com`
  - `SC_SMTP_PORT` — usually 587
  - `SC_SMTP_USER` / `SC_SMTP_PASS`
  - `SC_SMTP_FROM` — e.g. `noreply@safecadence.com`
- Pick a provider this week. My recommendation: **Postmark** ($15/mo,
  best deliverability for transactional). SendGrid and AWS SES also work.
- Until SMTP is configured, the wizard runs in `SC_AUTH_DISABLED=1` mode
  (the current behavior — anyone can hit `/reports`).

### 2. Multi-tenancy data layout
- I chose **shared SQLite with `org_id` column on every row** (simpler).
- Trade-off: a single corrupted DB takes down everyone. Acceptable for v1.
- If you'd rather do **one-SQLite-per-org**, ping me and I'll migrate. The
  abstraction layer in `safecadence.storage.org_store` already supports
  either backend.

### 3. Billing (v10.9 — code-complete this session)
- Full **Stripe billing module** is built: stdlib-only client, webhook
  HMAC verification, plan tiers, per-org quotas, usage metering, signup,
  customer portal at `/portal/*`, and a pricing page mirror at
  `outputs/safecadence-site/pricing/index.html`.
- Before going live you need to:
  1. Create the Stripe products in dashboard.stripe.com:
     - Pro ($49/mo) → copy the price id, set env `STRIPE_PRICE_PRO=price_xxx`.
     - Enterprise ($499/mo) → set `STRIPE_PRICE_ENTERPRISE=price_yyy`.
     - Free is in-process, no Stripe product needed.
  2. Copy the keys into env on the droplet:
     - `STRIPE_SECRET_KEY=sk_live_…` (or `sk_test_…` for staging).
     - `STRIPE_WEBHOOK_SECRET=whsec_…` (from the webhook endpoint config).
     - Optional: `STRIPE_PUBLIC_KEY=pk_live_…` if/when we add Stripe
       Elements UI inline.
  3. In Stripe dashboard → Webhooks → Add endpoint:
     - URL: `https://app.safecadence.com/api/billing/webhook`.
     - Events: `checkout.session.completed`,
       `customer.subscription.{created,updated,deleted}`,
       `invoice.{paid,payment_failed}`.
- Rsync the two HTML files from `outputs/safecadence-site/` onto the droplet
  at `/srv/safecadence/sites/safecadence.com/` before announcing. The
  pricing page is a static deliverable — no nginx/Caddy config change needed,
  it'll be served from the existing site root.
- Screenshot the pricing page at three breakpoints (375 / 768 / 1280) before
  the launch email goes out — copy + spacing need a once-over.
- Until Stripe keys are set, every billing endpoint returns
  `503 {"error":"billing_not_configured"}` and the signup flow falls back
  to a Free plan (paid plan signups complete but no checkout URL is generated).

### 4. Slack integration (v10.6)
- Built the OAuth flow + slash command handlers.
- You need to:
  1. Create a Slack app at api.slack.com/apps.
  2. Add OAuth scopes: `commands`, `chat:write`, `users:read`.
  3. Set Redirect URL: `https://app.safecadence.com/oauth/slack/callback`.
  4. Copy Client ID + Client Secret into env: `SLACK_CLIENT_ID` /
     `SLACK_CLIENT_SECRET`.
- Without these, the `/slack/install` button shows a placeholder error.

### 5. Jira integration (v10.6)
- OAuth 2.0 (3LO) flow built; same shape as Slack.
- Atlassian developer console → Create app → OAuth 2.0 → Get Client ID +
  Secret → put in env `JIRA_CLIENT_ID` / `JIRA_CLIENT_SECRET`.
- Redirect URL: `https://app.safecadence.com/oauth/jira/callback`.

### 6. OpenAI / Anthropic API keys (v10.6)
- Set `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY` env vars to enable real
  AI on executive summaries and CVE explanations. Without either, falls
  back to deterministic stubs (current behavior).

## Infrastructure to provision

### 7. Failover cluster (v10.7)
- Code is ready; needs the actual second droplet.
- DigitalOcean control panel → Create Droplet → same image as primary.
- Then:
  1. Create a DO Load Balancer ($12/mo).
  2. Add both droplets as backends.
  3. Set health check to `GET /healthz/detail` expecting 200.
  4. Update DNS for `analyzer.safecadence.com`, `studio.safecadence.com`,
     `demo.safecadence.com`, `app.safecadence.com` to point at the LB's IP
     instead of the primary droplet.
- Adds ~$50/mo to hosting.
- Postgres needs to be configured for streaming replication — I wrote a
  setup script at `deploy/postgres-replication-setup.sh`.

### 8. Redis (v10.7)
- For the background job queue.
- Option A: install on the primary droplet (`apt install redis-server`,
  ~5 min).
- Option B: DigitalOcean managed Redis ($15/mo, easier).
- Set `SC_REDIS_URL=redis://localhost:6379/0` on both droplets.

### 9. S3 / DO Spaces (v10.7)
- For rendered reports + media.
- DO Spaces: $5/mo for 250GB. Create one bucket per environment.
- Set `SC_S3_ENDPOINT`, `SC_S3_BUCKET`, `SC_S3_ACCESS_KEY`,
  `SC_S3_SECRET_KEY` env vars.

### 10. PostgreSQL (v10.7)
- Replacing SQLite for shared deployments.
- Option A: install on primary droplet (`apt install postgresql-16`).
- Option B: DO managed Postgres ($15/mo, includes backups, easier).
- I wrote a `safecadence migrate --from sqlite --to postgres` command to
  move existing data.

## External processes (months, not days)

### 11. SOC 2 Type II (v12.0)
- Pick an auditor: Vanta (~$15K/year, includes platform), Drata (similar),
  or a regional firm direct.
- 6-9 month evidence collection process.
- Will cost ~$30-50K total.

### 12. ISO 27001 (v12.0)
- Parallel track to SOC 2. Same auditor often handles both.

### 13. FedRAMP (v12.0)
- Only worth pursuing if you have a federal pipeline.
- 18-24 months, ~$250K. Requires a sponsoring federal agency.

### 14. Mobile native apps (v11.1)
- Code skeleton exists in `mobile/` (React Native).
- Submitting to App Store / Play Store needs:
  - Apple Developer account ($99/year).
  - Google Play Developer account ($25 one-time).
  - 1-4 weeks of review per store.
- I can't push these from here; you'll need to run `eas build` from a
  Mac with Xcode installed.

## Quick-wins you can do in 10 minutes each

- **Snapshot the droplet** through DO control panel (rollback insurance).
- **Star the GitHub repo** + ask the team to (algorithm signal).
- **Set up a status page** at BetterStack / UptimeRobot free tier.
- **Publish ROADMAP.md** as a public roadmap page on safecadence.com.
- **Set up the GitHub milestone for v10.5** so contributions can be tracked.

---

*Generated alongside the v10.5 → v11.3 build sprint. Re-generate as items
get checked off.*

---

# v10.5 — items that need a human touch (added 2026-05-10)

These ship with the v10.5 code but need an operator to wire the
environment before they go live in production.

## 1. SMTP env vars for magic-link login
The flow works locally with `SC_AUTH_DISABLED=1` (demo bypass) but in
real prod we need the same `SC_SMTP_*` env vars that already power
the report-email scheduler. On the droplet:

```
sudo systemctl edit safecadence-analyzer.service
# add:
[Service]
Environment=SC_SMTP_HOST=smtp.sendgrid.net
Environment=SC_SMTP_PORT=587
Environment=SC_SMTP_USER=apikey
Environment=SC_SMTP_PASS=...  # set via secret manager
Environment=SC_SMTP_FROM=no-reply@safecadence.com
Environment=SC_PUBLIC_URL=https://app.safecadence.com
```

Until those are set, `POST /login/request` returns
"SMTP not configured — set SC_SMTP_HOST, ..." and the demo bypass
keeps the public demo open.

## 2. Confirm demo continues to work
After deploy, hit `https://demo.safecadence.com/reports` — should still
load without a sign-in (the systemd unit has `SC_AUTH_DISABLED=1` in
its Environment block). If anyone forgot to set it on this droplet,
the demo will start asking for a login link nobody can receive.

## 3. /metrics scrape config (optional)
Once it's deployed you can point Prometheus / VictoriaMetrics /
Grafana Cloud Agent at `https://app.safecadence.com/metrics`. There's
no auth on `/metrics` right now (that's typical for in-VPC scrapes);
**if you expose this publicly, add Caddy basic auth in front**.

## 4. Migrate the demo to its own org
Right now the demo continues to read from the legacy global
`~/.safecadence/platform_assets/` dir because `compose_report()` is
called without `org_id`. The infra is in place to issue
`create_org("Demo", "demo@safecadence.com")` and start passing
`org_id=demo_org.id` through the wizard payload — but the wizard JS
doesn't yet send `org_id`. v10.6 candidate.

## 5. RBAC enforcement on real endpoints
The dependency factory `require_role(min_role)` exists and is unit-
tested, but no real endpoint depends on it yet (each call site needs
auditing first to make sure VIEWER-allowed reads aren't accidentally
fenced off). v10.6 candidate.

---

# 2026-05-10 — v10.6 follow-ups

## 6. LLM provider keys
- Real AI is **env-gated**. With nothing set, every call falls back to
  the deterministic stub (the demo behavior). To turn it on:
  - `OPENAI_API_KEY=…`  → `gpt-4o-mini` (default)
  - or `ANTHROPIC_API_KEY=…` → `claude-haiku-4-5-20251001`
- The droplet's `/etc/safecadence-demo.env` does **not** carry either
  key today, by design — `demo.safecadence.com` should keep using the
  stub path so we don't burn credits on anonymous traffic.
- For the paid analyzer/studio droplet, drop the key into
  `/etc/safecadence-analyzer.env` next time you SSH in, then
  `systemctl restart safecadence-analyzer`.

## 7. Slack app — register at api.slack.com
The OAuth flow is wired but Slack itself needs a registered app to
provide `SLACK_CLIENT_ID` + `SLACK_CLIENT_SECRET` + `SLACK_SIGNING_SECRET`.
Steps (15 minutes):
  1. https://api.slack.com/apps → **Create New App** → "From scratch".
  2. Bot scopes: `chat:write`, `commands`, `channels:read`, `team:read`.
  3. Add slash command `/safecadence` → request URL
     `https://app.safecadence.com/slack/commands`.
  4. OAuth redirect URL `https://app.safecadence.com/oauth/slack/callback`.
  5. Copy Client ID / Secret / Signing Secret into
     `/etc/safecadence-analyzer.env` and restart.
Until those env vars are set, `/oauth/slack/install` returns 503
`{"error":"not_configured"}` — install button can still be shown.

## 8. Jira / Atlassian Cloud — register at developer.atlassian.com
Same shape as Slack but Atlassian:
  1. https://developer.atlassian.com/console/myapps/ → **Create** →
     "OAuth 2.0 integration".
  2. Permissions: `read:jira-work`, `write:jira-work`, `read:jira-user`,
     `offline_access`.
  3. Callback URL `https://app.safecadence.com/oauth/jira/callback`.
  4. Copy Client ID/Secret into env, restart.
Optional: `JIRA_PROJECT_KEY` defaults to `SAFE`. Set it per-tenant if
multiple Jira projects are involved.

## 9. Dashboard widget UI
Backend is in place (`/api/v1/dashboard/widgets` GET/PUT, per-widget
GET). What's **not** built yet: a front-end editor for arranging the
widgets (drag/drop, type picker). For now you can hand-edit
`~/.safecadence/orgs/<org_id>/widgets.json` or PUT a payload to the
endpoint. v10.7 candidate to add a real UI.

## 10. Quick-wins endpoint is currently demo-only
`POST /api/reports/ai/quick-wins` returns ranked actions but nothing
in the wizard UI calls it yet. Consider adding a "Top fixes" card in
the preview step that consumes it — five-line JS change.


# 2026-05-10 — v10.7 follow-ups

All code is in place; these need **external action / provisioning**
before scale + failover actually kicks in. None of them block the
single-node demo — without these env vars, v10.7 behaves identically
to v10.6.

## 11. Install Redis on the active droplet
- One-liner: `apt-get install -y redis-server && systemctl enable --now redis-server`.
- Lock it down to localhost in `/etc/redis/redis.conf` (`bind 127.0.0.1`) until we move to two-node.
- Add to `/etc/safecadence-analyzer.env`:
  - `SC_REDIS_URL=redis://127.0.0.1:6379/0`
- Restart: `systemctl restart safecadence-analyzer`.
- Verify: `curl -s localhost:8002/healthz/detail | jq .redis_status` → should report `"ok"`.

## 12. Provision Postgres
- DigitalOcean Managed Postgres is fine: $15/mo for the 1-CPU/1GB/10GB option.
- Note the connection string (it includes `?sslmode=require`).
- On the droplet:
  - `pip install 'psycopg[binary]'` into the analyzer venv.
  - Add to env: `SC_POSTGRES_URL=postgresql://safe:…@db.example/safecadence?sslmode=require`
- Run the migrate command **once** from the droplet to bring history over:
  - `safecadence migrate --from sqlite --to postgres`
- Verify: `safecadence history list --limit 5` still returns rows; check Managed Postgres dashboard for new connections.

## 13. Create the DigitalOcean Spaces bucket
- DO control panel → Spaces → Create Bucket → `safecadence-reports`.
- Generate a Spaces access key/secret pair (separate from droplet API token).
- Env:
  - `SC_S3_ENDPOINT=https://nyc3.digitaloceanspaces.com`
  - `SC_S3_REGION=nyc3`
  - `SC_S3_BUCKET=safecadence-reports`
  - `SC_S3_ACCESS_KEY=…`
  - `SC_S3_SECRET_KEY=…`
- Smoke test: render any report from the wizard — the response URL should be `https://safecadence-reports.nyc3.digitaloceanspaces.com/…` instead of `file:///…`.
- CORS: set up bucket CORS for `https://app.safecadence.com` if browsers need to fetch report URLs directly. Otherwise leave it private and proxy through Caddy.

## 14. Stand up the DigitalOcean Load Balancer (optional, only when going active-passive)
- Follow `deploy/load-balancer.md` step by step.
- Two droplets in the same VPC.
- Run `deploy/postgres-replication-setup.sh` with `ROLE=primary` on droplet A, `ROLE=standby` on droplet B.
- Point `app.safecadence.com` at the LB hostname.
- Cost delta: ~$29/mo on top of the current single droplet.
- This is **not urgent** — we have the code, but a single droplet at $12/mo is fine until paid customer #5 or so.

## 15. ServiceNow / Teams / Splunk credentials
- ServiceNow: create a dedicated integration user with `itil` + `rest_api_explorer` roles; basic-auth password. Env:
  - `SC_SERVICENOW_INSTANCE`, `SC_SERVICENOW_USER`, `SC_SERVICENOW_PASS`.
- Teams: any Teams admin can create an Incoming Webhook on a channel; copy the URL. Env: `SC_TEAMS_WEBHOOK_URL`.
- Splunk: create an HTTP Event Collector token in Splunk Settings → Data inputs → HTTP Event Collector. Env: `SC_SPLUNK_HEC_URL`, `SC_SPLUNK_HEC_TOKEN`.
- Until those are set, every helper returns `None` and logs "not configured" at INFO — never crashes.


# 2026-05-10 — v10.8 follow-ups

All v10.8 code is in place; these are external actions / decisions
needed before each piece can serve a real production tenant.

## 16. SAML IdP registration (Okta / Azure AD / OneLogin)

`safecadence.auth.saml` is a **stub-level SP** — good for development
and lab integrations, **not** a substitute for `python3-saml` in a
hardened production deployment. Specifically:

- Signature verification uses HMAC-SHA256 over a custom canonicalised
  XML rendering of the assertion. Real IdPs sign with RSA-SHA256 over
  W3C XML-DSig exclusive canonicalisation (`exc-c14n`) — verifying
  that requires `xmlsec1` or `signxml`.
- No encrypted assertion support, no `InResponseTo` replay protection,
  and only the simplest single-attribute extractors.

What an operator needs to do to bring even the stub online:

1. Pick an IdP (Okta is fastest). Create a SAML 2.0 app:
   - SSO URL: `https://app.safecadence.com/auth/saml/acs`
   - Audience: the value you set in `SC_SAML_SP_ENTITY_ID`
   - NameID format: `EmailAddress`
   - Attribute statements: `email` (required), `groups` (optional).
2. Export the IdP metadata XML. Save its URL to
   `SC_SAML_IDP_METADATA_URL`.
3. Decide on a shared secret for the stub signature path and put it in
   `SC_SAML_IDP_SHARED_SECRET`. **The stub will reject every assertion
   without this secret** — that's by design (real signature verification
   isn't wired yet).
4. Set `SC_SAML_SP_ENTITY_ID` to match the audience.
5. Restart the analyzer service. Hit `GET /auth/saml/metadata` to grab
   the SP metadata for the IdP side.

**Action item before paying customers:** swap the stub for the real
`python3-saml` library. Track this as a v10.9 candidate.

## 17. AWS Security Hub IAM role + Caddy egress

`safecadence.integrations.aws_security_hub.ingest_findings()` calls the
Security Hub `/findings` endpoint with SigV4-signed requests. The droplet
needs:

- An IAM user (or assumed role) with `securityhub:GetFindings`. The
  least-privilege policy:

      {
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": "securityhub:GetFindings",
          "Resource": "*"
        }]
      }

- Env vars on the droplet:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_SESSION_TOKEN` (when using STS assumed roles)
  - `AWS_REGION=us-east-1` (or whatever region your Security Hub lives in)

- Verify with: `safecadence ingest aws-security-hub --region us-east-1 --max 5`.

If the droplet sits behind a strict egress firewall, add an allow rule
for `securityhub.<region>.amazonaws.com:443`.

## 18. SOC 2 evidence collection — operator process

The `safecadence.workflow.soc2_evidence` module is the box that holds
the evidence; auditors still want a *process* describing how evidence
lands in the box. Operator checklist:

1. Decide a refresh cadence per control (quarterly is typical for
   NIST 800-53; monthly for SOC 2 CC*).
2. Stand up a recurring calendar reminder for the security lead to
   `attach_evidence` for each control with the latest screenshot /
   policy snapshot / audit log export.
3. The `compose_report` auto-capture takes care of "report ran on
   <date>" evidence automatically when the scope carries `framework`
   + `controls`; document this in the auditor walkthrough so they
   know which entries are auto-captured vs manually attached.
4. `GET /api/v1/evidence/export?framework=NIST+800-53` produces the
   ZIP we hand the auditor; teach the security team to use the
   wizard's download button or hit the endpoint directly.

## 19. Approval chains — pick a default per org

`define_chain(org_id, name, role_steps)` is the building block; the
question is which chain to default to. Recommendation:

- `standard_risk_acceptance` → `[editor, admin]` (peer review + final).
- `regulated_risk_acceptance` → `[editor, admin, CISO]` (for HIPAA /
  PCI tenants). Note that `CISO` isn't a built-in RBAC role; assign
  members via `assign_custom_role(org_id, "CISO", email)`.

Bake those into the org-creation flow so new tenants don't start
without any chain defined.


# 2026-05-11 — v11.0 follow-ups

The v11.0 ML surface ships as heuristic + interpretable code. Every
function returns sensible answers on real data today, but the *real*
ML wins (better than 90% precision on drift forecast, learned
clusterings that match incident postmortems) require trained models
that we don't have yet.

What the v11.0.x point releases need to deliver:

1. **Risk model artifact** — collect labelled drift events from
   customer change-logs + matching outcomes (incident yes/no inside
   30 days). Train a gradient-boosted classifier offline, freeze it
   as `models/risk_30d_v1.json` (stdlib-loadable feature thresholds),
   ship it next to the heuristic so we can A/B the two scores side
   by side. Heuristic stays as the fallback when the trained model
   refuses (out-of-distribution / low coverage).

2. **Anomaly model** — the sliding z-score works on stationary
   series; production telemetry has trends + level shifts. Train a
   small STL-decomposition replacement (or a tiny LSTM artifact, if
   we accept a single torch dep) and ship the residuals-based
   detector behind the same `detect_anomalies` signature.

3. **Cluster labelling** — silhouette-picked k is good enough as a
   default. The customer-facing win is labelling each cluster ("MFA
   gaps on cloud admins", "ACL drift on east-region firewalls"). LLM
   call against the representative finding + member summaries; cache
   the label on the `Cluster` dataclass. Requires
   `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`.

4. **Drift forecast** — the inter-arrival heuristic understates risk
   when changes cluster. Switch to a Hawkes-process-style intensity
   estimator (still stdlib — it's ~80 lines).

5. **NLQ** — the rule parser hits ~70% on the demo phrasebook. Wire
   the LLM fallback into the wizard search bar and instrument
   `parse_failed` rate so we can see which phrasings deserve their
   own rule.

6. **Playbooks** — add `ransomware_response`, `data_exfil`, and
   `cloud_keys_leaked` next. Each one is ~120 lines of context-aware
   Step generation; the harder lift is wiring them into the
   `/api/v1/ml/playbook/{id}/run` UI so a SOC analyst can drive them
   from a finding card without a CLI.

7. **API quotas** — v10.9's UsageMeteringMiddleware counts every
   `/api/v1/ml/*` hit as an `api_calls` event. That's correct, but
   ML workloads burn quota fast. Add a separate `ml_calls` resource
   to `safecadence.billing.plans` for Pro/Enterprise so we can give
   ML a budget independent of the REST API.

The release notes should make clear that the v11.0 baseline is
heuristic on purpose: customers can use the platform productively
today, and every point release sharpens a specific module without
breaking the public interface.


---

# 2026-05-11 — v11.1 follow-ups

UI-quality release shipped tonight. Mostly safe-by-default polish — these
items are non-blocking, just the punch list for when you next sit down.

## Translations (i18n)

- The four stub catalogs (`es.json`, `fr.json`, `de.json`, `ja.json`) have
  ~25 keys each, all prefixed `[TODO-XX]`. **None of them are real
  translations** — they exist so the framework is provably wired.
- Pick a translation vendor (Smartling, Phrase, or a Fiverr translator
  with a security/SaaS background) and ship them `en.json` + a glossary
  of NetRisk terms (CVE, KEV, EPSS, EOL, drift, blast radius). Budget
  ~$0.10/word × 50 keys × 4 languages ≈ $200 for the seed catalog.
- Once translations come back, drop them into
  `src/safecadence/i18n/catalogs/<lang>.json` and the wizard will
  switch over with no code change.

## Mobile (React Native)

- `mobile/README.md` documents the init recipe. Don't run it until:
  1. Apple Developer Program account is active ($99/yr).
  2. Google Play Console account is active ($25 one-time).
  3. You decide whether the v1 app is read-only (recommended — much
     less App Store review friction) or read-write.
- PWA already covers the "Add to Home Screen" path on both iOS and
  Android. No native app needed for the public demo.

## Real PNG icons

- `manifest.json` ships SVG data-URL icons because we don't have PNG
  rasterizations yet. Most browsers accept SVG manifest icons; Safari
  on iOS prefers PNG.
- When you have time, rasterize the SVG at 192×192 and 512×512, save to
  `src/safecadence/ui/pwa/icon-192.png` and `icon-512.png`, and update
  the manifest `icons[].src` to `/static/icon-192.png` (you'll need to
  serve those via the same `/static/` route the responsive CSS uses).

## Accessibility — assistive tech smoke pass

- The audit in `src/safecadence/ui/accessibility.md` is static-only.
- Spend 30 min with VoiceOver (macOS Cmd+F5) walking the dashboard,
  inventory, and reports wizard. Capture anything weird in a follow-up
  v11.1.1 ticket.
- NVDA on Windows is the other free option.

## Severity-pill redundant cues

- Severity pills use color + text label. For colorblind users, add an
  icon prefix (•, ▲, ★) so the cue isn't color-only.
- Touch `_chrome.py` `.pill-crit / .pill-high / .pill-med` rules.

## Inventory table mobile expand-row

- Wired in CSS only. The actual "tap row → reveal extra columns" JS
  toggle isn't in v9_pages.py yet. The columns are simply hidden under
  768px right now. Add an `onclick` handler that toggles
  `.expanded` on `<tr>` when we next touch the inventory page.


# 2026-05-11 — v11.2 follow-ups

The v11.2 release shipped the scaffolds — these are the real-world
publish steps still to do:

## Python SDK — real PyPI publish

- `cd sdk/python && python -m build && twine upload dist/*`
- Verify install: `pip install safecadence-sdk` resolves to 0.1.0.
- Reserve the package name on TestPyPI first if not already taken.

## JavaScript SDK — real npm publish

- `cd sdk/js && npm install && npm run build && npm test`
- `npm publish --access public` (scope `@safecadence` must be created
  on the npm org first).

## Go SDK — Go module proxy

- Push a tag at the repo root: `git tag sdk/go/v0.1.0 && git push origin sdk/go/v0.1.0`.
- The Go module proxy will fetch automatically the first time someone
  runs `go get github.com/famousleads/safecadence-go@v0.1.0`.

## Terraform provider — Terraform Registry submission

- `cd terraform/provider-safecadence && go mod tidy && go build`
- Sign release artifacts with the registry-required GPG key.
- Submit to https://registry.terraform.io/ under the `famousleads` namespace.
- Note: registry publish requires a signed GitHub release, which means
  we need the GPG key in CI secrets first.

## Docker Hub publish

- `docker buildx build --platform linux/amd64,linux/arm64 -t famousleads/safecadence-netrisk:11.2.0 -t famousleads/safecadence-netrisk:latest --push .`
- Replaces the existing `fkarim1/netrisk` image; update docs to point
  at the new repo.

## Artifact Hub — Helm chart publish

- Set up a GitHub Pages branch (`gh-pages`) serving `index.yaml` +
  `*.tgz` archives.
- Run `helm package helm/safecadence-netrisk -d charts/` and `helm repo
  index charts/`.
- Register the repo URL with https://artifacthub.io/.

## OpenAPI export — wire into CI

- Add a GitHub Action step that runs `safecadence openapi export --out openapi.json`
  on every release tag, uploads as a release artifact, and triggers SDK
  code-gen for the JS + Go bindings.


# 2026-05-11 — v11.3 follow-ups

- **Set up the real `security@safecadence.com` mailbox.** The address is
  promised in `SECURITY.md` but no MX record yet routes it anywhere.
  Either point it at the operator (`famousleads@gmail.com`) via a
  forwarder, or mint a Google Workspace user. Until this lands, the
  bounty SLAs are aspirational, not honored.
- **Run a backup-restore test against production.** On the droplet:
  `sudo -u safecadence /srv/safecadence/apps/analyzer/.venv/bin/safecadence ops backup --out /var/backups/`
  then `… ops verify --from <path>` to confirm the manifest matches the
  tarball. Aim for one weekly via the existing scheduler (cron entry
  in `deploy/safecadence/` if we want it tracked in-repo).
- **Schedule the daily retention pass in production.** The scheduler
  hook (`reports/scheduler.py::_builtin_retention_pass`) already fires
  at 03:00 UTC, but it only runs when `safecadence report schedule
  daemon` is active. Confirm the systemd unit for that daemon is
  enabled on the droplet, OR add a separate `safecadence-retention.timer`
  if reports daemon isn't running.
- **Generate + publish the real PGP key.** `SECURITY.md` still ships a
  TBD fingerprint placeholder. Run `gpg --full-gen-key`, publish the
  public block, replace the placeholder.
- **Decide whether the v11.3 chained audit is opt-in or default for
  new writes.** Today, only callers that explicitly call
  `log_event_chained` get into the chained log. Sweep the ~6 sites
  that call `log_event` and decide which (if any) should ALSO call
  the chained version. Compliance use cases (signature requests,
  privileged config changes) are the obvious candidates.
