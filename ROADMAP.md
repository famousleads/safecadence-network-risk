# SafeCadence NetRisk — Roadmap

This file documents the planned evolution from v10.4 onward. Versions are
*targets*, not commitments — real-world timing depends on customer feedback,
funding, and how much rope each release gives us.

**Current**: v10.4.0 (May 2026) — Office-grade reports, scheduled & scriptable,
compliance depth (NIS2 / FedRAMP / CMMC + SLA + audit trail), inventory polish.

---

## v10.5 — Foundation (target: 2 weeks)

The point of v10.5 is to make NetRisk *deployable for more than one user*.
Nothing in v10.6+ matters until this lands.

- **Magic-link auth** — reuse the SecurityAlgo `app/platform/auth.py` pattern.
  Email-based, no passwords. Sessions in HttpOnly cookies.
- **Per-org data isolation** — replace the single `~/.safecadence/` dir with
  `~/.safecadence/orgs/<org_id>/`. All reads + writes scoped by tenant.
- **Org-scoped share tokens** — share links work only within the same org.
- **Audit log** — append-only `~/.safecadence/orgs/<org_id>/audit.jsonl` of
  every report generation, template save, share link issued.
- **RBAC** — three levels: viewer (read), editor (write), admin (settings + users).
- **Prometheus `/metrics` endpoint** — request counts, latencies, queue depth.
- **`/healthz/detail` dashboard** — DB status, disk space, scheduled-job age,
  recent errors.
- **Built-in error tracking** — Sentry-style local error log at
  `~/.safecadence/errors.jsonl`, last-100 visible in admin dashboard.
- **Fix `tests/test_link_audit.py`** — the 2 pre-existing failures on `/reports`
  route registration from the asset cockpit.

**Out of scope**: SAML/SSO (deferred to v10.6 Theme F), self-serve signup
(deferred to v10.9 commercialization).

---

## v10.6 — Intelligence + first integrations (target: 3 weeks)

- **Real OpenAI / Anthropic API calls** when keys are set. Env-gated, falls back
  to deterministic stubs. Replaces `ai_helpers.generate_executive_summary`,
  `explain_cve`, `detect_quick_wins`.
- **Per-finding "explain like I'm new here"** — natural-language expansion of any
  finding for non-technical readers.
- **Natural-language inventory query** — "show me all internet-facing assets with
  KEV CVEs over CVSS 8".
- **Slack OAuth bot** — slash commands `/safecadence report exec_brief`,
  `/safecadence status`. Posts daily summaries to a configured channel.
- **Jira / Atlassian integration** — bidirectional. Create tickets from
  findings; status updates flow back when issues close.
- **Custom dashboard widgets** — admin can configure which KPI cards / charts
  appear on the home page per role.

---

## v10.7 — Scale + failover cluster (target: 4 weeks)

- **Redis-backed job queue** — replace the in-memory `_REPORT_JOBS` dict.
  Workers can run on separate machines.
- **PostgreSQL replacing SQLite** — required for any deployment with > 1 node.
  Streaming replication for the standby.
- **S3 / DO Spaces object store** — rendered reports + media stored centrally,
  not on the rendering node.
- **Stateless API layer** — sessions in Redis, no sticky disk state.
- **Active-passive failover cluster** — two droplets behind DO Load Balancer.
  Health-probe-driven failover (~30s). Postgres streaming replication for the
  hot standby. Adds ~$50/mo to hosting.
- **Daily encrypted backups to S3** — Postgres + media + config.
- **Continued integrations**: ServiceNow, Microsoft Teams bot, Splunk forwarder.

---

## v10.8 — Workflow + governance (target: 2 weeks)

For shops actually running this inside a compliance program.

- **Approval chains for risk acceptance** — CISO signoff before a finding can be
  marked as "accepted". Multi-step approvers configurable.
- **SOC 2 evidence collection** — auto-attach screenshots, scan logs, control
  test results to each control. Exportable as an auditor evidence package.
- **Change management hooks** — every config change creates a CR ticket; can be
  routed to Jira/ServiceNow.
- **Penetration test workflow** — planned date, scope definition, findings
  capture, signoff stage, gap-to-remediation tracking.
- **Continued integrations**: AWS Security Hub ingestion, SAML SSO (Okta, Azure
  AD, Google Workspace).

---

## v10.9 — Commercialization (target: 3 weeks)

After v10.5 you have multi-tenancy. v10.9 is what lets you charge for it.

- **Stripe subscriptions + billing** — plan tiers (Free / Pro / Enterprise).
- **Per-asset usage metering** — count tracked assets per org per day.
- **Self-service signup** — anyone hits safecadence.com → creates a tenant.
- **Customer portal** — `/billing`, `/team`, `/usage`, `/support`.
- **Pricing page + checkout** on safecadence.com.
- **14-day free trial** (no credit card).
- **Invoicing + receipts** + dunning when cards fail.
- **In-app upgrade prompts** when nearing plan limits.

---

## v11.0 — ML + analytical depth (target: 6 weeks)

The "AI" claims become real instead of just LLM wrappers.

- **Anomaly detection** on findings using statistical ML (Isolation Forest,
  z-score on time series).
- **Predictive risk scoring** — train on historical scan data to predict which
  assets will trend critical in 30 / 60 / 90 days.
- **Pattern recognition** — auto-cluster similar findings ("these 14 issues are
  the same root cause"). Privacy-preserving cross-tenant pattern learning.
- **Drift forecasting** — predict when configs will drift out of compliance.
- **Threat hunting playbooks** — guided investigations starting from a KEV.

---

## v11.1 — Mobile + accessibility (target: 6 weeks)

- **Mobile-responsive UI** — dashboard, inventory, reports wizard.
- **Native mobile apps** — iOS + Android via React Native. Glance dashboard,
  push notifications for critical findings.
- **PWA support** — installable, offline-capable.
- **Full WCAG 2.2 AA audit + fixes** — keyboard navigation, screen reader
  semantics, contrast, focus visibility.
- **Internationalization** — i18n framework + first translations (Spanish,
  French, German, Japanese).

---

## v11.2 — Developer experience (target: 3 weeks)

- **Public SDKs**: Python, JavaScript, Go. Auto-generated from OpenAPI 3.1.
- **Terraform provider** — `terraform-provider-safecadence`.
- **Helm chart** for Kubernetes deployment.
- **Docker Compose** for local dev.
- **OpenAPI 3.1 spec** generated from FastAPI, versioned.
- **API versioning + deprecation policy** documented.

---

## v11.3 — Operations + DR (target: 2 weeks)

- **Backup + restore** — proper snapshot/restore for tenant data.
- **Data export / portability** — Article 20 GDPR right to data portability.
  Full JSON export of everything for an org.
- **Documented disaster recovery runbook** — tested annually.
- **Bug bounty / responsible disclosure program** — HackerOne or Bugcrowd.
- **Immutable audit log** — append-only, integrity-checked with hash chains.
- **Per-org data retention policy** — auto-purge old scans on configurable cadence.

---

## v12.0 — Compliance certifications (target: 6-18 months, external)

This is what unlocks enterprise sales. Not code; process + paperwork + auditors.

- **SOC 2 Type II audit** — ~$30-50K, 6-9 month evidence-collection process.
- **ISO 27001 certification** — parallel track, similar cost.
- **GDPR compliance** + EU droplet for data residency.
- **HIPAA BAA support** for healthcare customers (requires SOC 2 first).
- **FedRAMP authorization** — only worth it if there's a federal pipeline.
  ~$250K, 18-24 months minimum.

---

## Ecosystem (continuous)

- Documentation site (Mintlify or Docusaurus).
- Blog + technical content marketing.
- Case studies + customer logos.
- Video tutorials for main workflows.
- Discord community.
- Marketplace for user-contributed presets, frameworks, vendor adapters.
- Plugin system.
- Partner program for consultancies.

---

## Things explicitly out of scope

- General-purpose CSPM (e.g. Wiz / Orca scope). NetRisk stays focused on
  network + identity policy.
- IDS / IPS functionality. NetRisk audits posture; it doesn't sit inline.
- Generic SIEM. We forward findings to existing SIEMs; we don't replace them.

---

*Last updated: 2026-05-10 alongside the v10.4 release.*
