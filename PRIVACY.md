# SafeCadence Privacy Commitments

**Last updated:** 2026-05-25

This document describes how SafeCadence handles your data — both
the open-source software running on your infrastructure, and (when
applicable) the optional hosted services we run.

The headline:

> **SafeCadence is local-first by design. The software you install
> does not send your configuration data, scan results, findings, or
> any other operational data to us — or anyone — unless you
> explicitly enable a feature that does.**

The rest of this document spells out exactly what that means and
what the exceptions are.

---

## What the open-source software collects: nothing

When you install SafeCadence via `pip install safecadence-netrisk`
and run it on your own infrastructure:

- No telemetry of any kind is sent anywhere
- No "phone home" check-ins
- No usage statistics
- No automatic error reporting
- No anonymous analytics
- No "improve the product" data collection

Your scan data, your configs, your findings, your reports — all of
it lives entirely on the machine you installed SafeCadence on.

You can verify this by inspecting the code (it's MIT-licensed, all
on GitHub) or by running SafeCadence on an air-gapped network and
confirming there is no outbound traffic.

---

## Features that DO communicate externally — and only when enabled

Some SafeCadence features intentionally make external calls.
Every one of them is opt-in, documented, and listed here.

### LLM provider integration (v11.3+)

When you configure an LLM provider via `/settings/llm`, SafeCadence
sends prompt content to the LLM provider you chose. This is the
explicit purpose of the feature.

- **What gets sent:** structured KPI data (numbers, not raw configs)
  + the system prompt + your custom prompt customizations
- **What does NOT get sent:** raw configuration text, customer
  identifiers (unless you put them in the prompt), credentials of
  any kind
- **Where it goes:** the provider you selected (OpenAI / Anthropic /
  Google / Groq / Cloudflare / DeepSeek / etc.)
- **How to disable:** set provider to "None — disable AI" in
  `/settings/llm`, or never configure a key

When you use a **local LLM** (Ollama, LM Studio, local Hugging Face
model), nothing leaves your machine even with AI enabled.

### Webhook delivery (v9+)

When you configure outgoing webhooks (Slack, Teams, Jira, etc.),
SafeCadence POSTs finding/scan/drift events to the URL you specify.

- **What gets sent:** the structured event data you configured to
  send (you choose the payload via webhook templates)
- **Where it goes:** the URL you specified
- **How to disable:** don't configure webhooks, or remove configured
  ones from `/settings/webhooks`

### CVE feed updates (v10+)

SafeCadence pulls CVE data from public sources (NIST NVD, CISA KEV,
EPSS) so it can match scanned device versions against known
vulnerabilities.

- **What gets sent:** an HTTPS GET request to the feed URL. No data
  from your environment is included
- **What gets received:** public vulnerability data
- **Where it goes:** the public feed source
- **How to disable:** use the **air-gap distribution bundle** (v12+)
  which ships with offline-cached feeds, or block the feed URLs at
  your firewall (SafeCadence falls back gracefully)

### Stripe billing (v12+, paid features only)

If you sign up for a paid SafeCadence service (support contract,
hosted orchestration plane, etc.), Stripe processes your payment.

- **What gets sent:** to Stripe — your billing email, payment method,
  org name, plan selection. SafeCadence (the company) sees only what
  Stripe shows us via webhook events (subscription state changes,
  payment success/failure)
- **Where it goes:** Stripe (US-based, PCI DSS Level 1 compliant)
- **How to avoid:** don't sign up for paid services. The software
  works fully without payment.

### Postmark transactional email (v12+, signup/notifications only)

If you create an account via magic-link signup, or receive a
"report ready" notification, that email is delivered via Postmark.

- **What gets sent:** to Postmark — recipient email, subject line,
  HTML/text email body (which contains a magic link, not your
  organizational data)
- **Where it goes:** Postmark (US-based)
- **How to avoid:** self-host without using the SafeCadence-hosted
  signup flow; configure your own SMTP provider instead

### Hosted orchestration plane (v14+, opt-in MSP feature)

If you opt into the **hosted orchestration plane SaaS** (a paid v14+
service for MSPs managing many customer fleets), specific metadata
flows to our infrastructure. This is the only feature that involves
SafeCadence-the-company holding any of your data.

- **What gets sent to us:** scan completion timestamps, finding
  COUNTS by severity, control roll-up PERCENTAGES, drift event
  COUNTS. Aggregate numbers only.
- **What does NOT get sent to us:** raw configuration text, individual
  finding details, CVE-by-host mapping, remediation commands,
  credentials, customer identifiers (only org IDs you've assigned)
- **Where it goes:** our infrastructure (DigitalOcean droplet today;
  AWS US-East / EU-West by v14 GA)
- **Data residency:** by v14 GA, customers can choose US or EU
  region; by v15+, AU region
- **How to avoid:** don't opt into hosted SaaS. Self-host the
  orchestration plane software (same OSS code).

---

## v14 ML training data — opt-in only

When the v14 ML features ship (predictive risk forecasting, anomaly
detection), they need training data to function meaningfully.

Our commitments:

- **Training data is opt-in only.** No customer data is used for ML
  training unless the customer explicitly enables it in
  `/settings/data-sharing`.
- **All training data is anonymized.** Customer identifiers, asset
  hostnames, IP addresses, and any free-text fields are stripped or
  hashed before training.
- **Models are trained on aggregated, statistical features** (severity
  distributions, time-to-remediation curves, control posture trends)
  — never on the raw scan data itself.
- **Models do not leak training data.** We use differential privacy
  techniques where applicable and review model outputs for memorized
  customer-specific information.
- **Customers retain access to their own training data.** You can
  request export of what we have on you (`safecadence ops export-org`
  already supports this) or deletion at any time.

---

## Data retention

For data that lives on YOUR infrastructure (the local install): you
control it entirely. Retention policies are configurable per-org via
`safecadence ops retention` (shipped in v11.3).

For data that flows to our hosted services (only if you opt-in):

- **Hosted orchestration plane metadata:** retained for 13 months by
  default; configurable per-org down to 30 days minimum
- **Stripe billing records:** retained per Stripe's policy (typically
  7 years for tax compliance)
- **Postmark email logs:** retained per Postmark's policy (45 days
  for delivery diagnostics)
- **Support ticket conversations** (paid support tiers): retained
  for the duration of the customer relationship + 2 years for
  legal-hold purposes

---

## GDPR / CCPA / regulatory stance

SafeCadence operates as a **data processor**, not a data controller,
for any of your data that touches our services. You remain the data
controller for all customer/employee/asset information you handle
with SafeCadence.

Specific stances:

- **GDPR:** we honor Article 17 (right to erasure) within 30 days of
  a verified request. We honor Article 20 (right to portability) via
  the existing `safecadence ops export-org` command.
- **CCPA:** we don't sell personal information. We don't have personal
  information to sell unless you've signed up for paid services, in
  which case we hold only the billing email + payment method.
- **HIPAA:** SafeCadence-the-company is not a HIPAA business
  associate today. The OSS software is HIPAA-friendly *when self-
  hosted by a HIPAA-covered entity*. If we ever offer hosted services
  to HIPAA-covered entities, we'll sign a BAA at that time (planned
  for v14+).
- **SOC 2:** SafeCadence-the-company is pursuing SOC 2 Type II
  attestation (planned ~Q1 2027). The full timeline is in
  `ROADMAP.md`.

---

## Subprocessors

If you use SafeCadence's hosted services (paid features only), the
following subprocessors may process your data:

| Subprocessor | What they do | Data they touch |
|---|---|---|
| Stripe | Payment processing | Billing email, payment method |
| Postmark | Transactional email delivery | Email addresses, email content |
| DigitalOcean (US) | Hosting (today) | Hosted orchestration plane metadata |
| AWS (US-East / EU-West) | Hosting (v14+) | Hosted orchestration plane metadata |
| Cloudflare | DNS + CDN | IP addresses (anonymized in logs) |
| GitHub | Source repo + CI + auto-deploy | Public repo data + signed deploy keys |
| PyPI | Python package distribution | Public package data |

We will provide 30 days' notice before adding any new subprocessor.

---

## How to verify everything in this document

- **For the OSS software:** read the code at
  github.com/famousleads/safecadence-network-risk. Every external
  call is grep-able: `grep -rn "https\?://" src/safecadence/`.
- **For the hosted services:** the trust center page at
  safecadence.com/trust includes the data-flow diagram, encryption
  posture, and subprocessor list above. The SOC 2 Type II report
  (once available, ~Q1 2027) provides third-party attestation.

---

## Reporting privacy concerns

- **Privacy questions:** privacy@safecadence.com
- **GDPR Article 17/20 requests:** gdpr@safecadence.com
- **General questions:** hello@safecadence.com
- **Security vulnerabilities:** see `SECURITY.md`

Response window: 5 business days for routine inquiries; 24 hours for
breach notifications.

---

*This document is a living commitment. Material changes are announced
30 days in advance via the SafeCadence release notes + GitHub
Discussions. Changes that reduce user privacy require a major version
bump.*
