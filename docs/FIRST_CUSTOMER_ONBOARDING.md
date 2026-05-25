# First-customer onboarding playbook

A step-by-step runbook for the first paying support customer (or the
first MSP managing a real client on top of SafeCadence). Goal: from
"contract signed" to "first scan + first report delivered" in **two
business days**.

> SafeCadence itself is free + MIT — this playbook is for the *managed
> service* layer wrapped around it. If you're a self-hoster, you can
> skim it for the operational checklists at the bottom.

---

## Day 0 — Before the kickoff call

**You** (the operator) prepare:

- [ ] Customer org name + brand color (used by the customer portal chrome).
- [ ] Primary contact's email + phone.
- [ ] A short list of in-scope IP ranges, sites, or hostnames.
- [ ] The compliance framework that matters most to them
      (SOC 2 / HIPAA / PCI / CMMC / generic).
- [ ] Postmark or SMTP account for outbound mail (see
      `notifier/postmark.py` + `notifier/email_notifier.py`).
- [ ] Domain for the customer portal URL
      (e.g. `customer.example.com`); DNS pre-flighted.

**Customer** prepares:

- [ ] List of network gear vendors + management IPs (read-only creds).
- [ ] Single Sign-On details if they want SAML/OIDC later (optional v1).
- [ ] Owner of "this account" on their side (one person, named).

---

## Day 1 — Kickoff call (60 minutes)

| Time   | Topic                                                  |
|--------|--------------------------------------------------------|
| 0:00   | Introductions; confirm primary contact + escalation    |
| 0:05   | Scope walkthrough — what's in / what's out             |
| 0:20   | Credentials handoff (use the vault, *not* email)       |
| 0:35   | First-report cadence + delivery method                 |
| 0:45   | Customer portal demo (read-only view)                  |
| 0:55   | Questions + next steps                                 |

**Action items captured in writing same day:**

- [ ] Scope confirmed in `~/safecadence/scope.yaml` (committed to your
      internal ops repo, not the customer's).
- [ ] Org row created in your operator install:
      `safecadence org create --name "Acme Co" --owner ops@yours.example`.
- [ ] Credentials stored in the vault
      (`safecadence identity vault put …` — never plain text).

---

## Day 2 — First scan + first report

### Morning: scan

```bash
# Run the first full discovery + scan
safecadence scan --org acme --site primary --all-vendors

# Verify count is reasonable
safecadence inventory --org acme
```

If the inventory comes back surprisingly small, **stop and confirm with
the customer** before generating a report — a too-small inventory almost
always means a missing credential, not a smaller-than-expected network.

### Afternoon: report

```bash
# Use the v12 flagship preset for the first deliverable
safecadence reports compose \
  --org acme \
  --preset executive_risk_brief \
  --format pdf \
  --output /tmp/acme-first-report.pdf
```

The Executive Risk Brief is intentionally 8 pages and board-ready — it
matches the format you described in the kickoff, so the customer's
expectations and the deliverable line up the first time.

### Delivery

- Upload PDF to the customer portal Reports tab (or attach to email).
- Send the cover note (template in `templates/first_report_email.txt`).
- Schedule the 30-day follow-up call.

---

## Week 1 — Stabilize

- [ ] Confirm scheduled scan cadence is running cleanly (no skipped
      runs, no auth failures in the audit log).
- [ ] Set up the customer's notification preferences
      (severity threshold, channels, quiet hours).
- [ ] Confirm the customer can log into the portal and see their data.
- [ ] Internal post-mortem: anything in onboarding that was harder
      than expected? Add it back into this doc.

---

## 30-day check-in agenda

| Time | Topic                                                   |
|------|---------------------------------------------------------|
| 0:00 | Recap of findings, what was remediated                  |
| 0:15 | Trend: Safe Score over 30 days                          |
| 0:25 | Anything new in scope (new sites, new vendors)          |
| 0:35 | Renewal / expansion conversation if applicable          |
| 0:50 | Questions + next steps                                  |

---

## When things go wrong — first 48 hours

| Symptom                                | First action                                                  |
|----------------------------------------|---------------------------------------------------------------|
| Scan returns 0 assets for a site       | Check credential vault entry, then network reachability       |
| Report renders but missing sections    | Confirm the preset's sections vs. what scope filters allow    |
| Customer can't log into portal         | Check `SC_AUTH_DISABLED` env, then magic-link delivery        |
| Outbound email silently dropped        | Check Postmark dashboard / SMTP logs; verify DKIM             |
| KEV-listed CVE showed up unexpectedly  | Don't panic-page; confirm in the audit log + brief customer   |

---

## What you do **not** do during onboarding

- Don't promise "we'll fix all your critical findings in week 1" —
  SafeCadence never auto-executes; the customer's change-management
  process still applies.
- Don't share screenshots of the customer's posture publicly, even
  for marketing — `PRIVACY.md` applies internally too.
- Don't enable the `RED` execute path during onboarding even if asked;
  defer until the customer has a documented rollback plan.

---

Last touched: 2026-05-25 — keep this doc dense; after each onboarding,
add the one thing that surprised you, prune the one thing that didn't matter.
