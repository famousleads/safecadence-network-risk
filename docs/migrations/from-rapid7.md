# Migrating from Rapid7 (InsightVM / Nexpose) → SafeCadence

InsightVM users typically pick it because they want one console covering
vuln + SIEM (InsightIDR) + attack surface (InsightConnect). SafeCadence
covers the vuln + attack-path + compliance slice cleanly; you'll keep
your SIEM separately.

## What stays the same

- Authenticated scans of the same gear.
- CVE list (NVD source-of-truth).
- Your remediation cadence.

## What changes

| Capability                       | Rapid7 InsightVM                 | SafeCadence                       |
|----------------------------------|----------------------------------|-----------------------------------|
| Deploy                           | Cloud + on-prem console          | Local-first; `pip install`        |
| Pricing                          | Per-asset license                | Free + MIT                        |
| Compliance suite                 | Reporting add-on                 | Built-in (5 frameworks)           |
| Attack-path graph                | Yes (Threat Command add-on)      | Built-in                          |
| Identity hygiene                 | No                               | Built-in                          |
| Multi-vendor config translation  | No                               | Yes (16 translators)              |
| Real-Time Threat Intelligence    | Yes (RTI feed)                   | KEV + EPSS built-in               |

## Step-by-step (3 days)

**Day 1**

```bash
pip install 'safecadence-netrisk[server]'
safecadence scan --all-vendors --site lab
safecadence ui &
```

**Day 2 — Findings parity**

In InsightVM: Sites → choose site → Asset Filtered Search → Export.
Then:

```bash
safecadence findings export --format csv > /tmp/sc.csv
diff <(sort /tmp/sc.csv) <(sort /tmp/r7.csv) | head -50
```

InsightVM's "Risk Score" and SafeCadence's Safe Score use different
formulas and you should *expect* them to differ. The question isn't
"do the scores match," it's "do we agree on the same critical findings."

**Day 3 — Side-by-side cycle**

Distribute the Executive Risk Brief alongside InsightVM's exec report.
The SafeCadence multi-dim radar makes a much better stand-alone exec
artifact than InsightVM's score-over-time chart; demo that to whoever
reads exec reports today.

## Cutover criteria

- [ ] At least one full scan cycle.
- [ ] Findings parity confirmed.
- [ ] Compliance reviewer signed off on the new pack.
- [ ] If you used InsightVM Adaptive Security to remediate via
      automation, decide whether SafeCadence's tier-3 SSH path covers
      the same use cases (it may not — fall back to your existing
      orchestrator).

## Things that *don't* migrate

- InsightConnect playbooks. SafeCadence doesn't have a SOAR. Keep your
  orchestrator, point it at the SafeCadence REST API instead of
  Rapid7's.
- InsightIDR / log data. SafeCadence is not a SIEM. Keep your SIEM.

## When to keep Rapid7 running anyway

- You bought the full InsightPlatform bundle and the contract has time
  remaining; coexist for the rest of the term.
- Your team uses InsightConnect playbooks as the single pane for SecOps;
  swapping that out is a separate project.
