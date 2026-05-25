# Migrating from Tenable (Nessus / Tenable.io / Tenable.sc) → SafeCadence

A weekend-sized migration guide. Goal: stand up SafeCadence alongside
Tenable, validate that nothing important is missed, then cut over.

## What stays the same

- Authenticated scans against the same network gear.
- The CVE list (NVD source-of-truth in both products).
- The remediation workflow your team already follows.

## What changes

| Capability                          | Tenable                          | SafeCadence                         |
|-------------------------------------|----------------------------------|-------------------------------------|
| Deploy                              | Cloud or on-prem appliance       | Local-first; `pip install`          |
| Pricing                             | Per-asset license                | Free + MIT; pay only for support    |
| Compliance suite                    | Add-on (Tenable.io)              | Built-in (5 frameworks shipped)     |
| Multi-vendor config translation     | No                               | Yes (16 translators)                |
| Attack-path graph                   | Add-on (Tenable Identity Exposure) | Built-in                          |
| Auto-execute remediation            | No                               | Tier-3 SSH with triple-gate (opt-in)|
| LLM / AI features                   | Tenable AI Aware (cloud only)    | BYO-AI; never leaves your machine   |

## Step-by-step (3 days)

**Day 1 — Stand up, scan one site**

```bash
pip install 'safecadence-netrisk[server]'
safecadence ui &              # poke around at http://127.0.0.1:8766
safecadence scan --site lab   # scan the same site Tenable scans
```

**Day 2 — Compare findings**

```bash
safecadence findings export --format csv > /tmp/sc.csv
# In Tenable: export the same site's plugin findings to CSV
# Then diff on (host, cve_id) tuples
diff <(sort /tmp/sc.csv) <(sort /tmp/tenable.csv) | less
```

Expect ~85–95% overlap on CVEs. Differences are usually:
- Tenable plugins SafeCadence doesn't ship (file these as issues — we add adapters quickly).
- Findings SafeCadence has but Tenable doesn't (config drift, identity hygiene, attack paths reaching crown jewels — these are net-new value).

**Day 3 — Run them side-by-side**

Keep Tenable running. Add SafeCadence's report cadence to the same
distribution list so stakeholders see both for a cycle. The
Executive Risk Brief preset is intentionally board-ready; show it to
the same person who reads your monthly Tenable summary.

## Cutover criteria (don't skip)

- [ ] At least one full scan cycle without missed assets.
- [ ] Findings parity confirmed (or net-new findings explained).
- [ ] Stakeholders received a SafeCadence-generated report and signed off.
- [ ] Compliance reviewer confirmed the SafeCadence compliance pack is
      acceptable for their next audit.

## Things to *not* migrate

- Tenable's per-finding "accepted risk" notes. Re-evaluate them in
  SafeCadence; the risk_acceptance_log section is the right place.
- Old scan history — no value, increases storage. Start fresh.

## When to keep Tenable running anyway

- You have a specific compliance attestation referencing Tenable
  plugin IDs. Keep both until that attestation renews.
- Your insurance policy names Tenable. Same answer.
