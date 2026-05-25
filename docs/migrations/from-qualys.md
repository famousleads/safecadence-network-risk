# Migrating from Qualys (VMDR / Qualys Cloud Platform) → SafeCadence

Qualys is cloud-only by design. SafeCadence is local-first by design.
The migration shape is "stand up local, validate parity, retire cloud."

## What stays the same

- Authenticated scans of the same network gear.
- The CVE list (both pull from NVD).
- Your team's remediation workflow.

## What changes

| Capability                  | Qualys                          | SafeCadence                       |
|-----------------------------|---------------------------------|-----------------------------------|
| Where the data lives        | Qualys cloud                    | Your laptop / server              |
| Data egress                 | Always on                       | None (no telemetry, no phone-home)|
| Pricing                     | Per-asset, multi-year contracts | Free + MIT                        |
| Compliance suite            | PC module add-on                | Built-in                          |
| Identity hygiene            | No                              | Built-in (IAM/MFA/NHI)            |
| Multi-vendor config         | No                              | Yes (16 translators)              |
| Air-gap support             | Cloud Agent only (limited)      | First-class                       |

## Step-by-step (3 days)

**Day 1 — Stand up local install**

```bash
pip install 'safecadence-netrisk[server]'
safecadence ui &
safecadence scan --site primary
```

**Day 2 — Pull a comparable Qualys export**

In the Qualys UI: Reports → Scan Report → Detailed Results → CSV. Export
the same asset group SafeCadence scanned. Then:

```bash
safecadence findings export --format csv > /tmp/sc.csv
diff <(sort /tmp/sc.csv) <(sort /tmp/qualys.csv)
```

Expect overlap. Where Qualys reports more, it's usually QID-specific
checks not yet covered by an adapter. Where SafeCadence reports more,
it's usually drift, attack-path, or identity hygiene — net-new value.

**Day 3 — Run side-by-side for one cycle**

Distribute one SafeCadence Executive Risk Brief through the same
channel as the monthly Qualys exec report. Confirm with stakeholders
that the new format works before retiring Qualys.

## Cutover criteria

- [ ] One full scan cycle with no missed assets.
- [ ] Findings overlap confirmed; deltas explained.
- [ ] Compliance reviewer reviewed the SafeCadence pack.
- [ ] Customer-facing portal (if MSP use case) tested with one client.

## Things to specifically check

- **Cloud Agent footprint.** If you've installed Qualys agents on
  endpoints, SafeCadence doesn't replace those today. Plan
  independently.
- **API integrations.** If a downstream system pulls from the Qualys
  API, see `docs/INTEGRATION_README.md` for SafeCadence's equivalent
  REST endpoints (`/api/v1/findings`, `/api/v1/cves`, `/api/v1/scores`).

## When to keep Qualys running anyway

- Cloud Agent telemetry from endpoints you can't reach over the network.
- Existing contractual commitments through end of term.
