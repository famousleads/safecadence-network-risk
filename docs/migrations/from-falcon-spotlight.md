# Migrating from CrowdStrike Falcon Spotlight → SafeCadence

This one's a partial migration. Falcon Spotlight is an *endpoint*
vulnerability module riding on the Falcon agent. SafeCadence is
*network and infrastructure* focused. The realistic outcome is "keep
Falcon for endpoints, add SafeCadence for everything else" — not a
straight replacement.

## What overlaps

- CVE awareness (both pull NVD).
- Per-host risk scoring (different formulas, same intent).
- Patch-status reporting.

## What doesn't overlap

| What Falcon Spotlight covers     | What SafeCadence covers                |
|----------------------------------|----------------------------------------|
| Windows / macOS / Linux endpoints | Network gear, identity, cloud, backup  |
| Real-time agent telemetry        | Authenticated remote scans             |
| EDR / NGAV                       | (not in scope — keep Falcon)           |
| Patch deployment via Falcon      | (not in scope — keep your patcher)     |
| Application-layer CVEs on user PCs | Infrastructure-layer CVEs            |

## Recommended deployment shape

```
Endpoints (Windows/Mac/Linux laptops + servers)  →  Falcon
Network gear / identity / cloud / backup        →  SafeCadence
```

One report-distribution list, two upstream products. The SafeCadence
Executive Risk Brief already has a section for "infrastructure
posture" — give your exec stakeholders both.

## When you'd actually *replace* Falcon Spotlight

Only when:
- You're descoping Falcon entirely (rare).
- You only have a handful of servers and don't run Falcon on them.
- You're moving to a different EDR and want to consolidate the
  remaining vuln scanning under SafeCadence.

In those cases, SafeCadence's adapter for `linux-systemd-scan` and
`windows-wmi-scan` covers the basics for server-class hosts.
**Endpoint laptops are not in scope today** — keep an endpoint product
on those.

## Step-by-step (1 day — overlap, not migrate)

```bash
pip install 'safecadence-netrisk[server]'
safecadence scan --vendor cisco --vendor fortinet --vendor okta --site primary
safecadence ui &
```

Then add the SafeCadence Executive Risk Brief to the same monthly
distribution list as your Falcon Spotlight summary. Tag the Falcon
section "endpoints" and the SafeCadence section "infrastructure" so
nobody mistakes them for redundant.

## Things to *not* do

- Don't try to import Falcon Spotlight findings into SafeCadence — the
  asset model is different, and the merged view will be misleading.
- Don't disable the Falcon agent on endpoints because "SafeCadence
  covers it now." It doesn't.

## When SafeCadence + Falcon is the right end-state

For most networks, *both* is the answer:
- Endpoints: Falcon (EDR + Spotlight).
- Infrastructure + identity + compliance: SafeCadence.
- One executive view: SafeCadence Executive Risk Brief, with Falcon
  attached as an appendix.
