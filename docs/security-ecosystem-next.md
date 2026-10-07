# NetRisk 17 Local Security Ecosystem Alpha

Status: 17.0.0a2 alpha prerelease. This is the first working increment, not full
integration of all 32 projects. Existing scan/history functionality is retained.

## Working Now

The `ecosystem` CLI tracks all 32 roadmap projects, with four file importers:

| Source | Supported supplied export | Limits |
| --- | --- | --- |
| Wazuh | JSON/JSONL alert records, or indexer `hits.hits[*]._source` | Alert rule level required; not full manager inventory/API support. |
| CrowdSec | JSON alerts or a `data` array of alerts | Scenario required; decisions/bouncer actions are not supported. |
| Zeek | JSON/JSONL connection observations with `uid` and `ts` | Not TSV/PCAP, not a complete protocol-log adapter. |
| Suricata | EVE JSON/JSONL alerts and other event observations | No sensor installation, packet capture or inline blocking. |

Files are bounded to 8 MiB and 10,000 records. Entire batches validate before
writing. Records preserve source version (operator supplied, not independently
verified), instance, timestamps, raw-record hash and redacted evidence. A changed
record is a new evidence version; identical replay does not multiply records.
Tenant and source-instance IDs are explicit. The CLI is trusted local-operator
access, not an authenticated multi-user service.

Import receipts do not prove live sensor health. Missing timestamps stay unknown;
alert severities use documented importer mappings, not verified compromise.
Graph projection uses existing NetRisk graph types and source-scoped asset IDs;
ordinary connection observations never become vulnerability findings.

A separate [Public Safety local import pilot](public-safety-local-pilot.md)
adds scoped Frigate/Home Assistant events, ThingsBoard local telemetry/alarm
envelopes and authorized organization-brand Sherlock/Maigret CSV imports through
`safety` commands. Brand ownership reviews bind to one evidence version, with
local reviewer attestations, revision checks and audit history; they never
establish person identity or authorize account actions.
Their minimized observations stay in separate tables, never vulnerability
findings. Source health remains unknown; no live subscriptions or physical
controls or public-site searches are implemented. ThingsBoard engine adoption
remains license-gated. The catalog exposes their separate
`public_safety_status` without claiming upstream engines are installed.

## Run Locally

After installing from an approved local wheel/dependency bundle:

```sh
safecadence-local ecosystem catalog
safecadence-local ecosystem import wazuh examples/security/wazuh-alerts.json \
  --tenant acme --instance manager-1 --source-version fixture-v1
safecadence-local ecosystem events --tenant acme
safecadence-local ecosystem status --tenant acme
safecadence-local ecosystem audit --tenant acme
safecadence-local ecosystem graph --tenant acme --output ./security-graph.db
```

Before wheel installation, the same commands run using:

```sh
PYTHONPATH=src python -m safecadence.security.local_only ecosystem --help
```

`SC_DATA_DIR` selects local storage. Otherwise evidence is stored under
`~/.safecadence/security-evidence.db`. `ecosystem --db PATH` overrides only the
evidence database path. The database is mode 0600, but is not encrypted by this
increment; use encrypted storage and appropriate local access controls.

The irreversible Python guard is installed by `safecadence-local` before CLI
imports. It blocks external connections/DNS, subprocesses and UDP/raw sockets.
Only loopback listeners are permitted. To approve an exact internal TCP target:

```sh
export SC_LOCAL_INTERNAL_TARGETS='[{"ip":"192.168.4.15","port":8444}]'
```

Use numeric addresses, not hostnames; private addressing alone is not permission.
Existing collection paths that require subprocesses or UDP will be denied until
separately isolated/reviewed. Use `ui --no-browser` with the guarded launcher;
the guard cannot govern a user's browser's external assets. The legacy
`safecadence` launcher and direct library calls are not globally protected by
this guard. OS egress isolation, browser CSP/assets and native-worker review are
still release blockers; do not advertise this alpha as an air-gap guarantee.

## Security Update Exception

The authorized exception is public security-data downloads, not hosted execution,
telemetry or customer-data synchronization. It runs in a separate updater process,
disabled unless explicitly authorized for each invocation:

```sh
safecadence-security-updates sources
safecadence-security-updates download nist-nvd --output ./nvd-staged.json \
  --allow-security-downloads
safecadence-security-updates download cisco-psirt --output ./psirt-staged.json \
  --allow-security-downloads
```

The request builder accepts only fixed public sources, not inventory, asset IDs,
questions, customer credentials or arbitrary URLs. It uses HTTPS validation,
disables inherited proxies, rejects redirects and bounds responses. Provider
servers still observe normal connection metadata, such as the updater's public
IP and generic User-Agent. Corporate proxy support is not implemented.

NVD downloads stage one recent 24-hour modified-record window, limited to one
API page; partial results are explicitly marked. Cisco RSS is a recent advisory
list, not comprehensive historical coverage. HTTPS and hashes are not publisher
signatures. There is no automatic activation, full database rebuild, pagination,
scheduled polling or new asset correlation from these packages yet. Offline
transfer remains available for isolated deployments. Keep the updater on a
separate management host when the operational environment must be air-gapped.

The local audit records accepted/rejected imports, failures/recommendations and
update outcomes. Hash-chain verification detects edits, not complete/tail
deletion by a privileged administrator; external anchoring is not implemented.
Heuristic redaction is not a substitute for reviewing sensitive source exports.

## Remaining Development

- OS/browser egress isolation and a full inventory of legacy network paths.
- Offline installer, signed intelligence/rule bundles, activation/rollback and
  source freshness checks; more vendor PSIRT adapters and NIST reference packs.
- Authenticated, read-only internal Wazuh/CrowdSec connectors and enrollment.
- Passive probe packaging, authenticated health/spooling, coverage maps and
  hardware/failure benchmarks. No probe has been deployed by this alpha.
- Reviewed defensive playbooks and remaining catalog integrations, following
  licensing, pinned-version, privacy and no-egress admission checks.
- User-facing workspaces, evidence review and separate approval/rollback paths
  for remediation. No executable response actions ship in these importers.

## Verification

Run the offline suite without installing anything online:

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p test_security_ecosystem_local.py -v
```

The suite uses local fixtures and fake update transports. Network-denial tests
run in separate processes; a benign loopback test requires local socket access.
Live upstream availability and the existing full pytest suite are separate
verification gates, not established by these fixture tests.

Official source references: [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
and [Cisco security RSS](https://sec.cloudapps.cisco.com/security/center/rss.x).
NIST frameworks describe controls/outcomes; NVD supplies vulnerability data.
Neither importing these sources nor mapping controls constitutes certification.
