# Public Safety Local Import Pilot

Status: NetRisk 17.0.0a3 / Public Safety 1.5.0a3 alpha prerelease. PS-INT-01/02/03 have scoped offline
event adapters; PS-INT-14 has organization-brand CSV imports and human review.
All use local audit and export-freshness reporting. Optional scoped local HTTPS
polling for Frigate, Home Assistant and ThingsBoard is now available in the
[local monitoring software pilot](local-monitoring-pilot.md). No customer feed is
connected by default. Live stream subscriptions, connected-source operator GUI,
policy-driven alert generation and field validation remain pending.
ThingsBoard engine adoption remains license-gated; supplied-report support does
not bundle or install its software. No upstream engine is installed.

## Working Capabilities

- Frigate `frigate/events` exports: person/car presence in approved camera zones,
  source score, false-positive flag and new/update/end lifecycle observations.
- Frigate `frigate/available` exports: reported online/offline/stopped state with
  an explicit capture timestamp and retained-message flag.
- Home Assistant `state_changed` WebSocket event exports or raw event objects:
  approved door/window/opening/moisture/occupancy/motion binary sensors and
  temperature sensors with C/F units. Unknown/unavailable/removed states remain
  visible; unrelated entities, actuator commands and service calls are rejected.
- ThingsBoard `netrisk-thingsboard-v1` local export envelopes: approved
  temperature/binary telemetry keys and source alarm status/severity/lifecycle.
  Unknown/unavailable readings stay visible. No device RPC, alarm mutations,
  command messages or derived threshold alerts. Devices and telemetry channels
  each have independent freshness; conflicting current readings stay unknown.
- Sherlock/Maigret CSV: organization-brand username and platform-host allowlists,
  required authorization reference and explicit report observation date.
  Account existence remains an unverified observation. No person profiles,
  recursive enrichment, live public searches, screenshots or page fetches.
- Human brand review: `confirmed-brand-account`, `not-brand-account` or
  `needs-more-evidence`, with local evidence reference, reviewer and expected
  revision. Decisions bind to the exact record hash/scope; corrections preserve
  history and new report versions do not inherit a review. This records an
  operator attestation, not proof of person identity or impersonation.
- Required tenant, site, instance, source version, purpose and camera-zone or
  entity scope. All rows validate before an atomic batch commits. Replay is
  idempotent; changed records/lifecycle updates remain separate evidence versions.
- Source and per-camera/entity freshness, independent of import receipt time.
  Old backfilled records do not replace newer observations. Changed scope
  invalidates prior status without deleting history. Conflicting same-time
  availability or sensor states are unknown, not arbitrarily treated as online.
- Shared local hash-chained audit for registration, accepted/rejected imports,
  observation reads, status reads and audit reads. Failures include a stable
  reason and recommended correction without echoing raw source payloads.

These are observations, not verified incidents, vulnerability findings,
identity matches, calibrated confidence or a declaration that a site is safe.
No threshold alarms are derived yet. Scores retain their source meaning.

## Try Device and Brand Evidence

After the Frigate/Home Assistant examples below, use the same local database:

```sh
export PYTHONPATH=src
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  register thingsboard --tenant demo-agency --site station --instance iot \
  --source-version fixture-v1 --purpose facility-safety \
  --scope examples/public-safety/thingsboard-scope.json
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  import thingsboard examples/public-safety/thingsboard-events.json \
  --tenant demo-agency --site station --instance iot
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  register sherlock --tenant demo-agency --site station --instance brand-report \
  --source-version fixture-v1 --purpose brand-protection \
  --scope examples/public-safety/brand-scope.json
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  import sherlock examples/public-safety/sherlock-brand.csv \
  --tenant demo-agency --site station --instance brand-report \
  --observed-at 2026-10-06T12:00:00Z
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  events --tenant demo-agency --site station --source sherlock
```

For Maigret repeat registration/import with source `maigret`, instance
`maigret-report`, the same brand scope and `maigret-brand.csv`. The examples
are fictional; nothing contacts `example.com`. The returned event `id` and
`review.revision` are the inputs for local review:

```sh
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  review-brand EVENT_ID --tenant demo-agency --site station \
  --decision needs-more-evidence --evidence-ref local-review-record-1 \
  --actor approved-reviewer --expected-revision 0
```

Use actual approved local ownership evidence before recording
`confirmed-brand-account`; a username match is insufficient. Only source
`Claimed` observations can be reviewed. `Available`, `Unknown` and `Illegal`
remain source results, not proof that an account is safe, absent or malicious.
Review cannot take down, message, report or otherwise act on an account.
Use `review` for current decisions; original `evidence.review_status` stays
unreviewed as immutable source evidence. A `scope_current=false` decision is
historical only and cannot authorize a new review.

## Try the Synthetic Fixtures

From the source checkout with provisioned local dependencies:

```sh
export PYTHONPATH=src
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  register frigate --tenant demo-agency --site station --instance camera-worker \
  --source-version fixture-v1 --purpose facility-safety \
  --scope examples/public-safety/frigate-scope.json
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  import frigate examples/public-safety/frigate-events.json \
  --tenant demo-agency --site station --instance camera-worker
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  register home-assistant --tenant demo-agency --site station --instance sensors \
  --source-version fixture-v1 --purpose facility-safety \
  --scope examples/public-safety/home-assistant-scope.json
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  import home-assistant examples/public-safety/home-assistant-events.json \
  --tenant demo-agency --site station --instance sensors
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  events --tenant demo-agency --site station
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  status --tenant demo-agency --site station
python -m safecadence.security.local_only safety --db ./safety-demo.db \
  audit --tenant demo-agency
```

After an approved offline installation, `safecadence-local safety` is the
equivalent entry point. Installer/wheel packaging is not established by this
increment. Omit `--db` to use `SC_DATA_DIR/security-evidence.db`, or the existing
`~/.safecadence` default. Public Safety and cybersecurity observations use
separate tables; Public Safety records do not enter the vulnerability graph.

The examples are fictional, dated 2026-10-06. Status may therefore show stale
or clock-invalid observations depending on the current clock. Never relabel
these as live field evidence. No camera or broker is accessed by these commands.

## Export Contracts

Frigate exports require a local wrapper with `topic`, a decoded JSON `payload`
(string for availability), and timezone-qualified/epoch `captured_at`.
`retained` defaults false; exporters must supply the actual flag, not fabricate
freshness for retained records. Only the fixed `frigate` topic prefix is supported
in this pilot. Presence uses `after.frame_time`, or `after.end_time` for end
events. A scoped entered zone permits an end/update with no current zone.
This is historical presence, not necessarily current restricted-zone occupancy.

Home Assistant records require `time_fired`, `data.entity_id` and matching
`new_state.entity_id` plus device class. Null `new_state` represents removal.
The outer WebSocket subscription ID is not a globally unique event ID; identity
uses the entity, observation time, source context and raw-record hash.
Snapshot states without a state-change event are not supported yet.

ThingsBoard imports require our explicit `netrisk-thingsboard-v1` envelope,
not arbitrary native API dumps. A reviewed exporter must select approved
`device`, `type` and original `observed_at`, with `key`, `state`, `value` and
`unit` for telemetry. Native ThingsBoard timestamps are milliseconds; convert
to timezone-qualified UTC accurately, never substitute import time. Only
numeric C/F temperatures bounded to +/-1,000,000 and boolean approved binary
values are accepted. Unknown/unavailable must have null values. Units must
match declared scope; calibration remains unverified.

Alarm envelopes require scoped `alarm_id`, `alarm_type`, source `status` and
`source_severity`, `start_at` and optional `end_at`. `observed_at` is the actual
snapshot observation time, not necessarily onset; record the original start
separately. Preserve ACTIVE_UNACK/ACTIVE_ACK/CLEARED_UNACK/CLEARED_ACK and
CRITICAL/MAJOR/MINOR/WARNING/INDETERMINATE. Snapshot history is not a complete
alarm event stream. No source acknowledge/clear/delete action is exposed.
Extra source details are discarded, not used for recommendations or commands.

Sherlock CSV headers: `username,name,url_main,url_user,exists,http_status,
response_time_s`. Maigret uses `error_reason` instead of `response_time_s`.
These specific reviewed CSV layouts are supported; JSON/XLSX/HTML and other
versions need separate qualification. Column order may vary; duplicate,
missing or unexpected columns reject the batch. UTF-8/BOM, standard CSV quoting,
8 MiB, 10,000 rows and 4096-character fields are bounded. Platform names and
brand/username identifiers use the pilot's ASCII identifier format; spaces
and special platform names need a reviewed mapping, not silent guessing.

Brand scopes require `subject_type=organization-brand`, a local
`authorization_ref`, explicit brands/usernames and exact lowercase DNS
`platform_hosts`. No wildcards, overlapping usernames, personal investigations
or authorization inferred from public accessibility. HTTPS account URLs must
match the allowed host, with no credentials, port, query, fragment or encoded
control/whitespace characters. Raw error strings, response metadata and
personal profile data are not retained. A report observation date is required
via `--observed-at`; it is operator-attested, not independently verified.
The event hash covers the parsed CSV row plus that date; the file hash covers
the original bytes. The local importer never launches either search tool.

Scope files list explicit source identifiers, not display names or wildcards.
Maximum 100 cameras/entities and 100 zones per camera. Only approved zone names
are retained; unscoped cameras/entities or events with no scoped zone reject
the entire batch. Source version and purpose are operator attestations, not
independently verified authorization. Re-registering is an audited scope change.

JSON/JSONL imports are bounded to 8 MiB and 10,000 records with shared duplicate
JSON key, nonfinite-number and nesting/field/array validation. Raw media, source
URLs, face/plate labels, personal contexts, arbitrary attributes and credentials
are not retained; only minimized observations and original-record/file hashes
are stored. The brand workflow intentionally retains only scoped organizational
username/platform/account URL evidence, not general personal profiles.
Operators must still review source identifiers and sensitive input.
Public Safety accepts only direct records/arrays or JSONL, not automatic
generic `data`/Elasticsearch `hits` wrappers that could discard outer command
metadata. The cybersecurity importers retain their own supported wrappers.

## Health and Safety Limits

`fresh-export` means an observation is within the registered freshness window
(`--stale-after`, 30-86400 seconds, default 300). It is not a verified heartbeat.
Frigate availability is connection-driven, not necessarily periodic. Missing,
stale, retained, future-dated or conflicting availability reports stay unknown.
Even a fresh reported-online record always has `sensor_health=unknown` and
`live_connector=false`. A fresh source does not hide missing individual sensors.
Quiet presence streams do not prove offline cameras or an empty/safe site.

No thresholds, alert acknowledgement, source reset, dispatch, lock/unlock,
device RPC, service calls or upstream automation creation exist in this CLI.
Independent certified alarms, agency procedures and human triage remain
authoritative. Camera models and all dependencies must be provisioned locally
before any future live pilot; no external model/media downloads are permitted.

## Security and Remaining Gates

This CLI trusts the local operator. Tenant/site isolation is data partitioning,
not multi-user authentication or RBAC. Invalid context IDs cannot be attributed
to an audit tenant; argument-parsing failures do not create operation receipts.
Source files and outputs remain under operator control. Database mode 0600 is
not encryption; use encrypted storage and reviewed retention/backup/access rules.
The shared audit detects chain edits, not privileged entire-chain/tail deletion.
Reviewer/authorization identifiers are attestations, not authenticated identities
or independently checked permissions. Future server/GUI integration must enforce
agency roles and authorization outside this CLI. Review revisions prevent lost
updates; they are not cryptographic signatures or legal verification.

The Python guard is not OS/browser/native isolation. Follow the existing
[local security alpha guide](security-ecosystem-next.md) for remaining release
gates. No claim of air-gap qualification, certified safety or legal admissibility
is made. Shared graph/incident UI mapping, read-only internal subscriptions,
credential isolation/revocation, thresholds, local notifications, licensing,
retention and hardware/site qualification remain subsequent increments.

## Verification

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p test_public_safety_imports_local.py -v
PYTHONPATH=src python -m unittest discover -s tests \
  -p test_public_safety_expansion_local.py -v
PYTHONPATH=src python -m unittest discover -s tests \
  -p test_security_ecosystem_local.py -v
```

These tests use synthetic local fixtures, mocked network/process denial and
guarded CLI subprocesses. The regression suite also checks a benign loopback
socket. Live upstream engines, full legacy pytest coverage, hardware and agency
field acceptance are separate gates.

Source contracts: [Frigate MQTT](https://docs.frigate.video/integrations/mqtt/),
[Home Assistant WebSocket API](https://developers.home-assistant.io/docs/api/websocket/),
[ThingsBoard telemetry](https://thingsboard.io/docs/user-guide/telemetry/),
[ThingsBoard alarms](https://thingsboard.io/docs/user-guide/alarms/),
[Sherlock CSV writer](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/sherlock.py)
and [Maigret CSV writer](https://github.com/soxoj/maigret/blob/main/maigret/report.py).
Pinned upstream versions and actual customer exports still need compatibility
validation before connecting any live source.
