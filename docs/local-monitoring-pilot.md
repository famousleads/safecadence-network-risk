# Local Monitoring Software Pilot

Version: NetRisk 17.0.0a3 / Public Safety 1.5.0a3 alpha prerelease.
Scope: customer-local read-only API polling and passive-engine log forwarding.
This is a software pilot, not a qualified appliance, certified alarm, complete
implementation of the upstream-tool roadmap, or permission to capture traffic.

## Available Software

| Source | Implemented transport | Collection limits |
| --- | --- | --- |
| Wazuh indexer | HTTPS GET search of an explicitly scoped `wazuh-alerts-*` index, Basic credentials supplied by operator | Recent bounded alert page, not manager inventory or complete history. Use an indexer account with read-only permissions. |
| CrowdSec local API | HTTPS GET `/v1/alerts` using an operator-provided watcher JWT | Bounded alerts only. No login, decisions/bouncer calls, bans or upstream writes. Bouncer API keys cannot read alerts. JWT renewal is an operator responsibility. |
| Home Assistant | HTTPS GET for each registered approved sensor entity | State snapshots using source `last_updated`, not a WebSocket stream or guaranteed transitions. No service calls, switches, locks or automation writes. |
| Frigate | HTTPS GET event pages restricted to registered cameras/zones and person/car labels | Historical presence snapshots. No current-occupancy claim, MQTT subscription, media, identities, recognition or camera controls. |
| ThingsBoard | HTTPS GET latest telemetry per explicitly mapped registered device UUID/key, using operator JWT | Temperature/binary telemetry only. No live alarm API, acknowledgment, clear, RPC or device commands. Units are operator-defined scope, not validated calibration. |
| Zeek / Suricata | Local JSONL following with atomic queue checkpoints; encrypted spool; signed delivery over internal mTLS | Engines are separately installed by the customer, never launched by the local CLI. No inline blocking, packet retention or remote-command endpoint. |

All API endpoints must be HTTPS numeric loopback/RFC1918/ULA addresses and
exactly listed in `SC_LOCAL_INTERNAL_TARGETS`. No DNS, proxies, redirects,
arbitrary source paths, public endpoints or TLS verification bypasses. Response
size is bounded to 8 MiB, page size to 1,000 and a snapshot to 10,000 records.
Requests have absolute deadlines, including trickled response headers. A
collection is atomic; a scope change before commit rejects the batch. A
successful read is `reachable` at that check, not proof of a healthy sensor,
complete coverage or site safety. Source version is operator-supplied metadata,
not independently discovered. Polling may miss intermediate changes/events.

Dependencies must be provisioned offline in operational installations.
The extra `local-monitoring` supplies `cryptography` for encrypted probe queues;
it does not download engines or configure any source automatically. CLI access
is trusted local operator access, not a hosted multi-user authorization boundary.

## Local Connector Setup

1. Give a dedicated source account the minimum upstream read permissions.
2. Provision the local server's CA and a certificate with a numeric-IP SAN.
   Mutual TLS is also available through optional client certificate/key paths.
3. Put credentials in an owner-only regular JSON file, mode 0600. No inline
   credentials in arguments, configuration, audit records or screenshots.
4. Register Public Safety entity/device/camera scope using the existing `safety
   register` workflow before polling. Scope, tenant/site, instance and version
   must match exactly. No live Sherlock/Maigret public-site collection exists.
5. Set the exact target, save the non-secret connector config and run one poll:

```sh
export SC_LOCAL_INTERNAL_TARGETS='[{"ip":"192.168.1.20","port":9443}]'
safecadence-local connections capabilities
safecadence-local connections poll --config /etc/netrisk/wazuh.json --db ./evidence.db
safecadence-local ecosystem --db ./evidence.db audit --tenant acme
```

Example Wazuh connector configuration (no credentials inside):

```json
{
  "source": "wazuh",
  "tenant": "acme",
  "instance": "indexer-1",
  "source_version": "operator-approved-version",
  "endpoint": "https://192.168.1.20:9443",
  "ca_file": "/etc/netrisk/source-ca.pem",
  "credential_file": "/etc/netrisk/private/wazuh.json",
  "index": "wazuh-alerts-*",
  "limit": 100
}
```

Wazuh's credential file uses `username` and `password`; the other sources use
`token`. Frigate requires an approved authenticated local gateway/account; this
adapter does not implement the upstream cookie-login flow. Public Safety configs
also require `site`; ThingsBoard requires `device_ids` mapping each registered
device name to its exact source UUID. API compatibility is bounded to the
documented schemas tested here; actual installation versions still need a pilot.

`local_connector_poll` records accepted and rejected outcomes with a stable
failure code and recommendation. `collection_mode` identifies polled evidence.
Do not treat old `state_changed`-shaped Home Assistant snapshot records as proof
that a transition was witnessed. The source time is preserved, never replaced
by poll time to make stale data look fresh.

## Probe Provisioning and Enrollment

```sh
safecadence-local probe provision --scope examples/probe/scope.json --directory ./new-probe
```

Creates a fresh private directory, 32-byte authentication secret, Fernet spool
key and owner-only settings. It never generates trusted production certificates,
automatically enrolls a probe or starts capture. Back up keys in the customer's
approved secure process; losing the spool key makes queued evidence unreadable.

After explicit site/segment/source approval, provision a unique client certificate
from the customer's CA. The collector registry is owner-only JSON:

```json
{
  "probes": {
    "probe-a": {
      "probe_id": "probe-a", "tenant": "acme", "site": "hq", "segment": "office",
      "instance": "probe-a", "source_version": "approved-engine-version",
      "sources": ["zeek", "suricata"], "enabled": true,
      "expires_at": "2026-11-01T00:00:00Z",
      "certificate_sha256": "REPLACE_WITH_64_HEX_SHA256_OF_CLIENT_CERT_DER",
      "auth_key_file": "/etc/netrisk-collector/private/probe-a.hex"
    }
  }
}
```

Transfer the authentication secret through an approved offline channel; do NOT
transfer the spool encryption key to the collector. Authentication secret and
exact client-certificate fingerprint must both match. Expired or disabled
enrollments fail closed. Registry is re-read for every request, so disabling an
entry takes effect without a restart. Scope is frozen once receipts exist;
changing tenant/site/segment/source identity requires a fresh enrollment ID and
new spool. Automated certificate issuance/rotation is not implemented.

Add collector `endpoint`, `ca_file`, `client_cert` and `client_key` paths to the
private probe settings. Add exact approved `log_files` paths for follow mode.
Use the guarded collector with explicit private listener authorization:

```sh
export SC_LOCAL_INTERNAL_LISTENERS='[{"ip":"192.168.1.30","port":9443}]'
safecadence-local probe serve --registry /etc/netrisk-collector/registry.json \
  --db /var/lib/netrisk-collector/evidence.db --cert /etc/netrisk-collector/server.pem \
  --key /etc/netrisk-collector/server.key --client-ca /etc/netrisk-collector/client-ca.pem \
  --bind 192.168.1.30 --port 9443
```

Only certificate-authenticated POST `/v1/probe/batch` ingestion exists. No remote
queries, configuration writes, credentials retrieval, engine execution or shell
endpoint exists. Application HMAC covers the entire bounded envelope. Tenant,
site, segment, instance and allowed sources must match enrollment. Sequence gaps
and conflicting replays are rejected; identical retry produces a matching
receipt. Evidence insertion, receipt and audit commit together. Collector DB and
spool DB must be on reliable local storage, not shared over a network filesystem.

```sh
safecadence-local probe follow zeek --config /etc/netrisk-probe/probe.json
safecadence-local probe follow suricata --config /etc/netrisk-probe/probe.json
safecadence-local probe heartbeat --config /etc/netrisk-probe/probe.json
safecadence-local probe deliver --config /etc/netrisk-probe/probe.json
safecadence-local probe status --config /etc/netrisk-probe/probe.json
safecadence-local probe health --db /var/lib/netrisk-collector/evidence.db --tenant acme
```

Queue capacity defaults to 10,000 observations / 32 MiB encrypted payload. Full
queues refuse new data with an audited recommendation and do not move log
checkpoints or silently discard batches. Source logs must be preserved outside
the queue with their own storage limits and retention. Missing acknowledgments
leave data queued. Restart resumes the durable sequence and encrypted payloads.
Complete newline-delimited records are checkpointed atomically with queueing.
Log truncation/rotation requires explicit review and `--accept-rotation`, which
records a possible coverage gap. Stage retained rotated logs separately before
accepting; the software cannot recover files already deleted by the engine.

Optional health files accept only capture-drop count, parser-error count,
interface-up flag and rule-version attestation. Missing fields remain unknown.
Neither a heartbeat nor a successful process launch proves capture coverage.
Collector heartbeat freshness is a report of source timing, not an independent
hardware, enrollment or capture-health certification. An empty report is unknown,
not an all-clear. Storage write failures preserve queued evidence. If audit
storage is also unwritable, the CLI reports that auditing is unavailable rather
than claiming a failure was recorded. Resolve disk pressure without deleting
unacknowledged evidence; queue bounds do not bound total audit/database storage.
Spool payloads are encrypted; collector evidence and audit SQLite are NOT
encrypted by this feature. Use customer-managed disk encryption, local access
controls, backups and retention. Audit detects edits, not privileged chain/tail
deletion. Queue metadata, hashes and scope remain visible to the local owner.

## Native Workers and Test Evidence

`examples/probe/*.service` and the timer are Linux templates, NOT validated
hardware installation scripts. Supply offline hash-approved binaries/rules,
dedicated users/directories, private source config and exact collector egress.
Capture workers expose AF_PACKET/AF_UNIX only, without IP egress or NET_ADMIN.
No capture service is enabled by this release. A reviewed `capture-approved`
marker is required. Use a receive-only TAP or correctly configured SPAN interface
without IP/routes, disable bridging/forwarding, and confirm transmit suppression.
Templates need testing against the chosen Linux/kernel/libpcap/engine builds;
some require additional restricted local socket families. Never fix this by
granting unrestricted privileges or internet access.

The forwarding template fails closed on parsing, queue pressure and rotation;
timer continues retrying. Provision health sampling independently when collection
must report outages despite a stuck source, and integrate service failures with
customer-local operations. Signed publisher-rule/software activation, unattended
certificate rotation, hardware watchdog and automatic gap recovery remain pending.

Real upstream lab verification used Zeek 8.2.2 and Suricata 8.0.4, pinned to
image digests in `examples/probe/engine_lab.py`, with networking disabled, all
capabilities removed, read-only container root and bounded CPU/memory/processes.
One generated benign UDP packet between two fictional subnets produced one
Zeek observation and a Suricata test alert plus flow/stats. Four source records
passed encrypted queueing, authenticated collector logic and audit verification.
This is NOT a two-segment physical network pilot, throughput measurement or
claim that production models/rules/dependencies are license/security cleared.

Run after installing the two reviewed images on a development host only:

```sh
PYTHONPATH=src python examples/probe/engine_lab.py --output ./new-lab-results
PYTHONPATH=src python -m pytest tests/test_local_monitoring.py -q
```

The lab script never pulls images or attaches to host devices/interfaces.
Actual TLS/mTLS loopback tests separately cover strict CA/IP identity validation,
certificate binding, revocation, signed-envelope rejection, replay, lost receipt,
queue pressure, scope changes, partial lines, rotation and deterministic failure
recommendations. External destinations and actuator paths are rejected.

## Remaining Field Gates

Requires customer-provided authorized source addresses, operator credentials,
approved site/segment mirror/TAP and selected Linux hardware/VM. Measure source
compatibility, benign traffic visibility, real capture drops, queue outage/power
loss, storage pressure, clock drift, rates/thermal load, genuine sensor calibration
and false-positive behavior. Record gaps and uncertain coverage, then independently
verify OS/browser/native-worker egress and source read permissions. No field
qualification, live sensor installation, hardware purchase or broad production
deployment can be honestly completed without that environment and authorization.

Official contracts: [Wazuh indexer](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html),
[CrowdSec LAPI schema](https://github.com/crowdsecurity/crowdsec/blob/master/pkg/models/localapi_swagger.yaml),
[Home Assistant REST](https://developers.home-assistant.io/docs/api/rest/),
[Frigate events](https://docs.frigate.video/integrations/api/events-events-get/),
[ThingsBoard REST](https://thingsboard.io/docs/reference/rest-api/),
[Zeek JSON logs](https://docs.zeek.org/en/current/tutorial/logs.html).
