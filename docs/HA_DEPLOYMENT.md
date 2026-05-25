# High Availability — active / standby deployment

SafeCadence supports two HA architectures, both implementing the same
"only one node mutates at a time" guarantee but with very different
operational profiles. Pick the one that matches how much shared
infrastructure you want to operate.

> If you don't need HA, you can stop reading. The default single-node
> mode is what 90% of installs use, and HA changes nothing about
> single-node behavior — `SC_HA_MODE` unset = "always active" forever.

| Architecture | When to pick it | Backing infra you operate |
|--------------|-----------------|--------------------------|
| **A — shared stores** (v12.1) | Enterprise installs where you already run Postgres + S3 + Redis | Postgres primary + standby, S3/MinIO bucket, Redis (optional Sentinel) |
| **B — peer-to-peer sync** (v12.2) | MSP / SMB / air-gapped — you want two boxes that just talk to each other | Nothing. Just the two SafeCadence nodes. |

Both architectures use the same `@active_only` mutation guards from
v12.1, so the four mutation paths (webhook fire, email send,
scheduled reports, scheduled evidence packs) are protected identically.
The difference is purely in **how the standby stays in sync** with the
active.

---

# Architecture A — Shared backing stores

---

## Topology

```
            ┌──────────────────┐
   client ──▶│  active  node-1  │ ──┐
            └──────────────────┘   │
            ┌──────────────────┐   ├──▶  Postgres  (streaming replication)
            │  standby node-2  │ ──┤    S3 / MinIO  (shared bucket)
            └──────────────────┘   │    Redis       (lease + cache)
                                   │
       both nodes always running, always read
       only ACTIVE writes; standby is hot-warm
```

Five things need to live outside the SafeCadence process:

| Component          | Purpose                                | HA story                 |
|--------------------|----------------------------------------|--------------------------|
| Postgres primary   | All findings, scans, audit log, etc.   | Native streaming repl    |
| Postgres standby   | Read-only mirror of primary            | Promoted via `pg_ctl promote` |
| S3 / MinIO bucket  | Reports, evidence PDFs, attachments    | Object storage = built-in |
| Redis              | Active-node lease coordination + cache | Optional Redis Sentinel  |
| Load balancer      | Routes traffic to whichever node is up | Caddy, nginx, or HAProxy |

---

## Step 1 — Postgres streaming replication (the foundation)

Replication is configured on the database servers, NOT inside
SafeCadence. We use the same Postgres setup that thousands of
production systems run today.

**Primary `postgresql.conf`:**

```
listen_addresses    = '*'
wal_level           = replica
max_wal_senders     = 4
wal_keep_size       = 1024
hot_standby         = on
```

**Primary `pg_hba.conf` — allow standby to connect:**

```
host  replication  replicator  10.0.0.0/24  scram-sha-256
```

**Replication user (run once on primary):**

```sql
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'change-me';
```

**Standby — clone from primary:**

```bash
pg_basebackup \
  -h primary.internal \
  -D /var/lib/postgresql/16/main \
  -U replicator -P -R -X stream
systemctl start postgresql
```

That's it. Standby now follows primary's WAL stream. Verify on standby:

```sql
SELECT pg_is_in_recovery();   -- expect: t
SELECT pg_last_xact_replay_timestamp();
```

---

## Step 2 — Shared object storage

SafeCadence writes reports, evidence packs, and uploaded attachments
to S3 / MinIO when configured. Both nodes point at the same bucket.

```bash
# /etc/safecadence.env on BOTH nodes
SC_S3_ENDPOINT=https://minio.internal:9000
SC_S3_BUCKET=safecadence-shared
SC_S3_ACCESS_KEY=...
SC_S3_SECRET_KEY=...
```

For single-region installs, AWS S3, Wasabi, Backblaze B2, or a
locally-run MinIO cluster all work. The bucket is the source of
truth — no copying needed.

---

## Step 3 — Redis (lease coordination)

A single Redis instance is enough for most deployments — even though
Redis becomes a single point of failure for the lease, losing Redis
just means failover stops working. Both nodes keep serving traffic.

```bash
# Lightweight Redis install for the lease
apt-get install -y redis
systemctl enable --now redis
```

Set on BOTH nodes:

```bash
SC_REDIS_URL=redis://redis.internal:6379/0
SC_NODE_NAME=node-1       # change to node-2 on the second host
SC_CLUSTER_PEERS=node-2.internal:8766
```

Want Redis itself HA? Run Redis Sentinel — three Redis nodes, automatic
failover. Overkill for most SafeCadence installs; needed only when
sub-second lease takeover matters.

---

## Step 4 — Database URL points both nodes at Postgres

```bash
# Active node (writes go here via the application; Postgres takes them)
DATABASE_URL=postgres://safecadence:password@primary.internal/safecadence

# Standby SafeCadence node points at the standby Postgres for reads.
# When it gets promoted (Postgres-side), the application doesn't need
# to change — the standby Postgres just becomes a primary.
DATABASE_URL=postgres://safecadence:password@standby.internal/safecadence
```

The application is read-mostly. Writes from the active node go to
primary Postgres; primary streams to standby Postgres; the standby
SafeCadence node serves reads from standby Postgres. When you promote
Postgres (via `pg_ctl promote` or the orchestration tool of your
choice), the application code doesn't care.

---

## Step 5 — Load balancer in front

Both nodes expose the UI/API on `:8766` (default `safecadence ui` port).
Put a load balancer in front:

**Caddy:**

```caddy
safecadence.example.com {
    reverse_proxy node-1.internal:8766 node-2.internal:8766 {
        lb_policy round_robin
        health_uri /healthz
        health_interval 5s
        health_timeout 2s
        fail_duration 30s
    }
}
```

Reads (UI page loads, GET /api/v1/*) can land on either node — both
serve them correctly.

Writes that go through the API (POST /api/v1/*) will succeed on the
active node and short-circuit (with a 200 + `"skipped": "standby"`
in the response body) on the standby. The load balancer doesn't need
to be aware of this; it'll naturally retry on the next request when
the active flips. If your write workload is heavy and you want only
the active node to receive POSTs, point a separate vhost at the
active-only endpoint (the cluster status API tells the LB which node
is active).

---

## Step 6 — Verify failover works (do this BEFORE production)

```bash
# 1. Confirm node-1 is active.
curl -s https://safecadence.example.com/api/v1/cluster/status | jq .local
# Expect: { ..., "is_active_node": true }

# 2. Kill node-1.
ssh node-1 systemctl stop safecadence

# 3. Wait up to 60s (the lease TTL) then check again.
sleep 65
curl -s https://safecadence.example.com/api/v1/cluster/status | jq .local
# Expect: { "node": "node-2", ..., "is_active_node": true }

# 4. Bring node-1 back.
ssh node-1 systemctl start safecadence
# node-1 comes up as standby (node-2 still holds the lease).

# 5. Manually transfer back (when convenient):
curl -X POST https://node-2/api/v1/cluster/transfer
sleep 5
curl -s https://safecadence.example.com/api/v1/cluster/status | jq .local
# Expect: node-1 active again.
```

Run this drill once when you deploy, then again every quarter.

---

## What the cluster status badge in the UI shows

In the top-right of every page, you'll see one of these (only when
`SC_CLUSTER_PEERS` is set):

* **green ACTIVE** — this node is the active leader.
* **amber STANDBY** — this node is a hot-warm standby; reads only.
* badge is hidden — not a clustered install.

The badge polls `/api/v1/cluster/status` every 30s. Hover for the
detailed tooltip: peer reachability + Postgres replication lag.

---

## Manual failover

Most operators want a quick "drain this node, I need to upgrade it"
button. That's the `transfer` endpoint:

```bash
# On the active node — releases the lease so the standby grabs it.
curl -X POST http://localhost:8766/api/v1/cluster/transfer
```

Returns `{"ok": true, "action": "released"}`. The standby will
detect the empty lease on its next lease-loop tick (within 15s) and
become active.

A "noop" response means the node you called wasn't active in the
first place.

---

## Things that explicitly do NOT happen automatically

We deliberately don't promote Postgres automatically when the primary
dies. Postgres promotion is a one-way operation that requires careful
data-loss tolerance assessment. Use Patroni, pg_auto_failover, repmgr,
or Crunchy Operator if you want automatic Postgres failover — those
are mature, battle-tested tools that are much better at this than we
would be.

We also don't fence the dead node. If node-1 is partitioned away
from Redis but still has network access to Postgres, both nodes would
think they're active. Mitigations:

* Postgres-level safeguards (only one node has the primary's
  connection string at a time).
* The lease TTL (60s) means the partitioned node loses its lease
  quickly.
* For real fencing, integrate with your VM/container orchestrator
  (Kubernetes liveness probes + StatefulSet, systemd watchdog, etc.).

---

## Sizing guidance

| Cluster size | Redis | Postgres | Notes |
|--------------|-------|----------|-------|
| 1 node       | none  | SQLite or Postgres | default install |
| 2 nodes      | single instance | primary + standby (streaming repl) | the recipe above |
| 3+ nodes     | Sentinel (3 nodes) | primary + 2 streaming standbys | unusual; only needed for very large fleets |

For most SafeCadence deployments, 2 nodes covers every realistic
failure mode without the operational complexity of 3+.

---

## Quick reference

| You want to                  | Do this                                  |
|------------------------------|------------------------------------------|
| See cluster status           | `curl /api/v1/cluster/status`            |
| See per-node health          | `curl /healthz/detail` on each node      |
| Drain the active for maint   | `curl -X POST /api/v1/cluster/transfer`  |
| Check replication lag        | `cluster/status` response → `replication_lag` |
| Add a third peer             | Update `SC_CLUSTER_PEERS` on every node, restart |
| Switch back to single-node   | Unset `SC_REDIS_URL`, restart            |

---

# Architecture B — Peer-to-peer continuous sync

Two SafeCadence nodes talking directly to each other over a single
TCP socket. No Postgres, no S3, no Redis. The active node ships every
state-changing event to the standby as it happens; the standby
applies them locally so it's always within seconds of the active.

## Topology

```
   ┌──────────────────┐        TCP (HMAC-signed         ┌──────────────────┐
   │  active  node-1  │◀────── JSON frames, port 8767)──▶│  standby node-2  │
   │  local SQLite    │                                   │  local SQLite    │
   │  peer_events log │   continuous event stream  ──▶   │  applier + dedupe │
   │  vault / files   │                                   │  vault / files    │
   └──────────────────┘                                   └──────────────────┘
        scans + writes                                      receives + applies
        heartbeats every 5s                                  ACKs every event
```

Perfect for:
- MSPs wanting a pfSense-CARP-style two-box pair.
- Air-gapped installs where S3 doesn't exist.
- Customers who don't operate a Postgres cluster.

## How to enable

Set on **both** nodes:

```bash
SC_HA_MODE=peer-sync
SC_PEER_SECRET=<shared HMAC secret, >= 24 chars, generate via `openssl rand -hex 32`>
SC_PEER_HOST=<the OTHER node's hostname or IP>
SC_PEER_PORT=8767                      # default; both nodes use the same
SC_PEER_LISTEN_HOST=0.0.0.0            # default
SC_PEER_LISTEN_PORT=8767               # default
SC_NODE_NAME=node-1                    # change to node-2 on the second host
SC_PEER_DB=~/.safecadence/peer_sync.db # default; per-node local sync state
```

That's it. No Postgres setup, no Redis, no S3 bucket. Restart the
`safecadence` service on each node; the peer-sync daemon threads
start automatically.

## How nodes decide who's active

On boot, both nodes start as `standby`. They listen for events from
the peer. If a node receives no events and no heartbeats for 30
seconds AND the peer's connection is silent, it auto-promotes itself
to `active` and starts shipping events. The other node sees those
events and stays standby.

To explicitly designate one as active at deployment time, run on that node:

```bash
curl -X POST http://localhost:8766/api/v1/cluster/peer/promote
```

## Wire format (for the curious)

Every frame is a 4-byte big-endian length prefix followed by a JSON
object. Six message types:

```
hello         — sent on connect, declares node identity + last_applied_seq
hello-ack     — peer responds with its own last_applied_seq for catchup
event         — { seq, kind, payload, hmac }
ack           — { applied_seq, ok, note }
heartbeat     — { ts }
heartbeat-ack — { ts }
```

HMAC is SHA-256 over `seq\nkind\npayload`, signed with `SC_PEER_SECRET`.
Every event is verified before apply.

## Failover behavior

| Event                              | What happens                                                    |
|------------------------------------|-----------------------------------------------------------------|
| Active dies cleanly                | Standby auto-promotes within ~30s once heartbeats stop          |
| Active dies hard (kernel panic)    | Same — standby detects silence via heartbeat timeout            |
| Network partition between nodes    | Standby promotes (both nodes briefly think they're active until partition heals) |
| Standby reboots                    | Reconnects on boot; active resends from `last_applied_seq` forward |
| Active reboots                     | Standby promotes; old active reconnects as standby on its return |
| Manual drain for maintenance       | `POST /api/v1/cluster/peer/demote` on the active you're draining |

## Operational endpoints

```
GET  /api/v1/cluster/peer/status     # full peer-sync state
POST /api/v1/cluster/peer/promote    # force this node to active
POST /api/v1/cluster/peer/demote     # force this node to standby
```

## Catchup after reconnect

When the standby reconnects to the active (after a network blip or
reboot), it sends its current `last_applied_seq` in the hello frame.
The active replays every event from `last_applied_seq + 1` forward
before resuming live tail. Same pattern Postgres WAL streaming uses,
and same idempotency guarantees: each event has a monotonic seq, and
the applier deduplicates on seq before invoking the handler.

The active's event log is auto-trimmed once the standby has confirmed
it's caught up past that point (the streamer keeps a recent buffer of
the last 100 events to handle transient reconnects without a full
resync).

## Failover test procedure

Run this once when you deploy, then every quarter:

```bash
# 1. Confirm node-1 is active.
curl -s http://node-1:8766/api/v1/cluster/peer/status | jq .role
# Expect: "active"

# 2. Kill node-1.
ssh node-1 systemctl stop safecadence

# 3. Wait 35s (heartbeat threshold + a few seconds).
sleep 35

# 4. Check node-2.
curl -s http://node-2:8766/api/v1/cluster/peer/status | jq .role
# Expect: "active"

# 5. Bring node-1 back. It boots as standby, catches up.
ssh node-1 systemctl start safecadence
sleep 10
curl -s http://node-1:8766/api/v1/cluster/peer/status | jq .role
# Expect: "standby"
curl -s http://node-1:8766/api/v1/cluster/peer/status | jq .last_applied_seq
# Expect: matches active's newest seq within a few seconds
```

## What this does NOT do (deliberately)

- **Does not** replicate the database file directly. We ship events at
  the application layer (idempotent insert/upsert by seq), not raw
  SQLite pages. That's why ANY event kind can be ignored gracefully —
  the standby keeps its `last_applied_seq` consistent regardless.
- **Does not** handle multi-master. Only one node mutates at a time.
- **Does not** fence the dead node at the network layer. If a
  partitioned active still has connectivity to clients, it'll keep
  serving writes — but those writes won't reach the standby. After
  the partition heals, the standby will already have promoted, and
  the old active's mutations are stranded. Mitigations: short heartbeat
  timeout (30s) + the lease TTL semantics protect the common cases.
  For true fencing, run both nodes behind a load balancer with
  health-check-based eviction.

## Which architecture should you pick?

| You're a... | Pick |
|-------------|------|
| Bank, hospital, or anyone with a DBA team | A (shared Postgres) |
| MSP with two boxes at a customer site | B (peer-to-peer) |
| Defense / classified — must be air-gapped | B (peer-to-peer) |
| Already running Kubernetes with cloud-managed databases | A |
| Just want HA without learning Postgres replication | B |
| Need to fail over in < 5 seconds | A with Redis Sentinel |
| OK with 30-second failover | Either |

You can switch between A and B by changing `SC_HA_MODE` and restarting.
The mutation guards work the same way under both.

Last touched: 2026-05-25 — after the v12.2 peer-sync work landed alongside v12.1.
