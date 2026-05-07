# SafeCadence Deployment Architecture

SafeCadence runs in five shapes that match real-world buyer profiles. The
**same wheel** powers every shape — no separate "enterprise edition." You
pick the topology that fits, install once, configure flags.

## TL;DR — pick your shape

| Shape | Who | Install | Auth | Storage |
|---|---|---|---|---|
| **1. Standalone laptop** | Individual engineer / consultant | `pipx install` | None (localhost) | SQLite + JSON files in `~/.safecadence/` |
| **2. Single team server** | SMB, single-site mid-market | `pipx install` + `safecadence api` | JWT | Postgres |
| **3. Site-local + central hub** | Enterprise, multi-DC | `pipx install` per site + `safecadence hub` | JWT + mTLS between sites | Postgres per site, optional central rollup |
| **4. Hub-and-spoke MSP** | Managed service providers | `pipx install` per customer + MSP hub | mTLS per customer | Per-customer Postgres |
| **5. Air-gapped / isolated** | Gov / OT / SCADA / classified | Tarball + `pipx install --offline` | None | SQLite + JSON files; sneakernet enrichment via `safecadence enrichment package` |

## Shape 1 — Standalone laptop (default)

```
[ engineer's laptop ]
  pipx install safecadence-netrisk
  safecadence ui
  ↓
  127.0.0.1:8765   (no auth, single user)
  ↓
  ~/.safecadence/
    ├── platform_assets/   (per-asset JSON snapshots)
    ├── policies/          (per-policy JSON)
    ├── policy_audit-*.jsonl
    └── ui.sqlite
```

**Fits:** consultants doing client audits, individual SREs/sysadmins, dev/test.
**Pros:** zero infrastructure, complete data sovereignty, instant teardown.
**Cons:** doesn't scale beyond one user.

## Shape 2 — Single team server

```
                     ┌─────────────────────────────┐
                     │ shared VM / container       │
                     │ safecadence api --host 0.0.0.0
                     │ + JWT auth (built-in)       │
                     │ + Postgres backend          │
                     └──────────────┬──────────────┘
                                    │ HTTPS (reverse proxy / TLS termination)
            ┌───────────────┬───────┼───────────────┐
            ▼               ▼       ▼               ▼
       engineer A      engineer B   ops    CI/CD pipeline
       (browser)       (browser)    (CLI)  (`safecadence policy ci-check`)
```

**Install:**
```bash
# On the team server
pipx install 'safecadence-netrisk[server]'
export SC_JWT_SECRET="$(openssl rand -hex 32)"
export DATABASE_URL=postgresql://user:pass@db:5432/safecadence
safecadence api --host 0.0.0.0 --port 8765
```

**Fits:** SMB / mid-market, single site, ~10-100 engineers sharing the install.
**Pros:** one source of truth, RBAC via JWT roles, durable Postgres backend.
**Cons:** all eggs in one basket; if the VM dies, ops loses visibility until restored.

## Shape 3 — Site-local + central aggregator (recommended for enterprise)

```
[ DC East ]              [ DC West ]              [ AWS us-east-1 ]
 safecadence node          safecadence node         safecadence node
  ↓ collects locally        ↓ collects locally      ↓ collects locally
  ↓ Postgres per site       ↓ Postgres per site     ↓ Postgres per site
  ↓ local UI                ↓ local UI              ↓ local UI
  └──────────┐    ┌─────────┘    ┌─────────────────┘
             ▼    ▼              ▼
        ┌────────────────────────────────────┐
        │  safecadence hub                   │
        │  - read-only mTLS to each node     │
        │  - aggregates findings + policies  │
        │  - hub UI = cross-site picture     │
        │  - central policy authoring        │
        │  - central audit log retention     │
        └────────────────────────────────────┘
```

**Why this beats centralized SaaS:**
- Each site owns its data (sovereignty / GDPR / data residency)
- Low WAN bandwidth (only deltas + summaries cross the WAN)
- Hub failure ≠ site failure (each site keeps working)
- Compliance audit at each site, then rolled up

**Install:**
```bash
# At each site (DC East, DC West, etc.)
pipx install 'safecadence-netrisk[server]'
safecadence api --host 0.0.0.0 --port 8765
# Generate per-node mTLS cert
safecadence cert init --node "dc-east"

# At the hub
pipx install 'safecadence-netrisk[server]'
safecadence hub start --listen 0.0.0.0:8766
safecadence hub register --node "dc-east" --cert dc-east.crt --url https://dc-east.internal:8765
safecadence hub register --node "dc-west" --cert dc-west.crt --url https://dc-west.internal:8765
```

**Federation protocol (hub ↔ node):**
- Direction: hub initiates; nodes never call out (firewall-friendly, polling)
- Auth: per-node mTLS certs issued by the hub
- Endpoints: `GET /api/federation/inventory`, `/api/federation/violations`, `/api/federation/health` (read-only on the node side)
- Frequency: 15 minutes default; configurable per node
- Schema versioning: `X-SafeCadence-Schema: 1` header
- Anonymization: optional `--anon` strips IPs/hostnames before responding

**Fits:** enterprises with multiple datacenters / regions / clouds.
**Pros:** scales horizontally, data residency by design, partial failure tolerance.
**Cons:** more moving parts; hub is single point of operational truth.

## Shape 4 — Hub-and-spoke for MSPs

```
[ Customer A — their VPC ]   [ Customer B — their VPC ]   [ Customer C ]
 safecadence (their data)     safecadence (their data)    safecadence
       │                              │                          │
       └──── per-customer mTLS ───────┴──────────────────────────┘
                                  │
                                  ▼
                  [ MSP hub — central operations console ]
                  - sees ALL customers in one view
                  - per-customer dashboards + reports
                  - generates per-customer remediation
                  - audit log per customer (compliance ↘)
                  - per-customer credential isolation (zero shared state)
```

**Why this is critical for SafeCadence's consulting business:**
- Each customer keeps their own data (sovereignty by design)
- MSP has read-only credentials per customer (no admin sprawl)
- Customer can revoke MSP access by rotating their per-MSP cert
- Compliance audit cleanly per customer

**Install:**
- Customer side: same as Shape 2 (single team server) inside their VPC
- MSP side: same as Shape 3 hub (central aggregator) — but with strict
  per-customer namespace isolation in the hub UI

## Shape 5 — Air-gapped / isolated network mode

```
[ classified / OT / SCADA network — no internet ]
  safecadence node (offline)
  ├── pipx install --offline (from a transferred wheel)
  ├── policies via `safecadence policy git-sync` from internal git
  └── enrichment refresh via `safecadence enrichment import bundle.tar.gz`
       └── bundle built on a connected machine via:
           safecadence enrichment package /tmp/enrichment.tar.gz
           (pulls latest CVE / KEV / EOL / EPSS into a sneakernet bundle)
```

**Fits:** government, defense, OT/SCADA, regulated industries.
**Pros:** zero-trust posture; nothing leaves the boundary, ever.
**Cons:** enrichment data is only as fresh as the last sneakernet update.

## Hierarchy across all shapes

```
Data plane (collection)        ALWAYS local. Never leaves the site.
   │
Control plane (policy + UI)    Local OR centralized via hub.
   │
Management plane (creds)       ALWAYS local. Hub never sees customer creds.
   │
Storage hierarchy:
   Tier 1: SQLite + JSON files     (Shape 1, 5)
   Tier 2: Postgres                 (Shape 2, 3, 4)
   Tier 3: S3-compat object store   (archived audit logs >90 days, optional)
   Tier 4: SIEM forwarding          (Splunk / Sentinel / Elastic, via webhooks)
```

## Sizing guidance

| Fleet size | Shape | RAM | CPU | Disk | Notes |
|---|---|---|---|---|---|
| <100 assets | 1 (laptop) | 4 GB | 2 cores | 1 GB | Default `safecadence ui` |
| 100-1,000 | 2 (team server) | 8 GB | 4 cores | 20 GB | Postgres on same host fine |
| 1,000-10,000 | 3 (site + hub) | per site: 16 GB / 8 cores / 50 GB; hub: 8 GB / 4 cores / 20 GB | Postgres separate per site |
| 10,000+ | 3 (site + hub) | site: 32 GB / 16 cores / 200 GB; hub: 16 GB / 8 cores / 50 GB | Postgres tuned, S3 archival |

## Network requirements

| Shape | Inbound to SafeCadence | Outbound from SafeCadence |
|---|---|---|
| 1 (laptop) | none (localhost) | only what your adapters poll (your devices) + optional BYO-AI provider |
| 2 (team server) | TCP 8765 (HTTPS) from your engineers' subnets | only what your adapters poll |
| 3 (site + hub) | site: TCP 8765 from hub IP only; hub: TCP 8766 from your engineers | site→devices (poll); hub→sites (poll for federation) |
| 4 (MSP) | per-customer site: TCP 8765 from MSP hub IP only | site→customer's devices |
| 5 (air-gapped) | none | none |

## Backup & disaster recovery

- **Shape 1, 5:** copy `~/.safecadence/` to an encrypted USB / S3 bucket. Restore = put it back.
- **Shape 2, 3, 4:** standard Postgres `pg_dump` + the file-system asset cache. Test restore quarterly.

## TLS / certificate management

- Shape 1: not applicable (localhost only).
- Shape 2: terminate TLS at a reverse proxy (nginx, Caddy, HAProxy). SafeCadence does plain HTTP behind the proxy.
- Shape 3, 4: SafeCadence has built-in mTLS for federation. Run `safecadence cert init` to generate; rotate annually.

## Upgrade path

```bash
# All shapes — single command
pipx upgrade safecadence-netrisk

# In Shape 3/4, upgrade hub LAST after all sites are upgraded.
# Schema version is checked per request; hub will refuse to talk to
# nodes >1 major version behind.
```

## Where this *isn't* a fit

- **Real-time intrusion detection.** SafeCadence polls; it doesn't tap traffic. Use Suricata/Zeek for IDS.
- **Endpoint EDR.** No agent; no in-memory inspection. Use CrowdStrike/SentinelOne for EDR.
- **DLP.** Not a content-inspection tool.
- **CASB.** Limited cloud-app coverage; only the 6 cloud adapters we ship.
