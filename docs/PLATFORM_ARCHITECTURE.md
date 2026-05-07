# SafeCadence Device Intelligence Platform — Architecture

This is the v3.0 expansion of safecadence-netrisk from a network-only audit tool
into a full multi-vendor enterprise infrastructure platform covering network,
servers, storage, virtualization, cloud, and backup.

**Status (v3.0.0):** Foundation built. ONE reference adapter (Dell iDRAC via
Redfish) production-ready. The remaining 30+ vendor adapters are spec'd here
but each requires real hardware to build + test. Community contributions welcome.

## Architecture diagram

```
                              ┌──────────────────────────┐
                              │  Web UI (existing tabs)  │
                              │  + new platform tabs     │
                              └────────────┬─────────────┘
                                           │
                              ┌────────────┴─────────────┐
                              │  FastAPI backend         │
                              │  /api/platform/*         │
                              └────────────┬─────────────┘
                                           │
              ┌────────────────────────────┴────────────────────────────┐
              │                                                          │
              ▼                                                          ▼
  ┌─────────────────────┐                              ┌─────────────────────────┐
  │  Adapter Framework  │                              │  Correlation + Scoring  │
  │  (BaseAdapter +     │   ─── UnifiedAsset ───►     │  + AI engine            │
  │   registry)         │                              │  + Reports              │
  └──────────┬──────────┘                              └─────────────────────────┘
             │
   ┌─────────┼─────────┬──────────┬─────────┬──────────┬─────────┐
   ▼         ▼         ▼          ▼         ▼          ▼         ▼
network_*  server_*  storage_*  virt_*   cloud_*   backup_*   custom_*
adapters   adapters  adapters   adapters adapters  adapters   adapters
   │         │         │          │         │          │         │
   ▼         ▼         ▼          ▼         ▼          ▼         ▼
  SSH/    Redfish/    REST/      vSphere   AWS/       REST/     plugin
  SNMP/   IPMI/       SOAP/       SDK/      Azure/     SDK       contract
  REST    SDK         SDK         REST      GCP SDK
   │         │         │          │         │          │         │
   ▼         ▼         ▼          ▼         ▼          ▼         ▼
   ┌──────────────────────────────────────────────────────────────┐
   │              Connection Manager (rate-limited, auditable)    │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────┐
   │       Platform Vault (Fernet-encrypted multi-vendor creds)   │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────┐
   │       UnifiedAsset SQLite store + diff engine                │
   └──────────────────────────────────────────────────────────────┘
```

## Core abstraction: UnifiedAsset

Every adapter normalizes vendor-specific data into the same dataclass (see
`src/safecadence/platform/schema.py`). Downstream consumers (UI, reports,
correlation, AI) operate on UnifiedAsset objects without caring about vendor.

```python
@dataclass
class UnifiedAsset:
    identity: AssetIdentity                # who is this asset?
    hardware: Hardware                     # physical layer
    os: OperatingSystem                    # software layer
    interfaces: list[Interface]            # network connections
    storage: Storage                       # storage details (if applicable)
    virtualization: Virtualization         # hypervisor/VM details
    cloud: Cloud                           # cloud-specific (AWS/Azure/GCP)
    backup: Backup                         # backup state
    security: Security                     # vulns + findings + actions
    lifecycle: Lifecycle                   # EOL/EOS/warranty
    health: HealthScores                   # 4 dimensions + composite + grade
    relationships: list[dict]              # links to other assets
    raw_collection: dict                   # debug: raw vendor response
```

Adapters fill only the sub-objects relevant to their asset type. A network
switch leaves `cloud` and `backup` empty; an EC2 instance leaves `hardware`
mostly empty.

## Adapter contract

Every vendor adapter inherits from `BaseAdapter` and implements 4 methods:

```python
class MyVendorAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="my_vendor",
        vendor="MyVendor",
        asset_types=["server"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://...",
    )

    def test_connection(self) -> dict: ...      # cheap auth check
    def discover(self) -> list[dict]: ...       # enumerate assets at this target
    def collect(self, asset_id: str) -> dict: ... # pull all raw data
    def normalize(self, asset_id, raw) -> UnifiedAsset: ... # → UnifiedAsset
```

Registered with a decorator: `@register_adapter("my_vendor")`.

The platform handles connection pooling, rate limiting, retry, credential
encryption, and audit logging — the adapter just focuses on vendor-specific
data extraction + normalization.

## Database schema

Adds 3 new SQLite stores beyond the existing ones:

| Store | Path | Purpose |
|---|---|---|
| `platform_assets` | `~/.safecadence/platform.sqlite` | UnifiedAsset persistence + history |
| `platform_credentials` | `~/.safecadence/platform_credentials.sqlite` | Fernet-encrypted multi-vendor credentials + audit log |
| `platform_relationships` | (same DB) | Asset-to-asset edges for correlation |

```sql
CREATE TABLE platform_assets (
    id          INTEGER PRIMARY KEY,
    asset_id    TEXT UNIQUE NOT NULL,
    asset_type  TEXT,                -- network | server | storage | hypervisor | cloud | backup
    vendor      TEXT,
    adapter     TEXT,                -- which adapter collected it
    payload     TEXT NOT NULL,        -- JSON-serialized UnifiedAsset
    health_score INTEGER,
    risk_band   TEXT,
    discovered_at TEXT,
    last_collected_at TEXT
);

CREATE TABLE platform_relationships (
    id          INTEGER PRIMARY KEY,
    source_id   TEXT,                -- asset_id
    target_id   TEXT,                -- asset_id
    relationship TEXT,               -- hosts | consumes_storage | backed_up_by | located_in
    discovered_at TEXT
);

CREATE TABLE platform_collection_history (
    id          INTEGER PRIMARY KEY,
    asset_id    TEXT,
    payload     TEXT,                -- snapshot of UnifiedAsset
    collected_at TEXT
);
```

## API endpoints (planned for v3.0)

```
POST  /api/platform/credentials               # store creds (encrypted)
GET   /api/platform/credentials               # list (no secrets)
DELETE /api/platform/credentials/{label}

POST  /api/platform/adapter/test              # test connection to an asset
POST  /api/platform/adapter/discover          # enumerate assets at target
POST  /api/platform/adapter/collect           # pull data + normalize
POST  /api/platform/adapter/collect-all       # discover + collect all assets

GET   /api/platform/assets                    # list all UnifiedAssets
GET   /api/platform/assets/{asset_id}         # one asset
GET   /api/platform/assets/{asset_id}/history # collection history
DELETE /api/platform/assets/{asset_id}

GET   /api/platform/correlations              # all asset relationships
POST  /api/platform/correlate                 # compute relationships fresh

POST  /api/platform/report                    # generate cross-asset report
GET   /api/platform/adapters                  # list registered adapters
```

## Correlation engine

The platform's most valuable output: cross-layer relationships.

```
Network device (switch port 1/0/3)
    └── connects to ──> Server (NIC eth0)
                          └── runs ──> Hypervisor (ESXi)
                                         └── hosts ──> VM (vm-prod-db-01)
                                                        └── stores on ──> Storage (NetApp vol01)
                                                                              └── backed up by ──> Veeam job-prod-db-daily
```

The correlation engine looks for matches across UnifiedAssets:
- MAC address on a switch port → server NIC MAC → server identity
- Storage protocol target IQN → hypervisor datastore mount → VM disk
- Cloud security group reference → EC2 instance → backup target

Outputs an asset graph that the UI renders as an interactive topology.

## AI scoring model

Per asset:
- **Hardware health** (0-100) — power supplies, fans, temps, RAID
- **Security health** (0-100) — KEV CVEs, vulns, exposed services, weak protocols
- **Lifecycle health** (0-100) — EOL/EOS proximity, warranty
- **Operational health** (0-100) — uptime, errors, backup status

Composite: weighted average (security weighted highest at 40%, hardware 25%,
lifecycle 20%, operational 15%). Grade A-F + risk band safe/low/medium/high/critical.

Each deduction is documented (transparent, auditable, no black-box ML).

AI augments scoring with:
- Cross-device pattern recognition (handled by existing v2.5 bulk-analyze)
- Architecture review (handled by existing v2.7 AI architect)
- Per-asset deep-dive (handled by existing v2.4 AI deep-analyze)

## MVP roadmap

**Phase 1 (this release, v3.0.0):**
- ✅ Adapter framework
- ✅ UnifiedAsset schema
- ✅ Connection manager
- ✅ Platform credential vault
- ✅ Health scoring engine
- ✅ Dell iDRAC reference adapter (Redfish)
- ☐ HPE iLO adapter (Redfish — easy, mostly identical to iDRAC)
- ☐ Cisco UCS adapter (XML API — needs UCS Manager test access)
- ☐ VMware vCenter adapter (pyvmomi or REST — needs vCenter access)
- ☐ NetApp ONTAP adapter (REST API — needs NetApp test rig)
- ☐ AWS adapter (boto3 — straightforward, needs AWS account)

**Phase 2 (v3.1+):**
- Fortinet, Palo Alto, Pure Storage, Veeam, Azure, Nutanix
- Multi-tenant + RBAC
- Customer-facing portal (white-label)

**Phase 3 (v3.2+):**
- Topology auto-mapping with correlation
- Compliance audit packs at multi-asset scope
- MSP multi-tenant view
- Advanced AI: attack surface analysis, predictive failure

## What I (Claude/AI) cannot build well in a single session

These adapters require real hardware/SDK access to test against — building them
blind produces fictional code that breaks in production:

- Pure Storage FlashArray (need Pure to confirm REST API responses)
- NetApp ONTAP (need a NetApp filer; ONTAP REST API has many quirks)
- Cisco UCS Manager (XML-RPC, very specific)
- IBM Power Systems HMC (proprietary API, niche)
- Hitachi Vantara (need access to a Hitachi array)
- Veeam / Commvault / Rubrik (each proprietary REST API, each different)

**Recommendation:** open these as GitHub issues, attract a vendor specialist
contributor for each (e.g., a Veeam engineer who wants to add a Veeam adapter
to give back to the community). Provide them this architecture doc + the Dell
iDRAC adapter as a template.

## Contributing an adapter

```
1. Fork github.com/famousleads/safecadence-network-risk
2. Copy src/safecadence/platform/adapters/dell_idrac.py as a template
3. Rename → src/safecadence/platform/adapters/your_vendor.py
4. Update class name, capabilities, all four methods
5. Add to src/safecadence/platform/adapters/__init__.py imports
6. Test against real gear (or vendor's test/dev environment)
7. Open a PR with at least one passing functional test
```

## Honest scope reality

This platform is genuinely a $5M-$50M ARR product opportunity, but building it
to feature-parity with Lansweeper / Device42 / ServiceNow Discovery requires
**6-12 months of focused work for a 2-3 engineer team**. Each vendor adapter
(beyond the Redfish-standard ones like Dell/HPE/Lenovo BMCs) is genuinely
80-160 hours of build + test work.

The right product strategy is to:

1. **Pick ONE vertical and dominate it** — datacenter switches + UCS + VMware,
   or AWS + Azure + GCP, or Veeam + Commvault + Rubrik. Going deep on one
   vertical beats going shallow on all.
2. **Recruit vendor specialists** as contributors. A Cisco engineer who
   contributes the Cisco UCS adapter is worth more than 3 months of generalist
   build time.
3. **Sell the foundation as a service** — even before all adapters exist,
   the Dell iDRAC adapter alone + the existing network audit tooling is a
   sellable product for any company with Dell servers + multi-vendor switches.
