# SafeCadence active-passive deployment via DigitalOcean Load Balancer

This is the network-layer companion to `postgres-replication-setup.sh`
and the in-app `safecadence.cluster.failover` lease. Goal: when the
active droplet dies, the load balancer drains it and the standby (which
already holds a hot Postgres replica + an empty Redis-backed lease)
takes over within ~60 seconds.

## Topology

```
                                         +-------------------+
                                         |  DO Load Balancer |
                                         |  443 → 8002 (TLS) |
                                         +---------+---------+
                                                   |
                              +--------------------+--------------------+
                              |                                         |
                +-------------v-------------+             +-------------v-------------+
                |     droplet-active        |             |     droplet-standby       |
                |  safecadence-analyzer     |             |  safecadence-analyzer     |
                |  postgres-16 (primary)    |  ---WAL---> |  postgres-16 (standby)    |
                |  redis-7 (master)         |  ---repl--> |  redis-7 (replica)        |
                |  HAS lease — active node  |             |  No lease — passive       |
                +---------------------------+             +---------------------------+
```

Both droplets run the **same** systemd unit `safecadence-analyzer.service`.
The only difference is which one currently holds the Redis-backed lease
`safecadence:cluster:active_node`.

## DO Load Balancer config (one-time)

1. **Create the LB** in the same VPC as both droplets.
2. Forwarding rules:
   - HTTPS 443 → HTTP 8002 (Let's Encrypt cert, sticky-session OFF).
3. Health check:
   - **Protocol:** HTTP
   - **Port:** 8002
   - **Path:** `/healthz/active`  (returns 200 only on the active node;
     503 on the standby. The route is implemented by
     `safecadence.cluster.health.node_health()`.)
   - **Interval:** 10s
   - **Unhealthy threshold:** 3 (≈ 30s)
   - **Healthy threshold:** 2
4. Add both droplets as backends.
5. DNS: point `app.safecadence.com` at the LB's hostname (not at either
   droplet directly).

## Why a `/healthz/active` instead of plain `/healthz`?

The LB needs to route traffic to **only** the node that currently holds
the lease. If we used `/healthz`, both nodes would return 200 and the LB
would split traffic between them — but the standby database is
read-only and would 500 on every write.

A 503 from the standby's `/healthz/active` is *intentional* — it tells
the LB "I am up but please don't send me writes".

## Promotion drill

1. SSH into the standby:
   ```bash
   sudo -u postgres pg_ctlcluster 16 main promote
   ```
2. Update the Postgres URL on the **previous** active droplet (if it's
   still alive) so it now points at the new primary.
3. The in-app failover thread will detect the lease expired and grab it.
4. Once verified, run `postgres-replication-setup.sh` with `ROLE=standby`
   on the *old* primary to rejoin the cluster as the new standby.

## Redis (active-passive, not active-active)

We deliberately don't run Redis in cluster mode — it's overkill for the
two-node footprint. Either:

- **Sentinel** (recommended): three sentinels, one Redis master, one
  Redis replica. Sentinel handles automatic master promotion.
- **Manual:** Run Redis only on the active droplet. On failover, start
  Redis on the standby. Note the in-memory job queue is empty after
  this — fine, since the LB drains pending requests anyway.

## Smoke test

```bash
# from your laptop
curl -s https://app.safecadence.com/healthz/cluster | jq
```

Expected:

```json
{
  "local": {"is_active_node": true, "db_status": "ok", ...},
  "peers": [{"peer": "10.0.0.6", "reachable": true, "data": {...}}],
  "reachable_peers": 1,
  "healthy": true
}
```

## Cost notes (DigitalOcean, May 2026 pricing)

- 2× s-2vcpu-2gb droplets:    $24/mo
- 1× DO Load Balancer:        $12/mo
- 1× DO Spaces bucket:        $5/mo (250 GB included)
- Postgres replication WAL:   free (over VPC)

Total ≈ $41/mo for active-passive vs $12/mo for the current single-droplet
setup. Document this in the next pricing review before flipping it on.
