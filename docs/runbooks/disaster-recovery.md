# Disaster Recovery Runbook

> **Audience:** SafeCadence platform operators (on-call). Every scenario
> below has been rehearsed in staging at least once. The exact commands
> work against the production droplet `104.131.183.149`.
>
> Keep this file in sync with `~/.safecadence/audit.jsonl` after any
> real-world execution. Append a brief post-mortem to the end of this
> file or — preferably — open a doc PR with the lessons learned.

## How to use this runbook

1. Identify which scenario matches what you're seeing.
2. Confirm the trigger conditions (don't fire DR procedures on a
   one-off blip).
3. Execute the steps **in order**. Each step has a success criterion;
   don't move on until that criterion is met.
4. After resolution, fill out the post-mortem template at the bottom of
   this file (Markdown copy/paste — keep them in `docs/runbooks/postmortems/`).

---

## Scenario 1 — Primary droplet down

**Trigger conditions (any of):**
- `/healthz` returns 5xx or times out for ≥ 5 minutes from two different
  geographic checks (DO uptime monitor + an external probe).
- SSH to `root@104.131.183.149` fails AND console shows the droplet is
  not booted.
- Active customer reports of "site is down" across more than one org.

**Prerequisites:**
- DigitalOcean dashboard access (operator login).
- A current backup tarball within the last 24 h (check
  `/var/backups/safecadence-backup-*.tar.gz`).
- DO Load Balancer is provisioned (a one-time setup; see
  `docs/DEPLOY.md`). If it isn't, **stop and read that section first**.

**Steps:**

1. Confirm the outage from a clean network.

   ```bash
   curl -sS -o /dev/null -w "%{http_code}\n" https://analyzer.safecadence.com/healthz
   ```

   Expected: `200`. If you see `000` (timeout) or `5xx` proceed.

2. Open the DigitalOcean droplet page and check the graphs (CPU /
   network / disk). If they're flat-lined for ≥ 5 minutes the droplet
   is the problem, not the app.

3. Fail over via the DO Load Balancer:

   - Settings → Load Balancers → `safecadence-lb`.
   - Move the active backend to the standby droplet (or the
     warm-standby snapshot — both are documented in the LB notes).

4. Validate the failover.

   ```bash
   for i in 1 2 3 4 5; do
     curl -sS -o /dev/null -w "%{http_code} " https://analyzer.safecadence.com/healthz
     sleep 5
   done; echo
   ```

   Success criterion: 5/5 `200` responses.

5. Document.

   - Append a row to `docs/runbooks/postmortems/INCIDENTS.md`.
   - Notify customers via the status page (`status.safecadence.com`).
   - File a follow-up ticket for the root cause of the primary failure.

---

## Scenario 2 — Database corruption

**Trigger conditions:**
- Portal returns 500 errors specifically on routes that read the DB.
- Logs show `sqlite3.DatabaseError` / `database disk image is malformed`
  / `OperationalError: no such table:`.
- `sqlite3 /var/lib/securityalgo/portal.db ".tables"` reports an error
  or empty output (when it should list ≥ 12 tables).

**Prerequisites:**
- A recent backup tarball (last 24 h).
- SSH access to the droplet (or a DO Recovery Console session).

**Steps:**

1. Take the app offline (prevent further writes during repair).

   ```bash
   systemctl stop safecadence-analyzer.service
   ```

2. Move the corrupt DB aside (never delete it — auditors will ask).

   ```bash
   mv /var/lib/securityalgo/portal.db /var/lib/securityalgo/portal.db.corrupt.$(date +%s)
   ```

3. Restore from the latest backup.

   ```bash
   /srv/safecadence/apps/analyzer/.venv/bin/safecadence ops restore \
       --from /var/backups/safecadence-backup-LATEST.tar.gz
   ```

   The CLI writes the new `portal.db` to `$SAFECADENCE_HOME` (== the
   `state/portal.db` member of the backup) and reports the number of
   files restored.

4. If a `change_log.jsonl` exists between the backup time and the
   outage time, replay it. The change log is best-effort — only
   `change_mgmt.py` events are guaranteed there, so this is a partial
   recovery for everything else.

   ```bash
   /srv/safecadence/apps/analyzer/.venv/bin/safecadence \
       change-log replay --since "2026-05-11T00:00:00Z"
   ```

5. Start the app and verify.

   ```bash
   systemctl start safecadence-analyzer.service
   journalctl -u safecadence-analyzer.service -n 50 --no-pager
   curl -sS https://analyzer.safecadence.com/healthz
   ```

   Success criterion: `200` from `/healthz` AND the dashboard renders
   project rows for the operator's test org.

6. Run the audit-chain verifier for every org as a sanity check.

   ```bash
   for org in $(ls ~/.safecadence/orgs); do
       /srv/safecadence/apps/analyzer/.venv/bin/safecadence ops verify-audit \
           --org-id "$org" || echo "  ✗ chain BROKEN for $org"
   done
   ```

   Any "BROKEN" message means data was tampered with OR truncated
   during the restore. Restore that specific org from an older backup.

---

## Scenario 3 — Lost SSH access

**Trigger conditions:**
- SSH to the droplet hangs / drops / "permission denied (publickey)".
- DigitalOcean Web Console shows "All configured authentication
  methods failed" or "SSH Connection Lost".
- The droplet itself is up (DO graphs show CPU/network activity).

**This is the recovery procedure that has been rehearsed in production
twice. It works. Don't improvise.**

**Prerequisites:**
- DigitalOcean operator login.
- A workstation with the deploy keypair handy (the `DEPLOY_SSH_KEY` value
  from GitHub Actions secrets, base64-decoded into an actual private key
  file).

**Steps:**

1. Open the droplet → **Power** → power off.

2. Settings → **Recovery** → "Boot from Recovery ISO" → **Save** → power on.

3. Open the Recovery Console. Choose option **1 (Mount disk)**, then
   option **5 (chroot into mounted disk)**.

4. Inside the chroot, append the working public key to root's
   authorized_keys and confirm sshd config is correct.

   ```bash
   mkdir -p /root/.ssh
   chmod 700 /root/.ssh
   cat >> /root/.ssh/authorized_keys <<'PUBKEY'
   ssh-ed25519 AAAA…  deploy@safecadence
   PUBKEY
   chmod 600 /root/.ssh/authorized_keys

   grep -E '^PermitRootLogin|^PubkeyAuthentication' /etc/ssh/sshd_config.d/*.conf
   # Expected:
   #   PermitRootLogin prohibit-password
   #   PubkeyAuthentication yes
   ```

5. **If `ssh.service` is not enabled** (we hit this twice — stock
   `ssh.service` doesn't auto-start on this droplet), enable our
   `force-sshd.service` override. Verify it exists:

   ```bash
   systemctl cat force-sshd.service
   ```

   Should show `ExecStart=/usr/sbin/sshd -D -e`. If it doesn't exist,
   create it (see `~/Desktop/SecurityAlgo/CLAUDE.md` failure mode #7
   for the exact unit content).

6. Exit the chroot. Option **1 (Unmount)** in the recovery menu.

7. Settings → Recovery → "Boot from Hard Drive" → Save → power on.

8. From a workstation:

   ```bash
   ssh -i ~/.ssh/safecadence_deploy_key root@104.131.183.149 \
       'systemctl status safecadence-analyzer.service'
   ```

   Success criterion: SSH connects in < 5 s, service is `active (running)`.

---

## Scenario 4 — Postgres replication lag > 5 min

> Only relevant when running the v10.7 Postgres-backed deployment (the
> SQLite default has no replication). If you don't know which mode
> you're on, run `psql $DATABASE_URL -c "SELECT 1;"` — if it errors,
> you're on SQLite and this scenario does not apply.

**Trigger conditions:**
- Observability dashboard: `pg_replication_lag_seconds > 300` for ≥ 5 min.
- Replica logs show `WARNING: could not receive data from WAL stream`.

**Prerequisites:**
- Replica connection string (`DATABASE_REPLICA_URL`).
- Approval to force a failover (operator on call OR engineering lead).

**Steps:**

1. Confirm lag isn't a one-off (a 30-second blip is fine; sustained > 5 min is the trigger).

   ```bash
   psql "$DATABASE_REPLICA_URL" -c \
     "SELECT now() - pg_last_xact_replay_timestamp() AS lag;"
   ```

2. Investigate the cause.

   - Disk full on replica? `df -h` on both nodes.
   - Network saturation? Check the WAL sender stats:
     `psql "$DATABASE_URL" -c "SELECT * FROM pg_stat_replication;"`.
   - Long-running query on primary holding xmin? Kill it.

3. If the cause is non-recoverable in < 10 minutes, force failover.

   ```bash
   # Promote the replica
   ssh replica 'pg_ctl promote -D /var/lib/postgresql/15/main'

   # Flip the app's DATABASE_URL to point at the new primary
   sed -i 's|DATABASE_URL=postgresql://.*|DATABASE_URL=postgresql://NEW_PRIMARY|' \
       /etc/safecadence-analyzer.env
   systemctl restart safecadence-analyzer.service
   ```

4. Validate writes go to the new primary.

   ```bash
   curl -sS -X POST https://analyzer.safecadence.com/api/v1/projects \
        -H "Authorization: Bearer $SC_API_KEY" \
        -d '{"name": "dr-test"}'
   psql "$DATABASE_URL" -c "SELECT id FROM projects WHERE name='dr-test';"
   ```

   Success criterion: the project row exists in the new primary.

5. File the post-mortem. Replica re-bootstrap is a separate runbook
   (see `docs/runbooks/postgres-replica-rebuild.md`).

---

## Scenario 5 — Stripe webhook missed events

**Trigger conditions:**
- Customer reports their plan upgrade didn't take effect.
- Stripe dashboard shows the event delivered with a 5xx response from
  our webhook endpoint.
- `~/.safecadence/orgs/*/billing_events.jsonl` is missing entries that
  appear in Stripe's event log.

**Prerequisites:**
- Stripe secret key (`STRIPE_SECRET_KEY`) — operator-only.
- `STRIPE_WEBHOOK_SECRET` so HMAC verification works.

**Steps:**

1. Pull the last 100 events from Stripe.

   ```bash
   stripe events list --limit 100 --api-key $STRIPE_SECRET_KEY > /tmp/events.json
   ```

2. Identify which event ids did NOT appear in our local log.

   ```bash
   jq -r '.data[].id' /tmp/events.json | sort > /tmp/stripe_ids.txt
   jq -r '.event_id // empty' \
       ~/.safecadence/orgs/*/billing_events.jsonl | sort -u > /tmp/local_ids.txt
   comm -23 /tmp/stripe_ids.txt /tmp/local_ids.txt > /tmp/missing.txt
   wc -l /tmp/missing.txt
   ```

3. Replay each missing event through our handler.

   ```bash
   while read id; do
       stripe events retrieve "$id" --api-key $STRIPE_SECRET_KEY \
           > /tmp/event.json
       /srv/safecadence/apps/analyzer/.venv/bin/safecadence \
           billing replay --event /tmp/event.json
   done < /tmp/missing.txt
   ```

4. Verify the customer's plan now matches what Stripe says.

   ```bash
   /srv/safecadence/apps/analyzer/.venv/bin/safecadence \
       billing show --org-id $ORG
   stripe customers retrieve $CUST_ID --api-key $STRIPE_SECRET_KEY | jq .subscriptions
   ```

   Success criterion: both report the same plan + status.

5. Notify the affected customer that their billing state is now
   consistent. File the post-mortem.

---

## Post-mortem template

Use this template for every DR execution — real or rehearsal. Save to
`docs/runbooks/postmortems/YYYY-MM-DD-<short-tag>.md`.

```markdown
# Post-mortem — <one-line summary>

- **Date / time (UTC):** 2026-05-11 14:32 → 15:09
- **Severity:** SEV-2
- **On-call:** @operator
- **Customer impact:** ~12 min of 502s for studio.safecadence.com
- **Scenario invoked:** #1 — Primary droplet down

## Timeline
- 14:32 — Pager fires (`/healthz` 5xx)
- 14:35 — Confirmed outage, opened DO dashboard
- 14:41 — Triggered LB failover to standby
- 14:44 — `/healthz` returns 200 from external probe
- 15:09 — Status page updated, post-mortem started

## Root cause
The primary droplet OOM-killed the Python process after a memory
leak in the new ML clustering endpoint (`v11.0`). The standby was
already running the patched build.

## What went well
- LB failover was a one-click action and worked exactly as documented.
- Customers in the EU region never saw downtime.

## What went poorly
- We didn't have an alert on RSS climb pre-OOM; only on `/healthz`.
- The DO uptime monitor's debounce was 5 min; could be tuned to 90 s.

## Action items
- [ ] Add Prometheus alert: `process_resident_memory_bytes > 1.5 GiB`.
- [ ] Tune DO uptime probe to 90 s debounce.
- [ ] Profile the v11.0 clustering endpoint with `tracemalloc`.

## Lessons learned
Section to amend the runbook with anything new we learned.
```
