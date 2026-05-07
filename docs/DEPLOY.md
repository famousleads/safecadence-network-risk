# SafeCadence Network Risk — Deployment Guide

Pick the path that matches your scale.

| Path | Use when | Time | What you get |
|---|---|---|---|
| **A. Local laptop** | One operator, demo, evaluating | 5 min | Single-user UI on `127.0.0.1:8766` with file-backed storage |
| **B. Small server** | One team, real fleet, internal use | 30 min | Multi-user via systemd + nginx + TLS, file-backed |
| **C. Docker** | You prefer containers | 15 min | One-container deploy, easy to move |
| **D. Production** | Multi-team, audit-grade | 2–4 hrs | Postgres, OIDC SSO, TLS, daemon, alerting |

All paths share the same codebase. **Storage automatically upgrades from
file-backed to Postgres when `DATABASE_URL` is set** — no code changes.

---

## A. Local laptop (5 minutes)

The fastest path. Everything stays on your machine, no network exposure.

```bash
git clone <repo-url> safecadence-network-risk
cd safecadence-network-risk
./bootstrap.sh
```

`bootstrap.sh` builds a venv, installs the package editable, loads the
demo fleet, prompts for a UI password, and opens
`http://127.0.0.1:8766/home` in your browser.

**What you get out of the box:**
- 34 demo assets across network/server/identity/cloud/backup
- Three-tier identity demo — Okta (good, synced), ClearPass (medium,
  unsynced), AD (broken/misconfigured) — plus 6 NHIs across the
  lifecycle (well-attested → rotation overdue → stale → deprecated)
- 6 execution jobs across the full lifecycle (DRAFT → REVIEW →
  APPROVED+rollback plan → DONE+pre/post snapshots → FAILED →
  ROLLED_BACK), so `/execute`, `/approvals`, `/queue`, `/rollback`,
  `/per-device-diff` all populate on first run
- Compliance seeds — risk register, exceptions, control history, baselines
- All 8 hero cards on `/inventory` — LAN scan, SNMP harvest, AD, Entra,
  DHCP, AWS/Azure/GCP, CSV upload, manual add
- `/shadow-it`, `/policies`, `/asset/<id>` cockpit, `/tour`,
  `/identity`, `/identity/nhi`, `/builder`, `/per-device-diff`
- File-backed storage at `~/.safecadence/` (identity vault master
  key auto-bootstrapped to `~/.safecadence/.identity_vault.key`,
  chmod 600)

**Stopping & restarting:**

```bash
# stop: Ctrl-C in the terminal, or
kill $(cat ~/.safecadence/safecadence.pid)

# restart:
./bootstrap.sh           # idempotent — won't re-prompt for password
```

**Common gotchas:**
- Port 8766 in use → `safecadence ui --port 9000`
- Wiped your demo data → `safecadence demo --reload`
- Forgot UI password → `rm ~/.safecadence/password_hash` then re-bootstrap

---

## B. Small server (30 minutes)

For a team. Linux box (Ubuntu 22.04+ / Debian 12 / RHEL 9 assumed),
behind nginx with Let's Encrypt TLS.

### B.1 Install

```bash
# As a non-root user with sudo:
sudo apt-get update
sudo apt-get install -y python3.10 python3.10-venv git nginx \
                        snmp net-snmp-utils certbot python3-certbot-nginx
sudo useradd -r -m -s /bin/bash -d /opt/safecadence safecadence
sudo -u safecadence -i

git clone <repo-url> /opt/safecadence/app
cd /opt/safecadence/app
python3.10 -m venv .venv
.venv/bin/pip install -e . --break-system-packages
.venv/bin/safecadence demo --reload     # optional
```

### B.2 Persist secrets

```bash
# Generate a JWT signing secret (used to sign session cookies)
python3 -c "import secrets; print(secrets.token_urlsafe(48))" \
  > /opt/safecadence/.jwt_secret
chmod 600 /opt/safecadence/.jwt_secret

# Generate the UI password hash (replace with your password)
.venv/bin/safecadence admin set-password --password 'your-strong-pw'
```

### B.3 systemd unit

Save as `/etc/systemd/system/safecadence.service`:

```ini
[Unit]
Description=SafeCadence Network Risk
After=network.target

[Service]
Type=simple
User=safecadence
Group=safecadence
WorkingDirectory=/opt/safecadence/app
EnvironmentFile=/opt/safecadence/env
ExecStart=/opt/safecadence/app/.venv/bin/safecadence ui \
          --host 127.0.0.1 --port 8766 --no-open-browser
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/safecadence

[Install]
WantedBy=multi-user.target
```

Save as `/opt/safecadence/env`:

```
SC_JWT_SECRET=<paste contents of /opt/safecadence/.jwt_secret>
SC_DATA_DIR=/opt/safecadence/data
PYTHONUNBUFFERED=1

# --- Identity vault master key (encrypts connector credentials at rest)
# Auto-bootstraps to ~/.safecadence/.identity_vault.key on first run if
# unset. For prod, generate explicitly and persist outside the repo:
#   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# SAFECADENCE_VAULT_KEY=<44-char Fernet key>

# --- BYO-AI (optional). Leave SC_AI_DISABLED=1 for air-gapped installs.
# SC_AI_DISABLED=1
# OPENAI_API_KEY=...
# ANTHROPIC_API_KEY=...
# OLLAMA_HOST=http://127.0.0.1:11434

# --- Tier-3 SSH execution (off by default — triple-gated)
# SC_TIER3_ENABLED=0       # set to 1 only after you trust the cadence

# --- Approval notifications (optional, legacy single-channel)
# Modern installs use the registry under /settings#webhooks instead.
# SC_NOTIFIER_SLACK_WEBHOOK=https://hooks.slack.com/services/...
# SC_NOTIFIER_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
# SC_NOTIFIER_PAGERDUTY_KEY=...
# SC_NOTIFIER_HMAC_SECRET=<for generic webhooks>

# --- Customer SMTP (optional, drives email DM notifications)
# Configurable from /settings → Email tab too. The env vars are the
# zero-touch path for systemd / Docker installs.
# SC_SMTP_HOST=smtp.gmail.com
# SC_SMTP_PORT=587
# SC_SMTP_USER=safecadence@acme.com
# SC_SMTP_PASSWORD=<app-password>     # Fernet-encrypted at rest
# SC_SMTP_TLS=1
# SC_DIGEST_FROM=safecadence@acme.com
# SC_DIGEST_RECIPIENTS=secops@acme.com,nocops@acme.com
# SC_DIGEST_SUBJECT_PREFIX=[SafeCadence]

# --- User directory (the file backing /users + /api/users)
# SC_USERS_FILE=/opt/safecadence/safecadence-users.yaml
# Bootstrap with: safecadence admin add-user --username admin
#                                            --password <pw>
#                                            --tenant default

# --- Webhook registry path (auto-resolved under SC_DATA_DIR/settings/)
# Override only if you keep the registry on a separate volume from the
# rest of SafeCadence's working data.
# SC_DATA_DIR=/opt/safecadence/data    # already set above

# --- v9.47 Activity log
# Every authenticated mutation is appended to
# $SC_DATA_DIR/activity/YYYY-MM-DD.jsonl. Reads (GET) are NOT logged
# by default; turn on for forensic mode:
# SC_ACTIVITY_LOG_READS=1
# Disable the middleware entirely (e.g. in test envs):
# SC_ACTIVITY_DISABLED=1
# Retention is enforced from ops; v9.53 ships two example configs:
#   docs/examples/safecadence-activity.logrotate
#   docs/examples/safecadence-activity-prune.{service,timer}
# Or just run by cron:
#   find $SC_DATA_DIR/activity -mtime +90 -delete

# --- v9.49 Phase C: PagerDuty escalation on stale CRITICAL approvals
# Disabled when either var is unset. Idempotent — same job_id never
# pages twice, even across daemon restarts.
# SC_APPROVAL_ESCALATION_PD_KEY=<integration-key>
# SC_APPROVAL_ESCALATION_PD_URL=https://events.pagerduty.com/v2/enqueue
# SC_APPROVAL_ESCALATION_MINUTES=30      # 0 disables
```

### B.3a — Configuring multi-channel notifications

Once the daemon is running, populate the user directory + webhook
registry from the CLI (or the equivalent UI pages):

```bash
# Add operators
safecadence users add alice --email alice@acme.com --role admin
safecadence users add bob   --email bob@acme.com   --role approver
safecadence users list

# Wire outbound webhooks (URLs are Fernet-encrypted at rest)
safecadence webhooks add team-slack \
    --url https://hooks.slack.com/services/T/B/X \
    --provider slack \
    --category finding_critical --category drift_detected \
    --min-severity high
safecadence webhooks add ops-pagerduty \
    --url https://events.pagerduty.com/v2/enqueue \
    --provider pagerduty \
    --api-token <integration-key> \
    --category finding_critical \
    --min-severity critical
safecadence webhooks test team-slack    # fires a synthetic event

# Per-user routing overrides (defaults come from /settings → Defaults)
safecadence notify-prefs set alice approval_requested --channel email
safecadence notify-prefs set bob   finding_critical   --channel email --channel slack
```

The seven NOTIFY_CATEGORIES are: `approval_requested`,
`finding_critical`, `watchlist_change`, `drift_detected`,
`automation_fired`, `jit_granted`, `digest_daily`. Each fires from
at least one in-tree emitter (a CI test enforces this).

### B.3b — Capability-based RBAC (v9.48 onward)

Roles answer "what kind of user are you" (admin/analyst/viewer).
Capabilities answer "what specifically can you do?". An admin can
hand out fine-grained permissions per-user without promoting
someone to a higher role.

```bash
# What grants exist?
safecadence capabilities list
safecadence capabilities list-types     # the 26 canonical keys
safecadence capabilities show alice

# Grant / revoke
safecadence capabilities grant alice execute.real \
    --reason "incident-42 oncall"
safecadence capabilities revoke alice execute.real \
    --reason "rotation-ended"
```

Every grant/revoke writes to the v9.47 activity log so `/audit`
shows the full provenance trail.

**Tier-3 SSH execution** is the highest-stakes surface. v9.50 added
a dual-system gate: legacy role check AND v9.48 explicit grant.
The admin role short-circuit is BYPASSED for this surface — even
admins must run:

```bash
safecadence capabilities grant alice execute.real \
    --reason "<change-management-ticket>"
```

before Tier-3 will fire a single packet.

### B.3c — IdP-sourced approver groups (v9.49 Phase B)

The notification registry expands `@group:NAME` invitee entries
against a JSON cache populated from connected IdPs. The daemon
refreshes once per cycle; you can also force it manually:

```bash
safecadence groups list
safecadence groups show eng-leads
safecadence groups refresh
```

Okta and Entra return real members. AD via LDAP returns real
members (mapped to sAMAccountName). ISE and ClearPass return
groups with empty members (REST-API limitation; documented in the
adapter docstring). For human approver groups, use AD or Okta.

### B.3d-bis — /audit hardening tunables (v9.57)

The /audit endpoint has two operational tunables you'll typically
leave at defaults but that exist for hardening:

```bash
# Rate limit — token-bucket per (username, client_ip).
# Default 60 calls per 60s; raise for SIEM puller installs.
SC_AUDIT_RATE_LIMIT=60
SC_AUDIT_RATE_WINDOW_SEC=60

# Middleware skip-list — extends the default that already covers
# /api/v9/search, /favicon, /healthz, /readyz, /livez, /_status,
# /api/_ping, /robots.txt. Comma-separated.
SC_ACTIVITY_SKIP_PREFIXES=/api/internal-noise/,/_metrics
```

Multi-tenant note: non-admin callers are auto-scoped to their own
tenant. Admins can pass `tenant=*` to read across tenants. There
is no way for a viewer-tier user in tenant A to read tenant B's
activity, even with a hand-crafted query.

### B.3d — Activity log + retention (v9.47, v9.53, v9.54)

Every authenticated mutation writes one JSONL line under
`$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl`. The /audit page filters
by date / actor / method / path and exports CSV
(`?format=csv`). `READ_ACTIVITY` capability gates the endpoint;
all roles ≥ viewer get it via the role floor.

Retention is enforced three ways — pick one for your deployment:

**Option 1 — logrotate (preferred for traditional Linux servers):**

```bash
sudo cp docs/examples/safecadence-activity.logrotate \
    /etc/logrotate.d/safecadence-activity
# Default retention is 90 days; edit the file to change.
sudo logrotate --debug /etc/logrotate.d/safecadence-activity
```

**Option 2 — systemd .service + .timer (containers, minimal distros):**

```bash
sudo cp docs/examples/safecadence-activity-prune.service \
    /etc/systemd/system/
sudo cp docs/examples/safecadence-activity-prune.timer \
    /etc/systemd/system/
sudo systemctl enable --now safecadence-activity-prune.timer
```

**Option 3 — daemon hook (pip-install installs without systemd):**

```bash
# In /etc/safecadence.env (or wherever the systemd unit pulls
# EnvironmentFile=) — default 90, set to 0 to disable.
SC_ACTIVITY_RETENTION_DAYS=90
```

The daemon hook runs every cycle, prunes files older than the
threshold, and reports the result in the cycle log:

```json
{"retention_days": 90, "deleted": 3, "kept": 60,
 "freed_bytes": 1234567, "errors": []}
```

You can also run a one-shot prune from the CLI any time:

```bash
safecadence activity prune --retention 90
```

### B.3e — Capability privilege-change notifications (v9.53)

Every `grant`/`revoke`/`clear_deny` fires a
`dispatch_event(kind="capability_changed")` event in addition to
the audit row, so security-team Slack/Teams/PagerDuty channels
hear about privilege escalations in real time. High-value
capabilities (`execute.real`, `admin.users`, `admin.capabilities`,
`admin.webhooks`, `admin.settings`, `identity.apply.commit`)
fire with `severity=high`; the rest are `severity=info`.

Configure the per-channel routing in `/settings#notifications`
under the new "Capability changed" row, or skip it and let the
default tenant routing handle it.

### B.3f — OIDC SSO with capability auto-grant (v9.54)

When users authenticate via OIDC, their IdP group claims can
auto-grant SafeCadence capabilities. The mapping lives in
`SSOConfig.capability_map`:

```json
{
  "enabled": true,
  "flow": "oidc",
  "oidc_issuer": "https://acme.okta.com/oauth2/default",
  "oidc_client_id": "...",
  "oidc_redirect_uri": "https://safecadence.acme.com/api/auth/oidc/callback",
  "oidc_scopes": ["openid", "profile", "email", "groups"],
  "role_map": {"okta-admins": "admin", "okta-soc": "approver"},
  "default_role": "viewer",
  "capability_map": {
    "okta-secops":   ["read.audit", "admin.capabilities"],
    "okta-platform": ["execute.real", "execute.approve"],
    "okta-readonly": []
  }
}
```

On every successful login the server runs `reconcile_sso_grants`:

- Capabilities the user *should* have (per their current groups)
  but doesn't yet → granted.
- Capabilities tracked as SSO-managed but no longer in the
  computed set → revoked.
- Capabilities granted by other paths (CLI, /users UI) →
  **untouched**. The store tracks the SSO-managed set in a
  separate `sso_managed` field on the user record.

Misconfigured `capability_map` entries (referencing a non-existent
capability) raise on first reconcile so the issue shows up in the
audit log immediately instead of silently granting nothing.

### B.3g — Cross-tenant capability admin view (v9.54)

MSP-style installs can see grants across every tenant in one
response:

```bash
curl -H "Authorization: Bearer $JWT" \
    https://safecadence.acme.com/api/capabilities/all-tenants
```

Gate: the caller needs `admin.capabilities` on at least one
tenant, or the synthetic-admin role in single-user mode.

### B.3h — Automation engine (v9.55)

IF/THEN rules persisted in `~/.safecadence/intel/automation.json`.
Daemon evaluates every cycle. Disable site-wide:

```bash
SC_AUTOMATION_DISABLED=1
```

Eight actions ship: `auto_fix` (honors IR.targets, dry-run by
default, `commit=true` opt-in), `assign`, `notify_log`,
`notify_slack`, `add_to_watchlist`, `add_comment`,
`notify_pagerduty`, `notify_webhook`. Endpoints gated by the
`write.automation` capability.

```bash
safecadence automation list
safecadence automation create --name "auto-fix stale NHIs" \
    --when-kind stale_nhi --when-severity-at-least medium \
    --then-action auto_fix
safecadence automation preview      # side-effect-free
safecadence automation fires        # recent rule fires
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now safecadence
sudo systemctl status safecadence
```

### B.4 nginx + TLS

Save as `/etc/nginx/sites-available/safecadence`:

```nginx
server {
    listen 443 ssl http2;
    server_name safecadence.acme.local;

    # certbot will fill these in
    ssl_certificate /etc/letsencrypt/live/safecadence.acme.local/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/safecadence.acme.local/privkey.pem;

    # Required for SSE streaming discovery (Server-Sent Events)
    proxy_buffering off;
    proxy_read_timeout 600s;

    client_max_body_size 25m;     # CSV uploads

    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
    }
}

server {
    listen 80;
    server_name safecadence.acme.local;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/safecadence /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d safecadence.acme.local
```

### B.5 Firewall

```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp     # only for cert renewal
sudo ufw enable
```

You're live at `https://safecadence.acme.local`.

---

## C. Docker (15 minutes)

The repo ships a `Dockerfile` and `docker-compose.yml`. The container
runs the same `safecadence ui` and reads the same env vars as path B.

```bash
git clone <repo-url> safecadence-network-risk
cd safecadence-network-risk

# Configure
cat > .env <<EOF
SC_JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")
SC_UI_PASSWORD=changeme-strong-password
EOF

# Build & start
docker compose up -d
docker compose logs -f safecadence
```

Persistent state is mounted at `./data` on the host. Open
`http://localhost:8766`.

For TLS in front of Docker, run nginx (or Caddy / Traefik) on the host
and proxy to `localhost:8766` — same config block as path B.4.

---

## D. Production (2–4 hours)

For multi-team, audit-grade deployments. Stack:

- **App**: SafeCadence behind nginx (path B or C)
- **DB**: Postgres 14+ (set `DATABASE_URL` and the storage adapter takes over)
- **Auth**: OIDC SSO (Okta / Entra / Google) — local password becomes optional
- **Daemon**: separate systemd unit running `safecadence daemon` for
  scheduled re-evaluation, drift detection, JIT auto-revoke, identity
  resync of vault-backed connectors, and NHI staleness scanning. Each
  hook is best-effort — one failure never aborts the cycle.
- **Backups**: nightly `pg_dump` of the `safecadence` database

### D.1 Postgres

```bash
sudo apt-get install -y postgresql-14
sudo -u postgres psql <<SQL
CREATE USER safecadence WITH PASSWORD 'replace-me';
CREATE DATABASE safecadence OWNER safecadence;
SQL
```

Add to `/opt/safecadence/env`:

```
DATABASE_URL=postgresql://safecadence:replace-me@127.0.0.1:5432/safecadence
```

Restart: `sudo systemctl restart safecadence`. Schema migrations run
automatically on startup.

### D.2 OIDC SSO

Configure in `/opt/safecadence/env`:

```
SC_SSO_ENABLED=true
SC_SSO_FLOW=oidc
SC_OIDC_ISSUER=https://your-tenant.okta.com
SC_OIDC_CLIENT_ID=...
SC_OIDC_CLIENT_SECRET=...
SC_OIDC_REDIRECT_URI=https://safecadence.acme.local/api/auth/oidc/callback
SC_OIDC_ROLE_CLAIM=groups
SC_OIDC_ADMIN_GROUPS=safecadence-admins
SC_OIDC_WRITER_GROUPS=safecadence-writers
```

Users now sign in via your IdP at `https://safecadence.acme.local/login`.

### D.3 Daemon (continuous mode)

Save as `/etc/systemd/system/safecadence-daemon.service`:

```ini
[Unit]
Description=SafeCadence daemon (drift, JIT, identity sync, NHI staleness, scheduled re-eval)
After=safecadence.service

[Service]
Type=simple
User=safecadence
WorkingDirectory=/opt/safecadence/app
EnvironmentFile=/opt/safecadence/env
ExecStart=/opt/safecadence/app/.venv/bin/safecadence daemon \
          --interval-minutes 30
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now safecadence-daemon
```

### D.4 Backups

`/etc/cron.daily/safecadence-backup`:

```bash
#!/bin/sh
set -e
sudo -u postgres pg_dump -Fc safecadence \
  > /var/backups/safecadence/$(date +%Y%m%d).dump
find /var/backups/safecadence -mtime +30 -delete
```

`chmod 755 /etc/cron.daily/safecadence-backup`.

### D.5 Outbound network needs

For real-fleet operations, the SafeCadence host needs:

| Direction | Why | Where |
|---|---|---|
| Out → 22/tcp to network gear | SSH config collection (Tier 3) | LAN |
| Out → 161/udp to network gear | SNMP harvest (LLDP/CDP/MAC tables) | LAN |
| Out → 443 to login.microsoftonline.com | Entra OIDC + Graph | Internet |
| Out → 443 to graph.microsoft.com | Entra device + identity write-back | Internet |
| Out → 443 to {tenant}.okta.com | Okta identity sync + write-back | Internet |
| Out → 443/636 to AD (LDAPS) | AD computer + identity harvest | LAN |
| Out → 443 to ISE / ClearPass mgmt IP | Identity write-back via ERS / REST | LAN |
| Out → 443 to AWS/Azure/GCP APIs | Cloud connectors | Internet |
| Out → 443 to api.anthropic.com / api.openai.com | BYO-AI (optional) | Internet |
| Out → 443 to hooks.slack.com / outlook.office.com / events.pagerduty.com | Approval notifications (optional) | Internet |
| In → 443 from operator workstations | UI access | LAN |

---

## Hardening checklist (do these regardless of path)

- [ ] Use a long random `SC_JWT_SECRET` (≥ 48 chars, persisted to disk with mode 600)
- [ ] Bind to `127.0.0.1` only and put nginx in front for TLS — never expose 8766 directly
- [ ] Set a strong UI password (or wire SSO)
- [ ] Run as a dedicated unprivileged user (`safecadence`)
- [ ] Enable `NoNewPrivileges`, `ProtectHome`, `PrivateTmp` in systemd
- [ ] Use Postgres in prod (file-backed has no row-level locking)
- [ ] Enable nightly `pg_dump` backups
- [ ] Restrict DB user to its own database
- [ ] For SNMP: use a read-only community. SafeCadence never writes via SNMP.
- [ ] For AD: bind with a service account that has `Domain Computers` read only
- [ ] For Entra: app reg with `Device.Read.All`, admin consent. Rotate secret yearly.
- [ ] For AWS/Azure/GCP: scope IAM to read-only describe/list APIs
- [ ] BYO-AI key: store in env, never in the database. Rotate per your org policy.
- [ ] Identity vault master key: persist `SAFECADENCE_VAULT_KEY` outside the repo
      (e.g., `/opt/safecadence/.identity_vault.key`, mode 600). Losing this key
      makes saved connector credentials unrecoverable — back it up like an
      encryption root key.
- [ ] Tier-3 SSH execution: leave `SC_TIER3_ENABLED=0` until you've watched
      a week of dry-runs. Real execution requires `SC_TIER3_ENABLED=1` AND the
      `EXECUTE_REAL` capability on the role AND `acknowledge` + `i_mean_it`
      payload AND TOTP MFA — all four gates have to fire.
- [ ] Approval workflow: medium-risk approvals require `SUPER_ADMIN`. Submitters
      cannot approve their own jobs. Critical jobs need multiple approvers.
- [ ] Identity write-back: every commit needs an HMAC-bound confirm token (TTL
      600s, bound to the IR hash + scope + actor + adapter version).
- [ ] Air-gap mode: set `SC_AI_DISABLED=1` and don't configure the BYO-AI keys.
      All AI-fallback paths short-circuit cleanly; pack-driven plans still work.
- [ ] Review the audit log (`/api/execute/audit`) weekly until you trust the cadence

---

## Upgrades

```bash
sudo systemctl stop safecadence safecadence-daemon
cd /opt/safecadence/app
sudo -u safecadence git fetch && sudo -u safecadence git pull
sudo -u safecadence .venv/bin/pip install -e . --break-system-packages
sudo systemctl start safecadence safecadence-daemon
sudo systemctl status safecadence
```

Schema migrations run on startup. If something goes wrong, restore from
the most recent `pg_dump` and roll back the git checkout.

---

## Common operational scenarios

### Adding a new operator

```bash
.venv/bin/safecadence admin add-user alice --role writer
```
Or, if SSO is wired, just add `alice@acme.com` to the `safecadence-writers`
group in your IdP. No app config change needed.

### Rotating the JWT secret (forces all sessions to re-login)

```bash
python3 -c "import secrets;print(secrets.token_urlsafe(48))" \
  > /opt/safecadence/.jwt_secret
sed -i "s|^SC_JWT_SECRET=.*|SC_JWT_SECRET=$(cat /opt/safecadence/.jwt_secret)|" \
  /opt/safecadence/env
sudo systemctl restart safecadence
```

### Migrating from file-backed to Postgres

```bash
# Set DATABASE_URL in env, then:
.venv/bin/safecadence admin migrate-to-postgres
sudo systemctl restart safecadence
```

The CLI streams every asset/policy/finding from `~/.safecadence/*.json`
into the DB and writes a backup directory before deleting the source files.

### Disaster recovery drill

```bash
# 1. Take a fresh dump
sudo -u postgres pg_dump -Fc safecadence > /tmp/recovery-test.dump
# 2. Bring up a temp DB
sudo -u postgres createdb safecadence_test
sudo -u postgres pg_restore -d safecadence_test /tmp/recovery-test.dump
# 3. Confirm row counts vs production
sudo -u postgres psql safecadence_test -c "SELECT count(*) FROM assets;"
sudo -u postgres psql safecadence    -c "SELECT count(*) FROM assets;"
# 4. Tear down
sudo -u postgres dropdb safecadence_test
```

Run this monthly. A backup you've never restored is not a backup.

---

## Where things live

| What | Path |
|---|---|
| Code | `/opt/safecadence/app` |
| venv | `/opt/safecadence/app/.venv` |
| File-backed assets | `$SC_DATA_DIR/assets/*.json` |
| File-backed policies | `$SC_DATA_DIR/policies/*.json` |
| Identity vault | `$SC_DATA_DIR/identity_vault.json` (Fernet-encrypted) |
| Identity vault master key | `~/.safecadence/.identity_vault.key` (auto-bootstrap) or `$SAFECADENCE_VAULT_KEY` env |
| NHI store | `$SC_DATA_DIR/nhi_store.json` |
| Execution jobs / rollback plans | `$SC_DATA_DIR/execution/*.json` |
| Audit log | `$SC_DATA_DIR/audit/*.jsonl` |
| JWT secret | `/opt/safecadence/.jwt_secret` |
| systemd units | `/etc/systemd/system/safecadence*.service` |
| nginx | `/etc/nginx/sites-available/safecadence` |
| TLS certs | `/etc/letsencrypt/live/safecadence.acme.local/` |
| Backups | `/var/backups/safecadence/` |
| Postgres data | `/var/lib/postgresql/14/main/` |

---

## Questions to ask before going to production

1. **Who owns this?** SafeCadence touches network gear, identity systems,
   and cloud APIs. Set up an on-call rotation before turning on the daemon.
2. **What's our blast radius?** Tier 3 SSH command execution is real. Start
   with everyone in `viewer` role, promote to `writer` only after a week
   of dry-runs.
3. **What's our backup story?** `pg_dump` nightly is the floor. Consider
   off-site replication if SafeCadence becomes a load-bearing system.
4. **How do we handle credentials?** SafeCadence stores SNMP communities
   and SSH keys in the credential vault. Treat that vault like you'd
   treat root credentials — disk encryption + restrict who can SSH to the host.
