# SafeCadence v7.6 — Connecting Real Identity Systems

This is the operator's guide. After you've run `./bootstrap.sh` and have
`safecadence --version` printing `7.6.0`, follow the section below for
each identity system you want to integrate.

The model is the same for all five:

```
1. Get credentials with the right scopes (one-time, per system)
2. Set env vars OR pass --target-host / --cred-* flags on the CLI
3. Test connectivity        →  safecadence identity test --target <name>
4. Collect (optional)       →  visible in the UI dashboard
5. Translate intent → IR    →  AI or guided form, no system access needed
6. Preview per-system diff  →  no system access, no commits
7. Dry-run apply per system →  hits the IdP read-only? No, makes NO HTTP
                                 calls — proves the payload is correct
8. Commit                   →  Tier-3 gated (RBAC + TOTP + audit row)
```

> Step 7 (`--dry-run`) makes **zero** HTTP/LDAP calls. Step 8 (`--commit`)
> is the only step that ever touches your IdP.

---

## 1. Cisco Identity Services Engine (ISE)

### What we need

A local ISE admin with the **ERS Admin** role. Documented at:
*Administration → System → Settings → ERS Settings*. Enable "ERS for Read/Write".

### Env vars

```bash
export ISE_HOST=ise01.corp.local            # FQDN or IP
export ISE_USERNAME=ers-admin
export ISE_PASSWORD='your-password'
```

### Connectivity smoke test

```bash
safecadence identity test --target ise
# → expects {"ok": true, "error": null}
```

### Apply a policy (preview, then commit)

```bash
# 1. Translate
safecadence identity translate \
    "deny SSH for contractors without MFA in production" \
    --out /tmp/ir-contractors.json

# 2. Preview
safecadence identity preview /tmp/ir-contractors.json

# 3. Dry-run (still no HTTP)
safecadence identity apply /tmp/ir-contractors.json \
    --target ise --dry-run

# 4. Commit (PUTs the authz rule via ERS)
safecadence identity apply /tmp/ir-contractors.json \
    --target ise --commit
```

### Rollback

ISE assigns the rule a `id` field in the response. SafeCadence captures
it as `committed_ids[]` so you can `DELETE /ers/config/authorization/{id}`
either via the UI's Audit tab → "Rollback this change" or via:

```bash
safecadence identity rollback ise <committed_id>
```

---

## 2. HPE Aruba ClearPass

### What we need

An **API client** with `Read/Write Local Users, Roles, Enforcement
Profiles, Enforcement Policies` scope. Create at *Guest → Administration
→ API Services → API Clients*.

### Env vars

```bash
export CLEARPASS_HOST=clearpass01.corp.local
export CLEARPASS_CLIENT_ID=safecadence-svc
export CLEARPASS_CLIENT_SECRET='your-secret'
```

### Apply

```bash
safecadence identity apply /tmp/ir-contractors.json \
    --target clearpass --commit
```

ClearPass enforcement is two-tiered — SafeCadence creates an
**enforcement profile** (the action) AND an **enforcement policy**
(the trigger) and returns both IDs as `committed_ids`:
`profile:<id>` and `policy:<id>`.

---

## 3. Microsoft Active Directory (LDAP/LDAPS)

### What we need

A bind account with permission to *Modify Member* on the groups
SafeCadence will manage. **Strongly recommend** scoping this to a
purpose-built OU (e.g. `OU=SafeCadence-Managed`) — do NOT give the
bind account Domain Admin.

The `ldap3` package is required:

```bash
source ~/Documents/FamousTec/safecadence-network-risk/.venv/bin/activate
pip install ldap3
```

### Env vars

```bash
export AD_SERVER='ldaps://dc01.corp.local:636'
export AD_BIND_DN='CN=safecadence-svc,OU=Service Accounts,DC=corp,DC=local'
export AD_BIND_PASSWORD='your-password'
export AD_BASE_DN='DC=corp,DC=local'
```

### Apply

```bash
safecadence identity apply /tmp/ir-contractors.json \
    --target ad --commit
```

For `effect=deny`, SafeCadence:
1. Resolves members of each `subjects.groups` (e.g. `Contractors`).
2. Adds them to `SafeCadence-Quarantined` (an OU/group you must
    pre-create).
3. **Does not** remove them from their existing groups in v7.6 — that's
    a v7.7 task because cross-group remove-and-restore is more dangerous.

---

## 4. Microsoft Entra ID (Azure AD)

### What we need

An **App registration** with the following Microsoft Graph
**application** permissions (admin consent required):

- `Policy.ReadWrite.ConditionalAccess`
- `Application.Read.All` (to look up app IDs)
- `Group.Read.All`
- `User.Read.All`

Create at *Microsoft Entra → App registrations → New registration → Add
client secret*.

### Env vars

```bash
export ENTRA_TENANT='your-tenant-guid-or-domain.onmicrosoft.com'
export ENTRA_CLIENT_ID='your-app-id'
export ENTRA_CLIENT_SECRET='your-secret'
```

### Apply

```bash
safecadence identity apply /tmp/ir-contractors.json \
    --target entra --commit
```

Entra Conditional Access policies are CREATED in
`enabledForReportingButNotEnforced` if your IR has `severity: warn`,
and `enabled` if `severity: enforce`. Use `--dry-run` first to look
at the exact CA body — Conditional Access is the most consequential
of the five.

---

## 5. Okta

### What we need

An Okta API token from *Security → API → Tokens*. Create from a
service account user; Okta-recommends using **Okta Workflows API**
service users for this kind of automation.

### Env vars

```bash
export OKTA_DOMAIN='acme.okta.com'           # not the .com URL — just the host
export OKTA_API_TOKEN='your-token'
```

### Pre-create the SafeCadence groups

Okta's group-rule API can only assign users into existing groups. Before
the first `apply --commit`, create these groups in Okta (UI: *Directory
→ Groups → Add Group*):

- `SafeCadence-Quarantine` — empty target group for deny rules
- `SafeCadence-SSH-Allowed` — target for SSH allow rules
- `SafeCadence-RDP-Allowed` — target for RDP allow rules
- `SafeCadence-Admin` — target for admin allow rules
- `SafeCadence-RequiresStepUp` — target for step-up rules

### Apply

```bash
safecadence identity apply /tmp/ir-contractors.json \
    --target okta --commit
```

Okta group rules are created **inactive** by default — SafeCadence
issues a follow-up `PUT /lifecycle/activate` so the rule starts firing
immediately. If activation fails, the rule is created but inactive
and the failure shows up under `warnings[]` in the response.

---

## End-to-end one-liners

If you'd rather skip the JSON file and pipe everything:

```bash
# Translate, preview, dry-run all 5 in one shot
INTENT="deny SSH for contractors without MFA in production"

safecadence identity translate "$INTENT" --out /tmp/ir.json
safecadence identity preview /tmp/ir.json

for t in okta ise ad entra clearpass; do
  echo "================= $t =================="
  safecadence identity apply /tmp/ir.json --target $t --dry-run
done
```

When the dry-run output looks right for all five, commit one at a time
and watch the Audit tab in the UI:

```bash
for t in okta ise ad entra clearpass; do
  read -p "Commit to $t? (y/N) " yn
  [[ "$yn" == "y" ]] && safecadence identity apply /tmp/ir.json \
       --target $t --commit
done
```

---

## Just-in-Time access example

A real one — incident triage:

```bash
# Alice from on-call needs to SSH to prod-db-01 right now to debug
# something. Give her 4 hours of access, auto-revoked after.

safecadence identity jit grant \
    --principal alice@yourcorp.com \
    --action ssh \
    --resource prod-db-01 \
    --duration 4h \
    --target okta \
    --reason "INC-4321 — DB connection saturation"

# Listed and visible in the audit log
safecadence identity jit list --active-only

# Hourly cron job that the daemon runs — auto-revokes expired grants
safecadence identity jit expire-due
```

---

## Troubleshooting

**`HTTP 401` on apply** — credentials aren't right. Re-check the env
vars by `echo $OKTA_API_TOKEN` etc. The token may have been rotated.

**`No such command 'identity'`** — you're running an older `safecadence`.
Run `which safecadence` — it should point inside `.venv/bin/`. If not,
`source .venv/bin/activate` from the repo root and try again.

**`ModuleNotFoundError: No module named 'safecadence'`** — partial
editable install in the venv. Recovery:
```bash
cd ~/Documents/FamousTec/safecadence-network-risk
rm -rf .venv && ./bootstrap.sh
```

**`ldap3 not installed`** — only AD adapter needs it.
`pip install ldap3` inside the activated venv.

**`Entra Graph did not return policy id`** — your app registration
likely doesn't have `Policy.ReadWrite.ConditionalAccess` admin consent.
Re-grant in Entra → App registrations → API permissions → Grant admin
consent.

**`okta did not return rule id`** — most common cause is that the
Okta target group doesn't exist yet. See "Pre-create the SafeCadence
groups" above.

---

## What v7.6 does NOT do (yet)

- **No SCIM provisioning.** SafeCadence reads users; it does not
  create them in any IdP. v7.7 will add provisioning to Okta + Entra.
- **No automatic rollback on failure.** If `apply --commit` to Okta
  succeeds but Entra fails, the Okta change is not rolled back. v7.7
  will add transactional apply across multiple targets.
- **JIT auto-revoke is not yet wired into a daemon.** You must run
  `safecadence identity jit expire-due` on a schedule (cron / launchd /
  the existing `safecadence daemon` will pick it up in v7.7).
