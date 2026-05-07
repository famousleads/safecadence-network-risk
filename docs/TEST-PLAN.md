# SafeCadence — End-to-end test plan

How to verify every Tier S + Tier A feature works, without owning real
ISE / Okta / AD / Entra / ClearPass infrastructure. The plan uses the
built-in demo fleet plus stubbed adapter calls for write-back.

**Time budget:** ~45 minutes to walk through all 13 features.
**Prereqs:** Python 3.11+, ~200 MB disk, no internet required for
read-only paths (AI features need an OpenAI/Anthropic key, optional).

---

## 0. One-time setup

```bash
cd ~/Documents/FamousTec/safecadence-network-risk
./bootstrap.sh                # builds .venv, installs editable, loads demo
```

When the password prompt appears, type any password and press Enter.
The UI launches at `http://127.0.0.1:8766` and your browser opens to
`/home`.

**Verify setup is good:**

```bash
source .venv/bin/activate
safecadence --version          # → 9.0.0
safecadence demo --help        # → loads/clears demo fleet
```

The fleet is intentionally bad:

- 31 assets: 4 crown-jewels, 13 Domain Admins without MFA
- 3 NHIs: 1 stale (180d unused), 1 never-rotated, 1 orphan (departed owner)
- AD has 6-group over-privileged user (`alice.admin`)
- Cross-system drift: AD denies what Okta allows

This trips most detectors so you can see real output.

---

## Tier S features

### 1. Identity attack paths

**What it does:** Finds chains like
`alice → BuildEngineers → BuildBot → AdminRole → prod-db` that span
human → group → service-account → role → asset.

**Sample-data test:**

```bash
safecadence ui                  # if not already running
# In browser:
open http://127.0.0.1:8766/paths
```

**Expected:**
- Page loads with v9 chrome (sidebar visible)
- Subtitle reads "N paths detected · ranked by risk"
- Table has rows like `(8.4) ivan.devops@acme.local → BuildEngineers → nhi-build-bot → role:s3:GetObject → ...`
- "Remediate" button on each row → opens slide-over with severing IR

**Real-world equivalent:** Connect AD/Okta to populate the
`identity_block.group_memberships` and `nhi.owner_principal` fields.
Paths will then chain across your real principals.

**Failure modes:**
- Empty table after `safecadence demo` → demo data didn't include
  group_memberships. Run `safecadence demo --overwrite` to refresh.
- 401 error → token expired. Refresh the page; chrome reads localStorage.

---

### 2. AI policy translator (NL → IR → 5 IdPs)

**What it does:** Type a sentence, get a Unified Policy IR, see exactly
what would change in each of Okta / ISE / AD / Entra / ClearPass.

**Sample-data test (no AI key needed — uses guided form):**

```bash
safecadence identity translate --form \
    --groups Contractors --actions ssh --environments prod \
    --effect deny --require-mfa --targets all \
    --out /tmp/ir.json
cat /tmp/ir.json
safecadence identity preview /tmp/ir.json
```

**Expected output of preview:**
```
# Unified policy: deny ssh for Contractors
#   effect=deny  severity=enforce  targets=okta,ise,ad,entra,clearpass

  * [okta] upsert_group_rule: create/update Okta group rule '...'
  * [ise] upsert_authz_rule: upsert ISE authz rule '...' → profile=DenyAccess
  * [ad] modify_group_membership: AD: remove members of Contractors...
  * [entra] upsert_ca_policy: upsert Entra CA policy '...' (state=enabled, effect=deny)
  * [clearpass] upsert_enforcement: upsert ClearPass enforcement '...' (action=RADIUS:Reject)
```

**With AI (optional):**
```bash
export OPENAI_API_KEY='...'
safecadence identity translate "contractors without MFA cannot SSH to prod"
```

**Real-world equivalent:** Set `OKTA_API_TOKEN`, etc. and run
`safecadence identity apply /tmp/ir.json --target okta --commit`. It
calls the Okta REST API for real.

**Failure modes:**
- "AI translation failed: AI not configured" → use `--form` instead of
  the natural-language path
- "validation failed" → IR JSON malformed; check `--out` file

---

### 3. What-if simulator

**What it does:** Show what would happen if you applied a policy IR —
without applying it. Risk delta, closing findings, opening gaps.

**Sample-data test:**

```bash
# In the browser:
open http://127.0.0.1:8766/simulate
# Click "Load demo IR"
# Click "Run simulation"
```

**Expected:**
- Summary line: `matches N asset(s) · closes M finding(s) · opens K new gap(s) · net risk delta -X.X`
- "Closing findings" lists the no-MFA / over-priv findings that would resolve
- "Opening gaps" lists "no break-glass principals excluded" (real concern with deny-all rules)
- "Severed attack paths" lists chains terminating at matched assets

**Real-world equivalent:** Same workflow with your real fleet. The
simulator never makes external HTTP calls — it's pure-Python
projection over your in-memory snapshot.

**Failure modes:**
- "matches 0 assets" → your resource selector didn't match anything.
  Check `resources.environments` etc. in the IR.

---

### 4. Effective-permission resolver ("who-can")

**What it does:** Answers "Right now, can principal X do action Y on
resource Z?" by composing rules across all connected IdPs.

**Sample-data test:**

```bash
safecadence identity who-can ssh prod-db-01 \
    --as alice@contractor.com --groups Contractors --no-mfa
```

**Expected:**
```
  alice@contractor.com  →  ssh  →  prod-db-01
  Decision:  DENY
  Systems:   (none)
  Reasoning:
    - default deny: no matching rule
```

**With more realistic input:**
```bash
safecadence identity who-can ssh ad-acme-local \
    --as alice.admin --groups "Domain Admins" --no-mfa
```

**Real-world equivalent:** Once IdP adapters populate
`declared_rules`, the resolver composes ISE + AD + Entra + Okta rules
and returns a chain like:

```
[ise]  no-untrusted-cert     → step_up  (matched group:Contractors)
[ad]   ad-deny-no-mfa        → deny     (matched group:Domain Admins, mfa:false)
```

**Failure modes:**
- Always returns "default deny" → adapter `declared_rules` empty.
  v6.0 adapters don't populate this yet; v7.6+ adapters do.

---

### 5. JIT access workflow

**What it does:** Time-bounded grants with auto-revoke. "Alice gets
SSH to prod-db-01 for 4 hours, then it's revoked."

**Sample-data test:**

```bash
safecadence identity jit grant \
    --principal alice@yourcorp.com \
    --action ssh \
    --resource prod-db-01 \
    --duration 4h \
    --target okta \
    --reason "INC-4321 incident triage"

safecadence identity jit list
# → grant visible, status=active

# Fast-forward via env override (no real wait):
SC_JIT_STORE=~/.safecadence/jit.json \
  python -c "from safecadence.identity.jit import expire_due; \
              import time; print(expire_due(now=time.time()+86400))"

safecadence identity jit list
# → grant now status=expired
```

**In the UI:** `/jit` page shows the same data with a status pill.

**Real-world equivalent:** With `OKTA_API_TOKEN` set, the daemon
auto-applies the grant's revoke_ir to Okta when expired. Without
credentials, it just marks the grant expired locally.

**Failure modes:**
- "duration_seconds > 14 days" → max is 14 days by design (escalate
  longer needs to a real policy, not JIT).

---

## Tier A features

### 6. Morning briefing

```bash
safecadence ui                                           # ensure running
open http://127.0.0.1:8766/briefing
# Click "Generate briefing now"
```

**Expected:** A textarea with the daily digest:
```
SafeCadence — Morning briefing for default
Generated 2026-05-04T...

Top actions today:
  1. [critical] Remediate identity attack path: ...
  2. [critical] N critical finding(s) need review
  ...

Findings (top 10): ...
Identity attack paths: ...
JIT — N active, M expired
```

**Real-world delivery:** Schedule with cron + email:
```bash
crontab -e
# Add:
0 8 * * * cd /path/to/repo && \
          /path/to/.venv/bin/safecadence intel briefing-email \
              --to security@acme.com
```

(briefing-email CLI command not yet exposed; use the API
`POST /api/intel/briefing` until v9.2.)

---

### 7. Findings (stale NHI / no-MFA / over-priv / orphan SA)

```bash
open http://127.0.0.1:8766/findings
```

**Expected:** A table with severity-colored pills:
- `CRIT  orphan_service_account  nhi-legacy-importer  ...`  → owner departed
- `HIGH  never_rotated           nhi-build-bot         ...`  → 2yr since rotation
- `HIGH  no_mfa                  ad-acme-local         ...`  → tenant has 13 admins no MFA
- `MED   over_privileged         alice.admin@acme.local`  → in 6 groups

Click any row → "View IR" button → slide-over with the suggested
remediation IR + "Auto-fix (dry-run)" button.

**Real-world equivalent:** Same scanner runs against your fleet's
identity blocks. The thresholds (90 days stale, 5+ groups
over-privileged) are configurable.

---

### 8. Cross-system drift detector

```bash
safecadence policy drift-cross-system
```

**Expected:** ~17 detector reports. With demo data:
```
Detected drift:
  - AD-vs-Okta:  Domain Admins MFA — AD says no, Okta requires
  - ISE-vs-AD:   contractor authz — ISE permits, AD denies
  ...
```

**In the UI:** `/drift` (coming v9.1; meanwhile the data is in
`safecadence policy briefing`).

**Real-world equivalent:** When ISE and AD disagree on the same
principal+resource, this is the silent-failure class of incident.
Run it weekly.

---

### 9. Identity write-back to Okta

**Sample-data test (dry-run, no real Okta needed):**

```bash
safecadence identity translate --form \
    --groups Contractors --actions ssh --environments prod \
    --effect deny --targets okta --out /tmp/ir.json

safecadence identity apply /tmp/ir.json --target okta --dry-run
```

**Expected output:**
```json
{
  "target": "okta",
  "dry_run": true,
  "operations": [{
    "op_kind": "upsert_group_rule",
    "summary": "create/update Okta group rule 'sc-deny-ssh-for-contractors' → moves matched users to SafeCadence-Quarantine",
    "payload": {
      "rule_name": "sc-deny-ssh-for-contractors",
      "expression": "(isMemberOfGroupName(\"Contractors\")) and (user.factor.totp == null and user.factor.webauthn == null)",
      "target_group": "SafeCadence-Quarantine",
      ...
    },
    ...
  }],
  "diff": "...",
  "committed_ids": [],
  "warnings": [],
  "error": null
}
```

**The exact JSON shown is what would be POSTed to Okta's
`/api/v1/groups/rules`.** Read it carefully — that's your audit trail.

**Real-world commit:**
```bash
export OKTA_DOMAIN=yourcorp.okta.com
export OKTA_API_TOKEN='...'
safecadence identity apply /tmp/ir.json --target okta --commit
# → committed_ids: ["rul_abc123"]
```

You'd then see the rule in Okta UI: *Directory → Groups → Rules*.

**Repeat for every IdP:** `--target ise`, `--target ad`, `--target entra`,
`--target clearpass`. Each has matching env vars (see
`docs/IDENTITY-INTEGRATION.md`).

---

### 10. Watchlists

```bash
# Via CLI: not yet exposed (v9.2)
# Via UI:
open http://127.0.0.1:8766/inventory
# Click any asset → asset detail page → "+ Watchlist" button
open http://127.0.0.1:8766/watchlists
# → asset appears in the list
```

**Expected:** Once an asset is on your watchlist, the daemon's next
cycle compares its state to the snapshot taken at watchlist time. Any
change (new finding, MFA flipped, group count changed) appears in:
- The morning briefing under "Watchlist changes"
- The /timeline page
- The bell-icon notifications drawer

**Sample test:**
1. Pin `dc-01.acme.local` to watchlist
2. Manually edit `~/.safecadence/platform/dc-01.acme.local.json` to
   change `health.grade` from "C" to "F"
3. Run `safecadence daemon --once`
4. Check the timeline → should show a "watchlist change" event

---

### 11. Automation rules (IF/THEN)

```bash
open http://127.0.0.1:8766/automation
```

**Expected UI:**
- "New rule" form with kind / severity / action selects
- Existing rules table with last-fired timestamps

**Sample test:**
1. Create rule: kind=`stale_nhi`, severity ≥ medium, action=`notify_log`
2. Click "Preview what would fire now" → shows a fire record for
   `nhi-legacy-importer`
3. Run `safecadence daemon --once` → rule fires for real, log entry
   appended to `~/.safecadence/intel/automation.log`

**Real-world equivalent:** Replace `notify_log` with `notify_slack`
(channel `#sec-alerts`) and the rule posts to your Slack on every new
stale NHI.

---

### 12. Evidence pack PDF

```bash
# Via API:
curl -o /tmp/evidence.pdf \
     -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:8766/api/identity/evidence-pack?format=pdf
open /tmp/evidence.pdf

# Or JSON:
curl http://127.0.0.1:8766/api/identity/evidence-pack?format=json
```

**Expected PDF contents:**
- Cover page: generation timestamp, requested-by, asset count
- Findings list grouped by severity
- Attack paths top 10
- SOC 2 CC6 mapping (compliant / exceptions_present per control)
- ISO 27001 A.9 mapping
- NIST 800-53 AC-2 / AC-5 / IA-2 control posture

**Real-world delivery:** Send the PDF to your auditor. Or generate
weekly via cron and attach to the morning briefing email.

---

### 13. AI assistant (NL Q&A over fleet)

```bash
open http://127.0.0.1:8766/ask
# Type: "how many crown-jewel assets are there?"
# Click Ask
```

**Expected without AI key (deterministic fallback):**
```
There are 4 crown-jewel assets in your fleet: dc-01.acme.local,
crm-prod-01.acme.local, ad-acme-local, ...
```

**With AI key set:** Natural-language answer with citations to
specific asset IDs, e.g. "Of your 31 assets, 4 are tagged crown-jewel
(`dc-01.acme.local`, ...). Two of them have failing policies and one
sits on an attack path."

**Other questions to try:**
- "Which contractors are over-privileged?"
- "What NHIs haven't been rotated in 90 days?"
- "Summarize identity risk in plain English."
- "Are there any orphan service accounts?"

**Failure modes:**
- "AI not configured" → set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`
  before launching `safecadence ui`. Or use the deterministic fallback
  for common keyword queries.

---

## Verification matrix

Track that all 13 features work end-to-end:

| # | Feature        | CLI            | UI page    | Sample data | Real-world delta |
|---|----------------|----------------|------------|-------------|------------------|
| 1 | Attack paths   | (none)         | /paths     | Demo trips ≥1 path | Connect AD + Okta → richer paths |
| 2 | NL→IR translator | identity translate | /identity | Form path no AI needed | AI path needs key |
| 3 | Simulator      | (API only)     | /simulate  | Demo IR works | Real IRs work the same |
| 4 | who-can        | identity who-can | /home (planned) | Default deny | Real chains once adapters populate |
| 5 | JIT            | identity jit   | /jit       | Local-only | Real revoke once IdP creds set |
| 6 | Morning brief  | (API only)     | /briefing  | Renders text | Cron for delivery |
| 7 | Findings       | (none)         | /findings  | Demo trips 4-7 | Same scanner real fleet |
| 8 | Drift          | policy drift-cross-system | /drift (stub) | Demo trips ≥3 | Same on real |
| 9 | Write-back     | identity apply | /identity  | Dry-run only | Commit needs IdP creds |
| 10 | Watchlists    | (none)         | /watchlists | UI add | Daemon detects deltas |
| 11 | Automation    | (none)         | /automation | Preview shows fires | Real fires on cycle |
| 12 | Evidence pack | (API)          | (API)      | PDF generates | Attach to email |
| 13 | AI assistant  | (none)         | /ask       | Fallback works | Real AI w/ key |

---

## Common gotchas

- **Bootstrap fails with "ModuleNotFoundError"** → `rm -rf .venv && ./bootstrap.sh`
- **`/home` shows zero stats** → `safecadence demo --overwrite`
- **Bell badge stuck at 0** → daemon needs to run; `safecadence daemon --once`
- **Sidebar links 404** → you're on a stale install; redo step 0
- **AI assistant can't answer** → no key set; deterministic fallback covers common questions
- **JIT auto-revoke doesn't fire on real IdP** → no IdP creds; daemon marks expired locally only

---

## What this test plan does NOT cover

The test plan above exercises all Tier S+A features against demo data.
It does not exercise:

- **Real adapter integration** — needs actual ISE / Okta / AD instance.
  See `docs/IDENTITY-INTEGRATION.md` for per-IdP setup.
- **Multi-user RBAC** — single-admin demo only.
- **MSP control-plane server** — agent only ships in v8; server unbuilt.
- **SCIM provisioning** — never built.
- **PCI / HIPAA evidence** — only SOC 2 / ISO 27001 / NIST.

These gaps are documented honestly so you know what "works" means.
