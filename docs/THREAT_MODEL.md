# SafeCadence — Threat Model

A short, opinionated STRIDE-style threat model for SafeCadence itself. Updated alongside the codebase.

## What we are

A locally-installed Python package that:
- Reads network/server/identity configurations from connected sources
- Computes a security score and a list of findings
- Optionally writes back changes (firewall rules, identity policies, SSH commands)
- Stores its state in `~/.safecadence/` by default, optionally Postgres
- Serves a local web UI on `127.0.0.1:8766` by default
- Optionally pushes events to Splunk HEC, Slack, Teams, PagerDuty webhooks

## Trust boundaries

```
[ operator ] ──auth──> [ SafeCadence server (FastAPI) ]
                              │
                              ├──> [ vendor APIs ]    (configured per asset)
                              ├──> [ identity APIs ]   (configured)
                              ├──> [ cloud APIs ]      (configured)
                              ├──> [ Splunk / SIEM ]   (optional, opt-in)
                              ├──> [ BYO-AI provider ] (optional, opt-in)
                              └──> [ local file store ]
```

Every boundary that crosses out of the operator's machine is gated by an explicit configuration value. Nothing leaves the box without the operator setting an env var or a settings field.

## Adversaries we model

| Adversary | Goal | Capability |
|---|---|---|
| **External attacker on the same LAN** | Pivot through SafeCadence to network gear | Can probe `127.0.0.1:8766` only if the operator binds publicly |
| **Compromised operator workstation** | Exfiltrate vault credentials, network configs | Has shell access to operator's machine |
| **Malicious insider with read-only auth** | Trigger remediation, change policies | Has a viewer JWT token |
| **Malicious vendor API response** | Inject through parser into SafeCadence runtime | Returns crafted config text |
| **Supply-chain attacker** | Replace the wheel on PyPI, ship malicious update | Compromises maintainer or PyPI |
| **Network adversary in transit** | Read config exfil, modify Splunk events | MITMs an outbound HEC POST |

## STRIDE per surface

### Spoofing
- **Auth:** JWT bearer required for every `/api/*` endpoint. The local UI exchanges a password (or OIDC) for a JWT cookie.
- **Auditor portal:** Token-gated, scope-restricted, HMAC-safe verify, time-bound. Only the SHA-256 hash is persisted.
- **Webhooks out:** HMAC-SHA256 signed when `SC_WEBHOOK_SIGNING_SECRET` is set. Receivers verify.
- **Splunk HEC out:** Splunk's own token auth.

### Tampering
- **Settings file:** File-backed JSON, mode 0600 by default. Detect via SHA-256 sum if integrity matters.
- **Evidence chain:** Append-only hash chain. `verify_chain()` walks every record; tampering with any record breaks the chain forward of it.
- **Policy changes:** Logged in `policy_changes.jsonl` with before/after snapshots. Approval workflow gates activation.
- **Audit log:** Append-only, used by /timeline.

### Repudiation
- Every mutation in the FastAPI surface logs to the audit log with `user_id`, `timestamp`, `request_id`.
- Identity write-backs are recorded against the operator's JWT subject.
- Tier-3 SSH execution requires fresh TOTP per job — single-use codes proven against the user.

### Information disclosure
- **Vault:** Credentials encrypted at rest using cryptography's Fernet (AES-128-CBC + HMAC-SHA256). Master key derived from `SC_VAULT_PASSPHRASE` via PBKDF2-HMAC-SHA256, 600,000 iterations.
- **JWT secret:** Persisted at `$SAFECADENCE_HOME/jwt_secret` mode 0600; rotation supported via `safecadence admin rotate-jwt`.
- **AI calls:** Configs sent to BYO-AI provider are truncated to 8KB and the operator sees the exact prompt in the response.
- **Auditor portal scope:** Tokens are restricted to `/compliance`, `/evidence`, `/scores`, `/findings`, `/policies` by default. They cannot access `/inventory` raw configs unless explicitly scoped.

### Denial of service
- File upload limits enforced (configurable via `SC_MAX_UPLOAD_BYTES`).
- TOTP rate-limited at 6 attempts / 5 min.
- Login lockout after 5 bad attempts.
- Daemon scheduling is bounded — explicit `daily | weekly | monthly | quarterly`, no arbitrary cron.

### Elevation of privilege
- Three-tier execution model:
    - Tier 1: dry-run / preview only — no real device access
    - Tier 2: read-only collection (SNMP, REST GET, Cloud read APIs)
    - Tier 3: write — requires JWT writer cap + TOTP per job + approval workflow
- Identity write-back requires per-system credentials in the vault, additionally gated.
- RBAC for policies (v9.32) limits which scope each role can edit.

## Mitigations against the supply-chain attack

- Wheel + sdist published with SHA-256 sums in the release.
- CycloneDX SBOM published per release.
- Git tags signed with GPG.
- `pyproject.toml` pins all required dependencies to a minor version range; `[server]` extras pin tighter.
- Maintainer credentials stored in a hardware token (Yubikey).
- PyPI 2FA required for all maintainers.
- No CI auto-publish — every release is a manual maintainer action that must succeed both locally and on the publish CI.

## Things we explicitly do not protect against

- **Operator's workstation compromise.** If the workstation is owned, the JWT, the vault key, and the running configs are all exposed. SafeCadence is not an EDR.
- **Malicious operator.** A user with admin role can take any action SafeCadence supports. The audit log records what they did, but does not prevent it.
- **Compromised upstream vendor APIs.** If Cisco's REST API is malicious, our adapters parse what we're given. Vendor responses are size-bounded and parsed defensively, but SafeCadence is not a sandbox.

## Reporting

`security@safecadence.com`. See [SECURITY.md](../SECURITY.md) for disclosure policy.
