# Security Policy

SafeCadence is a security tool that runs inside customer networks, often with access to network configurations, identity systems, vault credentials, and the ability to execute remediation. We take the security of SafeCadence itself seriously. This document is the contract.

## Reporting a vulnerability

**Email: `security@safecadence.com`** (PGP key fingerprint published below).

Please include:
- Affected version(s)
- Reproduction steps or proof-of-concept
- Your assessment of impact
- Whether you'd like public credit

We acknowledge receipt within **2 business days**. We aim for a triage decision within **5 business days** and a fix or mitigation guidance within **30 days** for high-severity issues.

We will not pursue legal action against researchers acting in good faith under this policy. Don't access production data you don't own. Don't perform DoS testing against shared infrastructure. Don't social-engineer SafeCadence employees or contributors.

A coordinated disclosure window is **90 days** by default — you and we agree on the public-disclosure date when the fix lands.

## SLAs

| Severity | Acknowledge | Triage decision | Mitigation / fix |
|---|---|---|---|
| Critical (RCE, auth bypass, mass-data exposure) | 24 h | 48 h | 7 days |
| High (privilege escalation, stored XSS in auth'd surface) | 48 h | 5 business days | 30 days |
| Medium (CSRF, info disclosure not affecting identity) | 5 business days | 10 business days | 90 days |
| Low (rate-limit gaps, fingerprinting) | 10 business days | 20 business days | Next scheduled release |

If we miss an SLA, we will tell you why and propose a new date. We do
not silently slip.

## Rewards

This is a researcher-funded bounty paid by the SafeCadence project. We
do not run on HackerOne or Bugcrowd; we route payouts directly via
Stripe or wire. Pick whichever is easiest for you.

| Severity | Reward (USD) |
|---|---|
| Critical | $2,500 – $5,000 |
| High | $750 – $2,500 |
| Medium | $200 – $750 |
| Low | $50 – $200 |

The exact amount inside a band depends on:

- Quality of the report (reproducible, root-caused, optionally
  including a patch suggestion → upper end).
- Novelty (a never-before-reported class → upper end).
- Whether the issue is exploitable in production-default config or
  only with an unusual setting (production-default → upper end).

We do not pay for:

- Findings whose only impact is on a contributor's personal fork or
  PR-staging environment.
- Vulnerabilities in third-party services we use (Stripe, DigitalOcean,
  Caddy upstreams) — please report to those vendors directly.
- DoS that requires resource-exhaustion at the network layer (we will
  fix it if it lands, but it isn't bounty-eligible).
- Issues already in our public backlog (we'll show you the existing
  ticket and credit you on the Hall of Fame regardless).

## What's in scope

- The `safecadence-netrisk` Python package on PyPI (when shipped)
- The local UI (`safecadence ui`)
- The server mode (`safecadence-netrisk[server]` on FastAPI)
- The Docker image (when shipped)
- The CLI commands and their auth/RBAC paths
- The vendor adapters' parsing logic (config injection, etc.)
- The identity write-back path (Okta / ISE / AD / Entra / ClearPass)
- The execution engine (Tier 3 SSH executor)
- The compliance modules (mappings, exceptions, evidence chain, auditor portal)

## What's out of scope

- Vulnerabilities in third-party dependencies — please report to the upstream project. We monitor `pip-audit` / GitHub Dependabot and patch transitively.
- Issues affecting only end-of-life versions (anything more than 2 minor versions behind current).
- Misconfiguration of a customer's deployment that doesn't expose a flaw in SafeCadence itself.
- Social engineering of customers or contributors.
- Physical attacks against a customer's deployment.

## Trust posture by design

These properties hold in every release. We treat any change to them as a breaking change and ship a CHANGELOG note explicitly.

- **No telemetry, no phone-home, no auto-update.** SafeCadence does not transmit any data to any address you didn't configure. There is no opt-out toggle because there is nothing to opt out of. Verify yourself: search the codebase for `httpx`, `urllib`, or `requests` — every call site is gated behind an explicit configuration value.
- **BYO-AI keys never leave the operator's machine.** When the operator sets `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `OLLAMA_HOST`, that key is read at request time and sent only to the named provider. Set `SC_AI_DISABLED=1` to force the offline rule-based path.
- **Read-only by default.** First install never modifies anything. Tier-3 SSH execution requires both a writer JWT capability and TOTP enrollment per job. Identity write-back requires explicit per-system credentials in the vault.
- **Local-first storage.** File-backed JSON at `$SAFECADENCE_HOME` (default `~/.safecadence/`) is the default. Postgres is opt-in via `DATABASE_URL`. No managed cloud storage path exists.
- **Air-gap friendly.** Set `SC_AI_DISABLED=1` and disable scheduled-evidence email and the product runs entirely without outbound network access. The only outbound calls in that mode are explicit user-triggered actions like `safecadence demo --refresh-cve` (CVE database update).

## Cryptographic posture

- JWT secret: persisted at `$SAFECADENCE_HOME/jwt_secret` (mode 0600), generated at first boot via `secrets.token_urlsafe(32)`. Operator can override via `SC_JWT_SECRET`.
- Auditor portal tokens: 32-byte URL-safe random; only the SHA-256 hash is persisted; constant-time `hmac.compare_digest` for verification.
- Splunk HEC / Slack / Teams / PagerDuty webhooks: HMAC-SHA256 signed when `SC_WEBHOOK_SIGNING_SECRET` is set.
- Evidence pack tamper-evidence: SHA-256 hash chain at `$SC_DATA_DIR/evidence_chain.jsonl`; `verify_chain()` walks every record on read.
- TOTP (Tier 3 SSH MFA): RFC 6238 compliant, 30-second window, 6 digits.

## Build verification

Each release on PyPI publishes:
- The wheel + sdist
- A SHA-256 sum file (`safecadence_netrisk-VERSION.sha256.txt`)
- A CycloneDX SBOM (`safecadence_netrisk-VERSION.cdx.json`)
- A signed git tag (GPG)

To verify a build locally:

```bash
pip download safecadence-netrisk==<version>
sha256sum safecadence_netrisk-*.whl
# Compare against the .sha256.txt published with the release
```

## Threat model summary

A high-level threat model lives at [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). It covers attacker goals (config exfiltration, lateral movement, supply-chain insertion), trust boundaries (operator → CLI → server → vendor APIs), and our specific mitigations against each.

## PGP key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Replace this block with the actual key once minted.]
-----END PGP PUBLIC KEY BLOCK-----

Fingerprint: TBD — generate with `gpg --full-gen-key` and publish.
```

Until the PGP key is published, encrypted reports may use an age public key:

```
age1placeholder...
```

## Hall of fame

We credit security researchers who report valid vulnerabilities. Email us with your name + handle (or stay anonymous, your choice) and we'll add you to `docs/SECURITY-CREDITS.md` once the fix ships.

_No reports yet. Be the first — see "Reporting a vulnerability" above._
