# SafeCadence v7.5 — Identity Intelligence: write-back, effective permissions, NHI, AI

**Status:** Draft, started 2026-05-04. Owner: SafeCadence core.
**Predecessor:** v6.0 (read-only identity adapters). v7.0–v7.4 added the Secure Command Execution Engine, SSO, MSP, React UI scaffold.
**Successor:** v7.6 will extend write-back to the remaining 4 IdPs and add identity attack-path scoring + JIT access workflows.

## 1. Why this release exists

The v6.0 identity work shipped read-only adapters for Cisco ISE, HPE ClearPass, AD/LDAP, Entra ID, and Okta, plus translators that *generate* per-system policy artifacts as text the operator imports manually. That is half of what an identity intelligence platform actually needs.

The honest gap, per `platform/adapters/identity_adapters.py` line 1: *"v6.0 — Identity Intelligence adapters (5 read-only)."*

What we do not yet do, and what this release fixes:

- **Push policy back.** Translators emit syntax. They do not commit. Today nothing in the codebase calls `PUT /ers/config/authorization` against a real ISE.
- **Compute effective permissions.** We list what each system declares. We do not answer "right now, can principal X do action Y on resource Z, considering nested AD groups + ISE authz conditions + Entra conditional access state + Okta group rules + MFA/posture context."
- **First-class non-human identity.** Service accounts, AWS IAM roles, Azure managed identities, K8s service accounts, OAuth client credentials, machine certs — all collapsed into a generic "identity" today. NHI is where most 2026 breaches start.
- **One unified policy IR with round-trip semantics.** No single representation expresses one intent and emits the right change in all five systems, with a diff preview before commit.
- **AI-assisted authoring.** No path from "contractors with no MFA cannot SSH to prod" → unified IR → per-system change set → preview → approve → apply.

## 2. Scope of v7.5 (the smallest vertical slice that proves the architecture)

### In-scope, must-ship

1. **`NonHumanIdentity` schema block** added to `platform/schema.py`, with subtype enum and credential metadata.
2. **`AdapterCapabilities.supports_write` + `write_capabilities`** — adapters declare which mutations they implement.
3. **`identity/effective_permissions.py`** — pure-Python resolver. Composes ISE + AD + Entra + Okta declared rules from the existing UnifiedAsset graph and answers `decide(principal, action, resource, context) -> Decision`.
4. **`identity/ai_translator.py`** — uses the existing `ai/client.py` BYO-key plumbing. Plain-English intent → `UnifiedPolicyIR` → per-system change preview. Preview shape is deterministic; AI is only used for the natural-language → IR step.
5. **`OktaAdapter.apply_policy(ir)`** — first end-to-end write-back. Translates the IR into Okta group rules / app assignments and PUTs them. Includes dry-run mode that returns a structured diff without committing.
6. **CLI surface:** `safecadence identity translate "<intent>"`, `safecadence identity preview <ir.json>`, `safecadence identity apply <ir.json> --target okta [--dry-run] [--approve]`.
7. **Tier-3 gating:** every `apply` runs through the existing `execution/` engine — RBAC + TOTP + approval + audit row.
8. **Tests:** ≥3 tests per new module, all green. AI client mocked, Okta HTTP mocked.

### Explicitly deferred to v7.6+

- Write-back for ISE, ClearPass, AD/LDAP, Entra ID. (Architecture from #5 generalizes; just adapter work.)
- Identity attack-path edges in the graph (member-of, can-impersonate, can-assume-role).
- Just-in-time access workflows ("grant Alice prod-DB read for 4h, auto-revoke").
- Conflict-resolution policy ("when ISE and AD disagree, AD wins").
- Effective-permission engine extended to NHI chains (service principal can-impersonate user).
- React UI Identity tab. (CLI + existing `safecadence ui` Python tab is enough for v7.5.)

## 3. Schema additions

### 3.1 `NonHumanIdentity`

```python
@dataclass
class NonHumanIdentity:
    nhi_id: str = ""              # globally-unique
    subtype: str = ""             # service_account | managed_identity | iam_role
                                  # | k8s_sa | oauth_client | machine_cert | api_key
    display_name: str = ""
    owner_principal: str = ""     # human or NHI that owns/created this
    provider: str = ""            # aws | azure | gcp | k8s | github | okta | ad | entra
    created_at: str = ""
    last_used_at: str = ""
    last_rotated_at: str = ""
    expires_at: str = ""
    rotation_policy_days: int = 0
    credential_type: str = ""     # password | client_secret | private_key | jwt | x509
    effective_scopes: list[str] = field(default_factory=list)
    can_impersonate: list[str] = field(default_factory=list)  # principal IDs
    risk_findings: list[str] = field(default_factory=list)    # stale, over-privileged, etc.
```

`UnifiedAsset.nhi: NonHumanIdentity | None = None`. NHIs are first-class assets, not buried inside `Identity`.

### 3.2 `AdapterCapabilities` extension

```python
supports_write: bool = False
write_capabilities: list[str] = field(default_factory=list)
# values: ['authz_rule', 'group_membership', 'mfa_enforce', 'session_revoke',
#         'ca_policy', 'app_assignment', 'service_account_rotate']
```

Adapters that don't implement `apply_policy()` keep `supports_write=False`. CLI/UI hides "apply" actions for those adapters.

## 4. The unified policy IR

```python
@dataclass
class UnifiedPolicyIR:
    intent: str                    # the original natural-language input, preserved
    subjects: PrincipalSelector    # who this applies to
    resources: ResourceSelector    # what they're trying to access
    actions: list[str]             # ssh, http, rdp, read, write, admin, ...
    conditions: list[Condition]    # mfa_required, posture_compliant, time_window, ...
    effect: str                    # allow | deny | require_step_up
    severity: str                  # advisory | warn | enforce
    targets: list[str]             # ['okta', 'ise', 'ad'] — which systems must enforce
```

`PrincipalSelector` matches on `groups`, `roles`, `tags`, `nhi_subtype`, etc. `ResourceSelector` matches the existing UnifiedAsset graph (asset_type, environment, criticality, tag).

The IR is JSON-serializable. The AI translator emits IR; humans review IR; per-system translators consume IR; effective-permission resolver evaluates IR against the live graph.

## 5. Effective-permission resolver

```python
@dataclass
class Decision:
    allowed: bool
    chain: list[Rule]              # which rules fired, in order
    systems_consulted: list[str]   # ['okta', 'ise', 'ad']
    reasons: list[str]             # human-readable
    requires_step_up: bool

def decide(principal: str, action: str, resource: str, *,
           context: dict | None = None) -> Decision: ...
```

Pure-Python. Evaluates against the existing `platform_store` snapshot. Order: most-specific deny wins, then most-specific allow, default deny. Returns the full chain so the UI can show *why*.

## 6. AI-assisted authoring

The AI is used only for **NL → IR**. The IR → per-system translation is deterministic (mechanical), so the AI cannot hallucinate a policy that gets shipped. The flow:

1. User: `safecadence identity translate "contractors without MFA cannot SSH to prod"`
2. AI client (BYO-key, existing `ai/client.py`) returns IR as JSON.
3. We validate the IR against the schema. If invalid, refuse — never apply a malformed IR.
4. We compute the per-system change preview (deterministic), show it to the user.
5. User reviews, then `safecadence identity apply` with `--approve` triggers Tier-3 commit.

If no AI key is configured, the CLI offers a guided form fallback so the feature is usable air-gapped.

## 7. Okta write-back contract

`OktaAdapter.apply_policy(ir, *, dry_run: bool) -> ApplyResult`

```python
@dataclass
class ApplyResult:
    target: str                    # 'okta'
    dry_run: bool
    operations: list[Operation]    # what we will do / did
    diff: str                      # human-readable
    committed_ids: list[str]       # group rule IDs / app assignment IDs created
    warnings: list[str]
    error: str | None
```

Operations are computed from the IR:

- `subjects.groups=['contractors']` + `effect=deny` + `actions=['ssh']` + `conditions=[mfa_required]` →
  - Create / update group rule `sc-deny-contractors-no-mfa`
  - Update app assignment for the SSH-bastion app
  - PUT `/api/v1/groups/rules/{ruleId}` with the computed expression

`dry_run=True` runs the same code path but stops before the HTTP PUT and returns the diff.

## 8. Tier-3 gating

Every `apply` is a CommandJob in the existing execution engine (`src/safecadence/execution/`). Risk classifier marks identity changes as `high` by default, requiring 1+ approvals. TOTP challenge is required on commit per the existing v7.2 pattern. Audit row written before *and* after, with the IR and the per-system diff.

## 9. CLI surface

```
safecadence identity translate "<intent>"           # NL → IR (prints JSON)
safecadence identity preview <ir.json>              # IR → per-system diff
safecadence identity apply <ir.json> [flags]        # commit, gated
safecadence identity who-can <action> <resource>    # effective-permission lookup
safecadence identity scan-nhi                       # collect NHIs from connected providers
```

## 10. Test plan

`tests/identity/test_v7_5.py`:

- **Schema**: NHI round-trip through `dataclasses.asdict()` + JSON.
- **AdapterCapabilities**: every existing adapter still loads without `supports_write`.
- **Effective permissions**: fixture fleet has a contractor in AD group `Contractors` and Okta group `External-Workforce`; ISE authz rule denies SSH for unposted devices; verify `decide("alice@contractor.com", "ssh", "prod-db-01") == Decision(allowed=False, ...)` with full chain.
- **AI translator**: mock the AI client to return a fixed IR JSON; verify schema validation rejects malformed IR; verify the deterministic preview is byte-stable.
- **Okta write-back**: run apply against a fixture httpx mock; verify dry-run does no HTTP; verify commit produces `committed_ids` and writes an audit row.

Pass bar: every new module ≥3 tests, full repo `pytest` green.

## 11. Out of scope, intentionally

- Real-time identity threat detection (UEBA-style).
- Privileged-access-management (PAM) features (vaulting, session recording).
- Federation health monitoring (e.g. SAML cert expiry tracking).
- Full Microsoft Conditional Access policy modeling — we model the subset relevant to MFA + device-trust, not the full graph.

## 12. Acceptance criteria

- `safecadence identity translate "no SSH to prod for contractors without MFA"` returns a valid IR JSON.
- `safecadence identity preview` against that IR shows what would change in Okta (and stubs out the other 4 systems with "write-back deferred to v7.6").
- `safecadence identity apply --target okta --dry-run` runs without making HTTP calls and prints the diff.
- `safecadence identity who-can ssh prod-db-01 --as alice@contractor.com` returns ALLOW or DENY with the full reasoning chain.
- All v7.4 tests still pass.
- `pip install -e .` succeeds on Python 3.10+.
- `safecadence ui` boots and the Identity tab loads without 500s.
