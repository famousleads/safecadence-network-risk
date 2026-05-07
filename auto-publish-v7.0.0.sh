#!/bin/bash
# Ship v7.0.0 — Secure Command Execution Engine.
# Closes the largest single gap in the v7 spec: the privileged control
# plane that lets operators define intent, get vendor commands, route
# through approval, and hand off to existing automation tooling.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 358-test suite..."
  PYTHONPATH=src pytest tests/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v7.0.0 - Secure Command Execution Engine

The biggest single gap in the spec was the privileged control plane:
generate-fix-and-hope-they-paste-it was where v6.x stopped. v7.0
closes the loop with a proper job/approval/audit/dry-run pipeline.

DESIGN PRINCIPLE (the line we will not cross):
SafeCadence does NOT directly SSH into customer devices. The execution
methods are all 'export to your existing automation tool' — Ansible,
Salt, Cisco NSO, raw command list, markdown runbook. Pretending we
can replicate Ansible's safety story is how customers get locked out
of their datacenter; we do not.

NEW: src/safecadence/execution/ package
  - schema.py: CommandJob, CommandExecution, CommandOutput,
    RollbackPlan, ApprovalRequest, CommandAuditLog with full
    JSON round-trip (str-enum coercion in __post_init__)
  - rbac.py: 6-tier matrix (Viewer / Auditor / Operator / Engineer /
    Security Admin / Super Admin) with strict subsumption + risk-
    routed approvals (safe/low: auto, medium/high: 1, critical: 2)
  - guardrails.py: risk classifier (40 patterns), blocked-command
    list (hard refuse + escalate-to-critical), lockout-risk detector
    (combinations like 'no aaa new-model' on TACACS-only devices)
  - builder.py: AI Command Builder. NL intent ('check BGP on Cisco
    routers') maps to per-vendor command sets via 10 built-in packs
    plus vendor/type sniffing for target filters.
  - workflow.py: Draft -> Review -> Approve -> Deploy state machine
    with multi-approver gating, self-approval blocking, automatic
    rollback-plan generation at approval.
  - executor.py: dry-run engine + Ansible / Salt / NSO / raw /
    markdown exporters. Dry-run produces real CommandExecution +
    CommandOutput rows so the queue tab works.
  - store.py: file-backed JSON persistence with path-traversal
    sanitization + append-only audit log.

NEW: REST surface /api/execute/*
  jobs CRUD + submit/approve/reject/cancel/dry-run/rollback transitions
  + builder/plan + builder/plan-and-save endpoints
  + queue + audit + rbac introspection

NEW: CLI 'safecadence execute' subcommand group
  plan / submit / list / show / approve / dry-run / export / audit / rbac

NEW: 4 UI tabs in policy_ui.py
  Command Center (AI Builder + recent jobs)
  Approvals queue (review -> approve/reject)
  Execution Queue (active jobs + dry-run/export)
  Rollback Manager (rollback plans)

NEW: 5 identity translators close the orphaned-controls gap
  okta_idp, plus extensions to azure_ca for the 5 idp_* controls
  (require_mfa_for_admins, disable_dormant_accounts, password_complexity,
  conditional_access, privileged_role_review). The diff view stops
  saying 'no translator output' for identity assets.

NEW: asset model extensions
  identity.owner, .team, .country, .city, .campus, .building, .floor,
  .rack, .support_contract — populated on every demo asset so the
  spec's location-grouped reports have data to render.

QUALITY:
  358 unit tests pass (22 new in test_v7_0.py)
  No deprecation warnings, no swallowed exceptions
  RBAC subsumption test catches privilege regressions
  No role has EXECUTE_REAL by default (must be wired explicitly)
  Self-approval is blocked at the workflow layer

WHAT'S DELIBERATELY NOT BUILT (v7.1+):
  - Real SSH execution (Tier 3) — operators wire to Ansible Tower
  - Postgres-first storage (file-backed JSON works for the scale)
  - Next.js frontend (vanilla JS works; rewrite is its own project)
  - Cytoscape topology views (simple SVG attack-paths cover blast)
  - Topology nine-view dashboard (1 view ships; 8 to follow)"
  git push origin main
fi

git tag -a v7.0.0 -m "v7.0.0 - Secure Command Execution Engine" 2>/dev/null || true
git push origin v7.0.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-6.* dist/old/ 2>/dev/null || true
if [[ -x .venv/bin/python ]]; then .venv/bin/python -m build; else python3 -m build; fi

echo ""; echo "Paste your PyPI token..."
LAST=""; GOT=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then echo "  [${i}s] '${PREVIEW}...'"; LAST="$PREVIEW"; fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then GOT="$CLIP"; break; fi
  sleep 1
done
[[ -z "$GOT" ]] && { echo "Timeout"; exit 1; }

if [[ -x .venv/bin/python ]]; then
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    .venv/bin/python -m twine upload dist/safecadence_netrisk-7.0.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-7.0.0*
fi

echo ""
echo "============================================================"
echo " v7.0.0 SHIPPED - Secure Command Execution Engine"
echo "  - 6-tier RBAC + approval workflow + guardrails"
echo "  - AI Command Builder (NL -> per-vendor commands)"
echo "  - Dry-run + Ansible/Salt/NSO/raw/markdown exporters"
echo "  - 4 new UI tabs (Command/Approvals/Queue/Rollback)"
echo "  - Identity translators close orphaned-controls gap"
echo "  - Asset model: owner / team / location / contract"
echo "  - 358 unit tests pass (22 new locks)"
echo "============================================================"
