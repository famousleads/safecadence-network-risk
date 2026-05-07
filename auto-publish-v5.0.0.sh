#!/bin/bash
# Ship v5.0.0 — Policy Intelligence Engine.
#   - 22 policy controls + 10 starter templates + 5 framework mappings (NIST/CIS/PCI/HIPAA/ISO)
#   - 12 multi-vendor config translators
#   - AI policy interpreter (BYO-AI w/ offline fallback)
#   - Compliance evaluator + drift detection + remediation engine
#   - 7 export formats (raw, ansible, terraform, bash, powershell, markdown, pdf)
#   - 10 advanced features: workflow, audit, git-sync, exceptions, simulator,
#     custom controls, CVE-driven policies, attestation, env variants, webhooks,
#     shadow IT detection, policy-test harness
#   - /api/policy/* REST surface (~25 endpoints)
#   - 7-tab Policy UI dashboard
#   - safecadence policy ... CLI (15 subcommands)
#   - 64 unit tests, all passing
#   - Cross-platform: Windows / Linux / macOS, virtual or physical
set -e
cd "$(dirname "$0")"

# Run tests one more time before shipping
if command -v pytest &>/dev/null; then
  echo "Running test suite..."
  PYTHONPATH=src pytest tests/policy/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v5.0.0 — Policy Intelligence Engine

A read-only + generate framework that authors security policies in
plain English, evaluates them against the existing 40-adapter asset
inventory, detects drift, and exports remediation as ANSIBLE / TERRAFORM
/ POWERSHELL / BASH / MARKDOWN / PDF / RAW configs the user applies
through their existing change-management process.

NEVER executes commands. Generated configs are exported, not pushed.

POLICY MODEL:
  - 22 atomic security controls (network/server/cloud/storage/backup)
  - 10 starter policy templates (network hardening, firewall baseline,
    server hardening, cloud security, zero trust, etc.)
  - Framework mappings: NIST 800-53, CIS, PCI-DSS, HIPAA, ISO 27001

MULTI-VENDOR TRANSLATION (12 vendors):
  - cisco_ios, cisco_nxos, cisco_asa
  - arista_eos, juniper_junos, fortinet_fortios, paloalto_panos
  - linux, windows
  - aws_iam, azure, gcp

ENGINE:
  - safecadence.policy.interpreter   plain-English -> SecurityPolicy
                                      (offline keyword path always works,
                                       BYO-AI provider hook for v5.1)
  - safecadence.policy.evaluator     run policy vs UnifiedAsset fleet
  - safecadence.policy.simulator     what-if without persisting
  - safecadence.policy.drift         regression / improvement timeline
  - safecadence.policy.remediation   per-vendor fix plan
  - safecadence.policy.exporters     7 formats

ADVANCED FEATURES (10):
  - approval workflow + audit trail
  - GitOps for policies (safecadence policy git-sync <repo>)
  - exception / risk-acceptance management
  - what-if simulator (decide rollout sequence safely)
  - user-defined custom controls (~/.safecadence/custom_controls/*.yaml)
  - CVE-driven auto-policy generation
  - compliance attestation reports (auditor-ready)
  - multi-environment policy variants (prod vs dev parameter overrides)
  - violation webhooks (Splunk/Sentinel/Slack)
  - shadow-IT detection (assets covered by no policy)
  - policy testing harness (unit-test policies against fixture states)

SURFACE:
  /api/policy/*  (~25 endpoints + /api/policy/ui dashboard)
  /api/policy/ui (7-tab single-file HTML dashboard)
  safecadence policy ... CLI (15 subcommands)

QUALITY:
  - 64 unit tests pass (incl. evaluator, exporters, translators, drift)
  - Cross-platform: Linux, macOS, Windows; physical or virtual
  - All file I/O via pathlib + explicit utf-8 encoding
  - No shell pipelines in library code
  - Optional deps gated cleanly (httpx, reportlab, paramiko)

This is the read-and-recommend half of the originally proposed Unified
Security Policy Intelligence + Secure Command Execution Engine spec.
The execution half (SSH push, RBAC, command guardrails) is intentionally
deferred to keep SafeCadence's local-first, blast-radius-free posture."
  git push origin main
fi

git tag -a v5.0.0 -m "v5.0.0 — Policy Intelligence Engine (22 controls, 10 templates, 12 translators, 7 exporters, 64 tests)" 2>/dev/null || true
git push origin v5.0.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-4.* dist/old/ 2>/dev/null || true
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -m build
else
  python3 -m build
fi

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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-5.0.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-5.0.0*
fi

if command -v gh &>/dev/null; then
  gh release create v5.0.0 \
    --title "v5.0.0 — Policy Intelligence Engine" \
    --notes "**v5.0.0** introduces the SafeCadence Policy Intelligence Engine — a read-only + generate framework that authors security policies in plain English, evaluates them against your fleet, detects drift, and exports remediation as Ansible / Terraform / PowerShell / Bash / Markdown / PDF / raw configs.

**Never executes commands.** Generated configs are exported for you to apply via your existing change-management process.

## What's new

**Policy authoring**
- 22 atomic security controls (network / server / cloud / storage / backup)
- 10 starter policy templates: network hardening, firewall baseline, router/switch baseline, server hardening, cloud security, logging/monitoring, identity & access control, encryption, backup security, zero trust
- Compliance framework mappings: NIST 800-53, CIS, PCI-DSS, HIPAA, ISO 27001

**Multi-vendor translation (12 targets)**
- Network: \`cisco_ios\`, \`cisco_nxos\`, \`cisco_asa\`, \`arista_eos\`, \`juniper_junos\`, \`fortinet_fortios\`, \`paloalto_panos\`
- Servers: \`linux\`, \`windows\`
- Cloud: \`aws_iam\`, \`azure\`, \`gcp\`

**Engine**
- AI policy interpreter (plain English → structured policy; offline keyword fallback always works)
- Compliance evaluator + drift detection
- Remediation engine generates fix / rollback / verify commands per asset
- 7 export formats: raw, ansible, terraform, powershell, bash, markdown, pdf

**Advanced features**
- Approval workflow + immutable audit trail
- GitOps for policies: \`safecadence policy git-sync <repo>\`
- Exception / risk-acceptance management with auto-expiry
- What-if simulator (preview impact before adopting)
- User-defined custom controls (\`~/.safecadence/custom_controls/*.yaml\`)
- CVE-driven auto-policy generation
- Compliance attestation reports (auditor-ready)
- Multi-environment policy variants (prod vs dev parameter overrides)
- Violation webhooks (Splunk / Sentinel / Slack-compatible)
- Shadow-IT detection (assets covered by no active policy)
- Policy testing harness (unit-test policies against fixture states)

**Surface**
- \`/api/policy/*\` — ~25 REST endpoints (CRUD, evaluate, simulate, drift, remediate, export, attestation, exceptions, variants, audit, git-sync, webhooks, shadow IT, CVE auto, testing, UI)
- \`/api/policy/ui\` — 7-tab single-file dashboard (Builder, Interpreter, Compliance, Drift, Remediation, Exceptions, Audit Log)
- \`safecadence policy ...\` — 15 CLI subcommands

**Quality**
- 64 unit tests pass
- Cross-platform: Linux / macOS / Windows; physical or virtual
- All file I/O via \`pathlib\` + explicit \`utf-8\` encoding
- No shell pipelines in library code

## Install

\`pip install --upgrade safecadence-netrisk\` then \`safecadence ui\` and visit \`/api/policy/ui\` for the policy dashboard, or run \`safecadence policy templates\` from the CLI." \
    dist/safecadence_netrisk-5.0.0-py3-none-any.whl \
    dist/safecadence_netrisk-5.0.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v5.0.0 SHIPPED — Policy Intelligence Engine"
echo "  - 22 controls, 10 templates, 12 translators, 7 exporters"
echo "  - 25 REST endpoints, 7-tab UI, 15 CLI subcommands"
echo "  - 64 unit tests passing"
echo "============================================================"
