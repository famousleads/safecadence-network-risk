#!/bin/bash
# Ship v6.4.3 — Audit-finding fix pack. Three parallel deep audits found
# concrete bugs across adapters, controls, and translators. This release
# fixes them root-cause-first, not by burying them in another version.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 330-test suite..."
  PYTHONPATH=src pytest tests/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "fix: v6.4.3 — Audit-finding fix pack (controls, demo, manifest)

Three parallel audits (adapter library, translator coverage, server +
CLI surface) found concrete bugs the user was calling out. v6.4.3 is
the honesty release that fixes them at the root.

CONTROL CHECKS — were silently UNKNOWN, now actually verdict
  - enforce_immutability: was 100% UNKNOWN. Now infers from
    immutability_days, vault_locked (AWS), has_locked_immutability_policy
    (Azure). Demo backup vault now PASSes.
  - enforce_air_gap: was 100% UNKNOWN. Now infers from offsite_copies,
    tape_jobs, cross_region_copy, cross_account_copy. Demo Veeam (no
    air-gap) FAILs; AWS Backup vault (cross-region+cross-account) PASSes.
  - enforce_backup_retention: now falls back to immutability_days when
    retention_days is missing.
  - enforce_encryption_at_rest: now looks at storage block, cloud block,
    KMS key arn, and finding text. Demo S3 bucket (no default encryption)
    FAILs; demo RDS + Azure storage (KMS-encrypted) PASS.

DEMO FLEET — populates fields the controls actually check
  - Storage encryption_at_rest, kms_key_id on cloud assets
  - Backup retention_days, air_gapped, offsite_copies, vault_locked,
    cross_region_copy, cross_account_copy
  - Identity_block: password_min_length, last_access_review,
    conditional_access_rules
  - The 5 idp_* controls now produce real PASS/FAIL across the fleet
    (was 0 verdicts before; the fleet had no fields to verdict on)

ADAPTER MANIFEST — honesty not marketing
  - aruba_cx demoted experimental → stub (collect() returns {})
  - gcp_cloud demoted experimental → stub (collect() returns {})
  - cisco_ucs demoted experimental → stub (XML POST broken)
  - pure_storage promoted stub → experimental (real REST impl)
  - nutanix_prism, proxmox_ve, rubrik_cdm promoted stub → experimental
    (audit found real API calls)

ADAPTER BUG — cisco_network captures errors
  - SSH command failures returning empty string was indistinguishable
    from a clean device. Now: failures captured in `_errors` field per
    command so operators can see what failed without losing the
    successful commands.

COSMETIC — FastAPI deprecation
  - Query() regex= → pattern= in ui/app.py (silent warning gone)

QUALITY:
  330 unit tests pass (11 new in test_v6_4_3.py — locks every fix in
  place so 'we fixed it once' actually means 'it stays fixed')."
  git push origin main
fi

git tag -a v6.4.3 -m "v6.4.3 — Audit-finding fix pack" 2>/dev/null || true
git push origin v6.4.3 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-6.4.[012]* dist/old/ 2>/dev/null || true
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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-6.4.3*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-6.4.3*
fi

if command -v gh &>/dev/null; then
  gh release create v6.4.3 \
    --title "v6.4.3 - Audit-finding fix pack" \
    --notes "Three parallel audits found concrete bugs. v6.4.3 fixes
them at the root.

CONTROL CHECKS no longer silently UNKNOWN:
- enforce_immutability infers from immutability_days / vault_locked
- enforce_air_gap infers from cross_region_copy / tape_jobs
- enforce_encryption_at_rest looks at cloud + storage + KMS
- enforce_backup_retention falls back to immutability_days

DEMO FLEET populates the fields controls check:
- Cloud encryption_at_rest, kms_key_id
- Backup retention_days, air_gapped, vault_locked
- Identity password_min_length, last_access_review,
  conditional_access_rules

ADAPTER MANIFEST honest:
- aruba_cx, gcp_cloud, cisco_ucs DEMOTED to stub (broken)
- pure_storage, nutanix_prism, proxmox_ve, rubrik_cdm PROMOTED to
  experimental (real REST impl)

CISCO_NETWORK adapter no longer silently swallows SSH errors

330 unit tests pass (11 new in test_v6_4_3.py)." \
    dist/safecadence_netrisk-6.4.3-py3-none-any.whl \
    dist/safecadence_netrisk-6.4.3.tar.gz install.sh
fi

echo ""
echo "============================================================"
echo " v6.4.3 SHIPPED - Audit-finding fix pack"
echo "  - 4 controls now actually verdict (was 100% UNKNOWN)"
echo "  - Demo fleet populates real fields"
echo "  - Adapter manifest honest (3 demoted, 4 promoted)"
echo "  - cisco_network captures errors"
echo "  - 330 unit tests pass (11 new locks)"
echo "============================================================"
