#!/bin/bash
# Push the locally-committed GitHub Actions workflow to GitHub.
# Run: bash push-workflow.sh
cd "$(dirname "$0")"
echo "Pushing 1fd81e3 (ci: add PyPI Trusted Publishing workflow)..."
git push origin main
echo ""
echo "Done. View at: https://github.com/famousleads/safecadence-network-risk/blob/main/.github/workflows/publish-to-pypi.yml"
echo ""
echo "Next: complete the one-time PyPI side per launch-followup/07-pypi-trusted-publishing-setup.md"
