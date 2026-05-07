#!/bin/bash
# v9.23.0 publish script — DISABLED.
#
# You said you weren't ready to ship 9.23.0 to PyPI yet. This script
# is parked on purpose: running it as-is exits without publishing so
# you don't accidentally fire it from shell history.
#
# To re-enable when you're ready:
#   1. Delete this guard block.
#   2. Restore the publish body from git history (if committed) or
#      use ./auto-publish-v2.10.0.sh as the template.
#
# Built artifacts are sitting in dist/old/ (wheel + sdist).

echo "auto-publish-v9.23.0.sh is disabled. Edit the file to re-enable."
exit 1
