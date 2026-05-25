# SafeCadence Version Support Policy

**Last updated:** 2026-05-25

This document defines how long each version of SafeCadence receives
support — bug fixes, security patches, and compatibility updates.
Enterprise buyers can reference this when evaluating "is it safe
to standardize on version X for the next 18 months?"

---

## Support window definition

For every major release of SafeCadence, the support window is:

> **From GA date until the GA date of the second subsequent major
> release.**

Concretely:

| Major version | GA date (planned) | Support window ends | Reason |
|---|---|---|---|
| v9.x | 2026-03 (shipped) | v11 GA (2026-05) ✓ ended | Security patches only after v10 GA, fully EOL at v11 GA |
| v10.x | 2026-05 (shipped) | v12 GA (Q3 2026, planned) | Security patches only after v11 GA, EOL at v12 GA |
| v11.x | 2026-05 (shipped) | v13 GA (Q1 2027, planned) | Currently in primary support |
| v12.x | Q3 2026 (planned) | v14 GA (Q3 2027, planned) | Will become primary support window after v12 GA |
| v13.x | Q1 2027 (planned) | v15 GA (Q1 2028, planned) | Future support window |
| v14.x | Q3 2027 (planned) | v16 GA (Q3 2028, planned) | Future support window |

**Translation:** at any time, the two most recent major versions are
supported (primary support for the latest, security-patches-only for
the previous one). The third-most-recent major version is EOL.

---

## What "supported" includes

For a version in the **primary support window** (latest major
release):

- ✅ Security patches for any vulnerability (per `SECURITY.md`
  severity criteria)
- ✅ Bug fixes for confirmed regressions
- ✅ Compatibility updates (Python version support, dependency
  updates)
- ✅ Documentation corrections
- ✅ New minor releases (vX.Y) with backwards-compatible features
- ✅ New patch releases (vX.Y.Z)

For a version in the **security-patches-only window** (previous
major release):

- ✅ Security patches for High and Critical severity vulnerabilities
- ✅ Security patches for Medium severity vulnerabilities when
  feasible
- ❌ New features
- ❌ Bug fixes (unless they prevent successful security patch
  installation)
- ❌ Dependency upgrades beyond what security patches require

For a version that is **EOL**:

- ❌ No further updates of any kind
- Users are expected to upgrade to a supported version

---

## Breaking changes policy

Breaking changes only happen at **major version boundaries** (v11 → v12,
v12 → v13, etc.). Within a major version line, every minor and patch
release is backwards-compatible with the previous version in the same
line.

What counts as "breaking" for this policy:

- Removing a public CLI command, flag, or argument
- Removing or renaming a public Python API function or class (anything
  in `safecadence.*` not prefixed with `_`)
- Changing the on-disk config file format incompatibly
- Changing the JSON API response shape for any documented endpoint
- Removing a vendor adapter
- Changing default behavior of any feature that's been in 2+ major
  versions

What does NOT count as breaking (allowed in minor releases):

- Adding new commands, flags, arguments, fields, endpoints, adapters
- Internal API changes (anything `_` prefixed)
- Performance improvements that change timing characteristics
- New optional config fields with defaults that preserve behavior
- Bug fixes that change incorrect behavior to correct behavior

---

## Pre-announcement window for breaking changes

When a breaking change is planned for the next major release, it is
announced **at least 6 months before that major release ships**.

Pre-announcement happens via:

1. `CHANGELOG.md` entry in the prior major version's minor releases
   marked `DEPRECATED — to be removed in vX`
2. Runtime deprecation warnings emitted by the affected code paths
3. Migration guide published to `docs/migration/vX-from-vY.md`
4. GitHub Discussion + release-notes mention

For v12 (next major, planned Q3 2026), all planned breaking changes
will be pre-announced by Q1 2026 at the latest. The list of v12
breaking changes will be maintained in `docs/migration/v12-from-v11.md`
once it exists.

---

## Security disclosure process

See `SECURITY.md` for the full vulnerability disclosure process.
Summary:

- Critical: acknowledged within 24 hours, patched within 7 days,
  coordinated disclosure with reporter
- High: acknowledged within 48 hours, patched within 14 days
- Medium: acknowledged within 5 business days, patched within 30 days
- Low: acknowledged within 10 business days, patched in next minor
  release

Security patches for supported versions are issued as patch releases
(vX.Y.Z) and announced via GitHub Security Advisory + release notes.

---

## Long-term support (LTS) considerations

SafeCadence does **not** currently offer LTS releases (extended
support beyond the standard policy above). If enterprise customer
demand emerges (typically 3+ customers willing to pay specifically
for LTS), we will revisit.

The honest reason: maintaining patches for multiple major versions
in parallel is a real engineering burden, and we'd rather invest
that time in moving the supported versions forward.

---

## How to know what version you're on

```bash
safecadence --version
# Returns the current version, e.g. "safecadence, version 11.6.0"
```

For the supported-version status of your current install:

```bash
safecadence support-status
# v12+ command; reports current support tier (Primary / Security-only / EOL)
# and the date the current window expires
```

---

## Migration paths

When a version reaches EOL, the recommended upgrade path is to the
current primary-support version (e.g. when v10 became EOL, the
recommended path was directly to v11).

Migration guides published per major-to-major:

- `docs/migration/v11-from-v10.md` — exists
- `docs/migration/v12-from-v11.md` — will be published by Q2 2026
- `docs/migration/v13-from-v12.md` — published when v13 enters beta
- `docs/migration/v14-from-v13.md` — published when v14 enters beta

Migration is always best-effort to be one-command:
`safecadence ops migrate --from vX --to vY`. When that's not possible,
the migration guide spells out the manual steps with reasoning.

---

*Questions? Open a GitHub Discussion tagged `support-policy` or email
hello@safecadence.com.*
