# SafeCadence Governance

**Last updated:** 2026-05-25
**Current model:** Single-maintainer (BDFL-track)

This document describes how decisions are made in the SafeCadence
project today, how that will evolve as the project grows, and what
happens if the primary maintainer becomes unavailable.

---

## Today: single-maintainer (the honest truth)

SafeCadence is currently maintained by **Faz Karim**
([@famousleads](https://github.com/famousleads)). Final decisions
about scope, features, releases, and project direction are made by
Faz. Contributions are welcome and reviewed publicly, but the
maintainer has final say.

This is intentional. Single-maintainer projects can move fast,
maintain coherent vision, and avoid the design-by-committee trap.
The cost is bus-factor risk — addressed in the Continuity section
below.

### How decisions are made today

| Decision type | Process |
|---|---|
| Bug fixes | PR review by maintainer; merged when tests pass and review is approved |
| New feature (small) | GitHub Discussion or issue first; if approved, PR welcome |
| New feature (major / breaking) | Public RFC in GitHub Discussions, 7-day comment period, maintainer decision |
| Roadmap changes | Updated in `ROADMAP.md` with changelog entry; major reordering announced via release notes |
| Security fixes | Private disclosure (per `SECURITY.md`), maintainer fixes, coordinated disclosure |
| Release timing | Maintainer judgment; release cadence is "when it's ready," not calendar-driven |

### What contributors can expect

- PR triage within 7 days for non-trivial PRs (acknowledgment + initial
  review). Faster for security PRs.
- Constructive feedback on rejections — explanation of why, suggestion
  for alternative direction.
- Credit in `CHANGELOG.md` for accepted contributions.
- Roadmap input is genuinely welcomed via GitHub Discussions tagged
  `roadmap-feedback` — see `ROADMAP.md`.

---

## Evolution: when single-maintainer ends

The project graduates from single-maintainer governance when **all three**
of these conditions are met:

1. **5+ active contributors** (each with 10+ merged PRs in the prior
   12 months)
2. **3+ paying companies** on Support contracts (provides funding for
   coordinator role)
3. **Maintainer-council charter ratified** — documented voting rules,
   conflict resolution, code-of-conduct enforcement process

At that point, governance shifts to a **Maintainer Council** model:

- 3–7 maintainers, each elected for 2-year staggered terms
- Decisions by simple majority for routine matters, supermajority
  (2/3) for breaking changes
- Founding maintainer (Faz) retains "founder seat" with veto power
  for the first 5 years post-transition (to protect against
  hostile-takeover scenarios)
- Quarterly public roadmap review
- Annual community survey informs roadmap priorities

When this transition happens, this document is updated with the
ratified charter and a `CHANGELOG.md` entry announces it publicly.

---

## Continuity / bus-factor plan

If the primary maintainer becomes unavailable (illness, accident,
loss of interest, etc.), here's what is in place to ensure the
project continues:

### Technical continuity

- **GitHub organization** (`famousleads`): commit rights held by Faz
  + 1 designated successor (currently being identified for v12 GA;
  will be a long-time technical collaborator with documented OSS
  experience). Both have admin rights to the org.
- **PyPI account access**: Trusted Publishing via GitHub Actions OIDC
  is the primary release path (no API tokens to lose). Backup PyPI
  maintainer account credentials are escrowed with a designated
  legal entity (to be set up for v12).
- **Domain ownership**: `safecadence.com` registered under a legal
  entity (to be set up for v12) with documented succession.
- **Trademark**: SafeCadence wordmark + logo registered in US under
  the legal entity (planned for v12-v13 timeframe).
- **Encryption keys** (Fernet vault keys, GPG signing keys for air-gap
  bundles): documented escrow procedure with the same legal entity.

### Legal continuity

- **MIT license** ensures the worst-case outcome is *always* "anyone
  can fork." Even if every continuity measure above fails, the code
  remains free for the community to continue.
- **Trademark** held by the entity (not by an individual) so it
  survives the founder.
- **Repository history** is public and globally distributed via Git;
  cannot be deleted by any single party.

### Communication continuity

- Status updates published to a designated channel (mailing list,
  GitHub Discussions) at least quarterly. Extended silence (60+ days
  with no activity) triggers a community check-in.
- Designated successor has commit access to publish a "transition"
  announcement if needed.

---

## How to escalate disagreements

If a community member disagrees with a maintainer decision:

1. **First**, comment on the relevant PR or issue with reasoning. Most
   disagreements are clarified at this stage.
2. **If unresolved**, open a GitHub Discussion tagged `governance` with
   the question. Maintainer responds within 14 days with a public
   reasoned decision.
3. **If still unresolved**, the MIT license guarantees forking is
   always an option. We hope it doesn't come to that, but the option
   exists by design.

Once the Maintainer Council is established (per the evolution
criteria above), this process becomes a vote.

---

## Code of Conduct enforcement

See `CODE_OF_CONDUCT.md` for the community behavior expectations.
Enforcement today is by the maintainer (Faz) and via standard tools:
- Warnings
- Temporary bans from project communication channels
- Permanent bans for repeated or severe violations

When the Maintainer Council is established, enforcement becomes a
council vote with documented appeal process.

---

## Funding & ownership commitments

These are firm commitments, not aspirations:

- **No venture capital.** SafeCadence will not take VC funding. The
  business model in `ROADMAP.md` and `MONETIZATION_STRATEGY.md` is
  structured to be sustainable without it.
- **No proprietary fork.** No "SafeCadence Enterprise Edition" with
  features the OSS doesn't have. See `ROADMAP.md` for the full
  "free for anyone" commitment.
- **No silent acquisition.** If SafeCadence is ever acquired, the
  community will be notified 90 days in advance, the acquiring entity
  must publicly affirm the OSS commitments in this document, and the
  community has standing to fork if they disagree.

---

*Questions? Open a GitHub Discussion or email hello@safecadence.com.*
