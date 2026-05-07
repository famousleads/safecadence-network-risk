## [10.0.1] — 2026-05-07

### Pre-ship validation pass + epic HOWTO rewrite

Final pre-ship validation before public release. Nothing
functional changed — this release is the verification + docs
that the v10.0.0 milestone deserves.

#### Validation pass

- **Full test suite — 1263/1263 passing.** Every directory, no
  skips. Six-batch run to fit pytest discovery + execution
  inside the wall-clock budget.
- **325 module import smoke — 0 failures.** `pkgutil.walk_packages`
  walked every `safecadence.*` module and imported it cleanly.
  Catches typos, missing deps, circular imports.
- **CLI smoke — every command + subcommand renders `--help`.**
  32 top-level commands tested (activity, automation,
  capabilities, groups, identity, execute, users, webhooks,
  notify-prefs, vault, demo, daemon, ui, selfcheck, etc.). All
  good.
- **UI walkthrough — 41 sidebar pages confirmed by link audit
  (61 tests passing).** Every advertised page renders 200, no
  404s, no JSON-on-nav-link regressions.
- **Demo smoke — 34 assets + identity vault + NHIs + execution
  jobs + rollback plans + compliance artifacts + capability
  grants + IdP groups + automation rules** all populate on
  `safecadence demo`.

#### HOWTO.md — complete rewrite

Pre-v10.0.1 the HOWTO was 970+ lines of reference material —
useful but unfriendly to a buyer / new operator coming in cold.
v10.0.1 ships a from-scratch rewrite designed for Google +
new-user onboarding:

- **One-minute pitch** — what SafeCadence does, in five
  bullet points
- **5-minute quick start** — `pip install` → `safecadence demo`
  → `safecadence ui`
- **The big idea: read first, write rarely, log always** —
  the design philosophy in three rules
- **Killer features** — eight illustrated paragraphs covering
  capability gating, OIDC auto-grant, Tier-3 SSH, activity log,
  notifications, compliance, AI assistant, automation
- **Real-life workflows** — Day 1, Daily briefing, Weekly
  compliance, Incident response, Auditor visit (each with
  the actual commands an operator would run)
- **Per-section deep dives** — Capabilities, Identity,
  Tier-3, Automation, AI assistant, Activity log,
  Notifications, Demo dataset
- **CLI reference + REST API reference + env-var tunables**
- **FAQ** — 12 questions buyers and operators actually ask
  (dial-home, air-gap, SaaS, JWT rotation, Windows support,
  PyPI flow, etc.)

The doc is built for SEO: clear H2/H3 headings, table of
contents with deep links, descriptive section titles
(`/audit deep filter set` not just `/audit`), CSS-class-free
Markdown that GitHub + GitBook + Pandoc all render the same.

#### UI friendliness assessment (no fixes needed)

Honest review of every sidebar page. The friendliness story is
already strong:

- Every page has a hero band explaining what it is
- Empty states across discovery / drift / per-device-diff /
  changes / tags / scope have explainer cards (v9.20.2)
- /audit has 5 quick-filter chips, browser-local time on hover,
  "My actions only" toggle, deep filter set
- /capabilities matrix shows G/R/D/— glyphs with tooltip
- Universal nav, command palette (Ctrl-K), keyboard shortcuts
  + ? help overlay, dark mode

Known-rough but not v10.0.1 blockers (these are in the v10.x
backlog):
- `v9_pages.py` is 9700+ lines (architectural debt, no
  user-facing impact)
- No screenshot library in docs (we ship a UI, not a
  marketing site)
- UTC-only timestamps in chrome's "last updated" stamps
  (only /audit got the local-time hover)

#### Known follow-ups (intentional, documented)

These were called out in the v10.0.0 milestone CHANGELOG and
are unchanged for v10.0.1 — none customer-blocking:

- PyPI publishing (flow needs re-validation; wheels exist)
- SAML 2.0 response validation (xmlsec hard-dep concern)
- Activity log hash chain (compliance/evidence already has one)
- `v9_pages.py` split (architectural cleanup release)
- Comments/assignments capability migration (workflow surface)

#### Ship

Version 10.0.1 in `__init__.py` and `pyproject.toml`. README,
DEPLOY.md, HOWTO.md all current. CHANGELOG carries the full
v9.x → v10.0.x journey.

The project is finished.

---


---

**Install:** `pip install safecadence-netrisk==10.0.1`

**PyPI:** https://pypi.org/project/safecadence-netrisk/10.0.1/

**Full changelog:** [CHANGELOG.md](https://github.com/famousleads/safecadence-network-risk/blob/main/CHANGELOG.md)
