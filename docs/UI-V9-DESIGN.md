# SafeCadence UI v9 — design spec

**Status:** Draft, May 2026. No code shipped yet. Read me, react, then we build.

This is what I would design if I had a clean slate and 20+ years of
product UX behind me. The goal is to take the **25+ tools** SafeCadence
already has and surface them in a way where:

- A new operator finds value in 60 seconds
- A daily user opens it before their first coffee
- A CISO/auditor can be sent a URL and immediately understand
- Mobile works
- Keyboard-first power users move 5× faster than mouse users

Not "feature additions". A re-organization. Same engine, dramatically
better wrapper.

---

## 1. Why the current UI doesn't work

Honest list:

1. **Twelve top-level URLs.** `/`, `/home`, `/hub`, `/identity`, `/ask`, `/timeline`, `/briefing`, `/automation`, `/onboarding`, `/simulate`, `/share`, `/asset/{id}`. No hierarchy. Users get lost.
2. **No persistent navigation chrome on every page.** The new pages have it; the legacy 1800-line UI doesn't. Two products under one roof.
3. **Stats fragmented.** Compliance % on `/home`. Findings count on `/identity`. Activity on `/timeline`. Should be one screen.
4. **Hidden features.** Watchlists, comments, JIT, evidence pack, share — all exist, none discoverable from the home screen.
5. **No command palette.** Power users want `Cmd+K`. We have nothing.
6. **No empty-state design.** Lists with zero rows look broken, not inviting.
7. **No light theme.** Forces dark on everyone.
8. **No mobile.** Phones approve nothing.
9. **No "at a glance" hero score.** Drata has "92% compliant" front-and-center. We don't.
10. **Demo data isn't visually distinct from real data.** Confusing.

---

## 2. Design principles for v9

1. **One screen, one job.** Every page has a single primary task.
2. **Progressive disclosure.** Five things visible, fifty things one click away.
3. **Show, don't tell.** Replace explanatory text with live data.
4. **Empty states are first impressions.** Every blank list has a magnetic CTA.
5. **Speed feels like value.** Sub-100ms transitions. Skeletons, not spinners.
6. **Keyboard ≥ mouse.** Every action has a shortcut. `Cmd+K` opens everything.
7. **Color carries meaning.** Severity, status, trend — pre-attentive.
8. **Real-time is alive.** Background polls every 60s; UI animates updates.
9. **AI is embedded, not adjacent.** "Ask AI about this" lives on every list.
10. **Mobile is first-class.** Sidebar collapses to bottom tab bar < 720px.

---

## 3. Information Architecture

### Left sidebar (persistent, collapsible)

```
SafeCadence
─────────────
🔎  Search…                  ⌘K
─────────────
🏠  Home

🔍  Discover
    · Inventory
    · Topology
    · Auto-discover

✅  Compliance
    · Policies
    · Findings
    · Drift
    · Per-device diff
    · Evidence

🔐  Identity
    · Translator
    · Effective permissions
    · JIT grants
    · Attack paths

⚙️  Execute
    · Builder
    · Approvals
    · Queue
    · Rollback

🤖  Automation
    · Rules
    · Watchlists
    · Briefings

📜  Audit
    · Timeline
    · Evidence packs
    · Public shares

⚙️  Settings
    · Connections
    · RBAC
    · Notifications
─────────────
👤 admin
🌗 theme · ⌨ shortcuts
```

Seven groups. Every existing tool finds a home in exactly one. No tool
is hidden — every page is two clicks from anywhere.

### Top bar (persistent across all pages)

```
[Logo]   <Page title · breadcrumb>            🔎 ⌘K   🤖 Ask AI   🔔(3)   👤
```

Always visible. Logo collapses sidebar. Breadcrumb tells you where you
are. Cmd+K opens the command palette. AI button opens slide-over chat.
Bell shows live activity count. Avatar = user menu.

### Command palette (Cmd+K, anywhere)

```
┌────────────────────────────────────────────┐
│  Search assets, tools, findings, runs…     │
├────────────────────────────────────────────┤
│  📊 Tools                                  │
│    Identity translator                     │
│    What-if simulator                       │
│  🖥 Recent assets                           │
│    srv-prod-db-01                          │
│    nhi-build-bot                           │
│  🚩 Findings                               │
│    [HIGH]  Stale NHI: build-bot…           │
│  🤖 Ask AI                                  │
│    Ask: "..."                              │
└────────────────────────────────────────────┘
```

One input. Fuzzy matching across everything. Arrow keys + enter to
navigate. Ranked by recency + relevance.

---

## 4. Home page

The single most important screen. If a user only opens one URL daily,
this is it.

```
┌─────────────────────────────────────────────────────────────────┐
│   COMPLIANCE SCORE                                              │
│        ┌─────────┐                                              │
│        │  87%    │   ↗ +3% this week        [demo data badge]   │
│        └─────────┘                                              │
│                                                                 │
│  ╔═════════════╗  ╔═════════════╗  ╔═════════════╗              │
│  ║  4          ║  ║  2          ║  ║  1          ║              │
│  ║  Critical   ║  ║  Attack     ║  ║  Active     ║              │
│  ║  findings   ║  ║  paths      ║  ║  JIT grants ║              │
│  ╚═════════════╝  ╚═════════════╝  ╚═════════════╝              │
│                                                                 │
│   YOUR NEXT 3 ACTIONS                                           │
│   1.  🎯  Remediate path: alice → BuildBot → AdminRole → DB     │
│           Risk: 8.4   ⏱ ~2 minutes                              │
│   2.  🚩  Rotate stale NHI: nhi-legacy-importer (180 days)      │
│           Severity: HIGH   ⏱ ~1 minute                          │
│   3.  ❌  Fix policy "MFA on Domain Admins" (failing on 3 hosts) │
│           Severity: HIGH   ⏱ ~5 minutes                         │
│                                                                 │
│   📡 Live activity                            🤖 Ask anything   │
│   ─────────────────                           ─────────────     │
│   2 mins ago · finding · stale_nhi…           [input box]       │
│   8 mins ago · jit · grant created…                             │
│   12 mins · audit · policy approved…                            │
│   …                                                             │
└─────────────────────────────────────────────────────────────────┘
```

Hero score + three risk cards + three actions + live feed + AI box.
That's the entire home. Everything else is a click away.

---

## 5. List views (universal pattern)

Every page that shows rows of things — assets, findings, policies,
JIT grants — follows the same pattern.

```
┌──────────────────────────────────────────────────────────────┐
│  Findings                                                    │
│                                                              │
│  Filters: [severity ▼] [kind ▼] [assigned to me ☐]   ⌘F      │
│                                                              │
│  [☑] [↻] Saved view: My queue                                │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ ◯  HIGH   stale_nhi    nhi-build-bot                  │  │
│  │     Last used 92 days ago       suggested IR ↗        │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │ ◯  CRIT   orphan_sa    nhi-legacy-importer            │  │
│  │     Owner departed                  Auto-fix ↗        │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  Bulk actions: [Auto-fix] [Assign…] [Watchlist] [Comment]    │
└──────────────────────────────────────────────────────────────┘
```

Consistent across every list:
- Filters at top (severity, kind, assignee, date range)
- "Saved view" dropdown for personalized queries
- Multi-select with bulk actions
- Each row is clickable → slide-over detail
- Inline AI: "Ask about this finding"

Empty state replaces the table entirely:

```
┌────────────────────────────────────────────────┐
│            🎉  No critical findings.           │
│                                                │
│   Your fleet is healthy. To stay healthy,      │
│   set up an automation rule that fires when    │
│   one appears.                                 │
│                                                │
│   [Set up automation →]   [Take the tour]      │
└────────────────────────────────────────────────┘
```

---

## 6. Detail pages (slide-over, not full-page navigation)

Click a finding / asset / NHI / JIT grant → a slide-over panel opens
on the right. The list stays visible underneath. You can dismiss with
`Esc`. This is faster than full-page nav.

```
                                       │ Finding · stale_nhi              ✕│
┌─────────────────────────┐            ├──────────────────────────────────┤
│ Findings list (visible) │            │ ◯ HIGH                           │
│                         │            │ NHI nhi-build-bot                │
│  ◯ HIGH   stale_nhi     │            │ Last used 92 days ago            │
│  ◯ HIGH   no_mfa        │ ◀────────▶ │                                  │
│  ◯ MED    over_priv…    │            │ EVIDENCE                         │
│  …                      │            │ provider: okta                   │
│                         │            │ subtype: service_account         │
│                         │            │ owner: ivan.devops               │
│                         │            │                                  │
│                         │            │ SUGGESTED REMEDIATION            │
│                         │            │ Deactivate this NHI in Okta.     │
│                         │            │ [Preview IR] [Auto-fix]          │
│                         │            │                                  │
│                         │            │ COMMENTS · ASSIGN · WATCH        │
│                         │            │ ─────                            │
└─────────────────────────┘            └──────────────────────────────────┘
```

Detail = slide-over. List = always visible. Back button = `Esc`.

---

## 7. Visual language

- **Severity colors** (consistent everywhere):
  - critical: `#ef4444` red
  - high: `#f59e0b` orange
  - medium: `#fde68a` amber
  - low: `#3b82f6` blue
  - info: `#9ca3af` gray
- **Status dots:** green / yellow / red, 8px circles, prepended to every entity name
- **Trend arrows:** `↑ +3%` (good), `↓ -2%` (bad), color-coded
- **Sparklines:** below every score, last 30 days, no axes
- **Avatars:** for assignments, monogrammed if no photo
- **Demo-data badge:** subtle but visible "DEMO" pill on cards when fleet is the demo set
- **Live indicator:** small green pulsing dot near "Live activity"
- **Loading skeletons:** rectangle shapes the size of the data, animated shimmer — no spinners

---

## 8. Mobile (< 720px)

- Sidebar collapses to bottom tab bar (4 tabs: Home / Compliance / Identity / Audit)
- Top bar shrinks: just hamburger + search icon + bell
- List rows become cards (one per row, full width)
- Slide-overs become full-screen modals
- Cmd+K becomes a "+" floating action button → search modal

Approve from your phone walking the dog. That's the test.

---

## 9. Theme

Two themes from day one:

- **Dark** (current default) — `#0b1020` background, sharp contrast
- **Light** — `#fafbfd` background, `#1f2937` text, same accents

Toggle in user menu. Respects `prefers-color-scheme` if not explicitly set.

---

## 10. AI integration (embedded, not adjacent)

Drop the dedicated `/ask` page. Instead:

- Top bar has 🤖 button → slide-over chat from right
- Every list has "Ask AI about this" inline
- Every detail panel has "Explain this in plain English"
- Cmd+K results include "Ask: <your query>"
- Morning briefing arrives in the chat as the day's first message

AI feels everywhere, not somewhere.

---

## 11. Onboarding

First-visit experience replaces the home page until the user dismisses:

```
Step 1 of 5  ──●──○──○──○──○

  Welcome to SafeCadence.

  In 5 minutes you'll have:
   ✓ A loaded fleet (real or demo)
   ✓ Identity connected
   ✓ Your first policy applied as dry-run
   ✓ One automation rule running
   ✓ A morning briefing waiting tomorrow

  [Use demo data] [Import CSV] [Connect identity]
```

Each step is a single decision. The whole tour finishes in 5 minutes
with the user at a meaningful home dashboard. Dismissable. Resumable.

---

## 12. What v9 is NOT

- Not a React rewrite. The existing FastAPI server-rendered approach is fine; we just need a coherent design system.
- Not a new backend. All endpoints stay. We re-skin and re-organize.
- Not a feature dump. Every feature in v8 stays; nothing new ships in v9.
- Not a renaming exercise. Same vocabulary, same engine.

---

## 13. Build order (when you say go)

1. **Design tokens module** — colors, spacing, typography, severity scale
2. **Persistent shell** — sidebar + top bar component, used by every page
3. **Command palette** — Cmd+K modal with fuzzy search
4. **Redesigned home** — hero score + three cards + three actions
5. **Universal list-view pattern** — applied to findings, JIT, audit
6. **Slide-over detail panels** — replaces full-page nav for entity views
7. **Empty-state library** — every list has its own
8. **Light theme** — toggle + matching styles
9. **Mobile responsive sweep** — every screen
10. **Onboarding flow** — 5-step tour as first-visit experience

Roughly two focused sessions. No new features. Just the shell every
existing feature lives inside.

---

## 14. The mockup

Open `docs/v9-mockup.html` in any browser. It's a static, fully
clickable preview of what v9 would feel like. No backend. No JWT.
Just the structure. React, click around, tell me what's wrong.

---

## 15. The decision

If this design resonates:
- I build steps 1–4 in the next session (sidebar, top bar, command palette, redesigned home)
- You see real progress in the running UI within ~2 hours of work
- Steps 5–10 ship after you've felt the first half

If something feels wrong:
- Mark it up. Tell me what to change. We iterate on the doc + mockup *before* writing production code.

This is the conversation we should have had at v6.
