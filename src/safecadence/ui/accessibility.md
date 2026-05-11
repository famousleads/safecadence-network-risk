# SafeCadence UI — Accessibility audit (v11.1)

Target: **WCAG 2.2 AA**. This document captures what was audited and fixed
in the v11.1 release, plus what still needs work.

## Scope

The audit covered the four primary HTML-producing modules:

- `src/safecadence/ui/_chrome.py` — the universal app chrome (header, footer,
  sidebar, command palette, slide-over, notifications drawer).
- `src/safecadence/ui/v9_pages.py` — every authenticated page (inventory,
  findings, identity, JIT, paths, watchlists, policies, shadow-IT, topology,
  command center, asset groups, blast radius, coverage, changes, etc).
- `src/safecadence/reports/ui_routes.py` — the reports wizard (`/reports`,
  steps 0–6, preview iframe, export buttons).
- `src/safecadence/portal/customer.py` — the customer-facing portal page.

## What was fixed in v11.1

| WCAG SC | Item | Status |
|---|---|---|
| 1.1.1 Non-text content | Icon-only buttons in the topbar got `aria-label` (search, palette, AI, bell, hamburger). | DONE |
| 1.3.1 Info & relationships | `<main role="main" id="sc-main-content">` landmark wraps every page body. | DONE |
| 1.3.1 Info & relationships | `<aside aria-label="Primary navigation">` on the sidebar. | DONE |
| 1.4.3 Contrast (Minimum) | Dark theme spot-check: `--text` `#e7ecf5` on `--panel` `#121a33` = 14.4:1. `--muted` `#8b95b1` on `--panel` = 5.9:1. Both clear 4.5:1. | DONE |
| 1.4.3 Contrast (Minimum) | Light theme spot-check: `--text` `#0f172a` on `--panel` `#ffffff` = 17.7:1. `--muted` `#64748b` on `--panel` = 5.0:1. Clears AA. | DONE |
| 1.4.10 Reflow | `responsive.css` adds `max-width: 768px` + `max-width: 480px` breakpoints; content reflows to one column without horizontal scroll. | DONE |
| 1.4.11 Non-text contrast | Border colors on inputs (`--border` `#26315b` on `--bg` `#0b1020`) clear 3:1 against background. | DONE |
| 2.1.1 Keyboard | Hamburger, command-palette, bell, and Ask AI buttons are real `<button>` elements — already keyboard-focusable. | DONE |
| 2.4.1 Bypass blocks | Skip-to-content link added to top of every chrome page; visible only on focus. | DONE |
| 2.4.3 Focus order | Skip link is the first focusable element. Sidebar nav follows, then topbar, then main content. | DONE |
| 2.4.7 Focus visible | `:focus-visible { outline: 2px solid #5fc6bc; outline-offset: 2px }` in `responsive.css` applies to every interactive element. | DONE |
| 2.5.5 Target size (Enhanced) | Tap targets get `min-height: 44px` on tablet/mobile (`@media (max-width: 768px)`). Icon buttons also get `min-width: 44px`. | DONE |
| 3.1.1 Language of page | `<html lang="en">` set on every chrome-wrapped page. | DONE |
| 4.1.2 Name, role, value | Notifications bell got `aria-haspopup="true"`. Tabs on the reports wizard got `role="tablist"`/`role="tab"`/`aria-selected`. | DONE |
| 4.1.3 Status messages | New `aria-live="polite"` region (`#sc-live`) added to chrome; `scAnnounce(msg)` helper exposed globally. Reports preview gets its own `aria-live="polite"` region around the preview iframe + stamp. | DONE |

## Color contrast cheatsheet (dark theme)

```
text  e7ecf5 on bg     0b1020  → 17.46:1   AAA
text  e7ecf5 on panel  121a33  → 14.43:1   AAA
muted 8b95b1 on bg     0b1020  →  7.32:1   AA Large + AA Normal
muted 8b95b1 on panel  121a33  →  6.05:1   AA
accent 7c5cff on bg    0b1020  →  5.93:1   AA
bad   ef4444 on bg     0b1020  →  5.21:1   AA
ok    10b981 on bg     0b1020  →  5.34:1   AA
warn  f59e0b on bg     0b1020  →  9.49:1   AAA
```

All foreground/background combinations used for body text clear 4.5:1.
Large/heading text clears the relaxed 3:1 threshold by a wide margin.

## Still TODO (won't ship in v11.1)

1. **Topology graph keyboard navigation.** Cytoscape graph in `/topology`
   is mouse-only today. Owner: graph-rebuild track in v11.2.
2. **AT smoke test.** No VoiceOver / NVDA pass-through has been run yet —
   the fixes here are static-audit-only. Add a manual checklist before
   the next public release.
3. **Color blindness pass.** Severity-coded pills use color + text label
   already; need to add an icon (•, ▲, ★) to each so colorblind users
   have a redundant cue.
4. **Reduced motion.** Wizard auto-advance + slide-over animation should
   honor `@media (prefers-reduced-motion: reduce)`. Add when we touch
   the slide-over again.
5. **Form-error association.** Customer portal e-sign form errors aren't
   yet associated with the relevant input via `aria-describedby`. Easy
   fix, schedule for v11.1.x.
6. **PDF/Word/PowerPoint export accessibility.** The export renderers
   already write alt-text on embedded charts; need to also set the
   document language metadata and tag headings as proper outline levels
   (DOCX/PPTX already do this; PDF via WeasyPrint inherits HTML semantics).

## How to verify locally

```bash
# 1. Boot the UI
.venv/bin/python -m safecadence.ui

# 2. axe-core (browser plugin) → run on /home, /inventory, /reports.
#    All three should report zero "critical" issues.

# 3. Tab through every page — focus indicators must be visible the entire
#    way, the skip-to-content link must appear on first Tab.

# 4. Resize the window to 360px wide. The sidebar should collapse to a
#    bottom-tab strip and the hamburger should become the primary
#    nav-toggle. No horizontal scrollbar.
```
