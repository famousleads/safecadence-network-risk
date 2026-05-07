# SafeCadence Quick Console (Chrome extension)

A small Manifest V3 popup that gives operators 1-click access to a
locally-running SafeCadence instance. Shows live KEV-CVE / policy /
drift counts, lets you plan a quick command via the AI builder, and
links into the four most-used pages of the full UI.

## What it does

- Reads the configured host + bearer token from `chrome.storage.local`.
- Polls `/api/policy/executive-briefing`, `/api/policy/cross-system-drift`,
  and `/api/platform/license` when the popup opens.
- Surfaces KEV-CVE count, policy-failure count, overall compliance %,
  and license status.
- Lets you submit a natural-language intent to `/api/execute/builder/plan`
  and see the matched command pack + risk verdict without leaving the
  current tab.
- Deep-links to the full UI's Compliance / Interpreter / Drift / Audit
  views.

## What it does NOT do

- It does **not** call home. There is no SafeCadence cloud control
  plane. All requests go to the user-configured host.
- It does **not** store credentials in `chrome.storage.sync` (which
  would replicate across the user's other Chrome profiles). We use
  `chrome.storage.local` so the token stays on this machine.
- It does **not** execute commands. Even Tier3 dry-run is a click
  through to the full UI's Command Center.

## Loading it (developer mode)

1. Open `chrome://extensions` in Chrome.
2. Enable "Developer mode" in the top-right.
3. Click "Load unpacked".
4. Pick this `chrome-extension/` directory.

The popup appears in your toolbar. Click it, paste your SafeCadence
host (e.g. `http://localhost:8765`) and a bearer token, hit Connect.

## Generating icons

The repo doesn't ship binary icons; copy any 16/32/48/128-pixel PNGs
named `icon-16.png` / `icon-32.png` / `icon-48.png` / `icon-128.png`
into this directory before publishing to the Chrome Web Store. For
local dev, Chrome shows a generic puzzle-piece icon if they're absent.

## Future work (v7.2+)

- Service worker subscribes to `/api/execute/audit` via SSE and
  badges the toolbar icon with "N pending approvals."
- Right-click context menu integration ("submit URL as policy
  evidence") — useful when you're reading a CVE advisory.
- Multi-host support (cycle through several SafeCadence instances
  from the popup).
