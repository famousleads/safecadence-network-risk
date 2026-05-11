# SafeCadence Mobile — React Native scaffold (not yet built)

This folder is a placeholder. The mobile app is **not** scaffolded yet —
that needs the App Store + Play Console accounts and a developer machine
with the iOS / Android toolchains installed.

When you're ready, run the steps below from this directory.

---

## Prerequisites

- **macOS** for iOS builds (Xcode 15+, CocoaPods).
- **Android Studio** with the latest SDK + an emulator image.
- **Node.js 20 LTS** and **Yarn** (or npm).
- An Apple Developer Program account (USD 99/yr) and a Google Play
  Console account (USD 25 one-time) before submitting builds.
- A backend reachable from a phone — i.e. SafeCadence running on a
  public hostname with HTTPS (the demo at `demo.safecadence.com` is
  read-only and good enough for early dev; the customer-portal API at
  `app.safecadence.com` will be the production target).

## One-time scaffold

```bash
# From /mobile (this directory)
npx react-native@latest init SafeCadence --version 0.74
cd SafeCadence

# Install runtime deps
yarn add @react-navigation/native @react-navigation/native-stack \
        react-native-screens react-native-safe-area-context \
        react-native-mmkv axios
```

On iOS:

```bash
cd ios && pod install && cd ..
```

## Point the app at the SafeCadence backend

Create `src/config.ts`:

```ts
export const API_BASE = __DEV__
  ? 'https://demo.safecadence.com'    // read-only demo while developing
  : 'https://app.safecadence.com';    // multi-tenant production API
```

Then in `src/api.ts`:

```ts
import axios from 'axios';
import { API_BASE } from './config';

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 12000,
  headers: { 'Accept': 'application/json' },
});

// Auth: pass the user's Bearer token from MMKV once they've signed in
// via the web app. The native app does NOT re-implement magic-link sign-in
// for v1 — it consumes existing sessions.
```

## First screens to build

1. **Dashboard** — KPI cards (calls `GET /api/dashboard.json`).
2. **Inventory** — paginated host list (calls `GET /api/devices`).
3. **Findings** — severity-grouped (calls `GET /api/findings`).
4. **Reports** — list saved reports + open shared link (calls
   `GET /api/reports/templates`).

The web UI lives at `https://app.safecadence.com`. The native app is
intentionally **read + alert** in v1; all writes (scans, approvals,
ticket creation) stay on the web.

## Push notifications

- Use **Firebase Cloud Messaging** for both platforms (free tier, one SDK).
- The backend webhook delivery in `safecadence.reports.webhooks` already
  supports custom URLs — point a webhook at the FCM HTTP v1 endpoint
  with an auth header to fan out push from report-ready events.

## Submission

Don't submit until:

1. The wizard, dashboard, and inventory screens are functional against
   the real `app.safecadence.com` API.
2. App Store screenshots are produced (6.7-inch and 5.5-inch on iOS;
   phone + 7-inch tablet on Android).
3. A privacy policy lives at `https://safecadence.com/privacy` covering
   what the app reads from the backend.
4. The App Store reviewer test account has read-only access to a seeded
   demo org.

## Why this isn't built yet

v11.1 ships the **PWA** (`/manifest.webmanifest` + `/sw.js`) so users
can "Add to Home Screen" on iOS Safari and Android Chrome today. That
covers ~90% of the value of a native app and ships in zero submission
time. The native scaffold here is the next step once the App Store
accounts are set up.
