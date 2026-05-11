# @safecadence/sdk

Official TypeScript/JavaScript SDK for the SafeCadence NetRisk REST API.

Zero runtime dependencies — uses the native global `fetch` (Node >= 18, modern
browsers, Deno, Bun).

## Install

```
npm install @safecadence/sdk
```

## Quickstart

```ts
import { Client } from "@safecadence/sdk";

const sc = new Client({
  baseUrl: "https://demo.safecadence.com",
  apiKey: process.env.SC_API_KEY,
});

// 1. Inventory
const hosts = await sc.listInventory();
console.log(`${hosts.length} hosts`);

// 2. Compose a report
const pdf = await sc.composeReport({ preset: "exec_brief", format: "pdf" });
require("node:fs").writeFileSync("brief.pdf", Buffer.from(pdf));

// 3. Findings filtered by severity
const crits = await sc.getFindings({ severity: "critical" });

// 4. Save a custom template
await sc.saveTemplate(
  "Monthly board pack",
  ["compliance_executive_summary", "risk_register"],
  { sites: ["nyc-dc-1"] }
);
```

## Errors

- `AuthError` — 401 / 403
- `NotFound` — 404
- `RateLimitError` — 429 (carries `.retryAfter` in seconds)
- `SafeCadenceError` — base class for everything else

## Build

```
npm install
npm run build
npm test
```

## License

MIT
