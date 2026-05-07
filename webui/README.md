# SafeCadence Web UI (Next.js + React + Tailwind)

This is the Phase-1 modern frontend for SafeCadence. It coexists with
the vanilla HTML UI under `src/safecadence/ui/` — both talk to the
same FastAPI backend over `/api/*`. The vanilla UI keeps working;
this app provides the same surfaces in React for shops that prefer a
typed component model.

## Status

**Phase 1 (v7.1):** three views ported.

- `/` — Compliance dashboard (briefing + drift KPIs + top failing policies)
- `/inventory` — Asset inventory with filter and grade/KEV columns
- `/command` — Command Center (AI Builder + plan + submit + recent jobs)

**Coming in Phase 2 (v7.2+):**
- Builder wizard
- Drift timeline
- Approval Queue + Execution Queue + Rollback Manager
- Topology views (Cytoscape integration)
- Audit log viewer
- Settings (BYO-AI configuration)

## Running locally

```bash
cd webui
npm install
SAFECADENCE_BACKEND_URL=http://localhost:8765 npm run dev
```

Then open http://localhost:3000. The backend at port 8765 (the FastAPI
server you already run with `safecadence ui`) handles all `/api/*`
calls — Next.js rewrites proxy them.

You'll need a bearer token from `/api/login`. Paste it into the home
page's setup card; it gets stored in `localStorage` and reused.

## Building for production

```bash
npm run build
npm start
```

For air-gapped deployment, `npm run build` produces a static-export-
friendly bundle as long as you don't use server actions. The current
codebase keeps everything client-side, so an `output: 'export'` switch
in `next.config.mjs` produces a static `/out` directory you can serve
from any CDN.
