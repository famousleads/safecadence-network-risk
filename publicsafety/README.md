# SafeCadence Public Safety

Situational awareness for law-enforcement agencies, built on the
open-source [safecadence-netrisk](https://pypi.org/project/safecadence-netrisk/)
platform (installed automatically as a dependency).

```
pip install safecadence-publicsafety
safecadence ui
```

The **free 90-day trial starts on first use** — no key, no signup, no
call home. After the trial, the module locks until licensed; the
open-source core keeps working and your data stays yours.

## What it adds

- **Asset map** (`/map`) — GeoJSON, risk-banded, vendor-neutral
- **Evidence-infrastructure health** (`/evidence-infrastructure`) —
  capture → transfer → store → access → preserve chain scoring
- **Incidents** (`/incidents`) and **Events** (`/events`) pages over
  the core's native incident lifecycle + syslog/SNMP/webhook ingestion
- **Public-safety asset taxonomy** — cameras, ALPR, body cams, radio,
  access control, evidence storage, CAD/RMS classified automatically
- **CJIS Security Policy mapping** with integrity-hashed evidence packs
- **Sheriff evaluation tenant** — `safecadence demo --sheriff`

## Local-first, by design

Runs on your hardware. No cloud requirement, no telemetry, no external
map tiles. Because it deploys on your infrastructure, SafeCadence never
stores, transmits, or takes custody of CJI.

**Live demo (no signup):**
https://analyzer.safecadence.com/netrisk/public-safety

**Licensing:** flat annual per-agency pricing — no per-gigabyte or
per-seat fees. hello@safecadence.com — a real person replies within 24h.

© FamousTec LLC · Hillsborough County, Florida
