# Roadmap

This is a living document. Vote with your PRs.

## v0.1 — Foundation + Multi-vendor (shipped)

- **Five vendor adapters**: Cisco IOS / IOS-XE, Cisco NX-OS, Cisco ASA,
  Aruba CX (AOS-CX), Arista EOS.
- **64 config audit rules** across all vendors.
- Health + Risk scoring with business-criticality weighting.
- Five report formats: terminal table, Markdown, JSON, brand-able HTML,
  Microsoft Word .docx.
- BYOK AI executive briefings (OpenAI / Anthropic).
- Local SQLite scan history.
- 49-test pytest suite + CI matrix.

## v0.2 — Enrichment (target: 4-6 weeks)

- Bulk scan: `safecadence scan --dir ./configs/` with parallel workers.
- More rules per vendor (target: 25+ each — currently 10-34).
- Juniper Junos adapter + rules.
- PDF report renderer (consultant-style, paginated).

## v0.3 — Enrichment

- **EOL/EoS database** lookup (Cisco, Aruba, Juniper public datasets).
- **CVE matching** against NVD by `(vendor, model, os, version)`.
- Pluggable enrichment provider interface so commercial sources can plug in.
- Findings get a `published_cve` and `eol_date` field.

## v0.4 — Live collection

- SSH-based collection for adapters that opt in (`paramiko` extra).
- SNMP-based collection (`pysnmp` extra) for inventory + neighbors.
- Concurrent device sweeps with rate limiting.
- Connection profiles in `~/.safecadence/profiles.yaml`.

## v0.5 — Topology

- LLDP/CDP-derived asset graph.
- Mermaid + GraphViz topology export.
- Asset-graph aware rules (e.g. "no two routers on the same VLAN with conflicting OSPF area IDs").

## v1.0 — Web UI (optional, opt-in)

- Local-only Next.js dashboard launched via `safecadence ui`.
- Multi-device drill-down, finding suppression, change tracking.
- Export to Jira / GitHub Issues / Linear.

## Always

- More rules. More vendors. Tighter regexes. Real-world test fixtures.
