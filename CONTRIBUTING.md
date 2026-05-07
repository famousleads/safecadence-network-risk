# Contributing to SafeCadence Network Risk

Thanks for thinking about helping. This project succeeds only if it
becomes the best open source network audit tool available — and that
needs many hands.

## Quick start

```bash
git clone https://github.com/safecadence/safecadence-network-risk.git
cd safecadence-network-risk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[ai]"
pip install pytest
pytest
safecadence scan examples/sample_configs/cisco_ios_running.txt
```

## What we need most (in priority order)

1. **More vendor adapters.** Aruba CX, Arista EOS, Juniper Junos, FortiOS,
   Palo Alto PAN-OS, Cisco NX-OS proper, MikroTik RouterOS. See
   [docs/ADAPTER_GUIDE.md](docs/ADAPTER_GUIDE.md).
2. **More rule packs.** Each adapter ships 30+ rules at minimum. See
   [docs/RULE_GUIDE.md](docs/RULE_GUIDE.md). Rules are YAML — no Python required.
3. **EOL / EoS data.** Cisco, Aruba, Juniper publish EoL dates. We need a
   pluggable enrichment layer that maps `(vendor, model, version)` → EoL date.
4. **CVE matching.** Map parsed `os` + `version` to NVD CVE records.
5. **Real-world test fixtures.** Sanitized configs (hostnames + IPs scrubbed)
   from production environments make our rules sharper. PRs welcome.
6. **Output formats.** Word/PDF/HTML renderers. SBOM, OSCAL.
7. **Discovery + topology.** SNMP/LLDP-driven asset graph.

## Coding standards

- Python 3.10+.
- The core package depends on `click`, `rich`, and `pyyaml`. Anything
  else (httpx, paramiko, etc.) lives behind an optional extra so a
  vanilla `pip install` stays light.
- Type hints throughout; `from __future__ import annotations` at the top
  of every module.
- No emojis in code, docs, or commits.

## Submitting a PR

1. Fork the repo and create a branch off `main`.
2. Add tests for any new behavior. The existing pattern is `pytest`.
3. Run `pytest` locally — it must pass.
4. Add an entry to `CHANGELOG.md` under an `## [Unreleased]` heading.
5. Open the PR against `main` with a clear description and link any
   related issues.

## Reporting security issues

Please do **not** open a public issue. Email `security@safecadence.com`
with details and a way to reproduce. We will respond within 48 hours.

## License

By contributing, you agree your contribution will be licensed under the
[MIT License](LICENSE).
