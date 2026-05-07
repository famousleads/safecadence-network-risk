# Architecture

SafeCadence Network Risk is intentionally small at the core and grows
through pluggable adapters and rule packs.

## Layers

```
                           +---------------------+
                           |        CLI          |   safecadence.cli
                           |  (click + rich)     |
                           +----------+----------+
                                      |
        +-----------------------------+-----------------------------+
        |                             |                             |
+---------------+          +----------+-----------+        +--------+--------+
|  Vendor       |          |  Engines             |        |  Reports        |
|  Adapters     |--parse-->|  - config_audit      |--------|  - markdown.py  |
|  (cisco_ios,  |          |  - health            |        |  - json.py      |
|   aruba_cx,   |          |  - risk              |        |  (HTML/PDF/DOCX |
|   arista_eos, |          |                      |        |   coming v0.2)  |
|   ...)        |          +----------+-----------+        +-----------------+
+-------+-------+                     |
        |                             |
        |                  +----------+-----------+
        |                  |   Rule packs (YAML)  |
        |                  |   data/rules/<vend>/ |
        |                  +----------------------+
        |
+-------+-------+              +----------------+
|  ParsedConfig |              |  AI module     |   safecadence.ai
|  (schema.py)  |              |  - BYOK key    |   (OpenAI/Anthropic,
+---------------+              |  - prompts.py  |    httpx, optional)
                               +----------------+
```

## Data model

Everything ultimately becomes a `ScanResult` (`safecadence/core/schema.py`):

- `ParsedConfig` — adapter output: hostname, model, OS, interfaces, neighbors,
  raw_config text. Vendor-agnostic.
- `Finding` — one rule hit. Severity, evidence, remediation, fix snippet,
  references.
- `Asset` — top-level inventory record with computed scores.
- `ScanResult` — wraps all of the above with timing and summary.

## Adapter contract

Each adapter implements `BaseAdapter.parse_config(text) -> ParsedConfig`
and registers itself via `@register_adapter`. The registry auto-discovers
adapters at first use by walking `safecadence.adapters.*`.

Detection is content-driven first (substrings in the config), filename-driven
second (e.g. `running-config.txt`). The adapter with the highest detection
score wins.

## Rule contract

Rules are YAML files under `safecadence/data/rules/<vendor_underscore>/`.
A rule is `{ id, title, severity, vendor, domain, description, remediation,
fix_snippet, references, match_regex|absent_regex|custom }`. The audit
engine evaluates them lazily, sorts findings by severity weight, and feeds
them to the scoring engines.

## Privacy

The CLI makes no network calls except the BYOK AI explainer, which only
runs when the user explicitly asks for it and only sends the user's own
key to their chosen provider. All scan outputs stay on local disk.
