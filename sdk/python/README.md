# safecadence-sdk (Python)

Official Python SDK for the SafeCadence NetRisk REST API.

## Install

```
pip install safecadence-sdk
```

## Quickstart

### 1. List inventory

```python
from safecadence_sdk import Client

sc = Client("https://demo.safecadence.com", api_key="scapi_xxx")
for host in sc.list_inventory():
    print(host["hostname"], host.get("risk_score"))
```

### 2. Compose a report (one-shot)

```python
pdf_bytes = sc.compose_report(preset="exec_brief", format="pdf")
open("brief.pdf", "wb").write(pdf_bytes)
```

### 3. Pull findings filtered by severity

```python
crits = sc.get_findings(severity="critical")
print(f"{len(crits)} critical findings")
```

### 4. Save a custom report template

```python
sc.save_template(
    name="Monthly board pack",
    sections=["compliance_executive_summary", "risk_register"],
    scope={"sites": ["nyc-dc-1"]},
)
```

## Errors

The SDK raises typed exceptions inheriting from `SafeCadenceError`:

- `AuthError` — 401 / 403
- `NotFound` — 404
- `RateLimitError` — 429 (carries `.retry_after` in seconds)
- `SafeCadenceError` — everything else, with `.status_code` and `.response_body`

## License

MIT — same as the rest of SafeCadence NetRisk.
