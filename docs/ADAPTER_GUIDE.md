# Adapter Guide

Adding a vendor takes about an hour for an MVP and a day to polish. The
core team will mentor PRs — open a draft early.

## File layout

```
src/safecadence/adapters/<vendor_slug_with_underscores>/
    __init__.py
    adapter.py
    parser.py    # optional, but strongly recommended
```

`__init__.py`:

```python
from safecadence.adapters.<vendor>.adapter import <Vendor>Adapter
__all__ = ["<Vendor>Adapter"]
```

`adapter.py`:

```python
from safecadence.adapters.<vendor> import parser as vp
from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig

@register_adapter
class <Vendor>Adapter(BaseAdapter):
    slug = "<vendor-slug>"          # hyphens, e.g. "aruba-cx"
    label = "Aruba CX"
    os_family = ["aos-cx"]
    filename_hints = ("running-config", "show-running")
    content_hints = ("ArubaOS-CX", "interface 1/1/1")

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        return vp.parse(text)
```

## What `parse_config` must populate

At minimum:

- `vendor` — your slug.
- `device_type` — one of `switch | router | firewall | wlc | server | cloud`.
- `os` — short string (e.g. `aos-cx`).
- `version` — version string, ideally semver-shaped.
- `raw_config` — the original text. Engines run regex against this.

Strongly recommended:

- `hostname`, `model`.
- `interfaces` — for health scoring.

Optional (great for v0.2 features):

- `neighbors` — populates topology.
- `extras` — anything vendor-specific you want preserved for rule custom expressions.

## Adding tests

Place a sample config in `examples/sample_configs/<vendor>_running.txt`
and add a test under `tests/` that asserts hostname, version, and at least
one rule fires. See `tests/test_parser.py` for the pattern.

## Submitting

1. Open a PR titled `feat(adapter): add <vendor>`.
2. Include an `examples/` sanitized config and a `data/rules/<vendor>/` pack
   of at least 10 rules to start.
3. Add an entry to `CHANGELOG.md`.
