"""Adapter contract test harness.

Every adapter we ship as 'production' in the manifest must pass this
harness against captured fixtures. Operators can also run it against
their own hardware (``--live --host x.x.x.x``) to validate that an
adapter works end-to-end before they trust it on a 1000-device fleet.

The contract: every production adapter must implement
  test_connection(target, **kwargs) -> bool
  discover(cidr_or_target) -> list[asset_dict]   # optional for some
  collect(target, **kwargs) -> dict[str, str]     # raw command outputs
  normalize(asset_id, raw) -> UnifiedAsset

The harness drives those four methods, validates the result, and
reports a pass/fail score per adapter.

Fixture layout:
  tests/fixtures/adapters/{adapter_name}/
    expected.json      # what normalize() should produce
    raw/
      {command}.txt    # captured 'show' outputs

Live mode:
  --host 10.0.0.1 --username admin --key ~/.ssh/lab.key
  Runs the same contract against the real device.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ContractResult:
    adapter: str
    pass_count: int = 0
    fail_count: int = 0
    findings: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.fail_count == 0

    @property
    def total(self) -> int:
        return self.pass_count + self.fail_count


def _record(r: ContractResult, name: str, passed: bool, *,
             detail: str = "") -> None:
    if passed:
        r.pass_count += 1
    else:
        r.fail_count += 1
    r.findings.append({
        "check": name,
        "passed": passed,
        "detail": detail[:300],
    })


def _has_method(obj: Any, name: str) -> bool:
    return callable(getattr(obj, name, None))


def _validate_unified_asset(d: dict) -> list[str]:
    """Return a list of contract-violation messages for a single asset."""
    issues: list[str] = []
    ident = d.get("identity") or {}
    if not ident.get("asset_id"):
        issues.append("identity.asset_id required")
    if not ident.get("asset_type"):
        issues.append("identity.asset_type required")
    if not ident.get("vendor"):
        issues.append("identity.vendor required")
    # Type checks on optional blocks
    for block in ("os", "network", "security", "lifecycle", "health",
                  "cloud", "identity_block", "backup", "storage",
                  "virtualization", "hardware"):
        v = d.get(block)
        if v is not None and not isinstance(v, dict):
            issues.append(f"{block} must be a dict (got {type(v).__name__})")
    # Tags must be a list of strings if present
    tags = d.get("tags")
    if tags is not None:
        if not isinstance(tags, list):
            issues.append("tags must be a list")
        elif any(not isinstance(t, str) for t in tags):
            issues.append("every tag must be a string")
    return issues


# --------------------------------------------------------------------------
# Fixture-driven mode
# --------------------------------------------------------------------------

def run_fixture(adapter: Any, fixture_dir: Path, *, name: str = ""
                ) -> ContractResult:
    """Drive the adapter's normalize() with a captured raw/ tree and
    compare the output to expected.json."""
    name = name or adapter.__class__.__name__
    r = ContractResult(adapter=name)

    if not fixture_dir.exists():
        _record(r, "fixture_dir_exists", False,
                 detail=f"fixture dir not found: {fixture_dir}")
        return r
    raw_dir = fixture_dir / "raw"
    if not raw_dir.exists():
        _record(r, "raw_dir_exists", False,
                 detail=f"raw/ subdirectory missing in {fixture_dir}")
        return r
    expected_path = fixture_dir / "expected.json"

    # Adapter contract: must declare the four methods
    for method in ("test_connection", "collect", "normalize"):
        _record(r, f"has_method:{method}", _has_method(adapter, method),
                 detail=f"{method} missing on {name}")

    # Compose raw dict from the captured files
    raw: dict[str, str] = {}
    for f in raw_dir.glob("*.txt"):
        raw[f.stem.replace("_", " ")] = f.read_text(encoding="utf-8")
    if not raw:
        _record(r, "raw_files_present", False,
                 detail=f"no .txt files in {raw_dir}")
        return r
    _record(r, "raw_files_present", True)

    if not _has_method(adapter, "normalize"):
        return r
    try:
        produced = adapter.normalize("fixture-asset-1", raw)
        produced_dict = (produced.__dict__
                          if hasattr(produced, "__dict__") else dict(produced))
    except Exception as e:
        _record(r, "normalize_returns", False,
                 detail=f"{type(e).__name__}: {e}")
        return r

    issues = _validate_unified_asset(produced_dict)
    _record(r, "normalize_unified_asset_shape", not issues,
             detail="; ".join(issues))

    if expected_path.exists():
        try:
            expected = json.loads(expected_path.read_text())
        except Exception as e:
            _record(r, "expected_json_loads", False,
                     detail=f"{type(e).__name__}: {e}")
            return r
        # Field-by-field comparison on the keys expected.json declares.
        # We don't require an exact match — adapters can emit extra
        # blocks the fixture doesn't pin down. The fixture is the
        # contract, not a snapshot.
        for key in expected:
            actual = produced_dict.get(key)
            if expected[key] != actual:
                _record(r, f"matches:{key}", False,
                         detail=f"expected {expected[key]!r}, "
                                f"got {actual!r}")
            else:
                _record(r, f"matches:{key}", True)

    return r


# --------------------------------------------------------------------------
# Live-hardware mode
# --------------------------------------------------------------------------

def run_live(adapter: Any, *, host: str, username: str = "",
              password: str = "", key_filename: str = "",
              port: int = 22, name: str = "") -> ContractResult:
    """Drive the adapter against real hardware. Calls test_connection,
    discover (if available), collect, and normalize. Useful for
    ``safecadence adapter test cisco_ios --live --host x.x.x.x``."""
    name = name or adapter.__class__.__name__
    r = ContractResult(adapter=name)

    if not _has_method(adapter, "test_connection"):
        _record(r, "has_method:test_connection", False)
        return r
    try:
        ok = adapter.test_connection(
            host, username=username, password=password,
            key_filename=key_filename, port=port,
        )
    except Exception as e:
        _record(r, "test_connection", False,
                 detail=f"{type(e).__name__}: {e}")
        return r
    _record(r, "test_connection", bool(ok))
    if not ok:
        return r

    if _has_method(adapter, "discover"):
        try:
            assets = adapter.discover(host) or []
            _record(r, "discover_returns_list", isinstance(assets, list),
                     detail=f"got {type(assets).__name__}")
        except NotImplementedError:
            pass     # discover is optional for many adapters

    try:
        raw = adapter.collect(host, username=username, password=password,
                                key_filename=key_filename, port=port) or {}
    except Exception as e:
        _record(r, "collect", False, detail=f"{type(e).__name__}: {e}")
        return r
    _record(r, "collect_returns_nonempty", bool(raw),
             detail=f"got keys: {list(raw)[:5]}")

    try:
        produced = adapter.normalize(host, raw)
        produced_dict = (produced.__dict__
                          if hasattr(produced, "__dict__") else dict(produced))
    except Exception as e:
        _record(r, "normalize", False, detail=f"{type(e).__name__}: {e}")
        return r
    issues = _validate_unified_asset(produced_dict)
    _record(r, "normalize_unified_asset_shape", not issues,
             detail="; ".join(issues))
    return r


# --------------------------------------------------------------------------
# Production-adapter sweep
# --------------------------------------------------------------------------

def sweep_fixtures(fixture_root: Path | None = None) -> dict[str, ContractResult]:
    """Run every production adapter that has a fixture dir under
    fixture_root. Returns adapter_name → ContractResult."""
    from safecadence.adapter_manifest import PRODUCTION_ADAPTERS
    fixture_root = (fixture_root
                     or Path(__file__).resolve().parents[2]
                     / "tests" / "fixtures" / "adapters")
    out: dict[str, ContractResult] = {}
    for name in PRODUCTION_ADAPTERS:
        fdir = fixture_root / name
        if not fdir.exists():
            r = ContractResult(adapter=name)
            _record(r, "fixture_dir_exists", False,
                     detail="no fixtures captured yet")
            out[name] = r
            continue
        adapter = _load_adapter(name)
        if not adapter:
            r = ContractResult(adapter=name)
            _record(r, "adapter_loadable", False)
            out[name] = r
            continue
        out[name] = run_fixture(adapter, fdir, name=name)
    return out


def _load_adapter(name: str):
    """Best-effort import of a production adapter by its manifest key."""
    try:
        from safecadence.platform import adapters as _pkg     # noqa: F401
        from safecadence.platform.adapters import (
            cisco_network, arista_eos, juniper_junos,
            fortinet_fortigate, palo_alto_panos, aws_account,
            identity_adapters, dell_idrac,
        )
    except Exception:
        return None
    # Map manifest keys to importable classes. Production adapters only.
    # The Linux server adapter lives in src/safecadence/adapters/ (the
    # v2 path) so we route those separately.
    table = {
        "cisco_ios":     getattr(cisco_network, "CiscoNetworkAdapter", None),
        "cisco_nxos":    getattr(cisco_network, "CiscoNetworkAdapter", None),
        "cisco_asa":     getattr(cisco_network, "CiscoNetworkAdapter", None),
        "arista_eos":    getattr(arista_eos, "AristaEOSAdapter", None),
        "juniper_junos": getattr(juniper_junos, "JuniperJunosAdapter", None),
        "fortinet_fortigate": getattr(fortinet_fortigate,
                                         "FortinetFortiGateAdapter", None),
        "palo_alto_panos":    getattr(palo_alto_panos,
                                         "PaloAltoPanOSAdapter", None),
        "aws_account":   getattr(aws_account, "AWSAccountAdapter", None),
        "active_directory": getattr(identity_adapters,
                                      "ActiveDirectoryAdapter", None),
        "dell_idrac":    getattr(dell_idrac, "DellIDRACAdapter", None),
    }
    cls = table.get(name)
    if not cls:
        return None
    try:
        return cls()
    except Exception:
        return None
