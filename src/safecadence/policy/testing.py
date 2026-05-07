"""
Policy testing harness — unit-test policies against fixture asset states.

A test file is YAML:

    name: network_hardening_basic
    policy: tmpl_network_hardening      # template id OR a policy_id
    fixture:
      identity: {asset_id: r1, vendor: cisco, asset_type: network}
      os: {os_type: ios-xe}
      raw_collection:
        show_running-config: |
          line vty 0 4
           transport input ssh
          ip ssh version 2
    expect:
      pass: [enforce_ssh_v2]
      fail: [require_aaa, enable_syslog]
      na:   []

`run_test_file()` returns a list of test results — pass/fail + diffs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None

from safecadence.policy.evaluator import evaluate
from safecadence.policy.schema import EvaluationResult, SecurityPolicy
from safecadence.policy.store import get
from safecadence.policy.templates import load_template


def _resolve_policy(ref: str) -> SecurityPolicy | None:
    """Try template loader first, then store."""
    p = load_template(ref)
    if p:
        return p
    return get(ref)


def run_test_dict(spec: dict) -> dict[str, Any]:
    name = spec.get("name", "(unnamed)")
    pol = _resolve_policy(spec.get("policy", ""))
    if not pol:
        return {"name": name, "passed": False, "error": "policy not resolvable"}
    fixture = spec.get("fixture") or {}
    ev = evaluate(pol, [fixture])
    actual: dict[str, str] = {}
    if ev.asset_results:
        actual = ev.asset_results[0].get("controls", {})
    expect = spec.get("expect") or {}
    expected_pass = set(expect.get("pass") or [])
    expected_fail = set(expect.get("fail") or [])
    expected_na = set(expect.get("na") or [])

    actual_pass = {cid for cid, r in actual.items() if r == EvaluationResult.PASS.value}
    actual_fail = {cid for cid, r in actual.items() if r == EvaluationResult.FAIL.value}
    actual_na = {cid for cid, r in actual.items() if r == EvaluationResult.NOT_APPLICABLE.value}

    diffs = {
        "missing_pass": sorted(expected_pass - actual_pass),
        "unexpected_pass": sorted(actual_pass - expected_pass) if expected_pass else [],
        "missing_fail": sorted(expected_fail - actual_fail),
        "unexpected_fail": sorted(actual_fail - expected_fail) if expected_fail else [],
        "missing_na": sorted(expected_na - actual_na),
    }
    passed = (not diffs["missing_pass"] and not diffs["missing_fail"]
              and not diffs["missing_na"])
    return {"name": name, "passed": passed, "actual": actual, "diffs": diffs}


def run_test_file(path: str | Path) -> list[dict]:
    if not yaml:
        return [{"name": str(path), "passed": False, "error": "PyYAML required"}]
    p = Path(path)
    if not p.exists():
        return [{"name": str(path), "passed": False, "error": "file not found"}]
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if isinstance(raw, list):
        return [run_test_dict(s) for s in raw]
    return [run_test_dict(raw)]


def run_all_tests(dir_path: str | Path) -> list[dict]:
    p = Path(dir_path)
    out = []
    for f in sorted(p.glob("*.yaml")):
        out.extend(run_test_file(f))
    for f in sorted(p.glob("*.yml")):
        out.extend(run_test_file(f))
    return out
