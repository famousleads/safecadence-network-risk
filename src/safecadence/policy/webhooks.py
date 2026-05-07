"""
Violation webhooks — fire HTTP POSTs on policy violations.

Targets are loaded from ~/.safecadence/policy_webhooks.yaml, looking
something like:

    - name: splunk
      url: https://splunk.local:8088/services/collector/event
      headers:
        Authorization: 'Splunk SECRET'
      severities: [critical, high]
    - name: slack
      url: https://hooks.slack.com/services/T000/B000/XXX
      severities: [critical]

Cross-platform: uses httpx if available, falls back to urllib.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None

from safecadence.policy.audit import log as audit_log
from safecadence.policy.schema import PolicyEvaluation, Severity


def _config_path() -> Path:
    return Path.home() / ".safecadence" / "policy_webhooks.yaml"


def load_targets() -> list[dict]:
    f = _config_path()
    if not f.exists() or not yaml:
        return []
    try:
        return yaml.safe_load(f.read_text(encoding="utf-8")) or []
    except Exception:
        return []


def _post(url: str, headers: dict[str, str], payload: dict, timeout: int = 8) -> tuple[bool, str]:
    body = json.dumps(payload, default=str).encode("utf-8")
    try:
        import httpx
        r = httpx.post(url, content=body, headers={**headers, "Content-Type": "application/json"},
                       timeout=timeout, verify=True)
        return 200 <= r.status_code < 300, f"{r.status_code}"
    except ImportError:
        pass
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300, str(r.status)
    except urllib.error.HTTPError as e:
        return False, str(e.code)
    except Exception as e:
        return False, str(e)


def fire_for_evaluation(evaluation: PolicyEvaluation, *, actor: str = "system") -> dict:
    """Send violations to every configured webhook honoring severity filters."""
    targets = load_targets()
    if not targets or not evaluation.violations:
        return {"sent": 0, "targets": len(targets)}
    sent = 0
    failures: list[str] = []
    for tgt in targets:
        sev_filter = [s.lower() for s in (tgt.get("severities") or [])]
        for v in evaluation.violations:
            sev = v.severity.value if isinstance(v.severity, Severity) else v.severity
            if sev_filter and sev.lower() not in sev_filter:
                continue
            ok, info = _post(
                tgt.get("url") or "",
                tgt.get("headers") or {},
                {"event": "policy.violation", "violation": v.serialize(),
                 "policy_id": evaluation.policy_id,
                 "evaluation_id": evaluation.evaluation_id},
            )
            sent += 1 if ok else 0
            if not ok:
                failures.append(f"{tgt.get('name', tgt.get('url'))}:{info}")
    audit_log("webhook_fired", actor=actor, policy_id=evaluation.policy_id,
              detail={"sent": sent, "failures": failures[:20]})
    return {"sent": sent, "failures": failures[:20], "targets": len(targets)}
