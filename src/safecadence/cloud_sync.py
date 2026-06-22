"""Optional Cloud Sync — send scan results to a SafeCadence Security Graph.

SafeCadence NetRisk is local-first and does NOT call home by default. This
module exists only so a user who *explicitly* runs `safecadence cloud connect`
can opt in to pushing their results to a SafeCadence Security Graph (for MSP
dashboards, cross-site rollups, and the 90-second briefing).

Guarantees that keep this honest:
  * OFF unless the user connects. No config file → nothing is ever sent.
  * The user provides a per-tenant token issued to THEIR organization; the cloud
    binds data to that org, so an install can't write to anyone else's.
  * Plain stdlib HTTP, HTTPS endpoint, no third-party deps, no telemetry.
  * `cloud disconnect` removes the config and stops all syncing.
  * Every push is best-effort: a cloud failure never breaks a local scan.

Config lives at ``~/.safecadence/cloud.json`` (or ``$SC_DATA_DIR``).
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path


def _config_dir() -> Path:
    base = os.environ.get("SC_DATA_DIR")
    return Path(base) if base else (Path.home() / ".safecadence")


def _config_path() -> Path:
    return _config_dir() / "cloud.json"


@dataclass
class CloudConfig:
    url: str           # the import endpoint
    token: str         # per-tenant bearer token (sgt_...)
    enabled: bool = True

    def to_dict(self) -> dict:
        return {"url": self.url, "token": self.token, "enabled": self.enabled}


def load_config() -> CloudConfig | None:
    p = _config_path()
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        if not d.get("url") or not d.get("token"):
            return None
        return CloudConfig(url=d["url"], token=d["token"],
                           enabled=bool(d.get("enabled", True)))
    except Exception:
        return None


def is_enabled() -> bool:
    c = load_config()
    return bool(c and c.enabled and c.url and c.token)


def connect(token: str, *, url: str) -> CloudConfig:
    """Opt in: save the endpoint + per-tenant token locally."""
    token = (token or "").strip()
    url = (url or "").strip()
    if not token.startswith("sgt_"):
        raise ValueError("Token must look like 'sgt_...'. Ask your SafeCadence "
                         "operator to issue one for your organization.")
    if not url.startswith("https://"):
        raise ValueError("Cloud Sync requires an https:// endpoint.")
    cfg = CloudConfig(url=url, token=token, enabled=True)
    d = _config_dir()
    d.mkdir(parents=True, exist_ok=True)
    _config_path().write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")
    try:
        os.chmod(_config_path(), 0o600)   # the token is a secret
    except Exception:
        pass
    return cfg


def disconnect() -> bool:
    """Opt out: delete the config so nothing is ever sent again."""
    p = _config_path()
    if p.exists():
        p.unlink()
        return True
    return False


def set_enabled(enabled: bool) -> bool:
    c = load_config()
    if not c:
        return False
    c.enabled = bool(enabled)
    _config_path().write_text(json.dumps(c.to_dict(), indent=2), encoding="utf-8")
    return True


def status() -> dict:
    c = load_config()
    if not c:
        return {"connected": False,
                "detail": "Local-first. Cloud Sync is OFF — nothing leaves this host."}
    masked = c.token[:8] + "…" + c.token[-4:] if len(c.token) > 14 else "set"
    return {"connected": True, "enabled": c.enabled, "url": c.url, "token": masked,
            "queued": queued_count(),
            "detail": "Scan results push to your SafeCadence Security Graph when "
                      "enabled. Run `cloud disconnect` to stop."}


def _queue_dir() -> Path:
    return _config_dir() / "cloud_queue"


def _enqueue(payload: object) -> None:
    """Persist a payload that couldn't be sent (offline) for a later retry."""
    try:
        d = _queue_dir()
        d.mkdir(parents=True, exist_ok=True)
        import time
        fp = d / f"{int(time.time()*1000)}-{os.getpid()}.json"
        fp.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass


def queued_count() -> int:
    d = _queue_dir()
    if not d.exists():
        return 0
    return len(list(d.glob("*.json")))


def _post(cfg: "CloudConfig", payload: object, timeout: int) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        cfg.url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg.token}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(4000)
    try:
        return {"sent": True, "response": json.loads(data.decode("utf-8"))}
    except Exception:
        return {"sent": True}


def flush_queue(*, timeout: int = 20) -> dict:
    """Retry every queued payload; delete each on success. No-op if disconnected."""
    c = load_config()
    if not (c and c.enabled and c.url and c.token):
        return {"flushed": 0, "remaining": queued_count(), "reason": "not connected"}
    d = _queue_dir()
    if not d.exists():
        return {"flushed": 0, "remaining": 0}
    flushed = 0
    for fp in sorted(d.glob("*.json")):
        try:
            payload = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            fp.unlink(missing_ok=True)   # corrupt entry — drop it
            continue
        try:
            _post(c, payload, timeout)
            fp.unlink(missing_ok=True)
            flushed += 1
        except Exception:
            break   # still offline — stop, keep the rest queued
    return {"flushed": flushed, "remaining": queued_count()}


def push(payload: object, *, timeout: int = 20, queue_on_fail: bool = True) -> dict:
    """POST one result (or a list/batch) to the Security Graph. No-op unless the
    user has connected. Best-effort — returns a result dict, never raises. On a
    network failure the payload is queued for a later `flush_queue()`/`cloud flush`."""
    c = load_config()
    if not (c and c.enabled and c.url and c.token):
        return {"sent": False, "reason": "not connected"}
    # Opportunistically drain anything queued from a previous offline run first.
    if queued_count():
        flush_queue(timeout=timeout)
    try:
        return _post(c, payload, timeout)
    except Exception as exc:
        if queue_on_fail:
            _enqueue(payload)
            return {"sent": False, "queued": True, "reason": str(exc)}
        return {"sent": False, "reason": str(exc)}


def push_scan_result(result, *, timeout: int = 20) -> dict:
    """Push one ScanResult (has .to_dict()). Used by the scan command hook."""
    if not is_enabled():
        return {"sent": False, "reason": "not connected"}
    try:
        payload = result.to_dict() if hasattr(result, "to_dict") else result
    except Exception as exc:
        return {"sent": False, "reason": f"serialize failed: {exc}"}
    return push(payload, timeout=timeout)
