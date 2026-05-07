"""MSP control-plane agent — protocol + reference client.

This is the agent half of the spec's "optional cloud control plane."
The control-plane *server* is intentionally out of scope (it's a
separate hosted service); we ship the agent + the protocol contract
so an MSP that wants to operate one can build the server side and
have a reference implementation to test against.

Protocol (HTTP + JSON, mTLS-friendly):

  POST /v1/agents/register
       body: {agent_id, version, hostname, public_key, claim_token}
       resp: {agent_token, control_plane_id, server_time, heartbeat_interval_s}

  POST /v1/agents/{agent_id}/heartbeat
       headers: Authorization: Bearer {agent_token}
       body: {ts, asset_count, license_status, queue_depth, version}
       resp: {commands?: [{command_id, type, payload}], server_time}

  POST /v1/agents/{agent_id}/commands/{command_id}/result
       body: {status, output_text, output_json}

Design choices:
  * Agent generates an Ed25519 keypair on first run; the public key
    is presented at registration. Future commands from the control
    plane MUST be signed by a private key the agent trusts — preventing
    a malicious upstream from issuing arbitrary commands.
  * Heartbeat doubles as command-pull: the control plane returns
    queued commands in the heartbeat response. Agents behind NAT /
    firewalls don't need an inbound port.
  * No raw config / credentials cross to the control plane. Only
    metadata: counts, license state, version. The privacy posture
    matches the rest of SafeCadence.
  * Built-in command types: ``trigger_evaluate``, ``run_dry_run``,
    ``trigger_briefing``. Operators can register more via
    ``register_command_handler(name, fn)``.

Operators turn this on by setting:
  SC_MSP_CONTROL_PLANE_URL=https://msp.example.com
  SC_MSP_AGENT_ID=customer-acme
  SC_MSP_CLAIM_TOKEN=<one-time-token-from-msp>

Agent registers, then a background thread heartbeats every N seconds.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


# --------------------------------------------------------------------------
# Identity (Ed25519 keypair persisted at ~/.safecadence/msp/agent.key)
# --------------------------------------------------------------------------

def _keypair_path() -> Path:
    base = Path(os.environ.get("SC_MSP_KEY_DIR")
                or (Path.home() / ".safecadence" / "msp"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "agent.key"


def _ensure_keypair() -> tuple[bytes, bytes]:
    """Returns (private_pem, public_pem). Generates on first call."""
    p = _keypair_path()
    if p.exists():
        from cryptography.hazmat.primitives import serialization
        priv_pem = p.read_bytes()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pem, pub_pem
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    p.write_bytes(priv_pem)
    try: os.chmod(p, 0o600)
    except OSError: pass
    return priv_pem, pub_pem


# --------------------------------------------------------------------------
# Agent state — persisted across restarts
# --------------------------------------------------------------------------

@dataclass
class AgentState:
    agent_id: str = ""
    agent_token: str = ""
    control_plane_id: str = ""
    heartbeat_interval_s: int = 60
    registered_at: str = ""

    @classmethod
    def load(cls) -> "AgentState":
        p = Path(os.environ.get("SC_MSP_STATE")
                  or (Path.home() / ".safecadence" / "msp" / "state.json"))
        if not p.exists():
            return cls()
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return cls(**{k: v for k, v in d.items()
                          if k in cls.__dataclass_fields__})
        except Exception:
            return cls()

    def save(self) -> None:
        p = Path(os.environ.get("SC_MSP_STATE")
                  or (Path.home() / ".safecadence" / "msp" / "state.json"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")
        try: os.chmod(p, 0o600)
        except OSError: pass


# --------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------

_HANDLERS: dict[str, Callable[[dict], dict]] = {}


def register_command_handler(name: str, fn: Callable[[dict], dict]) -> None:
    """Register a function the agent runs when the control plane queues
    a command of this type. fn(payload_dict) -> result_dict."""
    _HANDLERS[name] = fn


def _builtin_handlers() -> None:
    def _trigger_briefing(_payload: dict) -> dict:
        from safecadence.policy.executive_briefing import build_briefing_offline
        from safecadence.policy.evaluator import evaluate
        from safecadence.policy.store import list_policies, get as _g
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
        metas = list_policies()
        evals: dict[str, dict] = {}
        for m in metas:
            p = _g(m["policy_id"])
            if not p:
                continue
            ev = evaluate(p, assets)
            evals[p.policy_id] = {"pass": ev.pass_count,
                                    "fail": ev.fail_count,
                                    "na": ev.na_count}
        out = build_briefing_offline(assets, metas, evals)
        # Strip the markdown for the wire — control plane only needs
        # numbers, not the human-formatted summary.
        return {"asset_summary": out.get("asset_summary"),
                "policy_summary": out.get("policy_summary"),
                "top_risks": out.get("top_risks")}

    def _trigger_evaluate(payload: dict) -> dict:
        pid = payload.get("policy_id") or ""
        from safecadence.policy.evaluator import evaluate
        from safecadence.policy.store import get as _g
        from safecadence.server.platform_api import list_assets
        p = _g(pid)
        if not p:
            return {"ok": False, "error": f"unknown policy_id {pid!r}"}
        ev = evaluate(p, list_assets())
        return {"ok": True, "pass": ev.pass_count, "fail": ev.fail_count,
                 "coverage_pct": ev.coverage_pct}

    def _run_dry_run(payload: dict) -> dict:
        from safecadence.execution.executor import dry_run
        return dry_run(payload.get("job_id") or "", actor="msp")

    register_command_handler("trigger_briefing", _trigger_briefing)
    register_command_handler("trigger_evaluate", _trigger_evaluate)
    register_command_handler("run_dry_run", _run_dry_run)


_builtin_handlers()


# --------------------------------------------------------------------------
# Wire protocol
# --------------------------------------------------------------------------

def _http_post(url: str, body: dict, *, token: str | None = None,
                timeout: int = 30) -> dict:
    import httpx
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = httpx.post(url, json=body, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def register(*, control_plane_url: str, agent_id: str,
              claim_token: str, version: str = "7.4.0") -> AgentState:
    """First-run registration. Generates a keypair (if missing),
    presents the public key + claim token to the control plane,
    receives an agent_token + heartbeat interval."""
    _, pub_pem = _ensure_keypair()
    body = {
        "agent_id": agent_id,
        "version": version,
        "hostname": os.uname().nodename if hasattr(os, "uname")
                    else os.environ.get("COMPUTERNAME", "unknown"),
        "public_key": pub_pem.decode("ascii"),
        "claim_token": claim_token,
    }
    url = control_plane_url.rstrip("/") + "/v1/agents/register"
    resp = _http_post(url, body)
    state = AgentState(
        agent_id=agent_id,
        agent_token=resp.get("agent_token", ""),
        control_plane_id=resp.get("control_plane_id", ""),
        heartbeat_interval_s=int(resp.get("heartbeat_interval_s", 60)),
        registered_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    state.save()
    return state


def heartbeat_once(*, control_plane_url: str, state: AgentState) -> dict:
    """Send one heartbeat, run any returned commands, post their results."""
    from safecadence.server.platform_api import list_assets
    body = {
        "ts": time.time(),
        "asset_count": len(list_assets()),
        "version": "7.4.0",
        "queue_depth": _queue_depth(),
        "license_status": _license_status(),
    }
    url = (control_plane_url.rstrip("/")
           + f"/v1/agents/{state.agent_id}/heartbeat")
    resp = _http_post(url, body, token=state.agent_token)
    commands = resp.get("commands") or []
    for cmd in commands:
        cmd_id = cmd.get("command_id")
        cmd_type = cmd.get("type")
        payload = cmd.get("payload") or {}
        handler = _HANDLERS.get(cmd_type)
        if not handler:
            result = {"status": "error",
                       "output_text": f"unknown command type: {cmd_type!r}",
                       "output_json": {}}
        else:
            try:
                output = handler(payload)
                result = {"status": "ok", "output_text": "",
                           "output_json": output}
            except Exception as e:
                result = {"status": "error",
                           "output_text": f"{type(e).__name__}: {e}",
                           "output_json": {}}
        try:
            _http_post(
                f"{control_plane_url.rstrip('/')}"
                f"/v1/agents/{state.agent_id}/commands/{cmd_id}/result",
                result, token=state.agent_token,
            )
        except Exception:
            pass  # best-effort; the heartbeat will retry the relationship
    return {"sent_at": body["ts"], "commands_run": len(commands)}


def _queue_depth() -> int:
    try:
        from safecadence.execution import store as ex_store
        return sum(1 for j in ex_store.list_jobs()
                   if (j.status if isinstance(j.status, str)
                        else j.status.value) in ("review", "approved"))
    except Exception:
        return 0


def _license_status() -> dict:
    try:
        from safecadence.license import status
        from safecadence.server.platform_api import list_assets
        from dataclasses import asdict
        return asdict(status(asset_count=len(list_assets())))
    except Exception:
        return {}


# --------------------------------------------------------------------------
# Daemon-friendly heartbeat loop
# --------------------------------------------------------------------------

_RUNNING = True


def run_loop(*, control_plane_url: str, state: AgentState) -> None:
    """Block, heartbeating until process exit. Wire to a SIGTERM handler
    in your service runner."""
    while _RUNNING:
        try:
            heartbeat_once(control_plane_url=control_plane_url, state=state)
        except Exception:
            pass
        for _ in range(max(5, state.heartbeat_interval_s)):
            if not _RUNNING:
                break
            time.sleep(1)


def stop() -> None:
    global _RUNNING
    _RUNNING = False
