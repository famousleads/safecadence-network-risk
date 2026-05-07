"""
SSH-based config collection for many devices.

Reads a YAML inventory:

    devices:
      - host: 10.10.10.1
        vendor: cisco-ios          # adapter slug
        username: netops
        password: env:DEVICE_PW    # or password: <literal> or key_file: ~/.ssh/id_rsa
        # optional:
        # port: 22
        # name: DC-CORE-01
        # command: show running-config

Then runs the right "show running-config" per vendor over SSH (paramiko)
in parallel and writes per-device .txt files into an output directory.
"""

from __future__ import annotations

import concurrent.futures
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml


# Vendor slug -> default "show full running-config" command
_DEFAULT_CMDS = {
    "cisco-ios":          "show running-config",
    "cisco-nxos":         "show running-config",
    "cisco-asa":          "show running-config",
    "aruba-cx":           "show running-config",
    "arista-eos":         "show running-config",
    "juniper-junos":      "show configuration | display set | no-more",
    "fortinet-fortigate": "show full-configuration",
    "palo-alto-panos":    "show config running",
}


@dataclass
class CollectResult:
    host: str
    name: str
    vendor: str
    bytes_received: int = 0
    duration_ms: int = 0
    output_path: str = ""
    error: str = ""


def _resolve_secret(value: str) -> str:
    """Allow `env:VARNAME` syntax for secrets pulled from environment."""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value or ""


def _import_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError as exc:
        raise RuntimeError(
            "SSH collection requires paramiko. Install with: "
            "pip install 'safecadence-network-risk[ssh]'"
        ) from exc


def _ssh_collect(device: dict, *, timeout: int = 30) -> CollectResult:
    started = time.perf_counter()
    host = device["host"]
    name = device.get("name") or host
    vendor = device.get("vendor", "cisco-ios")
    cmd = device.get("command") or _DEFAULT_CMDS.get(vendor, "show running-config")

    try:
        paramiko = _import_paramiko()
    except RuntimeError as exc:
        return CollectResult(host=host, name=name, vendor=vendor, error=str(exc))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        port = int(device.get("port", 22))
        username = device["username"]
        password = _resolve_secret(device.get("password", ""))
        key_file = device.get("key_file") or device.get("key_path")
        connect_kw = dict(hostname=host, port=port, username=username, timeout=timeout,
                          allow_agent=False, look_for_keys=False)
        if key_file:
            connect_kw["key_filename"] = os.path.expanduser(str(key_file))
        else:
            connect_kw["password"] = password
        client.connect(**connect_kw)

        # Use an interactive shell to pre-disable paging
        chan = client.invoke_shell()
        chan.settimeout(timeout)
        # Disable paging across all vendors
        for prelude in ("terminal length 0\n",      # cisco
                        "no page\n",                 # aruba CX
                        "set cli pager off\n",       # PAN-OS
                        "config\nset cli pager status disable\nend\n",  # forti
                        "set cli screen-length 0\n"):
            try:
                chan.send(prelude)
            except OSError:
                pass
        time.sleep(0.4)
        try:
            chan.recv(65535)
        except Exception:
            pass

        chan.send(cmd + "\n")
        time.sleep(2.0)
        out = b""
        idle_loops = 0
        while True:
            if chan.recv_ready():
                out += chan.recv(65535)
                idle_loops = 0
            else:
                idle_loops += 1
                if idle_loops > 6:
                    break
                time.sleep(0.4)

        text = out.decode("utf-8", errors="replace")
        return CollectResult(
            host=host, name=name, vendor=vendor,
            bytes_received=len(text),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )._with_text(text)
    except Exception as exc:
        return CollectResult(host=host, name=name, vendor=vendor, error=str(exc)[:200])
    finally:
        try:
            client.close()
        except Exception:
            pass


# ----- helpers ---------------------------------------------------- #
def _with_text(self, text: str):
    self._text = text
    return self
CollectResult._with_text = _with_text


def load_inventory(path: Path | str) -> list[dict]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "devices" not in raw:
        raise ValueError("Inventory must be a YAML mapping with a top-level 'devices:' key.")
    return list(raw["devices"])


def collect_all(
    inventory: list[dict],
    *,
    out_dir: Path | str,
    workers: int = 8,
    timeout: int = 30,
    progress_cb=None,
) -> list[CollectResult]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results: list[CollectResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_ssh_collect, d, timeout=timeout): d for d in inventory}
        for i, fut in enumerate(concurrent.futures.as_completed(futures)):
            r = fut.result()
            if not r.error and getattr(r, "_text", ""):
                fname = (r.name or r.host).replace("/", "_") + ".txt"
                target = out / fname
                target.write_text(r._text, encoding="utf-8")
                r.output_path = str(target)
            results.append(r)
            if progress_cb:
                progress_cb(i + 1, len(inventory), r)
    return results
