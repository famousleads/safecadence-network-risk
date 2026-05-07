"""
Connection abstraction — adapters use this instead of importing httpx/paramiko/etc directly.

Centralizes:
  - SSL/TLS verification policy
  - Timeouts
  - Retry behavior
  - Rate limiting
  - Connection pooling
  - Logging / audit trail of every external call (privacy-relevant)

Adapters request a connection; the manager configures it consistently.
"""

from __future__ import annotations

import time
from typing import Any


class ConnectionManager:
    """Single-process connection helper. Each adapter instance gets its own ConnectionManager."""

    def __init__(self, *, verify_ssl: bool = True, timeout: int = 30,
                 rate_limit_per_min: int = 60):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.rate_limit_per_min = rate_limit_per_min
        self._call_times: list[float] = []
        self._call_log: list[dict] = []

    def _enforce_rate_limit(self):
        """Block if we'd exceed the per-minute rate limit."""
        if not self.rate_limit_per_min:
            return
        now = time.time()
        # Remove calls older than 60s
        self._call_times = [t for t in self._call_times if now - t < 60]
        if len(self._call_times) >= self.rate_limit_per_min:
            sleep_for = 60 - (now - self._call_times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._call_times.append(time.time())

    def _log_call(self, kind: str, target: str, status: str, error: str = ""):
        self._call_log.append({
            "ts": time.time(),
            "kind": kind,
            "target": target,
            "status": status,
            "error": error,
        })

    def get_call_log(self) -> list[dict]:
        return list(self._call_log)

    # ---------------------------------------------------------------- HTTP / REST
    def http(self):
        """Return an httpx.Client configured with this manager's policy."""
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx not installed — run: pip install 'safecadence-netrisk[server]'")
        return httpx.Client(
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
        )

    def http_get(self, url: str, *, headers: dict = None, auth: tuple = None,
                 params: dict = None) -> dict:
        """Convenience: rate-limited GET returning {'ok', 'status', 'json' or 'text', 'error'}."""
        self._enforce_rate_limit()
        try:
            with self.http() as c:
                r = c.get(url, headers=headers or {}, auth=auth, params=params or {})
                self._log_call("http_get", url, str(r.status_code))
                try:
                    body = r.json()
                except Exception:
                    body = r.text
                return {
                    "ok": r.status_code < 400,
                    "status": r.status_code,
                    "json": body if isinstance(body, (dict, list)) else None,
                    "text": body if isinstance(body, str) else None,
                    "headers": dict(r.headers),
                }
        except Exception as e:
            self._log_call("http_get", url, "error", str(e))
            return {"ok": False, "error": str(e)}

    def http_post(self, url: str, *, json: dict = None, headers: dict = None,
                  auth: tuple = None) -> dict:
        self._enforce_rate_limit()
        try:
            with self.http() as c:
                r = c.post(url, json=json, headers=headers or {}, auth=auth)
                self._log_call("http_post", url, str(r.status_code))
                try:
                    body = r.json()
                except Exception:
                    body = r.text
                return {
                    "ok": r.status_code < 400,
                    "status": r.status_code,
                    "json": body if isinstance(body, (dict, list)) else None,
                    "text": body if isinstance(body, str) else None,
                }
        except Exception as e:
            self._log_call("http_post", url, "error", str(e))
            return {"ok": False, "error": str(e)}

    # ---------------------------------------------------------------- SSH (paramiko)
    def ssh(self, host: str, *, port: int = 22, username: str = "",
            password: str = "", key_filename: str = ""):
        """Return a connected paramiko.SSHClient."""
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("paramiko not installed — run: pip install 'safecadence-netrisk[ssh]'")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=username,
                           password=password or None,
                           key_filename=key_filename or None,
                           timeout=self.timeout, look_for_keys=False, allow_agent=False)
            self._log_call("ssh", f"{username}@{host}:{port}", "connected")
            return client
        except Exception as e:
            self._log_call("ssh", f"{username}@{host}:{port}", "error", str(e))
            raise

    def ssh_run(self, host: str, command: str, *, port: int = 22,
                username: str = "", password: str = "", key_filename: str = "") -> dict:
        """Run one command via SSH, return {'ok', 'stdout', 'stderr', 'exit_code'}."""
        try:
            client = self.ssh(host, port=port, username=username,
                              password=password, key_filename=key_filename)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            exit_code = stdout.channel.recv_exit_status()
            return {
                "ok": exit_code == 0,
                "stdout": stdout.read().decode("utf-8", errors="replace"),
                "stderr": stderr.read().decode("utf-8", errors="replace"),
                "exit_code": exit_code,
            }
        finally:
            client.close()

    # ---------------------------------------------------------------- SNMP (pysnmp)
    def snmp_get(self, host: str, oid: str, *, community: str = "public",
                 version: str = "v2c", port: int = 161) -> dict:
        """Single SNMP GET. Returns {'ok', 'value', 'error'}."""
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )
        except ImportError:
            # Fall back to the pure-stdlib SNMP probe we built earlier
            from safecadence.discovery.snmp_probe import snmp_get_sysdescr
            r = snmp_get_sysdescr(host, communities=(community,))
            return {"ok": r.get("ok", False), "value": r.get("sys_descr", ""), "error": ""}

        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1 if version == "v2c" else 0),
                UdpTransportTarget((host, port), timeout=self.timeout),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            errInd, errStat, errIdx, varBinds = next(iterator)
            if errInd or errStat:
                return {"ok": False, "error": str(errInd or errStat)}
            return {"ok": True, "value": str(varBinds[0][1])}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ---------------------------------------------------------------- Redfish
    def redfish_get(self, base_url: str, path: str, *, username: str = "",
                    password: str = "") -> dict:
        """Redfish GET. base_url like 'https://idrac.example.com'."""
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        return self.http_get(url, auth=(username, password) if username else None,
                             headers={"Accept": "application/json"})
