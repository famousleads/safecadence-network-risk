"""
Cisco network device adapter — SSH-based via existing safecadence-netrisk engine.

Bridges the existing CLI-based config audit (safecadence scan / safecadence collect)
into the new platform UnifiedAsset format. Pulls the running-config + show
commands via SSH, runs them through the existing Cisco IOS / NX-OS / ASA
adapters, and normalizes the output.

Supports Cisco IOS, IOS-XE, NX-OS, ASA. Auto-detects which.
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    BaseAdapter, AdapterCapabilities, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.schema import (
    UnifiedAsset, AssetIdentity, Hardware, OperatingSystem, Interface, Security,
)
from safecadence.platform.health_scoring import score_asset_health


_SHOW_COMMANDS = [
    "show version",
    "show inventory",
    "show running-config",
    "show ip interface brief",
    "show interfaces",
    "show ip route",
    "show processes cpu sorted | exclude 0.00",
    "show processes memory sorted | exclude 0.00",
    "show environment all",
    "show platform",
    "show module",
    "show license summary",
]


@register_adapter("cisco_network")
class CiscoNetworkAdapter(BaseAdapter):
    capabilities = AdapterCapabilities(
        name="cisco_network",
        description="Cisco IOS / IOS-XE / NX-OS / ASA via SSH",
        vendor="cisco",
        asset_types=["network"],
        connection_types=[ConnectionType.SSH],
        required_credentials=["username", "password"],
        rate_limit_calls_per_minute=15,  # SSH is slow
        documentation_url="https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/configuration/15-mt/fundamentals-15-mt-book.html",
    )

    def __init__(self, target: str, credentials: dict[str, str], **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.username = credentials.get("username", "")
        self.password = credentials.get("password", "")
        self.enable_password = credentials.get("enable_password", "")

    def test_connection(self) -> dict:
        result = self.cm.ssh_run(self.target, "show clock",
                                 username=self.username, password=self.password)
        if result.get("ok"):
            return {"ok": True, "detail": result.get("stdout", "").strip()[:80]}
        return {"ok": False, "error": result.get("error") or result.get("stderr", "?")}

    def collect(self, asset_id: str) -> dict[str, Any]:
        """Run all show commands via SSH, return dict of {cmd: output}.

        v6.4.3: capture errors per command in `_errors` so an operator
        can see what failed instead of silently treating empty config
        as a clean device. Some commands legitimately fail on certain
        platforms (e.g. NX-OS doesn't have `show running-config`)
        which is why we still return an empty string, but the failure
        no longer disappears.
        """
        out: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for cmd in _SHOW_COMMANDS:
            r = self.cm.ssh_run(self.target, cmd,
                                username=self.username, password=self.password)
            if r.get("ok"):
                out[cmd] = r.get("stdout", "")
            else:
                out[cmd] = ""
                errors[cmd] = (r.get("error") or r.get("stderr")
                                or "ssh command failed")[:200]
        if errors:
            out["_errors"] = errors
        return out

    def normalize(self, asset_id: str, raw: dict) -> UnifiedAsset:
        """Hand off to existing adapter+engine for full audit, then map to UnifiedAsset."""
        from safecadence.core.registry import AdapterRegistry
        from safecadence.engines.config_audit import load_rules, run_audit

        running_config = raw.get("show running-config", "")
        show_version = raw.get("show version", "")

        # Detect adapter
        try:
            adapter_obj = AdapterRegistry.detect(running_config + "\n" + show_version)
            parsed = adapter_obj.parse(running_config)
        except Exception:
            parsed = None

        # Identity
        identity = AssetIdentity(
            asset_id=asset_id,
            vendor="Cisco",
            asset_type="network",
        )
        if parsed:
            identity.hostname = parsed.hostname or ""
            identity.product_family = parsed.os or ""
            identity.model = parsed.model or ""
        # Try to find serial number in show inventory
        inv = raw.get("show inventory", "")
        for line in inv.splitlines():
            if "SN:" in line:
                identity.serial_number = line.split("SN:")[1].strip().split()[0]
                break

        # Hardware (from show version + show inventory)
        hardware = Hardware()
        # Memory from show version (e.g. "8192K bytes of memory")
        import re
        m = re.search(r"([\d,]+)K bytes of memory", show_version)
        if m:
            hardware.memory_total_mb = int(m.group(1).replace(",", "")) // 1024

        # OS info
        os_obj = OperatingSystem()
        if parsed:
            os_obj.os_type = parsed.os or ""
            os_obj.os_version = parsed.version or ""
        # Uptime from show version
        m = re.search(r"uptime is (.+)", show_version)
        if m:
            os_obj.uptime_seconds = _parse_uptime_to_seconds(m.group(1))

        # Interfaces (basic — derive from show ip interface brief)
        interfaces = []
        ip_brief = raw.get("show ip interface brief", "")
        for line in ip_brief.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 5 and cols[0] != "Interface":
                interfaces.append(Interface(
                    name=cols[0],
                    ip_address=cols[1] if cols[1] != "unassigned" else "",
                    status=cols[4] if len(cols) > 4 else "",
                    protocol_status=cols[5] if len(cols) > 5 else "",
                ))

        # Security — run the existing 158-rule audit against the running-config
        security = Security()
        if parsed:
            try:
                rules = load_rules(vendor=parsed.os)
                findings = run_audit(parsed, rules)
                for f in findings:
                    sev = (f.severity or "").lower()
                    if sev == "critical":
                        security.critical_cves += 1
                    elif sev == "high":
                        security.high_cves += 1
                    security.findings.append(f"[{sev}] {f.title}")
                    if f.fix_snippet:
                        security.recommended_actions.append(f.fix_snippet[:200])
                # Detect weak protocols from config
                if "transport input telnet" in running_config:
                    security.weak_protocols.append("telnet")
                if "no service password-encryption" in running_config:
                    security.weak_protocols.append("cleartext-passwords")
            except Exception as e:
                security.findings.append(f"Audit engine error: {e}")

        asset = UnifiedAsset(
            identity=identity,
            hardware=hardware,
            os=os_obj,
            interfaces=interfaces,
            security=security,
            raw_collection=raw,
        )
        asset.health = score_asset_health(asset)
        return asset


def _parse_uptime_to_seconds(uptime_str: str) -> int:
    """Convert Cisco uptime string (e.g. '2 weeks, 3 days, 4 hours') to seconds."""
    import re
    total = 0
    for n, unit in re.findall(r"(\d+)\s*(year|week|day|hour|minute)s?", uptime_str):
        n = int(n)
        if unit == "year": total += n * 365 * 24 * 3600
        elif unit == "week": total += n * 7 * 24 * 3600
        elif unit == "day": total += n * 24 * 3600
        elif unit == "hour": total += n * 3600
        elif unit == "minute": total += n * 60
    return total
