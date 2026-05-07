"""
BaseAdapter — contract every vendor adapter implements.

A minimum viable adapter only needs to implement parse_config(). SSH/SNMP
collection is optional for v0.1 and lives behind feature flags so vendors
without active connections still work end-to-end.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from safecadence.core.schema import ParsedConfig


class BaseAdapter(ABC):
    """Inherit from this and register with @register_adapter."""

    #: Machine slug — must be unique. e.g. "cisco-ios", "aruba-cx", "arista-eos".
    slug: str = ""

    #: Human label shown to users. e.g. "Cisco IOS / IOS-XE".
    label: str = ""

    #: OS strings this adapter handles. Used for auto-detection. e.g. ["ios", "ios-xe"].
    os_family: list[str] = []

    #: Filename hints for vendor auto-detection.
    filename_hints: list[str] = []

    #: Substrings in the config text that hint this is the right adapter.
    content_hints: list[str] = []

    @classmethod
    @abstractmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        """Parse raw config text into a ParsedConfig. Required."""
        raise NotImplementedError

    @classmethod
    def detect(cls, text: str, filename: str = "") -> int:
        """
        Return a confidence score 0-100 for whether this adapter handles
        `text`. Default implementation does substring matching against
        content_hints and filename_hints. Adapters can override.
        """
        score = 0
        low_text = text[:8000].lower() if text else ""
        low_name = (filename or "").lower()
        for hint in cls.content_hints:
            if hint.lower() in low_text:
                score += 30
        for hint in cls.filename_hints:
            if hint.lower() in low_name:
                score += 15
        return min(score, 100)

    # ---- Optional capabilities (override to enable) ----

    @classmethod
    def supports_ssh(cls) -> bool:
        return False

    @classmethod
    def supports_snmp(cls) -> bool:
        return False

    @classmethod
    def collect_via_ssh(cls, host: str, username: str, password: str = "",
                        key_path: str = "", port: int = 22, timeout: int = 30) -> str:
        """Collect raw config via SSH. Optional — only if supports_ssh()."""
        raise NotImplementedError("This adapter does not implement SSH collection")

    # ---- Useful introspection helpers for the CLI ----

    @classmethod
    def info(cls) -> dict:
        return {
            "slug": cls.slug,
            "label": cls.label,
            "os_family": cls.os_family,
            "filename_hints": cls.filename_hints,
            "supports_ssh": cls.supports_ssh(),
            "supports_snmp": cls.supports_snmp(),
        }


def adapter_subclasses(base: type[BaseAdapter] = BaseAdapter) -> Iterable[type[BaseAdapter]]:
    """All concrete subclasses of BaseAdapter (recursive)."""
    seen: set[type] = set()
    queue = [base]
    while queue:
        cls = queue.pop(0)
        for sub in cls.__subclasses__():
            if sub not in seen:
                seen.add(sub)
                if not getattr(sub, "__abstractmethods__", None):
                    yield sub
                queue.append(sub)
