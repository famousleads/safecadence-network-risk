"""Adapter registry — global lookup keyed by slug."""

from __future__ import annotations

import importlib
import pkgutil
import threading
from typing import Type

from safecadence.core.adapter import BaseAdapter


class AdapterRegistry:
    _adapters: dict[str, Type[BaseAdapter]] = {}
    _load_lock = threading.RLock()

    @classmethod
    def register(cls, adapter: Type[BaseAdapter]) -> Type[BaseAdapter]:
        if not adapter.slug:
            raise ValueError(f"{adapter.__name__} has no .slug")
        if adapter.slug in cls._adapters:
            # Allow re-registration (during reloading); same module path = ok
            existing = cls._adapters[adapter.slug]
            if existing.__module__ != adapter.__module__:
                raise ValueError(
                    f"adapter slug '{adapter.slug}' already registered by {existing.__module__}"
                )
        cls._adapters[adapter.slug] = adapter
        return adapter

    @classmethod
    def get(cls, slug: str) -> Type[BaseAdapter] | None:
        cls._ensure_loaded()
        return cls._adapters.get(slug)

    @classmethod
    def all(cls) -> list[Type[BaseAdapter]]:
        cls._ensure_loaded()
        return list(cls._adapters.values())

    @classmethod
    def detect(cls, text: str, filename: str = "") -> Type[BaseAdapter] | None:
        """Return the highest-confidence adapter for the given text."""
        cls._ensure_loaded()
        best: tuple[int, Type[BaseAdapter]] | None = None
        for adapter in cls._adapters.values():
            score = adapter.detect(text, filename)
            if score > 0 and (best is None or score > best[0]):
                best = (score, adapter)
        return best[1] if best else None

    @classmethod
    def _ensure_loaded(cls) -> None:
        """Lazily import every package under safecadence.adapters so that
        decorator-style registration runs. Thread-safe via _load_lock."""
        if getattr(cls, "_loaded", False):
            return
        with cls._load_lock:
            # Double-check inside the lock (another thread might have loaded it)
            if getattr(cls, "_loaded", False):
                return
            try:
                from safecadence import adapters as adapters_pkg
            except ImportError:
                cls._loaded = True
                return
            for _finder, name, _ispkg in pkgutil.iter_modules(adapters_pkg.__path__):
                try:
                    importlib.import_module(f"safecadence.adapters.{name}")
                except Exception as exc:   # pragma: no cover
                    import sys
                    print(f"[adapter-load-warn] {name}: {exc}", file=sys.stderr)
            # Set _loaded ONLY after every adapter has been imported
            cls._loaded = True


def register_adapter(adapter: Type[BaseAdapter]) -> Type[BaseAdapter]:
    """Decorator for adapter modules."""
    return AdapterRegistry.register(adapter)


def get_adapter(slug: str) -> Type[BaseAdapter] | None:
    return AdapterRegistry.get(slug)
