"""SafeCadence i18n (v11.1).

Tiny, stdlib-only translation framework. There is intentionally **no**
``gettext`` dependency: the catalogs are plain JSON files in
``safecadence/i18n/catalogs/`` and lookups are O(1) dict gets.

Public API
----------

``t(key, lang=None, **vars)``
    Look up ``key`` in the active language catalog. Falls back to English
    if the key is missing or the language is unsupported. Supports
    ``str.format()``-style substitution via ``**vars`` — e.g.
    ``t("welcome", name="Ada")`` against ``"welcome": "Hi {name}"`` →
    ``"Hi Ada"``.

``set_lang(lang)`` / ``get_lang()`` / ``current_lang()``
    Thread-local active language. Default is ``"en"``.

``resolve_lang(query_lang, cookie_lang, accept_language)``
    Resolves the active language in priority order:
    query-string ``?lang=`` → cookie → ``Accept-Language`` header → ``"en"``.

``available_langs()``
    Returns the list of language codes for which a catalog exists.
"""

from __future__ import annotations

import json
import pathlib
import threading
from typing import Iterable, Optional


_CATALOG_DIR = pathlib.Path(__file__).resolve().parent / "catalogs"
_FALLBACK = "en"

_state = threading.local()
_catalogs: dict[str, dict[str, str]] = {}


# --------------------------------------------------------------------------
# catalog loading
# --------------------------------------------------------------------------


def _load_catalog(lang: str) -> dict[str, str]:
    path = _CATALOG_DIR / f"{lang}.json"
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:                          # pragma: no cover
        pass
    return {}


def _catalog(lang: str) -> dict[str, str]:
    """Return the cached catalog for ``lang`` (loading on first access)."""
    if lang not in _catalogs:
        _catalogs[lang] = _load_catalog(lang)
    return _catalogs[lang]


def available_langs() -> list[str]:
    """Return language codes for which a catalog file exists, sorted."""
    if not _CATALOG_DIR.exists():
        return [_FALLBACK]
    return sorted(p.stem for p in _CATALOG_DIR.glob("*.json"))


def reload_catalogs() -> None:
    """Drop the in-memory cache. Useful in tests."""
    _catalogs.clear()


# --------------------------------------------------------------------------
# thread-local active language
# --------------------------------------------------------------------------


def set_lang(lang: str) -> None:
    """Set the active language for this thread."""
    _state.lang = (lang or _FALLBACK).lower().split("-")[0]


def get_lang() -> str:
    """Return the active language for this thread (default: English)."""
    return getattr(_state, "lang", _FALLBACK)


# Alias for readability at call sites.
current_lang = get_lang


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------


def _split_accept_language(header: str) -> list[str]:
    """Parse an ``Accept-Language`` header and return language codes in
    priority order. Ignores q-values beyond ordering."""
    out: list[tuple[str, float]] = []
    for part in (header or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ";" in part:
            tag, _, q = part.partition(";")
            try:
                weight = float(q.replace("q=", "")) if q.startswith("q=") else 1.0
            except ValueError:
                weight = 1.0
        else:
            tag, weight = part, 1.0
        tag = tag.strip().lower().split("-")[0]
        if tag:
            out.append((tag, weight))
    out.sort(key=lambda x: -x[1])
    return [t for t, _ in out]


def resolve_lang(
    query_lang: Optional[str] = None,
    cookie_lang: Optional[str] = None,
    accept_language: Optional[str] = None,
) -> str:
    """Resolve the language to use for a given request.

    Priority:
      1. explicit query-string param (``?lang=fr``)
      2. cookie (``sc_lang``)
      3. ``Accept-Language`` header
      4. fallback ``"en"``
    """
    supported = set(available_langs())

    for cand in (query_lang, cookie_lang):
        if cand:
            code = cand.lower().split("-")[0]
            if code in supported:
                return code

    if accept_language:
        for code in _split_accept_language(accept_language):
            if code in supported:
                return code

    return _FALLBACK


# --------------------------------------------------------------------------
# t() — the lookup
# --------------------------------------------------------------------------


def t(key: str, lang: Optional[str] = None, **vars: object) -> str:
    """Translate ``key`` into the active (or explicit) language.

    Returns the English fallback when:
      * the requested language has no catalog file,
      * the catalog file is missing the key.

    If neither has the key, returns ``key`` itself so the UI never breaks.
    """
    active = (lang or get_lang() or _FALLBACK).lower().split("-")[0]
    value: Optional[str] = None

    cat = _catalog(active)
    if key in cat:
        value = cat[key]
    elif active != _FALLBACK:
        cat_en = _catalog(_FALLBACK)
        if key in cat_en:
            value = cat_en[key]

    if value is None:
        # Final fallback: return the key itself so the UI degrades gracefully.
        value = key

    if vars:
        try:
            return value.format(**vars)
        except (KeyError, IndexError, ValueError):     # pragma: no cover
            return value
    return value


__all__ = [
    "t",
    "set_lang",
    "get_lang",
    "current_lang",
    "resolve_lang",
    "available_langs",
    "reload_catalogs",
]
