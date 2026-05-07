"""
v9.26 — posture evaluator.

Loads ``data/posture_controls.yaml`` and runs each control against an
asset dict. Returns the list of controls satisfied + the points
earned, capped at the global posture cap (default +20).

Why this is a YAML pack and not Python:
  * No code execution per check — safer in a security tool.
  * Operators can extend the pack without touching the codebase.
  * Same shape as our existing policy controls, so ops people
    already know how to read it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


_POSTURE_CAP_DEFAULT = 20


@dataclass
class PostureControl:
    """One declarative check loaded from the YAML pack."""
    id: str
    category: str
    applies_to: list[str]
    weight: int
    description: str
    source_hint: str
    check: dict


@dataclass
class PostureResult:
    """Per-asset posture credit + breakdown for the cockpit."""
    asset_id: str
    credit: int
    cap: int
    earned: list[dict] = field(default_factory=list)
    eligible: list[dict] = field(default_factory=list)
    not_satisfied: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "credit": self.credit,
            "cap": self.cap,
            "earned": self.earned,
            "eligible": self.eligible,
            "not_satisfied": self.not_satisfied,
        }


# ---------------------------------------------------------- pack loader


_PACK_CACHE: list[PostureControl] | None = None
_PACK_PATH: Path | None = None


def _default_pack_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "posture_controls.yaml"


def load_pack(path: Path | None = None,
                force_reload: bool = False) -> list[PostureControl]:
    """Load (and cache) the posture controls YAML pack."""
    global _PACK_CACHE, _PACK_PATH
    target = path or _default_pack_path()
    if (not force_reload and _PACK_CACHE is not None
            and _PACK_PATH == target):
        return _PACK_CACHE
    try:
        import yaml
    except ImportError:                                     # pragma: no cover
        return []
    if not target.exists():
        _PACK_CACHE = []
        _PACK_PATH = target
        return _PACK_CACHE
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or []
    out: list[PostureControl] = []
    for entry in raw:
        try:
            out.append(PostureControl(
                id=entry["id"],
                category=entry.get("category", "general"),
                applies_to=list(entry.get("applies_to") or ["*"]),
                weight=int(entry.get("weight", 1)),
                description=entry.get("description", entry["id"]),
                source_hint=entry.get("source_hint", ""),
                check=dict(entry.get("check") or {}),
            ))
        except KeyError:
            continue
    _PACK_CACHE = out
    _PACK_PATH = target
    return out


# ---------------------------------------------------------- evaluation


def _get_field(asset: dict, dotted: str) -> Any:
    """Traverse a dotted path. Returns None if any segment is missing."""
    cur: Any = asset
    for part in (dotted or "").split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def _normalize(v: Any) -> Any:
    """Lowercase strings for case-insensitive compares."""
    if isinstance(v, str):
        return v.strip().lower()
    return v


def _matches(check: dict, asset: dict) -> bool:
    """Run a single declarative check against an asset."""
    field_path = check.get("field")
    if not field_path:
        return False
    op = (check.get("op") or "eq").lower()
    actual = _get_field(asset, field_path)
    expected = check.get("value")

    if op == "truthy":
        return bool(actual)
    if op == "eq":
        return _normalize(actual) == _normalize(expected)
    if op == "ne":
        return _normalize(actual) != _normalize(expected)
    if op == "in":
        if not isinstance(expected, (list, tuple, set)):
            return False
        a = _normalize(actual)
        return any(a == _normalize(v) for v in expected)
    if op == "not_in":
        if not isinstance(expected, (list, tuple, set)):
            return True
        a = _normalize(actual)
        return all(a != _normalize(v) for v in expected)
    if op == "gte":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False
    if op == "regex":
        try:
            return bool(re.search(str(expected), str(actual or "")))
        except re.error:
            return False
    return False


def _applies(control: PostureControl, asset: dict) -> bool:
    """Does this control even apply to this asset's type?"""
    if "*" in control.applies_to:
        return True
    ident = asset.get("identity") or {}
    asset_type = (ident.get("asset_type") or "").lower()
    targets = {t.lower() for t in control.applies_to}
    return asset_type in targets or "*" in targets


def evaluate_asset(asset: dict, *,
                    pack: Optional[Iterable[PostureControl]] = None,
                    cap: int = _POSTURE_CAP_DEFAULT) -> PostureResult:
    """Evaluate posture controls against one asset.

    Returns a :class:`PostureResult` capturing:
      * earned        — controls satisfied + their weights
      * not_satisfied — controls that applied but failed
      * eligible      — total controls that applied
      * credit        — sum of earned weights, capped at ``cap``

    Controls that don't apply (wrong asset type, missing field) do
    NOT count as failures — they're simply skipped. We don't penalize
    a router for not having BitLocker.
    """
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ident.get("hostname") or ""
    pack = list(pack) if pack is not None else load_pack()

    earned: list[dict] = []
    not_sat: list[dict] = []
    eligible: list[dict] = []
    raw_credit = 0

    for c in pack:
        if not _applies(c, asset):
            continue
        eligible.append({"id": c.id, "weight": c.weight,
                          "category": c.category,
                          "description": c.description})
        if _matches(c.check, asset):
            earned.append({"id": c.id, "weight": c.weight,
                            "category": c.category,
                            "description": c.description})
            raw_credit += c.weight
        else:
            not_sat.append({"id": c.id, "weight": c.weight,
                              "category": c.category,
                              "description": c.description,
                              "source_hint": c.source_hint})

    credit = min(cap, raw_credit)
    return PostureResult(
        asset_id=aid, credit=credit, cap=cap,
        earned=earned, eligible=eligible, not_satisfied=not_sat,
    )
