"""Asset Groups — the primitive that lets a policy say "apply to these
specific 17 devices, not the whole fleet."

Without groups, every policy runs against every asset. That's fine for
toy fleets, useless for the 200-2000 device shops we're actually
trying to win. Groups give the operator a way to say:

  * "All Cisco edge routers in the East-coast datacenter"  (dynamic)
  * "Exactly these 17 PCI-scope assets and nothing else"   (static)
  * "Crown-jewels MINUS anything currently in maintenance" (composed)

A group is a tiny dataclass: name, description, and either a static
list of asset_ids OR a filter dict. Groups are CRUDed through
``/api/platform/asset-groups`` and stored as JSON files alongside
the asset store, so they survive restarts and are git-able.

Design choices:
  * No SQL dependency — file-backed JSON store, same pattern as the
    policy store. Works in air-gapped + containerised deployments.
  * Filter language is deliberately small (field/op/value). Anyone
    introducing a new operator must update ``EVALUABLE_OPS`` AND
    ``_match`` in the same commit, so the surface stays auditable.
  * Empty filter / empty list = matches nothing, never the whole fleet.
    Operators have been bitten too many times by the inverse default.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# --------------------------------------------------------------------------
# Filter language — kept small on purpose
# --------------------------------------------------------------------------

EVALUABLE_OPS = {
    "eq",          # exact (case-insensitive on strings)
    "neq",
    "in",          # value is one of [...]
    "not_in",
    "contains",    # value is a substring (case-insensitive)
    "starts_with",
    "ends_with",
    "has_tag",     # asset has this tag
    "missing_tag", # asset does NOT have this tag
    "exists",      # field exists and is truthy
}


# Fields a clause can target. Anything outside this allow-list is rejected.
# We dot-walk into the asset dict; identity.* and security.* are first-class.
EVALUABLE_FIELDS = {
    "asset_id", "asset_type", "vendor", "hostname", "criticality",
    "site", "environment", "model",
    "identity.asset_id", "identity.asset_type", "identity.vendor",
    "identity.hostname", "identity.criticality", "identity.site",
    "identity.environment", "identity.model",
    "security.kev_cves", "security.critical_cves", "security.high_cves",
    "lifecycle.days_until_eos",
    "health.grade",
    "tags",  # list-valued field, used with has_tag / missing_tag
    "cloud.account_id", "cloud.subscription_id", "cloud.public_exposure",
    "network.public_ip", "network.internet_facing", "network.zone",
    "identity_block.provider", "identity_block.mfa_enrolled",
}


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

@dataclass
class AssetGroup:
    """A named selection of assets — static, dynamic, or composed.

    Exactly one of ``asset_ids`` (static) or ``filter`` (dynamic) is
    expected to be populated. ``exclude_asset_ids`` lets the operator
    carve specific exceptions out of either form ("crown-jewels minus
    these three under maintenance").
    """

    group_id: str = ""
    name: str = ""
    description: str = ""
    # Static: hand-picked asset_ids
    asset_ids: list[str] = field(default_factory=list)
    # Dynamic: filter spec like {"all": [{"field":..., "op":..., "value":...}]}
    filter: dict[str, Any] = field(default_factory=dict)
    # Composed: explicit exclusions applied to either form
    exclude_asset_ids: list[str] = field(default_factory=list)
    tenant: str = "local"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""

    def is_static(self) -> bool:
        return bool(self.asset_ids) and not self.filter

    def is_dynamic(self) -> bool:
        return bool(self.filter)


# --------------------------------------------------------------------------
# Filter evaluation
# --------------------------------------------------------------------------

def _get_field(asset: dict, field_name: str) -> Any:
    """Dot-walk into the asset dict — supports identity.vendor, etc."""
    if "." not in field_name:
        # Flat lookup — try top-level, then identity, then security.
        if field_name in asset:
            return asset.get(field_name)
        ident = asset.get("identity") or {}
        if field_name in ident:
            return ident.get(field_name)
        return None
    parts = field_name.split(".")
    cur: Any = asset
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _norm(v: Any) -> Any:
    """Lower-case strings for case-insensitive comparison; pass through everything else."""
    if isinstance(v, str):
        return v.lower()
    return v


def _match_clause(asset: dict, clause: dict) -> bool:
    """Evaluate a single {field, op, value} clause."""
    f = clause.get("field", "")
    op = clause.get("op", "")
    v = clause.get("value")
    if op not in EVALUABLE_OPS:
        return False
    if f not in EVALUABLE_FIELDS:
        return False
    actual = _get_field(asset, f)
    if op == "exists":
        return bool(actual)
    if op == "has_tag":
        return v in (asset.get("tags") or [])
    if op == "missing_tag":
        return v not in (asset.get("tags") or [])
    if op == "eq":
        return _norm(actual) == _norm(v)
    if op == "neq":
        return _norm(actual) != _norm(v)
    if op == "in":
        if not isinstance(v, list):
            return False
        return _norm(actual) in [_norm(x) for x in v]
    if op == "not_in":
        if not isinstance(v, list):
            return False
        return _norm(actual) not in [_norm(x) for x in v]
    if op == "contains" and isinstance(actual, str):
        return _norm(v) in _norm(actual)
    if op == "starts_with" and isinstance(actual, str):
        return _norm(actual).startswith(_norm(v))
    if op == "ends_with" and isinstance(actual, str):
        return _norm(actual).endswith(_norm(v))
    return False


def _match_filter(asset: dict, spec: dict) -> bool:
    """Evaluate a filter spec. Supports {all:[...]}, {any:[...]}, {not:{...}}.

    Recursive — but bounded by the filter document size, which is
    bounded by the API payload size, which is capped upstream.
    """
    if not spec:
        return False
    if "all" in spec:
        clauses = spec.get("all") or []
        if not clauses:
            return False
        return all(_match_clause_or_group(asset, c) for c in clauses)
    if "any" in spec:
        clauses = spec.get("any") or []
        if not clauses:
            return False
        return any(_match_clause_or_group(asset, c) for c in clauses)
    if "not" in spec:
        sub = spec.get("not") or {}
        return not _match_clause_or_group(asset, sub)
    if "field" in spec and "op" in spec:
        return _match_clause(asset, spec)
    return False


def _match_clause_or_group(asset: dict, item: dict) -> bool:
    if "all" in item or "any" in item or "not" in item:
        return _match_filter(asset, item)
    return _match_clause(asset, item)


def resolve_members(group: AssetGroup, all_assets: list[dict]) -> list[dict]:
    """Return the list of assets that currently belong to this group."""
    excluded = set(group.exclude_asset_ids or [])
    if group.is_static():
        target_ids = set(group.asset_ids) - excluded
        return [a for a in all_assets
                if (a.get("identity") or {}).get("asset_id") in target_ids]
    if group.is_dynamic():
        out: list[dict] = []
        for a in all_assets:
            if not _match_filter(a, group.filter):
                continue
            aid = (a.get("identity") or {}).get("asset_id")
            if aid in excluded:
                continue
            out.append(a)
        return out
    return []


# --------------------------------------------------------------------------
# Validation — refuses obviously broken specs early
# --------------------------------------------------------------------------

_GROUP_ID_RE = re.compile(r"^[A-Za-z0-9._\-:@]+$")


def validate_group(group: AssetGroup) -> list[str]:
    """Return a list of human-readable validation errors. Empty = OK."""
    errs: list[str] = []
    if not group.group_id:
        errs.append("group_id is required")
    elif not _GROUP_ID_RE.match(group.group_id) or ".." in group.group_id:
        errs.append("group_id contains illegal characters")
    elif len(group.group_id) > 128:
        errs.append("group_id is too long (max 128 chars)")
    if not group.name:
        errs.append("name is required")
    if group.asset_ids and group.filter:
        errs.append("a group is either static (asset_ids) OR "
                    "dynamic (filter) — not both")
    if group.filter:
        errs.extend(_validate_filter(group.filter, depth=0))
    return errs


def _validate_filter(spec: dict, *, depth: int) -> list[str]:
    if depth > 5:
        return ["filter is nested too deeply (max 5 levels)"]
    if not isinstance(spec, dict):
        return ["filter must be a dict"]
    if "all" in spec or "any" in spec:
        clauses = spec.get("all") or spec.get("any") or []
        if not isinstance(clauses, list) or not clauses:
            return [f"{'all' if 'all' in spec else 'any'} requires a non-empty list"]
        out: list[str] = []
        for c in clauses:
            out.extend(_validate_filter(c, depth=depth + 1))
        return out
    if "not" in spec:
        return _validate_filter(spec.get("not") or {}, depth=depth + 1)
    if "field" in spec and "op" in spec:
        out = []
        if spec["field"] not in EVALUABLE_FIELDS:
            out.append(f"unknown field '{spec['field']}'")
        if spec["op"] not in EVALUABLE_OPS:
            out.append(f"unknown op '{spec['op']}'")
        return out
    return ["filter clause must have field+op or be all/any/not"]


# --------------------------------------------------------------------------
# JSON-file store (mirrors the policy store pattern)
# --------------------------------------------------------------------------

def _store_dir() -> Path:
    base = Path(os.environ.get("SC_ASSET_GROUPS_STORE")
                or (Path.home() / ".safecadence" / "asset_groups"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def _safe_path(group_id: str) -> Path:
    if not _GROUP_ID_RE.match(group_id) or ".." in group_id:
        raise ValueError("group_id contains illegal characters")
    base = _store_dir().resolve()
    target = (base / f"{group_id}.json").resolve()
    try:
        target.relative_to(base)
    except ValueError as e:
        raise ValueError("group_id escapes store directory") from e
    return target


def save(group: AssetGroup) -> AssetGroup:
    errs = validate_group(group)
    if errs:
        raise ValueError("; ".join(errs))
    group.updated_at = datetime.now(timezone.utc).isoformat()
    p = _safe_path(group.group_id)
    p.write_text(json.dumps(asdict(group), indent=2, default=str),
                  encoding="utf-8")
    return group


def get(group_id: str) -> AssetGroup | None:
    try:
        p = _safe_path(group_id)
    except ValueError:
        return None
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return AssetGroup(**d)
    except Exception:
        return None


def list_groups() -> list[AssetGroup]:
    out: list[AssetGroup] = []
    for f in _store_dir().glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            out.append(AssetGroup(**d))
        except Exception:
            continue
    return sorted(out, key=lambda g: g.name.lower())


def delete(group_id: str) -> bool:
    try:
        p = _safe_path(group_id)
    except ValueError:
        return False
    if p.exists():
        try:
            p.unlink()
            return True
        except OSError:
            return False
    return False


# --------------------------------------------------------------------------
# Convenience — resolve a list of group_ids → unique asset_ids
# --------------------------------------------------------------------------

def asset_ids_in_groups(group_ids: Iterable[str],
                        all_assets: list[dict]) -> set[str]:
    """Union the membership of every named group. Used by the policy
    evaluator to decide whether a given asset is in scope."""
    out: set[str] = set()
    for gid in group_ids or []:
        g = get(gid)
        if not g:
            continue
        for a in resolve_members(g, all_assets):
            aid = (a.get("identity") or {}).get("asset_id")
            if aid:
                out.add(aid)
    return out
