"""License manager + per-tenant resource quota enforcement.

Self-hosted-only — there is no SafeCadence cloud control plane in
this code. The license file lives at ``~/.safecadence/license.json``
or wherever ``SC_LICENSE_PATH`` points. We support:

  * Time-bounded licenses (``valid_from`` / ``valid_until``)
  * Asset-count limits (``max_assets``)
  * Per-tenant quotas (``tenants[name].max_assets``,
    ``tenants[name].max_jobs_per_day``)
  * Feature flags (``features: [tier3, sso, branded_reports, ...]``)
  * Optional Ed25519 signature verification — set
    ``SC_LICENSE_PUBKEY_PATH`` to a public key file. If unset, the
    license is honoured but flagged unsigned in /api/license/status
    so an operator running in production can spot it.

The point of this module is NOT to be a copy-protection moat (that's
unsolvable for self-hosted code an attacker can read). It's to give
the operator clean knobs for:

  * "we sold the customer 500 assets — alert if they exceed it"
  * "this MSP-hosted instance has tenant alpha at 100 assets and
     tenant bravo at 1000; enforce that boundary so a misconfigured
     adapter doesn't accidentally leak across"
  * "tier3 is a paid add-on; allow it only if the license includes it"

The check itself is a couple of dict lookups, no calls home, no
network.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class License:
    licensee: str = "unknown"
    issued_at: str = ""
    valid_from: str = ""
    valid_until: str = ""
    max_assets: int = 0       # 0 = unlimited
    features: list[str] = field(default_factory=list)
    tenants: dict[str, dict[str, Any]] = field(default_factory=dict)
    signature: str = ""       # Ed25519 of the canonicalised payload
    notes: str = ""


def _license_path() -> Path:
    return Path(os.environ.get("SC_LICENSE_PATH")
                or (Path.home() / ".safecadence" / "license.json"))


def _pubkey_path() -> Path | None:
    p = os.environ.get("SC_LICENSE_PUBKEY_PATH")
    return Path(p) if p else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(d: dict) -> License:
    return License(
        licensee=d.get("licensee", "unknown"),
        issued_at=d.get("issued_at", ""),
        valid_from=d.get("valid_from", ""),
        valid_until=d.get("valid_until", ""),
        max_assets=int(d.get("max_assets") or 0),
        features=list(d.get("features") or []),
        tenants=dict(d.get("tenants") or {}),
        signature=d.get("signature") or "",
        notes=d.get("notes", ""),
    )


def _free_tier() -> License:
    """No license file = open-source free tier with sensible caps."""
    return License(
        licensee="open-source",
        valid_from=_now().isoformat(),
        valid_until="",
        max_assets=200,
        features=["base", "policy", "drift", "exec_dry_run"],
        notes=("Free tier: 200 assets, no Tier3 SSH, single tenant. "
               "Ship a license.json to lift these caps."),
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def load_license() -> License:
    p = _license_path()
    if not p.exists():
        return _free_tier()
    try:
        return _parse(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return _free_tier()


def signature_valid(lic: License) -> bool | None:
    """Returns True / False / None.

    None means we have no public key configured — the license is
    honoured but the UI shows an "unsigned" flag so the operator
    knows. False means a key is configured AND the signature failed
    to verify, which we treat as a hard refusal.
    """
    pk_path = _pubkey_path()
    if not pk_path or not pk_path.exists():
        return None
    if not lic.signature:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        pubkey = serialization.load_pem_public_key(
            pk_path.read_bytes())
        # Canonical payload = JSON of lic minus signature
        d = lic.__dict__.copy()
        d.pop("signature", None)
        canon = json.dumps(d, sort_keys=True,
                            separators=(",", ":")).encode("utf-8")
        sig = bytes.fromhex(lic.signature)
        pubkey.verify(sig, canon)
        return True
    except Exception:
        return False


@dataclass
class LicenseStatus:
    licensee: str
    valid: bool
    expires_at: str
    days_remaining: int
    asset_count: int
    max_assets: int
    over_limit: bool
    features: list[str]
    tenants: dict[str, dict[str, Any]]
    signature_state: str         # "signed" / "unsigned" / "invalid"
    notes: str


def status(asset_count: int = 0) -> LicenseStatus:
    lic = load_license()
    now = _now()
    valid = True
    days_left = 0
    if lic.valid_until:
        try:
            until = datetime.fromisoformat(lic.valid_until.replace("Z", "+00:00"))
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            days_left = (until - now).days
            if days_left < 0:
                valid = False
        except Exception:
            valid = False
    sig = signature_valid(lic)
    sig_state = ("signed" if sig is True
                  else "invalid" if sig is False and _pubkey_path()
                  else "unsigned")
    if sig is False:
        valid = False
    return LicenseStatus(
        licensee=lic.licensee,
        valid=valid,
        expires_at=lic.valid_until or "(no expiry)",
        days_remaining=days_left,
        asset_count=asset_count,
        max_assets=lic.max_assets,
        over_limit=(lic.max_assets > 0 and asset_count > lic.max_assets),
        features=list(lic.features),
        tenants=dict(lic.tenants),
        signature_state=sig_state,
        notes=lic.notes,
    )


def feature_enabled(name: str) -> bool:
    return name in load_license().features


def tenant_quota(tenant: str) -> dict[str, Any]:
    return load_license().tenants.get(tenant, {})


def enforce_asset_quota(tenant: str, current: int) -> tuple[bool, str]:
    """Return (allowed, reason). Used by ingestion paths to refuse
    adding more assets to a tenant that's at its license cap."""
    lic = load_license()
    cap = (lic.tenants.get(tenant, {}).get("max_assets")
           or lic.max_assets or 0)
    if cap == 0:
        return True, ""
    if current >= cap:
        return False, (
            f"Tenant '{tenant}' is at its license cap "
            f"({current} of {cap} assets). Buy more seats or remove "
            "stale assets."
        )
    return True, ""


def require_feature(name: str) -> None:
    """Raise PermissionError if feature isn't licensed. Wire-in points
    are paths that gate paid features (Tier3, SSO, branded reports).
    Free-tier callers see a clean refusal with an upgrade hint."""
    if not feature_enabled(name):
        raise PermissionError(
            f"Feature '{name}' is not enabled by your license. "
            "If you have a license file, place it at "
            f"{_license_path()}. Free tier features: "
            f"{', '.join(load_license().features)}."
        )


# --------------------------------------------------------------------------
# Free evaluation trials (per-feature, one-time, auto-start)
#
# Some paid features ship with a built-in free trial so `pip install
# safecadence-netrisk` is enough to evaluate them on real data — no key,
# no signup, no call home. The trial stamp lives next to the license
# file. Same philosophy as the license itself: this is a clean knob for
# honest operators, not a copy-protection moat.
# --------------------------------------------------------------------------

TRIAL_FEATURES: dict[str, int] = {
    "public_safety": 90,     # days
}


def _trial_path() -> Path:
    return Path(os.environ.get("SC_TRIAL_PATH")
                or (Path.home() / ".safecadence" / "trials.json"))


def _read_trials() -> dict:
    p = _trial_path()
    if not p.exists():
        return {}
    try:
        return dict(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return {}


def _write_trials(data: dict) -> None:
    p = _trial_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass                                     # read-only FS: trial just
                                                 # won't persist; degrade soft


def trial_status(feature: str) -> dict[str, Any]:
    """{eligible, started, started_at, days_total, days_remaining, expired}"""
    days_total = TRIAL_FEATURES.get(feature, 0)
    rec = _read_trials().get(feature) or {}
    started_at = rec.get("started_at", "")
    out: dict[str, Any] = {
        "feature": feature,
        "eligible": days_total > 0,
        "started": bool(started_at),
        "started_at": started_at,
        "days_total": days_total,
        "days_remaining": 0,
        "expired": False,
    }
    if not started_at:
        return out
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        elapsed = (_now() - start).days
        remaining = days_total - elapsed
        out["days_remaining"] = max(0, remaining)
        out["expired"] = remaining <= 0
    except Exception:
        out["expired"] = True                    # unparseable stamp = over
    return out


def start_trial(feature: str) -> dict[str, Any]:
    """Idempotent: stamps the trial start on first call, no-op after."""
    if TRIAL_FEATURES.get(feature, 0) <= 0:
        return trial_status(feature)
    trials = _read_trials()
    if not (trials.get(feature) or {}).get("started_at"):
        trials[feature] = {"started_at": _now().isoformat()}
        _write_trials(trials)
    return trial_status(feature)


def feature_access(feature: str) -> dict[str, Any]:
    """The one call gates should use.

    mode: 'licensed' | 'trial' | 'expired' | 'unavailable'
    A trial auto-starts on first access so install→use just works.
    """
    if feature_enabled(feature):
        return {"mode": "licensed", "days_remaining": 0,
                "detail": "licensed"}
    if TRIAL_FEATURES.get(feature, 0) <= 0:
        return {"mode": "unavailable", "days_remaining": 0,
                "detail": "no license and no trial for this feature"}
    ts = start_trial(feature)                    # idempotent auto-start
    if ts["expired"]:
        return {"mode": "expired", "days_remaining": 0,
                "detail": f"free {ts['days_total']}-day trial ended "
                          f"{ts['started_at'][:10]} + {ts['days_total']}d"}
    return {"mode": "trial", "days_remaining": ts["days_remaining"],
            "detail": f"free trial - {ts['days_remaining']} of "
                      f"{ts['days_total']} days remaining"}
