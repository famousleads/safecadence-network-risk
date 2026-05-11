"""SLA-aware remediation policy.

A finding's priority (P0..P3) implies an SLA window — the number of days
allowed between discovery (today, for the purposes of the report) and the
target remediation date. KEV-listed findings can shift priorities upward via
a configurable uplift (default: KEV findings always use the P0 SLA, regardless
of their priority class).

The policy is read from ``~/.safecadence/sla_policy.yaml`` when present, with
sane defaults baked in. Shape:

.. code-block:: yaml

    sla_days:
      P0: 14
      P1: 30
      P2: 60
      P3: 90
    kev_uplift_days: 0       # 0 = force KEV to immediate-priority SLA
    immediate_priority: "P0"  # which SLA bucket KEV findings should land in
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path


DEFAULT_SLA: dict = {
    "P0": 14,
    "P1": 30,
    "P2": 60,
    "P3": 90,
    "kev_uplift_days": 0,        # 0 means: KEV jumps to immediate-priority SLA
    "immediate_priority": "P0",  # which bucket KEV findings should use
}

DEFAULT_PATH = "~/.safecadence/sla_policy.yaml"


def _default_path() -> Path:
    return Path(os.path.expanduser(DEFAULT_PATH))


def load_sla_policy(path: str | None = None) -> dict:
    """Load the SLA policy from YAML, falling back to :data:`DEFAULT_SLA`.

    Unknown keys are preserved (forward-compatible). Missing keys are
    back-filled from ``DEFAULT_SLA``.
    """
    p = Path(path) if path else _default_path()
    merged: dict = dict(DEFAULT_SLA)
    if not p.exists():
        return merged
    try:
        import yaml
    except Exception:
        return merged
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return merged
    if not isinstance(doc, dict):
        return merged

    # Allow either flat shape (DEFAULT_SLA-like) or nested under 'sla_days'.
    flat = {}
    sla_days = doc.get("sla_days")
    if isinstance(sla_days, dict):
        flat.update({k: v for k, v in sla_days.items()
                     if k in ("P0", "P1", "P2", "P3")})
    for k in ("P0", "P1", "P2", "P3", "kev_uplift_days", "immediate_priority"):
        if k in doc:
            flat[k] = doc[k]
    merged.update(flat)
    return merged


def _today() -> _dt.date:
    return _dt.date.today()


def compute_due_date(
    priority: str,
    *,
    kev: bool = False,
    base: _dt.date | str | None = None,
    policy: dict | None = None,
) -> str:
    """Return an ISO date (``YYYY-MM-DD``) for when this finding's SLA expires.

    * ``priority`` — one of P0/P1/P2/P3 (unrecognized strings fall back to P3).
    * ``kev`` — if True, applies the KEV uplift: by default the finding is
      pulled into the immediate-priority SLA (P0) regardless of its
      ``priority`` argument. Alternatively, if ``kev_uplift_days`` is > 0 in
      the policy, that fixed number of days is used.
    * ``base`` — the date discovery/SLA clock starts. Defaults to today.
    * ``policy`` — override the loaded policy.
    """
    pol = policy or load_sla_policy()
    pri = (priority or "P3").upper()
    days = pol.get(pri)
    if not isinstance(days, int):
        days = pol.get("P3", 90)

    if kev:
        uplift = pol.get("kev_uplift_days", 0)
        if isinstance(uplift, int) and uplift > 0:
            days = uplift
        else:
            target_pri = pol.get("immediate_priority", "P0")
            days = pol.get(target_pri, 14)

    if isinstance(base, str):
        try:
            base_date = _dt.date.fromisoformat(base)
        except Exception:
            base_date = _today()
    elif isinstance(base, _dt.date):
        base_date = base
    else:
        base_date = _today()

    return (base_date + _dt.timedelta(days=int(days))).isoformat()


def is_breached(due_date: str, *, today: _dt.date | None = None) -> bool:
    """True if ``today`` is strictly after the SLA due date."""
    if not due_date:
        return False
    try:
        d = _dt.date.fromisoformat(str(due_date)[:10])
    except Exception:
        return False
    now = today or _today()
    return now > d


def sla_status(due_date: str, *, today: _dt.date | None = None) -> str:
    """Human-readable SLA bucket: ``ON_TRACK`` / ``DUE_SOON`` / ``BREACHED``.

    ``DUE_SOON`` if within 7 days of expiring.
    """
    if not due_date:
        return "UNKNOWN"
    try:
        d = _dt.date.fromisoformat(str(due_date)[:10])
    except Exception:
        return "UNKNOWN"
    now = today or _today()
    if now > d:
        return "BREACHED"
    if (d - now).days <= 7:
        return "DUE_SOON"
    return "ON_TRACK"


__all__ = [
    "DEFAULT_SLA",
    "DEFAULT_PATH",
    "load_sla_policy",
    "compute_due_date",
    "is_breached",
    "sla_status",
]
