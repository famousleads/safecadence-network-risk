"""
v14.0 — Per-customer dismissal learning.

When an operator dismisses a finding as "false positive" or "intentional
exception," remember it. Future findings that match the same signature
(same rule + same host class + same severity) are auto-tagged with the
prior decision so the operator can choose to skip them.

This is **per-customer** learning — every install learns from its own
operators, nothing flows out. No global training corpus required.

Storage
-------

A small SQLite table on the install's local DB::

    CREATE TABLE finding_dismissals (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id     TEXT NOT NULL,
        asset_class TEXT NOT NULL DEFAULT '',
        severity    TEXT NOT NULL DEFAULT '',
        decision    TEXT NOT NULL,         -- "false_positive" | "exception"
        reason      TEXT NOT NULL DEFAULT '',
        operator    TEXT NOT NULL,
        at          INTEGER NOT NULL,
        expires_at  INTEGER                -- nullable; permanent if NULL
    );

Signature-matching
------------------

A new finding `f` matches a prior dismissal `d` when:
  d.rule_id == f.rule_id
  AND (d.asset_class == '' OR d.asset_class == f.asset_class)
  AND (d.severity    == '' OR d.severity    == f.severity)
  AND (d.expires_at IS NULL OR d.expires_at > now())

The empty-string fallback lets an operator say "this rule is always
a false positive regardless of asset class" — useful for noisy rules.

Public API
----------

* ``ensure_dismissal_schema(conn)``
* ``record_dismissal(conn, rule_id, decision, operator, ...)``
* ``find_matching_dismissals(conn, finding)`` → list[dict]
* ``annotate_findings(conn, findings)`` → same list with ``dismissed_by``
  + ``dismissal_reason`` added when a match exists
* ``list_dismissals(conn, *, active_only=True)`` → list[dict]
"""
from __future__ import annotations

import time
from typing import Any

VALID_DECISIONS = ("false_positive", "exception")


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS finding_dismissals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    asset_class TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    operator    TEXT NOT NULL,
    at          INTEGER NOT NULL,
    expires_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_dismissals_rule
    ON finding_dismissals(rule_id);
"""


def ensure_dismissal_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def record_dismissal(
    conn: Any,
    *,
    rule_id: str,
    decision: str,
    operator: str,
    asset_class: str = "",
    severity: str = "",
    reason: str = "",
    ttl_days: int | None = None,
) -> dict:
    """Record an operator's dismissal of a finding pattern.

    Args:
        rule_id      — the finding's rule id (REQUIRED; the key for matching).
        decision     — "false_positive" or "exception".
        operator     — the user who made the call (recorded in audit log).
        asset_class  — restrict to this asset class (firewall / switch / …).
                       Empty string = applies to ANY asset class.
        severity     — restrict to this severity. Empty = ANY.
        reason       — free-text rationale.
        ttl_days     — if set, the dismissal expires after N days. Default
                       None = permanent.
    """
    if decision not in VALID_DECISIONS:
        raise ValueError(f"unknown decision: {decision!r}")
    now = int(time.time())
    expires = (now + ttl_days * 86_400) if ttl_days else None
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO finding_dismissals "
        "(rule_id, asset_class, severity, decision, reason, operator, at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (rule_id, asset_class or "", severity or "",
         decision, reason or "", operator, now, expires),
    )
    conn.commit()
    return {
        "id": cur.lastrowid,
        "rule_id": rule_id,
        "asset_class": asset_class,
        "severity": severity,
        "decision": decision,
        "reason": reason,
        "operator": operator,
        "at": now,
        "expires_at": expires,
    }


def find_matching_dismissals(
    conn: Any, finding: dict, *, now_ts: int | None = None,
) -> list[dict]:
    """Return any dismissals matching ``finding``. Most-recent first."""
    now = now_ts if now_ts is not None else int(time.time())
    rule_id = finding.get("rule_id") or finding.get("rule") or ""
    if not rule_id:
        return []
    asset_class = (finding.get("asset_class")
                    or finding.get("asset_type") or "").lower()
    severity = (finding.get("severity") or "").lower()

    rows = conn.execute(
        """
        SELECT id, rule_id, asset_class, severity, decision, reason,
               operator, at, expires_at
          FROM finding_dismissals
         WHERE rule_id = ?
           AND (asset_class = '' OR LOWER(asset_class) = ?)
           AND (severity    = '' OR LOWER(severity)    = ?)
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY at DESC
        """,
        (rule_id, asset_class, severity, now),
    ).fetchall()

    return [
        {"id": r[0], "rule_id": r[1], "asset_class": r[2],
         "severity": r[3], "decision": r[4], "reason": r[5],
         "operator": r[6], "at": r[7], "expires_at": r[8]}
        for r in rows
    ]


def annotate_findings(
    conn: Any, findings: list[dict], *, now_ts: int | None = None,
) -> list[dict]:
    """Decorate each finding with ``dismissed_by`` + ``dismissal_reason``
    when a matching dismissal exists. Does NOT remove findings — the
    operator UI decides whether to hide dismissed ones."""
    out: list[dict] = []
    for f in findings or []:
        matches = find_matching_dismissals(conn, f, now_ts=now_ts)
        f2 = dict(f)
        if matches:
            top = matches[0]
            f2["dismissed_by"] = top["operator"]
            f2["dismissed_at"] = top["at"]
            f2["dismissal_decision"] = top["decision"]
            f2["dismissal_reason"] = top["reason"]
        out.append(f2)
    return out


def list_dismissals(
    conn: Any, *, active_only: bool = True, now_ts: int | None = None,
) -> list[dict]:
    now = now_ts if now_ts is not None else int(time.time())
    sql = (
        "SELECT id, rule_id, asset_class, severity, decision, reason, "
        "operator, at, expires_at FROM finding_dismissals"
    )
    params: tuple = ()
    if active_only:
        sql += " WHERE expires_at IS NULL OR expires_at > ?"
        params = (now,)
    sql += " ORDER BY at DESC"
    rows = conn.execute(sql, params).fetchall()
    return [
        {"id": r[0], "rule_id": r[1], "asset_class": r[2],
         "severity": r[3], "decision": r[4], "reason": r[5],
         "operator": r[6], "at": r[7], "expires_at": r[8]}
        for r in rows
    ]


__all__ = [
    "VALID_DECISIONS",
    "ensure_dismissal_schema",
    "record_dismissal",
    "find_matching_dismissals",
    "annotate_findings",
    "list_dismissals",
]
