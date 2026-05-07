"""
v7.9 — Comments + assignments.

Generic comment+assign on any entity in the platform — findings,
policies, attack paths, JIT grants, assets, NHIs.

Stickiness lever — once a team is collaborating in SafeCadence, it
becomes the system of record for "who is fixing what". Switching
costs become real.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict

from safecadence.intel._store import read, write


@dataclass
class Comment:
    comment_id: str
    entity_kind: str
    entity_id: str
    user: str
    text: str
    created_at: float
    parent_comment_id: str = ""    # threading


@dataclass
class Assignment:
    assignment_id: str
    entity_kind: str
    entity_id: str
    assigned_to: str
    assigned_by: str
    note: str = ""
    status: str = "open"           # open | in_progress | resolved | wontfix
    created_at: float = 0.0
    updated_at: float = 0.0


def add_comment(*, entity_kind: str, entity_id: str, user: str, text: str,
                parent_comment_id: str = "") -> Comment:
    if not text.strip():
        raise ValueError("comment text is required")
    data = read("comments", {"comments": [], "assignments": []})
    c = Comment(
        comment_id="c_" + uuid.uuid4().hex[:10],
        entity_kind=entity_kind, entity_id=entity_id,
        user=user or "anonymous", text=text.strip(),
        created_at=time.time(),
        parent_comment_id=parent_comment_id,
    )
    data.setdefault("comments", []).append(asdict(c))
    write("comments", data)
    return c


def list_comments(*, entity_kind: str | None = None,
                  entity_id: str | None = None,
                  limit: int = 200) -> list[Comment]:
    data = read("comments", {"comments": [], "assignments": []})
    out: list[Comment] = []
    for c in (data.get("comments") or []):
        if entity_kind and c["entity_kind"] != entity_kind: continue
        if entity_id and c["entity_id"] != entity_id: continue
        out.append(Comment(**c))
    out.sort(key=lambda c: c.created_at, reverse=True)
    return out[:limit]


def assign(*, entity_kind: str, entity_id: str, assigned_to: str,
           assigned_by: str, note: str = "") -> Assignment:
    data = read("comments", {"comments": [], "assignments": []})
    t = time.time()
    a = Assignment(
        assignment_id="a_" + uuid.uuid4().hex[:10],
        entity_kind=entity_kind, entity_id=entity_id,
        assigned_to=assigned_to, assigned_by=assigned_by,
        note=note, status="open", created_at=t, updated_at=t,
    )
    data.setdefault("assignments", []).append(asdict(a))
    write("comments", data)
    return a


def list_assignments(*, assigned_to: str | None = None,
                     status: str | None = None) -> list[Assignment]:
    data = read("comments", {"comments": [], "assignments": []})
    out: list[Assignment] = []
    for a in (data.get("assignments") or []):
        if assigned_to and a["assigned_to"] != assigned_to: continue
        if status and a["status"] != status: continue
        out.append(Assignment(**a))
    out.sort(key=lambda a: a.updated_at, reverse=True)
    return out


def update_assignment(assignment_id: str, *, status: str) -> Assignment | None:
    if status not in ("open", "in_progress", "resolved", "wontfix"):
        raise ValueError(f"invalid status: {status}")
    data = read("comments", {"comments": [], "assignments": []})
    for a in (data.get("assignments") or []):
        if a["assignment_id"] == assignment_id:
            a["status"] = status
            a["updated_at"] = time.time()
            write("comments", data)
            return Assignment(**a)
    return None
