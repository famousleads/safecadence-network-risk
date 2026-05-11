"""
Finding-pattern clustering (v11.0).

K-medoids in stdlib. No sklearn / numpy.

The point: when a single root cause produces 14 separate findings,
the report builder should say "these 14 are the same problem" instead
of listing them individually. We cluster on a small categorical
feature vector — rule_id, severity, controls — using a hand-rolled
distance metric and pick ``k`` by maximising silhouette over a small
candidate range (2..6).

Silhouette score: for each point ``i``, ``a(i)`` is its mean
intra-cluster distance and ``b(i)`` is the smallest mean
inter-cluster distance to any *other* cluster. The point's
silhouette is ``(b - a) / max(a, b)`` and the score for a clustering
is the mean of those. ~30 lines, no SciPy needed.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Iterable


# --------------------------------------------------------------------------
# Dataclasses
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Cluster:
    representative_finding: dict
    members: list[dict]
    count: int
    common_remediation: str

    def to_dict(self) -> dict:
        return {
            "representative_finding": self.representative_finding,
            "members": self.members,
            "count": self.count,
            "common_remediation": self.common_remediation,
        }


# --------------------------------------------------------------------------
# Feature + distance
# --------------------------------------------------------------------------


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _feat(f: dict) -> tuple:
    rule = str(f.get("rule_id") or f.get("rule") or f.get("check_id") or "")
    sev = _SEVERITY_RANK.get(
        str(f.get("severity") or "").lower(), 1
    )
    ctrls = tuple(sorted(set(f.get("controls") or f.get("control_ids") or [])))
    cat = str(f.get("category") or f.get("kind") or "")
    return (rule, sev, ctrls, cat)


def _distance(a: dict, b: dict) -> float:
    fa = _feat(a)
    fb = _feat(b)
    d = 0.0
    # rule_id: exact match weight 3.0
    if fa[0] != fb[0]:
        d += 3.0
    # severity: absolute difference / 4
    d += abs(fa[1] - fb[1]) / 4.0
    # controls: jaccard distance on the set
    sa, sb = set(fa[2]), set(fb[2])
    if sa or sb:
        inter = len(sa & sb)
        union = len(sa | sb)
        d += 1.0 - (inter / union if union else 1.0)
    # category: weight 1.0
    if fa[3] != fb[3]:
        d += 1.0
    return d


# --------------------------------------------------------------------------
# K-medoids (PAM-style)
# --------------------------------------------------------------------------


def _assign(items: list[dict], medoid_idx: list[int]) -> list[int]:
    assign = []
    for i, it in enumerate(items):
        best = 0
        best_d = float("inf")
        for j, m in enumerate(medoid_idx):
            d = _distance(it, items[m])
            if d < best_d:
                best_d = d
                best = j
        assign.append(best)
    return assign


def _update_medoids(
    items: list[dict], assign: list[int], k: int
) -> list[int]:
    new_medoids = []
    for c in range(k):
        cluster_idx = [i for i, a in enumerate(assign) if a == c]
        if not cluster_idx:
            # empty cluster — keep a random point (avoids degenerate loop)
            new_medoids.append(random.randrange(len(items)))
            continue
        # Pick the point minimising sum of distances inside the cluster
        best = cluster_idx[0]
        best_cost = float("inf")
        for cand in cluster_idx:
            cost = sum(_distance(items[cand], items[i]) for i in cluster_idx)
            if cost < best_cost:
                best_cost = cost
                best = cand
        new_medoids.append(best)
    return new_medoids


def _kmedoids(items: list[dict], k: int, *, max_iter: int = 30, seed: int = 7):
    rng = random.Random(seed)
    if k <= 0 or not items:
        return [], []
    if k >= len(items):
        return list(range(len(items))), list(range(len(items)))
    medoids = rng.sample(range(len(items)), k)
    assign = _assign(items, medoids)
    for _ in range(max_iter):
        new_medoids = _update_medoids(items, assign, k)
        if new_medoids == medoids:
            break
        medoids = new_medoids
        assign = _assign(items, medoids)
    return medoids, assign


# --------------------------------------------------------------------------
# Silhouette score (from-scratch)
# --------------------------------------------------------------------------


def _silhouette(items: list[dict], assign: list[int], k: int) -> float:
    if k < 2 or len(items) < 2:
        return 0.0
    by_cluster: dict[int, list[int]] = {c: [] for c in range(k)}
    for i, c in enumerate(assign):
        by_cluster.setdefault(c, []).append(i)
    if any(len(v) == 0 for v in by_cluster.values()):
        return 0.0
    scores = []
    for i, ci in enumerate(assign):
        own = by_cluster[ci]
        if len(own) <= 1:
            scores.append(0.0)
            continue
        a = sum(_distance(items[i], items[j]) for j in own if j != i) / (
            len(own) - 1
        )
        best_b = float("inf")
        for cj, members in by_cluster.items():
            if cj == ci or not members:
                continue
            b = sum(_distance(items[i], items[j]) for j in members) / len(members)
            if b < best_b:
                best_b = b
        if best_b == float("inf"):
            scores.append(0.0)
            continue
        denom = max(a, best_b)
        scores.append(0.0 if denom == 0 else (best_b - a) / denom)
    return sum(scores) / len(scores)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _common_remediation(members: list[dict]) -> str:
    """Pick the most common remediation string from the cluster members."""
    counts: dict[str, int] = {}
    for m in members:
        rem = str(
            m.get("remediation") or m.get("fix") or m.get("recommendation") or ""
        ).strip()
        if not rem:
            continue
        counts[rem] = counts.get(rem, 0) + 1
    if not counts:
        return "Investigate shared root cause for clustered findings."
    return max(counts.items(), key=lambda kv: kv[1])[0]


def cluster_similar(
    findings: list[dict],
    *,
    k: int | None = None,
    k_min: int = 2,
    k_max: int = 6,
    seed: int = 7,
) -> list[Cluster]:
    """Cluster similar findings via k-medoids + silhouette-picked k.

    Parameters
    ----------
    findings:
        List of dicts with at minimum ``rule_id`` and ``severity``.
        ``controls`` (list of strings) and ``category`` improve quality.
    k:
        Force a specific cluster count. If ``None`` (default) we try
        ``k = k_min..k_max`` and pick the one with highest silhouette.
    """
    items = list(findings or [])
    if not items:
        return []
    if len(items) == 1:
        return [
            Cluster(
                representative_finding=items[0],
                members=items,
                count=1,
                common_remediation=_common_remediation(items),
            )
        ]
    if k is not None:
        best_k = max(1, min(k, len(items)))
        medoids, assign = _kmedoids(items, best_k, seed=seed)
    else:
        # Search 2..min(k_max, n-1) for the best silhouette.
        best_score = -2.0
        best_pair = (None, None)
        upper = min(k_max, len(items) - 1) if len(items) > 2 else 1
        candidates = range(max(1, k_min), max(2, upper + 1))
        for cand in candidates:
            medoids, assign = _kmedoids(items, cand, seed=seed)
            if cand == 1:
                # Single cluster: silhouette undefined; score 0
                sc = 0.0
            else:
                sc = _silhouette(items, assign, cand)
            if sc > best_score:
                best_score = sc
                best_pair = (medoids, assign)
                best_k = cand
        if best_pair[0] is None:
            return [
                Cluster(
                    representative_finding=items[0],
                    members=items,
                    count=len(items),
                    common_remediation=_common_remediation(items),
                )
            ]
        medoids, assign = best_pair

    by_cluster: dict[int, list[int]] = {}
    for i, c in enumerate(assign):
        by_cluster.setdefault(c, []).append(i)

    clusters: list[Cluster] = []
    for ci, idxs in by_cluster.items():
        members = [items[i] for i in idxs]
        rep_idx = medoids[ci] if ci < len(medoids) else idxs[0]
        rep = items[rep_idx]
        clusters.append(
            Cluster(
                representative_finding=rep,
                members=members,
                count=len(members),
                common_remediation=_common_remediation(members),
            )
        )
    # Sort by size descending — biggest patterns first
    clusters.sort(key=lambda c: c.count, reverse=True)
    return clusters


__all__ = ["Cluster", "cluster_similar"]
