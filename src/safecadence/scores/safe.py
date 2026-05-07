"""
Safe Score — how exposed is this asset/fleet right now?  (v9.24)

A single 0..100 number per asset, plus a fleet aggregate weighted by
asset criticality. Higher = safer.

Inputs (all optional — score degrades gracefully if a signal is
missing):
  * findings        — list of {asset_id, severity, kind, ...}
  * paths           — list of attack paths; each path has a 'nodes'
                      list (hop chain) and optional 'criticality'
                      on the target
  * cves            — per-asset list of {asset_id, cves: [...]}; each
                      cve has cvss, kev (bool), epss
  * drift_count     — number of declared-vs-running drifts on the asset
  * missing_controls— number of policy controls the asset doesn't pass

Why a single number when we already have severity / KEV / paths?
Because operators don't make decisions on dashboards full of numbers.
They make them on one number that goes up or down. Safe Score is the
single thing on the homepage that everything else reduces to.

Design choices:
  - Deterministic. Same inputs → same number. No randomness, no time.
  - Transparent. Every deduction comes with a reason string.
  - Bounded. Max possible deduction per category is capped so a single
    bad signal can't zero the score on its own.
  - Composable. score_fleet_safe() is just score_asset_safe() rolled
    up by criticality weight — no separate fleet logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# ------------------------------------------------------------- weights
#
# Each category has a max-deduction ceiling. The four ceilings sum to
# 100 — so even an asset with the worst possible signal in every bucket
# bottoms out at 0, never negative.

_MAX_DEDUCT_FINDINGS = 35       # active findings, weighted by severity
_MAX_DEDUCT_CVES = 30           # unpatched CVEs, prioritized by KEV+EPSS+CVSS
_MAX_DEDUCT_PATHS = 20          # this asset sits on attack paths
_MAX_DEDUCT_DRIFT_CTRL = 15     # drift + missing controls combined

# Per-finding deduction by severity. Capped at _MAX_DEDUCT_FINDINGS.
_SEV_WEIGHT = {
    "critical": 12,
    "high":     8,
    "medium":   4,
    "low":      1,
    "info":     0,
}

# Criticality multipliers used by the fleet aggregate. The same scale
# the rest of the platform uses (asset.identity.criticality).
_CRIT_WEIGHT = {
    "critical": 4.0,
    "high":     2.5,
    "medium":   1.5,
    "low":      1.0,
    "":         1.0,
    None:       1.0,
}


# ---------------------------------------------------------- public types


@dataclass
class SafeScore:
    """Result of scoring a single asset.

    Attributes:
        asset_id: the asset this score is for
        score: 0..100, higher is safer (clamp(posture + 100 - risk))
        band: 'A'..'F' for at-a-glance display
        reasons: contributing deductions, each a (category, points, msg)
        inputs: counts of each signal that fed into the score (handy
                for the UI's "why this number" tooltip)
        posture_credit: points ADDED for protective controls present (v9.26)
        risk_deduction: points subtracted for findings/CVEs/paths (v9.26)
        confidence: 0..1; how much signal we have. UI hides the number
                    when confidence is too low (v9.26)
        confidence_reasons: why confidence is what it is
    """
    asset_id: str
    score: int
    band: str
    reasons: list[tuple[str, int, str]] = field(default_factory=list)
    inputs: dict[str, int] = field(default_factory=dict)
    posture_credit: int = 0
    risk_deduction: int = 0
    confidence: float = 1.0
    confidence_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "score": self.score,
            "band": self.band,
            "reasons": [
                {"category": c, "deduction": p, "message": m}
                for c, p, m in self.reasons
            ],
            "inputs": dict(self.inputs),
            "posture_credit": self.posture_credit,
            "risk_deduction": self.risk_deduction,
            "confidence": round(self.confidence, 2),
            "confidence_reasons": list(self.confidence_reasons),
        }


# ---------------------------------------------------------- helpers


def _asset_id(a: dict) -> str:
    ident = a.get("identity") or {}
    return ident.get("asset_id") or ident.get("hostname") or ""


def _criticality(a: dict) -> str:
    ident = a.get("identity") or {}
    return (ident.get("criticality") or "medium").lower()


def _band(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _capped(deductions: list[tuple[int, str]], cap: int,
             category: str) -> tuple[int, list[tuple[str, int, str]]]:
    """Sum deductions, cap at `cap`. Return (total, reason rows).

    If the cap binds, the reason list still records every individual
    deduction for transparency; the total is just the capped sum.
    """
    if not deductions:
        return 0, []
    total = min(cap, sum(p for p, _ in deductions))
    rows = [(category, p, m) for p, m in deductions]
    return total, rows


# ---------------------------------------------------------- per-asset


def score_asset_safe(
    asset: dict,
    *,
    findings: Optional[Iterable[dict]] = None,
    paths: Optional[Iterable[dict]] = None,
    cves: Optional[Iterable[dict]] = None,
    drift_count: int = 0,
    missing_controls: int = 0,
    enable_posture: bool = True,
    enable_best_practice: bool = True,
    enable_software_currency: bool = True,
) -> SafeScore:
    """Score a single asset 0..100 (higher = safer).

    All inputs are optional. The score degrades when a signal is
    missing — meaning "we don't know" is treated as "no deduction"
    rather than "worst case." That's an opinionated choice: false
    positives in a security score erode trust faster than false
    negatives.
    """
    aid = _asset_id(asset)
    score = 100
    reasons: list[tuple[str, int, str]] = []
    inputs = {
        "findings": 0, "cves": 0, "paths": 0,
        "drift": int(drift_count or 0),
        "missing_controls": int(missing_controls or 0),
    }

    # -- findings
    finding_dedux: list[tuple[int, str]] = []
    if findings:
        seen_findings = 0
        for f in findings:
            if (f.get("asset_id") or f.get("target") or "") != aid:
                continue
            seen_findings += 1
            sev = (f.get("severity") or f.get("risk") or "medium").lower()
            pts = _SEV_WEIGHT.get(sev, 4)
            if pts:
                kind = f.get("kind") or f.get("type") or "finding"
                finding_dedux.append((pts, f"{sev} {kind}"))
        inputs["findings"] = seen_findings
    sub, rows = _capped(finding_dedux, _MAX_DEDUCT_FINDINGS, "findings")
    score -= sub
    reasons.extend(rows)

    # -- CVEs (priority = KEV strong, EPSS scaled, CVSS rounded)
    cve_dedux: list[tuple[int, str]] = []
    if cves:
        seen_cves = 0
        for entry in cves:
            target = entry.get("asset_id") or entry.get("target") or ""
            if target and target != aid:
                continue
            for cve in entry.get("cves") or []:
                seen_cves += 1
                cid = cve.get("id") or cve.get("cve_id") or "CVE-?"
                cvss = float(cve.get("cvss") or cve.get("cvss_score") or 0)
                kev = bool(cve.get("kev"))
                epss = float(cve.get("epss") or cve.get("epss_score") or 0)
                # KEV is the strongest single signal — known exploited.
                pts = 0
                if kev:
                    pts += 8
                if epss >= 0.5:
                    pts += 4
                elif epss >= 0.1:
                    pts += 2
                if cvss >= 9.0:
                    pts += 4
                elif cvss >= 7.0:
                    pts += 2
                if pts:
                    label = f"{cid}"
                    if kev: label += " (KEV)"
                    if epss >= 0.1: label += f" EPSS {epss:.2f}"
                    if cvss >= 7: label += f" CVSS {cvss:.1f}"
                    cve_dedux.append((pts, label))
        inputs["cves"] = seen_cves
    sub, rows = _capped(cve_dedux, _MAX_DEDUCT_CVES, "cves")
    score -= sub
    reasons.extend(rows)

    # -- attack paths this asset sits on
    path_dedux: list[tuple[int, str]] = []
    if paths:
        on_paths = 0
        for p in paths:
            nodes = p.get("nodes") or p.get("path") or []
            if any(_id_of(n) == aid for n in nodes):
                on_paths += 1
                tgt_crit = (p.get("target_criticality") or
                              p.get("criticality") or "medium").lower()
                pts = 6 if tgt_crit == "critical" else \
                       4 if tgt_crit == "high" else 2
                tgt = p.get("target") or _id_of(nodes[-1]) if nodes else "?"
                path_dedux.append((pts, f"on path → {tgt} ({tgt_crit})"))
        inputs["paths"] = on_paths
    sub, rows = _capped(path_dedux, _MAX_DEDUCT_PATHS, "paths")
    score -= sub
    reasons.extend(rows)

    # -- drift + missing controls (combined ceiling)
    dc_dedux: list[tuple[int, str]] = []
    if drift_count:
        dc_dedux.append((min(8, int(drift_count) * 2),
                          f"{int(drift_count)} drift item(s)"))
    if missing_controls:
        dc_dedux.append((min(8, int(missing_controls) * 2),
                          f"{int(missing_controls)} missing control(s)"))
    sub, rows = _capped(dc_dedux, _MAX_DEDUCT_DRIFT_CTRL, "drift_controls")
    score -= sub
    reasons.extend(rows)

    risk_deduction = 100 - score   # how much we deducted in v9.24 model

    # ---- v9.26: posture credit (+up to 20 added) -----------------
    posture_credit = 0
    if enable_posture:
        try:
            from safecadence.scores.posture import evaluate_asset as _post
            pres = _post(asset)
            posture_credit += pres.credit
            for row in pres.earned:
                reasons.append(("posture", -row["weight"],
                                f"+{row['weight']} {row['description']}"))
        except Exception:                                 # pragma: no cover
            pass

    if enable_best_practice:
        try:
            from safecadence.scores.best_practice import evaluate_asset as _bp
            bp = _bp(asset)
            if bp.vendor_key and bp.max_credit:
                # Scale to a max +5 contribution from best-practice
                # so it doesn't dominate the posture pool.
                bp_pts = round(5 * bp.credit / bp.max_credit) if bp.max_credit else 0
                posture_credit += bp_pts
                if bp_pts:
                    reasons.append(("best_practice", -bp_pts,
                                    f"+{bp_pts} vendor hardening "
                                    f"({bp.credit}/{bp.max_credit} checks)"))
                if bp.failed:
                    inputs["best_practice_failed"] = len(bp.failed)
        except Exception:                                 # pragma: no cover
            pass

    if enable_software_currency:
        try:
            from safecadence.scores.software_currency import \
                evaluate_asset as _sc
            sc = _sc(asset)
            if sc.posture_credit:
                posture_credit += sc.posture_credit
                reasons.append(("software_currency",
                                -sc.posture_credit,
                                f"+{sc.posture_credit} running "
                                f"recommended version ({sc.running_version})"))
            if sc.risk_deduction:
                score -= sc.risk_deduction
                risk_deduction += sc.risk_deduction
                reasons.append(("software_currency", sc.risk_deduction,
                                f"{sc.status}: {sc.notes[0] if sc.notes else ''}"))
            inputs["software_status"] = sc.status
        except Exception:                                 # pragma: no cover
            pass

    posture_credit = min(20, posture_credit)
    score += posture_credit
    score = max(0, min(100, score))

    # ---- v9.26: confidence (0..1). Lowers when signal is sparse. -
    confidence, conf_reasons = _compute_confidence(
        asset, inputs=inputs, findings_seen=bool(findings),
        paths_seen=bool(paths), cves_seen=bool(cves),
    )

    return SafeScore(asset_id=aid, score=score, band=_band(score),
                       reasons=reasons, inputs=inputs,
                       posture_credit=posture_credit,
                       risk_deduction=risk_deduction,
                       confidence=confidence,
                       confidence_reasons=conf_reasons)


def _compute_confidence(asset: dict, *,
                          inputs: dict,
                          findings_seen: bool,
                          paths_seen: bool,
                          cves_seen: bool) -> tuple[float, list[str]]:
    """Confidence = how much signal do we actually have on this asset?

    Returns (0..1, reasons[]). A score with confidence < 0.3 should be
    rendered as "—" / "scan first" by the UI rather than as a number.
    """
    from datetime import datetime, timezone, timedelta
    score = 0.0
    weight_total = 0.0
    reasons: list[str] = []

    def _hit(weight: float, label: str, ok: bool):
        nonlocal score, weight_total
        weight_total += weight
        if ok:
            score += weight
        else:
            reasons.append(label)

    ident = asset.get("identity") or {}
    _hit(0.20, "no last_seen timestamp",
          bool(ident.get("last_seen") or ident.get("last_evaluated")))

    # Recency: last_seen within 30 days
    last = ident.get("last_seen") or ident.get("last_evaluated") or ""
    is_recent = False
    if last:
        try:
            ts = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - ts < timedelta(days=30):
                is_recent = True
        except Exception:
            pass
    _hit(0.20, "last_seen older than 30 days", is_recent)

    raw = asset.get("raw_collection") or {}
    has_config = isinstance(raw, dict) and any(
        isinstance(raw.get(k), str) and raw.get(k)
        for k in ("running", "running_config", "config")
    )
    _hit(0.20, "no running config collected", has_config)

    _hit(0.15, "no findings store yet", findings_seen)
    _hit(0.15, "no CVE enrichment yet", cves_seen)
    _hit(0.10, "no attack-path data yet", paths_seen)

    confidence = score / weight_total if weight_total else 0.0
    return confidence, reasons


def _id_of(node) -> str:
    """Pull asset_id from a path-node, which may be a string or dict."""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        ident = node.get("identity") or {}
        return ident.get("asset_id") or node.get("asset_id") or ""
    return ""


# ---------------------------------------------------------- fleet


def score_fleet_safe(
    assets: Iterable[dict],
    *,
    findings: Optional[Iterable[dict]] = None,
    paths: Optional[Iterable[dict]] = None,
    cves: Optional[Iterable[dict]] = None,
    drift_by_asset: Optional[dict[str, int]] = None,
    missing_by_asset: Optional[dict[str, int]] = None,
) -> dict:
    """Score the whole fleet — criticality-weighted average of the
    per-asset scores. Returns a dict with the headline number plus
    the per-asset rollup the UI needs.

    The headline number is the criticality-weighted MEAN of per-asset
    scores. So one bad critical box drags the fleet number down more
    than five bad low-criticality boxes — which is correct: critical
    assets matter more.

    drift_by_asset / missing_by_asset are simple {asset_id: count}
    maps so callers don't have to filter findings themselves.
    """
    assets = list(assets)
    findings = list(findings or [])
    paths = list(paths or [])
    cves = list(cves or [])
    drift_by_asset = drift_by_asset or {}
    missing_by_asset = missing_by_asset or {}

    per_asset: list[SafeScore] = []
    total_w = 0.0
    weighted_sum = 0.0
    band_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}

    for a in assets:
        aid = _asset_id(a)
        s = score_asset_safe(
            a,
            findings=findings,
            paths=paths,
            cves=cves,
            drift_count=int(drift_by_asset.get(aid, 0)),
            missing_controls=int(missing_by_asset.get(aid, 0)),
        )
        per_asset.append(s)
        w = _CRIT_WEIGHT.get(_criticality(a), 1.0)
        total_w += w
        weighted_sum += w * s.score
        band_counts[s.band] += 1

    fleet_score = int(round(weighted_sum / total_w)) if total_w else 100

    # Top 5 worst — the cards the user wants to see on /home.
    worst = sorted(per_asset, key=lambda s: s.score)[:5]

    return {
        "fleet_score": fleet_score,
        "fleet_band": _band(fleet_score),
        "asset_count": len(assets),
        "band_counts": band_counts,
        "worst_assets": [s.to_dict() for s in worst],
        "per_asset": [s.to_dict() for s in per_asset],
    }


# ---------------------------------------------------------- weak link


def weak_link(
    assets: Iterable[dict],
    paths: Iterable[dict],
    *,
    findings: Optional[Iterable[dict]] = None,
    cves: Optional[Iterable[dict]] = None,
    drift_by_asset: Optional[dict[str, int]] = None,
    missing_by_asset: Optional[dict[str, int]] = None,
) -> Optional[dict]:
    """Find the asset whose remediation collapses the most attack paths,
    weighted by target criticality.

    Returns:
        {
          "asset_id": ...,
          "asset_label": "edge-fw-01",
          "paths_killed": 7,
          "weighted_paths": 23.0,
          "current_fleet_score": 64,
          "projected_fleet_score": 78,
          "reason": "Sits on 7 attack paths to 3 critical assets."
        }

    The math is dead simple: for each asset, count the paths it appears
    in (weighted by target criticality). Pick the asset whose removal
    (i.e. clean-bill-of-health remediation) cuts the most paths.

    "Projected fleet score" is the fleet score recomputed as if this
    asset had no findings/CVEs/path-membership. That's the screenshot:
    "Fix this and the fleet number jumps from 64 → 78."
    """
    assets = list(assets)
    paths = list(paths)
    if not assets:
        return None

    findings = list(findings or [])
    cves = list(cves or [])
    drift_by_asset = drift_by_asset or {}
    missing_by_asset = missing_by_asset or {}

    # --- count paths killed per asset -------------------------------
    by_asset_paths: dict[str, list[dict]] = {}
    for p in paths:
        nodes = p.get("nodes") or p.get("path") or []
        seen_ids = {_id_of(n) for n in nodes if _id_of(n)}
        # Don't credit the path's TARGET for "killing" itself;
        # the weak link is an intermediary that should be remediated.
        target = p.get("target") or (_id_of(nodes[-1]) if nodes else "")
        for aid in seen_ids:
            if aid == target:
                continue
            by_asset_paths.setdefault(aid, []).append(p)

    if not by_asset_paths:
        return None

    def _weight_for_path(p: dict) -> float:
        crit = (p.get("target_criticality") or
                  p.get("criticality") or "medium").lower()
        return _CRIT_WEIGHT.get(crit, 1.0)

    # Best candidate: maximise (sum of target-criticality weights).
    best_aid, best_paths, best_weight = None, [], 0.0
    for aid, plist in by_asset_paths.items():
        w = sum(_weight_for_path(p) for p in plist)
        if w > best_weight:
            best_aid, best_paths, best_weight = aid, plist, w

    if not best_aid:
        return None

    # --- compute current vs projected fleet score -------------------
    current = score_fleet_safe(
        assets, findings=findings, paths=paths, cves=cves,
        drift_by_asset=drift_by_asset, missing_by_asset=missing_by_asset,
    )

    # "Projected" = recompute pretending the weak-link asset has no
    # findings + no CVEs + no path membership.
    fixed_findings = [f for f in findings
                       if (f.get("asset_id") or f.get("target")) != best_aid]
    fixed_cves = [c for c in cves
                   if (c.get("asset_id") or c.get("target")) != best_aid]
    fixed_paths = [p for p in paths
                    if best_aid not in {_id_of(n)
                                          for n in (p.get("nodes")
                                                       or p.get("path") or [])}]
    fixed_drift = {k: v for k, v in drift_by_asset.items() if k != best_aid}
    fixed_missing = {k: v for k, v in missing_by_asset.items()
                      if k != best_aid}
    projected = score_fleet_safe(
        assets, findings=fixed_findings, paths=fixed_paths,
        cves=fixed_cves, drift_by_asset=fixed_drift,
        missing_by_asset=fixed_missing,
    )

    # Friendly label
    label = best_aid
    for a in assets:
        ident = a.get("identity") or {}
        if ident.get("asset_id") == best_aid:
            label = ident.get("hostname") or ident.get("name") or best_aid
            break

    crit_targets = {p.get("target") or _id_of(
        (p.get("nodes") or p.get("path") or [None])[-1])
                      for p in best_paths}
    n_crit = sum(1 for p in best_paths
                  if (p.get("target_criticality") or
                       p.get("criticality") or "").lower() == "critical")

    paths_killed = len(best_paths)
    reason = (f"Sits on {paths_killed} attack path"
              f"{'s' if paths_killed != 1 else ''}")
    if n_crit:
        reason += f" to {n_crit} critical asset{'s' if n_crit != 1 else ''}"
    reason += "."

    return {
        "asset_id": best_aid,
        "asset_label": label,
        "paths_killed": paths_killed,
        "weighted_paths": round(best_weight, 2),
        "critical_targets": sorted(t for t in crit_targets if t),
        "current_fleet_score": current["fleet_score"],
        "projected_fleet_score": projected["fleet_score"],
        "score_lift": projected["fleet_score"] - current["fleet_score"],
        "reason": reason,
    }
