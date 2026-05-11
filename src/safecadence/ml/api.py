"""
FastAPI router for v11.0 ML endpoints.

Mounted from :func:`safecadence.ui.app.create_app`. Every endpoint is
side-effect-free read-only (safe in the demo with ``SC_READONLY=1``).

Routes
------
* ``POST /api/v1/ml/anomalies``         — sliding-window z-score over
  a passed timeseries OR the org's daily finding-count series.
* ``POST /api/v1/ml/predict-risk``      — 30-day forecast for a single
  asset or every asset in the org.
* ``POST /api/v1/ml/cluster-findings``  — k-medoids over a passed list
  or the org's recent findings.
* ``POST /api/v1/ml/drift-forecast``    — per-asset or whole-org drift
  forecast.
* ``POST /api/v1/ml/nlq``               — natural-language query →
  filter dict + matched assets.
* ``GET  /api/v1/ml/playbooks``         — list available playbooks.
* ``POST /api/v1/ml/playbook/{id}/run`` — run a playbook against a
  context dict.
"""

from __future__ import annotations

try:
    from fastapi import APIRouter, Body, HTTPException
    _FASTAPI_OK = True
except Exception:                                    # pragma: no cover
    _FASTAPI_OK = False


def _make_router():
    if not _FASTAPI_OK:                              # pragma: no cover
        return None
    router = APIRouter()

    @router.post("/api/v1/ml/anomalies")
    def anomalies_route(payload: dict = Body(default_factory=dict)):
        from safecadence.ml.anomaly import (
            detect_anomalies,
            detect_finding_anomaly,
        )
        ts = payload.get("timeseries")
        window = int(payload.get("window") or 20)
        threshold = float(payload.get("threshold") or 3.0)
        if isinstance(ts, list) and ts:
            anomalies = detect_anomalies(
                ts, window=window, threshold=threshold
            )
        else:
            org_id = payload.get("org_id") or ""
            anomalies = detect_finding_anomaly(
                org_id or None, window=window, threshold=threshold
            )
        return {"anomalies": anomalies, "count": len(anomalies)}

    @router.post("/api/v1/ml/predict-risk")
    def predict_risk_route(payload: dict = Body(default_factory=dict)):
        from safecadence.ml.predict_risk import (
            predict_risk_30d,
            assets_trending_critical,
        )
        asset = payload.get("asset")
        asset_id = payload.get("asset_id")
        org_id = payload.get("org_id")
        if asset and isinstance(asset, dict):
            return {
                "result": predict_risk_30d(asset, payload.get("history")),
            }
        if asset_id and org_id:
            from safecadence.ml.predict_risk import _load_asset

            a = _load_asset(org_id, asset_id)
            if not a:
                raise HTTPException(404, "asset not found")
            return {"result": predict_risk_30d(a, payload.get("history"))}
        if org_id:
            horizon = int(payload.get("horizon_days") or 30)
            return {
                "trending": assets_trending_critical(
                    org_id, horizon_days=horizon
                )
            }
        raise HTTPException(400, "asset, asset_id+org_id, or org_id required")

    @router.post("/api/v1/ml/cluster-findings")
    def cluster_route(payload: dict = Body(default_factory=dict)):
        from safecadence.ml.cluster_findings import cluster_similar

        findings = payload.get("findings")
        if not findings:
            org_id = payload.get("org_id")
            findings = _findings_for_org(org_id)
        clusters = cluster_similar(findings or [])
        return {
            "clusters": [c.to_dict() for c in clusters],
            "count": len(clusters),
        }

    @router.post("/api/v1/ml/drift-forecast")
    def drift_route(payload: dict = Body(default_factory=dict)):
        from safecadence.ml.drift_forecast import (
            forecast_drift,
            assets_at_drift_risk,
        )
        asset_id = payload.get("asset_id")
        org_id = payload.get("org_id")
        days = int(payload.get("days") or 14)
        if asset_id:
            return {
                "result": forecast_drift(
                    asset_id, history=payload.get("history"), org_id=org_id
                )
            }
        if org_id:
            return {"at_risk": assets_at_drift_risk(org_id, days=days)}
        raise HTTPException(400, "asset_id or org_id required")

    @router.post("/api/v1/ml/nlq")
    def nlq_route(payload: dict = Body(default_factory=dict)):
        from safecadence.ml.nlq import parse_query, execute_query

        text = str(payload.get("query") or "").strip()
        if not text:
            raise HTTPException(400, "query required")
        parsed = parse_query(text)
        org_id = payload.get("org_id")
        matches = execute_query(parsed, org_id=org_id) if parsed.source != "parse_failed" else []
        return {
            "parsed": parsed.to_dict(),
            "matches": matches,
            "match_count": len(matches),
        }

    @router.get("/api/v1/ml/playbooks")
    def list_playbooks_route():
        from safecadence.ml.playbooks import list_playbooks

        return {"playbooks": list_playbooks()}

    @router.post("/api/v1/ml/playbook/{playbook_id}/run")
    def run_playbook_route(playbook_id: str, context: dict = Body(default_factory=dict)):
        from safecadence.ml.playbooks import run_playbook

        try:
            steps = run_playbook(playbook_id, context)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        return {"playbook": playbook_id, "steps": steps, "count": len(steps)}

    return router


def _findings_for_org(org_id: str | None) -> list[dict]:
    """Best-effort scan of platform_assets to build a findings list."""
    import json
    import os
    from pathlib import Path

    if org_id:
        try:
            from safecadence.storage.org_store import org_data_dir

            base = org_data_dir(org_id) / "platform_assets"
        except Exception:
            base = None
    else:
        base = None
    if base is None:
        root = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME")
        base = (Path(root) if root else Path.home() / ".safecadence") / "platform_assets"
    if not base.exists():
        return []
    out: list[dict] = []
    for f in base.glob("*.json"):
        try:
            a = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        host = (a.get("identity") or {}).get("hostname") or a.get("id") or f.stem
        for cve in a.get("cves") or a.get("vulnerabilities") or []:
            if not isinstance(cve, dict):
                continue
            out.append(
                {
                    "rule_id": cve.get("id") or "CVE",
                    "severity": str(cve.get("severity") or "medium").lower(),
                    "controls": cve.get("controls") or [],
                    "category": "vulnerability",
                    "host": host,
                    "remediation": cve.get("remediation")
                    or "Apply vendor patch and rescan.",
                }
            )
        for cfg in a.get("findings") or a.get("config_findings") or []:
            if not isinstance(cfg, dict):
                continue
            out.append(
                {
                    "rule_id": cfg.get("rule_id")
                    or cfg.get("rule")
                    or cfg.get("check_id"),
                    "severity": str(cfg.get("severity") or "medium").lower(),
                    "controls": cfg.get("controls") or [],
                    "category": "config",
                    "host": host,
                    "remediation": cfg.get("remediation") or "",
                }
            )
    return out


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
