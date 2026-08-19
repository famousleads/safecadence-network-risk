"""
GIS-lite — /api/v1/geo/assets (GeoJSON). The human-facing map lives
in the UI chrome at /map (ui/desat_pages.py).

Assets with coordinates (``public_safety.latitude/longitude``, set by
import/adapter/manual edit) become a GeoJSON FeatureCollection, styled
by risk band, ready for Leaflet/ArcGIS/QGIS — GeoJSON is the
vendor-neutral contract.

Local-first note: the /map page loads Leaflet + OpenStreetMap tiles
from the internet WHEN available and degrades to a plain feature list
when offline/air-gapped. The GeoJSON endpoint itself never needs the
internet — agencies can pull it into their own ArcGIS.
"""

from __future__ import annotations

from typing import Any


def asset_feature(asset: dict) -> dict | None:
    """One stored asset → GeoJSON Feature, or None without coordinates."""
    ps = asset.get("public_safety") or {}
    try:
        lat = float(ps.get("latitude") or 0.0)
        lon = float(ps.get("longitude") or 0.0)
    except (TypeError, ValueError):
        return None
    if lat == 0.0 and lon == 0.0:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    ident = asset.get("identity") or {}
    health = asset.get("health") or {}
    return {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [lon, lat]},
        "properties": {
            "asset_id": ident.get("asset_id", ""),
            "hostname": ident.get("hostname", ""),
            "vendor": ident.get("vendor", ""),
            "asset_type": ident.get("asset_type", ""),
            "ps_category": ps.get("ps_category", ""),
            "mission_function": ps.get("mission_function", ""),
            "site": ident.get("site", ""),
            "agency": ps.get("agency", ""),
            "criticality": ident.get("criticality", ""),
            "risk_band": health.get("risk_band", "safe"),
            "overall_score": health.get("overall_score", 100),
        },
    }


def assets_geojson(assets: list[dict], *, site: str = "",
                    ps_category: str = "", risk_band: str = "") -> dict:
    """FeatureCollection over assets that carry coordinates."""
    feats = []
    for a in assets:
        f = asset_feature(a)
        if f is None:
            continue
        p = f["properties"]
        if site and p["site"] != site:
            continue
        if ps_category and p["ps_category"] != ps_category:
            continue
        if risk_band and p["risk_band"] != risk_band:
            continue
        feats.append(f)
    return {"type": "FeatureCollection", "features": feats,
             "properties": {"count": len(feats),
                             "assets_without_geo":
                                 sum(1 for a in assets if asset_feature(a) is None)}}


def build_router():
    try:
        from fastapi import APIRouter, Depends
    except Exception:                                  # pragma: no cover
        return None

    try:
        from safecadence.auth.rbac import UserRole, require_role
        _viewer_dep = require_role(UserRole.VIEWER)
    except Exception:                                  # pragma: no cover
        def _viewer_dep():
            return None

    router = APIRouter(tags=["geo"])

    @router.get("/api/v1/geo/assets")
    def geo_assets(site: str = "", ps_category: str = "",
                    risk_band: str = "", _: Any = Depends(_viewer_dep)):
        from safecadence.server.platform_api import list_assets
        return assets_geojson(list_assets(), site=site,
                                ps_category=ps_category, risk_band=risk_band)


    return router
