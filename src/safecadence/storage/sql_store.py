"""
SQLAlchemy-backed store — works against PostgreSQL or any SQLAlchemy URL.

Activated when --db-url is provided OR DATABASE_URL is set in env.
Requires `pip install safecadence-netrisk[server]`.
"""


from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from safecadence.storage.base import BaseStore


def _import_sqlalchemy():
    try:
        from sqlalchemy import (Column, Integer, String, Text, DateTime, Index,
                                create_engine, func, select)
        from sqlalchemy.orm import declarative_base, sessionmaker
        return Column, Integer, String, Text, DateTime, Index, create_engine, func, select, declarative_base, sessionmaker
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL/SQLAlchemy backend requires the `server` extras: "
            "pip install 'safecadence-network-risk[server]'"
        ) from exc


class SqlStore(BaseStore):
    def __init__(self, db_url: str):
        (Column, Integer, String, Text, DateTime, Index, create_engine,
         func, select, declarative_base, sessionmaker) = _import_sqlalchemy()
        self._sa = {
            "Column": Column, "Integer": Integer, "String": String, "Text": Text,
            "DateTime": DateTime, "func": func, "select": select,
        }
        self.Base = declarative_base()

        class Scan(self.Base):
            __tablename__ = "sc_scans"
            id          = Column(Integer, primary_key=True, autoincrement=True)
            tenant_id   = Column(String(64), nullable=False, default="default", index=True)
            started_at  = Column(String(40), nullable=False)
            source      = Column(String(512), nullable=False)
            vendor      = Column(String(64), nullable=False)
            hostname    = Column(String(255), index=True)
            ip          = Column(String(64))
            site        = Column(String(128))
            health      = Column(Integer)
            risk        = Column(Integer)
            risk_band   = Column(String(16))
            eol_status  = Column(String(32))
            cves        = Column(Integer, default=0)
            findings    = Column(Integer, default=0)
            summary     = Column(Text)
            payload     = Column(Text, nullable=False)

        class AuditLog(self.Base):
            __tablename__ = "sc_audit_log"
            id          = Column(Integer, primary_key=True, autoincrement=True)
            tenant_id   = Column(String(64), nullable=False, index=True)
            actor       = Column(String(255))
            action      = Column(String(128), nullable=False)
            resource    = Column(String(255))
            detail      = Column(Text)
            at          = Column(String(40), nullable=False)

        self.Scan = Scan
        self.AuditLog = AuditLog
        self.engine = create_engine(db_url, future=True)
        self.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    # ---- BaseStore --------------------------------------------- #
    def save(self, scan_dict: dict, *, tenant_id: str = "default") -> int:
        asset = scan_dict.get("asset", {}) or {}
        ps    = scan_dict.get("parsed_summary", {}) or {}
        with self.SessionLocal() as s:
            row = self.Scan(
                tenant_id=tenant_id,
                started_at=scan_dict.get("started_at", ""),
                source=scan_dict.get("source", ""),
                vendor=scan_dict.get("vendor", ""),
                hostname=asset.get("hostname") or ps.get("hostname", ""),
                ip=asset.get("ip", ""),
                site=(asset.get("location") or {}).get("site", "") or asset.get("site", ""),
                health=int(scan_dict.get("health_score") or 0),
                risk=int(scan_dict.get("risk_score") or 0),
                risk_band=scan_dict.get("risk_band", ""),
                eol_status=(scan_dict.get("eol") or {}).get("status_today", ""),
                cves=len(scan_dict.get("cves", [])),
                findings=len(scan_dict.get("findings", [])),
                summary=scan_dict.get("summary", ""),
                payload=json.dumps(scan_dict, default=str),
            )
            s.add(row); s.commit(); s.refresh(row)
            return int(row.id)

    def list(self, *, limit: int = 50, source: str | None = None,
             tenant_id: str | None = None) -> list[dict]:
        with self.SessionLocal() as s:
            q = s.query(self.Scan).order_by(self.Scan.id.desc())
            if tenant_id: q = q.filter(self.Scan.tenant_id == tenant_id)
            if source:    q = q.filter(self.Scan.source == source)
            return [self._row_to_dict(r) for r in q.limit(limit).all()]

    def get(self, scan_id: int, *, tenant_id: str | None = None) -> dict | None:
        with self.SessionLocal() as s:
            q = s.query(self.Scan).filter(self.Scan.id == scan_id)
            if tenant_id: q = q.filter(self.Scan.tenant_id == tenant_id)
            row = q.first()
            return json.loads(row.payload) if row else None

    def latest_per_host(self, *, tenant_id: str | None = None) -> list[dict]:
        # GROUP BY hostname pulling the row with the max id
        from sqlalchemy import func as _f
        with self.SessionLocal() as s:
            sub = s.query(_f.max(self.Scan.id).label("mid"))
            if tenant_id: sub = sub.filter(self.Scan.tenant_id == tenant_id)
            sub = sub.group_by(self.Scan.hostname).subquery()
            rows = s.query(self.Scan).filter(self.Scan.id.in_(sub)).all()
            return [{
                "id": r.id, "hostname": r.hostname, "ip": r.ip,
                "vendor": r.vendor, "site": r.site,
                "health_score": r.health, "risk_score": r.risk,
                "risk_band": r.risk_band, "eol_status": r.eol_status,
                "cves": r.cves, "findings": r.findings,
                "started_at": r.started_at,
            } for r in rows]

    def audit(self, *, tenant_id: str, actor: str, action: str,
              resource: str = "", detail: str = "") -> None:
        with self.SessionLocal() as s:
            s.add(self.AuditLog(
                tenant_id=tenant_id, actor=actor, action=action,
                resource=resource, detail=detail,
                at=datetime.now(timezone.utc).isoformat(),
            ))
            s.commit()

    def close(self) -> None:
        self.engine.dispose()

    # ---- helpers ----------------------------------------------- #
    def _row_to_dict(self, r) -> dict:
        return {
            "id": r.id, "tenant_id": r.tenant_id, "started_at": r.started_at,
            "source": r.source, "vendor": r.vendor, "hostname": r.hostname,
            "ip": r.ip, "site": r.site, "health": r.health, "risk": r.risk,
            "risk_band": r.risk_band, "eol_status": r.eol_status,
            "cves": r.cves, "findings": r.findings,
        }
