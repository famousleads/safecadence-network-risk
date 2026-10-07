"""Atomic, tenant-scoped local evidence and hash-chained import audit."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .security_import import MAX_BYTES, ImportRejected, decode, digest, normalize
from .security_catalog import IMPORT_SOURCES

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    tenant TEXT NOT NULL, id TEXT NOT NULL, source TEXT NOT NULL,
    instance TEXT NOT NULL, event_id TEXT NOT NULL, payload TEXT NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX IF NOT EXISTS security_events_source ON security_events(tenant, source, instance);
CREATE TABLE IF NOT EXISTS security_imports (
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, source TEXT NOT NULL,
    instance TEXT NOT NULL, imported_at TEXT NOT NULL, file_hash TEXT NOT NULL,
    record_count INTEGER NOT NULL, inserted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS security_import_audit (
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL,
    previous_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ImportRejected("invalid_context_identifier")
    return value


def now():
    return datetime.now(timezone.utc).isoformat()


class SecurityEvidenceStore:
    def __init__(self, path=None):
        root = Path(os.environ.get("SC_DATA_DIR") or Path.home() / ".safecadence")
        self.path = Path(path) if path else root / "security-evidence.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        os.chmod(self.path, 0o600)

    def close(self):
        self.conn.close()

    def _audit(self, tenant, action, status, **details):
        last = self.conn.execute(
            "SELECT hash FROM security_import_audit WHERE tenant=? ORDER BY id DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        previous = last["hash"] if last else "0" * 64
        payload = json.dumps(dict(at=now(), action=action, status=status, **details),
                             sort_keys=True, separators=(",", ":"))
        chain_hash = hashlib.sha256((previous + payload).encode()).hexdigest()
        self.conn.execute(
            "INSERT INTO security_import_audit(tenant,payload,previous_hash,hash) VALUES(?,?,?,?)",
            (tenant, payload, previous, chain_hash),
        )

    def import_file(self, path, *, source, tenant, instance, source_version, actor="local-operator"):
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        except OSError:
            data = None
        return self.import_bytes(data, source=source, tenant=tenant, instance=instance,
                                 source_version=source_version, actor=actor)

    def import_bytes(self, data, *, source, tenant, instance, source_version,
                     actor="local-operator", collection_mode="supplied-file"):
        tenant, instance = _identifier(tenant), _identifier(instance)
        source, source_version, actor = map(_identifier, (source, source_version, actor))
        file_hash = None
        try:
            if source not in IMPORT_SOURCES:
                raise ImportRejected("unsupported_source")
            if not isinstance(data, bytes) or collection_mode not in {"supplied-file", "local-api", "probe"}:
                raise ImportRejected("file_or_schema_error")
            file_hash = hashlib.sha256(data).hexdigest()
            imported_at = now()
            rows = decode(data)
            events = [normalize(source, row, source_version=source_version,
                                instance=instance, imported_at=imported_at) for row in rows]
            for event in events:
                event["collection_mode"] = collection_mode
                if collection_mode != "supplied-file":
                    event["limitations"][0] = "Local collection; not verified compromise or complete coverage."
            # Validate the full batch before any writes; serialize writers for the audit chain.
            self.conn.execute("BEGIN IMMEDIATE")
            inserted = 0
            for event in events:
                identity = [tenant, source, instance, event["source_event_id"], event["evidence_hash"]]
                event["id"] = digest(identity)
                event["tenant"] = tenant
                result = self.conn.execute(
                    "INSERT OR IGNORE INTO security_events VALUES(?,?,?,?,?,?)",
                    (tenant, event["id"], source, instance, event["source_event_id"],
                     json.dumps(event, sort_keys=True, allow_nan=False)),
                )
                inserted += result.rowcount
            self.conn.execute(
                "INSERT INTO security_imports(tenant,source,instance,imported_at,file_hash,record_count,inserted) "
                "VALUES(?,?,?,?,?,?,?)",
                (tenant, source, instance, imported_at, file_hash, len(events), inserted),
            )
            self._audit(tenant, "import", "accepted", source=source, instance=instance,
                        actor=actor, file_hash=file_hash, records=len(events), inserted=inserted,
                        collection_mode=collection_mode)
            self.conn.commit()
            return dict(records=len(events), inserted=inserted, duplicates=len(events) - inserted,
                        file_hash=file_hash, status="imported", sensor_health="unknown")
        except (ImportRejected, OSError, TypeError, ValueError) as error:
            self.conn.rollback()
            reason = str(error) if isinstance(error, ImportRejected) else "file_or_schema_error"
            with self.conn:
                self.conn.execute("BEGIN IMMEDIATE")
                self._audit(tenant, "import", "rejected", source=source, instance=instance,
                            actor=actor, file_hash=file_hash, reason=reason,
                            recommendation="Use a supported, bounded UTF-8 export with valid fields and timestamps.")
            raise ImportRejected(reason) from None

    def events(self, *, tenant, source=None, limit=100):
        tenant = _identifier(tenant)
        if not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        sql = "SELECT payload FROM security_events WHERE tenant=?"
        params = [tenant]
        if source:
            sql += " AND source=?"
            params.append(_identifier(source))
        sql += " ORDER BY rowid DESC LIMIT ?"
        return [json.loads(row[0]) for row in self.conn.execute(sql, (*params, limit))]

    def audit(self, *, tenant):
        tenant = _identifier(tenant)
        rows = self.conn.execute(
            "SELECT * FROM security_import_audit WHERE tenant=? ORDER BY id", (tenant,)
        ).fetchall()
        previous = "0" * 64
        valid = True
        records = []
        for row in rows:
            expected = hashlib.sha256((previous + row["payload"]).encode()).hexdigest()
            valid = valid and row["previous_hash"] == previous and row["hash"] == expected
            previous = row["hash"]
            records.append(dict(json.loads(row["payload"]), hash=row["hash"]))
        return dict(chain_valid=valid, records=records,
                    limitation="Detects chain edits, not deletion of the entire chain or its tail; no external anchor.")

    def status(self, *, tenant):
        tenant = _identifier(tenant)
        rows = self.conn.execute(
            "SELECT i.* FROM security_imports i WHERE tenant=? AND id IN "
            "(SELECT MAX(id) FROM security_imports WHERE tenant=? GROUP BY source,instance)",
            (tenant, tenant),
        ).fetchall()
        cutoff = datetime.now(timezone.utc) - timedelta(days=2)
        return [dict(source=row["source"], instance=row["instance"],
                     last_import=row["imported_at"], records=row["record_count"],
                     receipt_stale=datetime.fromisoformat(row["imported_at"]) < cutoff,
                     sensor_health="unknown", live_connector=False,
                     coverage="unknown; bounded local evidence only",
                     limitation="Import receipts do not establish a currently connected or healthy sensor.") for row in rows]

    def export_graph(self, *, tenant, graph_path):
        from safecadence.graph.schema import Node, Edge
        from safecadence.graph.store import GraphStore
        tenant = _identifier(tenant)
        graph = GraphStore(graph_path)
        try:
            for row in self.conn.execute("SELECT payload FROM security_events WHERE tenant=?", (tenant,)):
                event = json.loads(row[0])
                if event["kind"] != "alert":
                    continue  # Observations do not become vulnerability findings.
                finding_id = "security:" + event["id"]
                graph.add_node(Node("finding", finding_id, event["title"], tuple({
                    "tenant": tenant, "severity": event["severity"], "source": event["source"],
                    "evidence_id": event["id"], "verification": "unverified alert",
                }.items())))
                if event["asset_ref"]:
                    asset_id = "security:" + digest([tenant, event["source"], event["instance"], event["asset_ref"]])
                    graph.add_node(Node("asset", asset_id, event["asset_ref"],
                                        (("tenant", tenant), ("identity_status", "source-scoped reference"))))
                    graph.add_edge(Edge("asset", asset_id, "exposes", "finding", finding_id))
            return graph.count()
        finally:
            graph._conn.close()
