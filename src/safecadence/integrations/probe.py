"""Encrypted, bounded passive-log forwarding with certificate-bound signed receipts.

No packet capture, engine downloads, remote commands or physical safety actions.
The separately installed capture worker supplies approved Zeek/Suricata JSON logs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from .local_connectors import ConnectorRejected, LocalHTTPS, private_file
from .security_import import MAX_BYTES, ImportRejected, decode, digest, normalize, redact, timestamp
from .security_store import SecurityEvidenceStore, _identifier, now

SOURCES = frozenset({"zeek", "suricata"})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def signing_key(path):
    key = private_file(path).strip()
    try:
        key = bytes.fromhex(key.decode("ascii"))
    except (UnicodeError, ValueError):
        raise ConnectorRejected("invalid_probe_key") from None
    if len(key) != 32:
        raise ConnectorRejected("invalid_probe_key")
    return key


def scope(config):
    if not isinstance(config, dict):
        raise ConnectorRejected("invalid_probe_scope")
    result = {key: _identifier(config[key]) for key in
              ("probe_id", "tenant", "site", "segment", "instance", "source_version")}
    sources = config["sources"]
    if not isinstance(sources, list) or not sources or len(sources) != len(set(sources)) or set(sources) - SOURCES:
        raise ConnectorRejected("invalid_probe_sources")
    result["sources"] = sorted(sources)
    return result


def health_metrics(metrics):
    allowed = {"capture_drops", "parser_errors", "interface_up", "rule_version"}
    if not isinstance(metrics, dict) or set(metrics) - allowed:
        raise ConnectorRejected("invalid_health_metrics")
    for key in ("capture_drops", "parser_errors"):
        if key in metrics and (isinstance(metrics[key], bool) or not isinstance(metrics[key], int) or metrics[key] < 0):
            raise ConnectorRejected("invalid_health_metrics")
    if "interface_up" in metrics and not isinstance(metrics["interface_up"], bool):
        raise ConnectorRejected("invalid_health_metrics")
    if "rule_version" in metrics:
        _identifier(metrics["rule_version"])
    return metrics


class ProbeSpool:
    def __init__(self, path, *, config, encryption_key_file, max_records=10000, max_bytes=32 * 1024 * 1024):
        from cryptography.fernet import Fernet
        self.scope = scope(config)
        if (isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= 100000 or
                isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1024 <= max_bytes <= 256 * 1024 * 1024):
            raise ConnectorRejected("invalid_spool_limits")
        self.cipher = Fernet(private_file(encryption_key_file).strip())
        self.max_records, self.max_bytes = max_records, max_bytes
        self.store = SecurityEvidenceStore(path)
        self.conn = self.store.conn
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript("""
          CREATE TABLE IF NOT EXISTS probe_queue(seq INTEGER PRIMARY KEY, payload BLOB NOT NULL, hash TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS probe_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        fingerprint = digest(self.scope)
        prior = self.conn.execute("SELECT value FROM probe_meta WHERE key='scope'").fetchone()
        if prior and prior[0] != fingerprint:
            self.close()
            raise ConnectorRejected("spool_scope_changed")
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO probe_meta VALUES('scope',?)", (fingerprint,))
            self.conn.execute("INSERT OR IGNORE INTO probe_meta VALUES('next','1')")

    def close(self):
        self.store.close()

    def stage(self, data, *, source, checkpoint=None):
        try:
            if source not in self.scope["sources"]:
                raise ConnectorRejected("probe_source_out_of_scope")
            rows = [] if checkpoint and not data.strip() else decode(data)
            if not rows:
                if checkpoint:
                    with self.conn:
                        self.conn.execute("BEGIN IMMEDIATE")
                        self.conn.execute("INSERT OR REPLACE INTO probe_meta VALUES(?,?)", (checkpoint[0], canonical(checkpoint[1]).decode()))
                        self.store._audit(self.scope["tenant"], "probe_log_checkpoint", "accepted",
                                          probe_id=self.scope["probe_id"], records=0,
                                          coverage_warning=checkpoint[1]["rotation_warning"])
                return dict(staged=0, **self.status())
            clean = []
            for row in rows:
                normalize(source, row, source_version=self.scope["source_version"],
                          instance=self.scope["instance"], imported_at=now())
                clean.append(redact(row))
            return self._enqueue("events", source, clean, checkpoint=checkpoint)
        except (ImportRejected, ValueError, TypeError, sqlite3.Error) as error:
            reason = str(error) if isinstance(error, ImportRejected) else "local_storage_failed" if isinstance(error, sqlite3.Error) else "probe_stage_failed"
            self._failure(reason)
            raise ConnectorRejected(reason) from None

    def heartbeat(self, metrics=None):
        try:
            metrics = health_metrics({} if metrics is None else metrics)
            return self._enqueue("heartbeat", None, dict(metrics=metrics, queue=self.status(), sampled_at=now(),
                                   capture_health="reported, not independently verified", coverage="unknown"))
        except (ImportRejected, ValueError, TypeError, sqlite3.Error) as error:
            reason = str(error) if isinstance(error, ImportRejected) else "local_storage_failed" if isinstance(error, sqlite3.Error) else "probe_heartbeat_failed"
            self._failure(reason)
            raise ConnectorRejected(reason) from None

    def follow_once(self, path, *, source, accept_rotation=False):
        """Read complete bounded JSONL records, checkpoint atomically with the queue."""
        cursor_key = "cursor:" + digest([source, str(Path(path).absolute())])
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ConnectorRejected("regular_log_file_required")
            identity = str(info.st_dev) + ":" + str(info.st_ino)
            prior = self.conn.execute("SELECT value FROM probe_meta WHERE key=?", (cursor_key,)).fetchone()
            previous = json.loads(prior[0]) if prior else None
            offset, warning = 0, None
            if previous:
                if previous["identity"] != identity or info.st_size < previous["offset"]:
                    if not accept_rotation:
                        self._failure("log_rotation_or_truncation_requires_review")
                        raise ConnectorRejected("log_rotation_or_truncation_requires_review")
                    warning = "possible_rotation_gap; stage retained rotated logs separately"
                else:
                    offset = previous["offset"]
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, MAX_BYTES)
            parts = data.split(b"\n", 10000)
            if len(parts) > 10000:
                data = b"\n".join(parts[:10000]) + b"\n"
            boundary = data.rfind(b"\n") + 1
            if not boundary:
                if len(data) == MAX_BYTES:
                    self._failure("incomplete_record_size_limit")
                    raise ConnectorRejected("incomplete_record_size_limit")
                return dict(staged=0, partial_record=bool(data), **self.status())
            checkpoint = (cursor_key, dict(identity=identity, offset=offset + boundary, rotation_warning=warning))
            result = self.stage(data[:boundary], source=source, checkpoint=checkpoint)
            if warning:
                result["coverage_warning"] = warning
            return result
        finally:
            os.close(fd)

    def _enqueue(self, kind, source, records, *, checkpoint=None):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            sequence = int(self.conn.execute("SELECT value FROM probe_meta WHERE key='next'").fetchone()[0])
            body = canonical(dict(schema=1, **self.scope, sequence=sequence, kind=kind, source=source,
                                  records=records, created_at=now()))
            if len(body) > MAX_BYTES:
                raise ConnectorRejected("probe_batch_size_limit")
            encrypted = self.cipher.encrypt(body)
            status = self.status()
            # Capacity counts actual queued observation rows, not just batches.
            count = len(records) if kind == "events" else 1
            queued_count = int(self.conn.execute("SELECT COALESCE(SUM(CAST(value AS INTEGER)),0) FROM probe_meta WHERE key LIKE 'count:%'").fetchone()[0])
            if queued_count + count > self.max_records or status["encrypted_bytes"] + len(encrypted) > self.max_bytes:
                raise ConnectorRejected("spool_capacity_exceeded")
            self.conn.execute("INSERT INTO probe_queue VALUES(?,?,?)", (sequence, encrypted, hashlib.sha256(body).hexdigest()))
            self.conn.execute("INSERT INTO probe_meta VALUES(?,?)", ("count:" + str(sequence), str(count)))
            self.conn.execute("UPDATE probe_meta SET value=? WHERE key='next'", (str(sequence + 1),))
            if checkpoint:
                self.conn.execute("INSERT OR REPLACE INTO probe_meta VALUES(?,?)", (checkpoint[0], canonical(checkpoint[1]).decode()))
            self.store._audit(self.scope["tenant"], "probe_stage", "accepted", probe_id=self.scope["probe_id"],
                              sequence=sequence, kind=kind, records=count,
                              coverage_warning=checkpoint[1]["rotation_warning"] if checkpoint else None)
            self.conn.commit()
            return dict(staged=count, sequence=sequence, **self.status())
        except Exception:
            self.conn.rollback()
            raise

    def _failure(self, reason):
        self.conn.rollback()
        try:
            with self.conn:
                self.conn.execute("BEGIN IMMEDIATE")
                self.store._audit(self.scope["tenant"], "probe_queue", "rejected", reason=reason,
                    probe_id=self.scope["probe_id"], recommendation="Preserve source logs; resolve invalid data or queue pressure, then retry. Data is not silently dropped.")
        except sqlite3.Error:
            self.conn.rollback()
            raise ConnectorRejected("local_storage_failed_audit_unavailable") from None

    def status(self):
        result = self.conn.execute("SELECT COUNT(*),COALESCE(SUM(length(payload)),0),MIN(seq) FROM probe_queue").fetchone()
        return dict(queued_batches=result[0], encrypted_bytes=result[1], next_pending=result[2],
                    capture_health="unknown", hardware_qualified=False)

    def pending(self):
        row = self.conn.execute("SELECT seq,payload,hash FROM probe_queue ORDER BY seq LIMIT 1").fetchone()
        if row is None:
            return None
        try:
            body = self.cipher.decrypt(row[1])
        except Exception:
            raise ConnectorRejected("spool_integrity_failed") from None
        if hashlib.sha256(body).hexdigest() != row[2]:
            raise ConnectorRejected("spool_integrity_failed")
        return row[0], body, row[2]

    def acknowledge(self, sequence, batch_hash, receipt):
        if (receipt.get("probe_id") != self.scope["probe_id"] or receipt.get("sequence") != sequence or
                receipt.get("batch_hash") != batch_hash or receipt.get("status") not in {"accepted", "duplicate"}):
            raise ConnectorRejected("collector_receipt_mismatch")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            pending = self.conn.execute("SELECT seq,hash FROM probe_queue ORDER BY seq LIMIT 1").fetchone()
            if pending is None or tuple(pending) != (sequence, batch_hash):
                raise ConnectorRejected("spool_ack_out_of_order")
            self.conn.execute("DELETE FROM probe_queue WHERE seq=?", (sequence,))
            self.conn.execute("DELETE FROM probe_meta WHERE key=?", ("count:" + str(sequence),))
            self.store._audit(self.scope["tenant"], "probe_delivered", "accepted", probe_id=self.scope["probe_id"],
                              sequence=sequence, batch_hash=batch_hash)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def deliver_one(self, transport, *, auth_key_file):
        pending = self.pending()
        if pending is None:
            return dict(delivered=0, **self.status())
        sequence, body, batch_hash = pending
        signature = hmac.new(signing_key(auth_key_file), body, hashlib.sha256).hexdigest()
        try:
            receipt = json.loads(transport.send_batch(body, signature))
            self.acknowledge(sequence, batch_hash, receipt)
            return dict(delivered=1, sequence=sequence, **self.status())
        except (ImportRejected, OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
            self._failure(str(error) if isinstance(error, ImportRejected) else "collector_delivery_failed")
            raise ConnectorRejected("collector_delivery_failed_queue_preserved") from None


class CollectorTransport(LocalHTTPS):
    def __init__(self, *args, **kwargs):
        if not kwargs.get("client_cert") or not kwargs.get("client_key"):
            raise ConnectorRejected("collector_mtls_required")
        super().__init__(*args, **kwargs)

    def send_batch(self, body, signature):
        return self._request("POST", "/v1/probe/batch", body=body,
                             headers={"Content-Type": "application/json", "X-Probe-Signature": signature})


class ProbeCollector(SecurityEvidenceStore):
    def __init__(self, path):
        super().__init__(path)
        self.conn.executescript("""
          CREATE TABLE IF NOT EXISTS probe_receipts(probe_id TEXT NOT NULL, seq INTEGER NOT NULL,
            hash TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(probe_id,seq));
          CREATE TABLE IF NOT EXISTS probe_enrollments(probe_id TEXT PRIMARY KEY, scope_hash TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS probe_health(probe_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, payload TEXT NOT NULL);
        """)
        self.conn.commit()

    def accept(self, body, signature, *, enrollment, certificate_sha256):
        approved = scope(enrollment)
        tenant = approved["tenant"]
        try:
            if enrollment.get("enabled") is not True:
                raise ConnectorRejected("probe_revoked")
            expires = timestamp(enrollment.get("expires_at"))
            if expires is None or datetime.fromisoformat(expires) <= datetime.now(timezone.utc):
                raise ConnectorRejected("probe_enrollment_expired")
            if (not isinstance(certificate_sha256, str) or len(certificate_sha256) != 64 or
                    not hmac.compare_digest(certificate_sha256, enrollment.get("certificate_sha256", ""))):
                raise ConnectorRejected("probe_certificate_mismatch")
            if not isinstance(body, bytes) or len(body) > MAX_BYTES:
                raise ConnectorRejected("probe_batch_size_limit")
            expected = hmac.new(signing_key(enrollment["auth_key_file"]), body, hashlib.sha256).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
                raise ConnectorRejected("probe_signature_invalid")
            rows = decode(body, unwrap=False)
            if len(rows) != 1:
                raise ConnectorRejected("probe_envelope_required")
            value = rows[0]
            required = set(approved) | {"schema", "sequence", "kind", "source", "records", "created_at"}
            if set(value) != required or scope(value) != approved or type(value["schema"]) is not int or value["schema"] != 1:
                raise ConnectorRejected("probe_scope_mismatch")
            sequence = value["sequence"]
            if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= 2**63 - 1:
                raise ConnectorRejected("invalid_probe_sequence")
            created = timestamp(value["created_at"])
            if created is None or datetime.fromisoformat(created).timestamp() > time.time() + 300:
                raise ConnectorRejected("invalid_probe_clock")
            source, records, kind = value["source"], value["records"], value["kind"]
            imported_at = now()
            if kind == "events":
                if source not in approved["sources"] or not isinstance(records, list) or not 1 <= len(records) <= 10000:
                    raise ConnectorRejected("invalid_probe_records")
                events = [normalize(source, record, source_version=approved["source_version"],
                                    instance=approved["instance"], imported_at=imported_at) for record in records]
            elif kind == "heartbeat":
                if source is not None or not isinstance(records, dict) or set(records) != {
                        "metrics", "queue", "sampled_at", "capture_health", "coverage"}:
                    raise ConnectorRejected("invalid_probe_heartbeat")
                health_metrics(records["metrics"])
                if timestamp(records["sampled_at"]) is None:
                    raise ConnectorRejected("invalid_probe_heartbeat")
                queue = records["queue"]
                if not isinstance(queue, dict) or set(queue) != {"queued_batches", "encrypted_bytes", "next_pending", "capture_health", "hardware_qualified"}:
                    raise ConnectorRejected("invalid_probe_heartbeat")
                for field in ("queued_batches", "encrypted_bytes"):
                    if isinstance(queue[field], bool) or not isinstance(queue[field], int) or queue[field] < 0:
                        raise ConnectorRejected("invalid_probe_heartbeat")
                if queue["next_pending"] is not None and (isinstance(queue["next_pending"], bool) or not isinstance(queue["next_pending"], int) or queue["next_pending"] < 1):
                    raise ConnectorRejected("invalid_probe_heartbeat")
                if (queue["hardware_qualified"] is not False or queue["capture_health"] != "unknown" or
                        records["coverage"] != "unknown" or records["capture_health"] != "reported, not independently verified"):
                    raise ConnectorRejected("invalid_probe_heartbeat")
                events = []
            else:
                raise ConnectorRejected("invalid_probe_kind")
            batch_hash = hashlib.sha256(body).hexdigest()
            self.conn.execute("BEGIN IMMEDIATE")
            frozen = self.conn.execute("SELECT scope_hash FROM probe_enrollments WHERE probe_id=?", (approved["probe_id"],)).fetchone()
            if frozen and frozen[0] != digest(approved):
                raise ConnectorRejected("collector_enrollment_scope_changed")
            prior = self.conn.execute("SELECT hash,payload FROM probe_receipts WHERE probe_id=? AND seq=?",
                                      (approved["probe_id"], sequence)).fetchone()
            if prior:
                if prior[0] != batch_hash:
                    raise ConnectorRejected("probe_sequence_collision")
                receipt = json.loads(prior[1])
                receipt["status"] = "duplicate"
                self._audit(tenant, "probe_collect", "duplicate", probe_id=approved["probe_id"], sequence=sequence)
                self.conn.commit()
                return receipt
            last = self.conn.execute("SELECT COALESCE(MAX(seq),0) FROM probe_receipts WHERE probe_id=?", (approved["probe_id"],)).fetchone()[0]
            if sequence != last + 1:
                raise ConnectorRejected("probe_sequence_gap")
            self.conn.execute("INSERT OR IGNORE INTO probe_enrollments VALUES(?,?)", (approved["probe_id"], digest(approved)))
            inserted = 0
            for event in events:
                event.update(tenant=tenant, collection_mode="probe", probe_id=approved["probe_id"],
                             site=approved["site"], segment=approved["segment"], queue_sequence=sequence)
                event["limitations"][0] = "Passive engine log; mirror coverage and hardware capacity not independently verified."
                event["id"] = digest([tenant, source, approved["instance"], event["source_event_id"], event["evidence_hash"]])
                result = self.conn.execute("INSERT OR IGNORE INTO security_events VALUES(?,?,?,?,?,?)",
                    (tenant, event["id"], source, approved["instance"], event["source_event_id"], canonical(event).decode()))
                inserted += result.rowcount
            receipt = dict(probe_id=approved["probe_id"], sequence=sequence, batch_hash=batch_hash,
                           status="accepted", inserted=inserted, received_at=imported_at)
            self.conn.execute("INSERT INTO probe_receipts VALUES(?,?,?,?)",
                               (approved["probe_id"], sequence, batch_hash, canonical(receipt).decode()))
            if kind == "heartbeat":
                health = dict(probe_id=approved["probe_id"], site=approved["site"], segment=approved["segment"],
                              received_at=imported_at, sequence=sequence, **records)
                self.conn.execute("INSERT OR REPLACE INTO probe_health VALUES(?,?,?)",
                                  (approved["probe_id"], tenant, canonical(health).decode()))
            self._audit(tenant, "probe_collect", "accepted", probe_id=approved["probe_id"], site=approved["site"],
                        segment=approved["segment"], sequence=sequence, kind=kind, inserted=inserted,
                        heartbeat=records if kind == "heartbeat" else None)
            self.conn.commit()
            return receipt
        except (ImportRejected, ValueError, TypeError, KeyError, OSError, sqlite3.Error) as error:
            self.conn.rollback()
            reason = str(error) if isinstance(error, ImportRejected) else "invalid_probe_envelope"
            try:
                with self.conn:
                    self.conn.execute("BEGIN IMMEDIATE")
                    self._audit(tenant, "probe_collect", "rejected", probe_id=approved["probe_id"], reason=reason,
                                recommendation="Verify enrollment, certificate, scope, sequence and queue integrity; preserve queued evidence.")
            except sqlite3.Error:
                self.conn.rollback()
                raise ConnectorRejected("collector_storage_failed_audit_unavailable") from None
            raise ConnectorRejected(reason) from None

    def health(self, *, tenant, stale_after=120, at=None):
        tenant = _identifier(tenant)
        if isinstance(stale_after, bool) or not isinstance(stale_after, int) or not 30 <= stale_after <= 86400:
            raise ConnectorRejected("invalid_probe_freshness_window")
        at = datetime.fromisoformat(timestamp(at or now()))
        result = []
        for row in self.conn.execute("SELECT payload FROM probe_health WHERE tenant=?", (tenant,)):
            value = json.loads(row[0])
            age = (at - datetime.fromisoformat(timestamp(value["sampled_at"]))).total_seconds()
            value.update(report_age_seconds=age, heartbeat_state="clock-skew" if age < -30 else
                         "stale" if age > stale_after else "recent-report",
                         sensor_health="unknown; operator/engine metrics are not independent coverage verification",
                         enrollment_current="not evaluated by this status command", hardware_qualified=False)
            result.append(value)
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            self._audit(tenant, "probe_health_read", "accepted", records=len(result))
        return result
