"""Scoped local observations; shared atomic evidence audit, no actuators or APIs."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .public_safety_import import SOURCES, normalize, validate_scope
from .public_safety_exposure import DECISIONS, EXPOSURE_SOURCES, decode_exposure_csv
from .security_import import MAX_BYTES, ImportRejected, decode, digest, timestamp
from .security_store import SecurityEvidenceStore, _identifier, now

_SCHEMA = """
CREATE TABLE IF NOT EXISTS safety_sources (
    tenant TEXT NOT NULL, site TEXT NOT NULL, source TEXT NOT NULL,
    instance TEXT NOT NULL, config TEXT NOT NULL,
    PRIMARY KEY(tenant, site, source, instance)
);
CREATE TABLE IF NOT EXISTS safety_events (
    tenant TEXT NOT NULL, site TEXT NOT NULL, id TEXT NOT NULL, source TEXT NOT NULL,
    instance TEXT NOT NULL, scope_hash TEXT NOT NULL, observed_at TEXT NOT NULL,
    kind TEXT NOT NULL, asset_ref TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(tenant, site, id)
);
CREATE INDEX IF NOT EXISTS safety_event_scope ON
    safety_events(tenant, site, source, instance, scope_hash, observed_at);
CREATE TABLE IF NOT EXISTS safety_imports (
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, site TEXT NOT NULL,
    source TEXT NOT NULL, instance TEXT NOT NULL, imported_at TEXT NOT NULL,
    file_hash TEXT NOT NULL, records INTEGER NOT NULL, inserted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS safety_brand_reviews (
    tenant TEXT NOT NULL, site TEXT NOT NULL, event_id TEXT NOT NULL,
    revision INTEGER NOT NULL, payload TEXT NOT NULL,
    PRIMARY KEY(tenant, site, event_id, revision)
);
CREATE TABLE IF NOT EXISTS safety_telemetry_channels (
    tenant TEXT NOT NULL, site TEXT NOT NULL, event_id TEXT NOT NULL,
    source TEXT NOT NULL, instance TEXT NOT NULL, scope_hash TEXT NOT NULL,
    asset_ref TEXT NOT NULL, channel TEXT NOT NULL, observed_at TEXT NOT NULL,
    PRIMARY KEY(tenant, site, event_id)
);
CREATE INDEX IF NOT EXISTS safety_channel_scope ON
    safety_telemetry_channels(tenant, site, source, instance, scope_hash, asset_ref, channel, observed_at);
"""


class PublicSafetyEvidenceStore(SecurityEvidenceStore):
    def __init__(self, path=None):
        super().__init__(path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def register_file(self, path, **context):
        tenant = _identifier(context["tenant"])
        details = {key: _identifier(context[key]) for key in ("site", "source", "instance")}
        details["actor"] = _identifier(context.get("actor", "local-operator"))
        try:
            with Path(path).open("rb") as stream:
                rows = decode(stream.read(MAX_BYTES + 1), unwrap=False)
            if len(rows) != 1:
                raise ImportRejected("one_scope_required")
        except (ImportRejected, OSError) as error:
            self._rejected(tenant, "safety_register", error, **details)
        return self.register(scope=rows[0], **context)

    def register(self, *, tenant, site, source, instance, source_version, purpose,
                 scope, stale_after=300, actor="local-operator"):
        tenant, site, source, instance, source_version, purpose, actor = map(
            _identifier, (tenant, site, source, instance, source_version, purpose, actor))
        try:
            if isinstance(stale_after, bool) or not isinstance(stale_after, int) or not 30 <= stale_after <= 86400:
                raise ImportRejected("invalid_freshness_window")
            clean_scope = validate_scope(source, scope)
            config = dict(tenant=tenant, site=site, source=source, instance=instance,
                          source_version=source_version, purpose=purpose, scope=clean_scope,
                          stale_after=stale_after, live_connector=False, control_allowed=False)
            config["scope_hash"] = digest(config)
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute("INSERT OR REPLACE INTO safety_sources VALUES(?,?,?,?,?)",
                              (tenant, site, source, instance, json.dumps(config, sort_keys=True)))
            self._audit(tenant, "safety_register", "accepted", actor=actor, site=site,
                        source=source, instance=instance, scope_hash=config["scope_hash"])
            self.conn.commit()
            return config
        except (ImportRejected, TypeError, ValueError) as error:
            self._rejected(tenant, "safety_register", error, site=site, source=source,
                           instance=instance, actor=actor)

    def _rejected(self, tenant, action, error, **details):
        self.conn.rollback()
        reason = str(error) if isinstance(error, ImportRejected) else "file_or_schema_error"
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            self._audit(tenant, action, "rejected", reason=reason, **details,
                        recommendation="Register approved site/source scope; use bounded UTF-8 event exports with valid timestamps and sensor fields.")
        raise ImportRejected(reason) from None

    def import_file(self, path, *, source, tenant, site, instance, actor="local-operator", observed_at=None):
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        except OSError:
            data = None
        return self.import_bytes(data, source=source, tenant=tenant, site=site,
                                 instance=instance, actor=actor, observed_at=observed_at)

    def import_bytes(self, data, *, source, tenant, site, instance, actor="local-operator",
                     observed_at=None, collection_mode="supplied-file", expected_scope_hash=None):
        tenant, site, source, instance, actor = map(_identifier, (tenant, site, source, instance, actor))
        file_hash = None
        try:
            if source not in SOURCES:
                raise ImportRejected("unsupported_safety_source")
            if not isinstance(data, bytes) or collection_mode not in {"supplied-file", "local-api"}:
                raise ImportRejected("file_or_schema_error")
            if source in EXPOSURE_SOURCES and collection_mode != "supplied-file":
                raise ImportRejected("live_brand_collection_forbidden")
            file_hash = hashlib.sha256(data).hexdigest()
            if source in EXPOSURE_SOURCES:
                rows = decode_exposure_csv(data, source, observed_at)
            else:
                if observed_at is not None:
                    raise ImportRejected("observation_time_override_not_allowed")
                rows = decode(data, unwrap=False)
            # Read scope while holding the writer lock; concurrent re-registration
            # cannot change authorization halfway through a batch.
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT config FROM safety_sources WHERE tenant=? AND site=? AND source=? AND instance=?",
                                    (tenant, site, source, instance)).fetchone()
            if row is None:
                raise ImportRejected("source_not_registered")
            config = json.loads(row[0])
            if expected_scope_hash is not None and config["scope_hash"] != expected_scope_hash:
                raise ImportRejected("collection_scope_changed")
            imported_at = now()
            events = [normalize(source, item, config=config, imported_at=imported_at) for item in rows]
            for event in events:
                event["collection_mode"] = collection_mode
                event["live_connector"] = collection_mode == "local-api"
                if collection_mode == "local-api":
                    event["limitations"][0] = "Polled local snapshot; not a complete event stream or verified sensor health."
            inserted = 0
            for event in events:
                event["id"] = digest([tenant, site, source, instance, config["scope_hash"],
                                      event["source_event_id"], event["evidence_hash"]])
                result = self.conn.execute("INSERT OR IGNORE INTO safety_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                                           (tenant, site, event["id"], source, instance, config["scope_hash"],
                                            event["observed_at"], event["kind"], event["asset_ref"], json.dumps(event, sort_keys=True)))
                inserted += result.rowcount
                if result.rowcount and event["kind"] == "telemetry":
                    self.conn.execute("INSERT INTO safety_telemetry_channels VALUES(?,?,?,?,?,?,?,?,?)",
                                      (tenant, site, event["id"], source, instance, config["scope_hash"],
                                       event["asset_ref"], event["evidence"]["key"], event["observed_at"]))
            self.conn.execute("INSERT INTO safety_imports(tenant,site,source,instance,imported_at,file_hash,records,inserted) VALUES(?,?,?,?,?,?,?,?)",
                              (tenant, site, source, instance, imported_at, file_hash, len(events), inserted))
            self._audit(tenant, "safety_import", "accepted", actor=actor, site=site,
                        source=source, instance=instance, scope_hash=config["scope_hash"],
                        file_hash=file_hash, records=len(events), inserted=inserted,
                        collection_mode=collection_mode)
            self.conn.commit()
            return dict(records=len(events), inserted=inserted, duplicates=len(events) - inserted,
                        file_hash=file_hash, status="imported", sensor_health="unknown",
                        live_connector=collection_mode == "local-api")
        except (ImportRejected, OSError, TypeError, ValueError) as error:
            self._rejected(tenant, "safety_import", error, site=site, source=source,
                           instance=instance, actor=actor, file_hash=file_hash)

    def events(self, *, tenant, site, source=None, limit=100):
        tenant, site = map(_identifier, (tenant, site))
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        sql = "SELECT payload FROM safety_events WHERE tenant=? AND site=?"
        params = [tenant, site]
        if source is not None:
            if source not in SOURCES:
                raise ImportRejected("unsupported_safety_source")
            sql += " AND source=?"
            params.append(source)
        sql += " ORDER BY observed_at DESC, id DESC LIMIT ?"
        result = [json.loads(row[0]) for row in self.conn.execute(sql, (*params, limit))]
        for event in result:
            if event["source"] in EXPOSURE_SOURCES:
                review = self.conn.execute("SELECT payload FROM safety_brand_reviews WHERE tenant=? AND site=? AND event_id=? ORDER BY revision DESC LIMIT 1",
                                           (tenant, site, event["id"])).fetchone()
                event["review"] = json.loads(review[0]) if review else dict(decision="unreviewed", revision=0)
                config = self.conn.execute("SELECT config FROM safety_sources WHERE tenant=? AND site=? AND source=? AND instance=?",
                                           (tenant, site, event["source"], event["instance"])).fetchone()
                event["review"]["scope_current"] = bool(config and json.loads(config[0])["scope_hash"] == event["scope_hash"])
                event["review"]["identity_verified"] = False
        self._read_audit(tenant, "safety_events_read", site=site, source=source, records=len(result))
        return result

    def review_brand(self, *, tenant, site, event_id, decision, evidence_ref, expected_revision, actor):
        tenant, site, event_id, actor = map(_identifier, (tenant, site, event_id, actor))
        try:
            evidence_ref = _identifier(evidence_ref)
            if decision not in DECISIONS:
                raise ImportRejected("unsupported_brand_review_decision")
            if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
                raise ImportRejected("invalid_review_revision")
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT payload FROM safety_events WHERE tenant=? AND site=? AND id=?", (tenant, site, event_id)).fetchone()
            if row is None:
                raise ImportRejected("brand_observation_not_found")
            event = json.loads(row[0])
            if event["source"] not in EXPOSURE_SOURCES or event["evidence"]["source_status"] != "Claimed":
                raise ImportRejected("brand_candidate_required")
            row = self.conn.execute("SELECT config FROM safety_sources WHERE tenant=? AND site=? AND source=? AND instance=?",
                                    (tenant, site, event["source"], event["instance"])).fetchone()
            if row is None or json.loads(row[0])["scope_hash"] != event["scope_hash"]:
                raise ImportRejected("review_scope_changed")
            previous = self.conn.execute("SELECT MAX(revision) FROM safety_brand_reviews WHERE tenant=? AND site=? AND event_id=?", (tenant, site, event_id)).fetchone()[0] or 0
            if expected_revision != previous:
                raise ImportRejected("review_revision_conflict")
            review = dict(decision=decision, revision=previous + 1, actor=actor,
                          evidence_ref=evidence_ref, at=now(), event_id=event_id,
                          evidence_hash=event["evidence_hash"], scope_hash=event["scope_hash"],
                          verification="human-attestation", identity_verified=False,
                          limitation="Brand ownership review is not person identification or proof of impersonation; no account action authorized.")
            self.conn.execute("INSERT INTO safety_brand_reviews VALUES(?,?,?,?,?)", (tenant, site, event_id, review["revision"], json.dumps(review, sort_keys=True)))
            self._audit(tenant, "safety_brand_review", "accepted", site=site, actor=actor, review=review)
            self.conn.commit()
            return review
        except (ImportRejected, TypeError, ValueError) as error:
            self._rejected(tenant, "safety_brand_review", error, site=site, event_id=event_id, actor=actor)

    def _read_audit(self, tenant, action, **details):
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            self._audit(tenant, action, "accepted", actor="local-operator", **details)

    def audit(self, *, tenant):
        tenant = _identifier(tenant)
        self._read_audit(tenant, "safety_audit_read")
        return super().audit(tenant=tenant)

    def status(self, *, tenant, site, as_of=None):
        tenant, site = map(_identifier, (tenant, site))
        at = datetime.fromisoformat(timestamp(as_of)) if as_of is not None else datetime.now(timezone.utc)
        result = []
        for row in self.conn.execute("SELECT config FROM safety_sources WHERE tenant=? AND site=? ORDER BY source,instance", (tenant, site)):
            config = json.loads(row[0])
            params = (tenant, site, config["source"], config["instance"], config["scope_hash"])
            query = "SELECT payload FROM safety_events WHERE tenant=? AND site=? AND source=? AND instance=? AND scope_hash=?"
            latest_row = self.conn.execute(query + " ORDER BY observed_at DESC, id DESC LIMIT 1", params).fetchone()
            latest = json.loads(latest_row[0]) if latest_row else None
            freshness = self._freshness(latest, at, config["stale_after"])
            reported = "unknown"
            availability = self.conn.execute(query + " AND kind='availability' ORDER BY observed_at DESC, id DESC LIMIT 1", params).fetchone()
            if availability:
                event = json.loads(availability[0])
                health_age = (at - datetime.fromisoformat(event["observed_at"])).total_seconds()
                count = self.conn.execute("SELECT COUNT(*) FROM safety_events WHERE tenant=? AND site=? AND source=? AND instance=? AND scope_hash=? AND kind='availability' AND observed_at=?",
                                          (*params, event["observed_at"])).fetchone()[0]
                if count == 1 and 0 <= health_age <= config["stale_after"] and not event["evidence"]["retained"]:
                    reported = event["evidence"]["reported_state"]
            assets = []
            refs = config["scope"].get("cameras", config["scope"].get("entities",
                   config["scope"].get("devices", config["scope"].get("brands", {}))))
            for ref in sorted(refs):
                asset_row = self.conn.execute(query + " AND asset_ref=? ORDER BY observed_at DESC, id DESC LIMIT 1", (*params, ref)).fetchone()
                observation = json.loads(asset_row[0]) if asset_row else None
                asset_freshness = self._freshness(observation, at, config["stale_after"])
                asset_state = "unknown"
                if observation and asset_freshness == "fresh-export" and observation["kind"] == "environment":
                    count = self.conn.execute("SELECT COUNT(*) FROM safety_events WHERE tenant=? AND site=? AND source=? AND instance=? AND scope_hash=? AND asset_ref=? AND observed_at=?",
                                              (*params, ref, observation["observed_at"])).fetchone()[0]
                    if count == 1:
                        asset_state = observation["evidence"]["state"]
                assets.append(dict(asset_ref=ref, freshness=asset_freshness,
                                   last_observation=observation["observed_at"] if observation else None,
                                   reported_state=asset_state, sensor_health="unknown"))
                if config["source"] == "thingsboard":
                    assets[-1]["telemetry_channels"] = self._telemetry_status(
                        params, ref, config["scope"]["devices"][ref]["telemetry"], at, config["stale_after"])
            result.append(dict(source=config["source"], instance=config["instance"], site=site,
                               purpose=config["purpose"], scope_hash=config["scope_hash"],
                               latest_observation=latest["observed_at"] if latest else None,
                               freshness=freshness, reported_source_state=reported,
                               sensor_health="unknown", coverage="unknown; scoped observations only",
                               live_connector=False, control_allowed=False,
                               assets=assets,
                               limitation="Fresh observations or online messages do not verify a current connection or live health; availability can be connection-driven rather than periodic."))
        self._read_audit(tenant, "safety_status_read", site=site, sources=len(result))
        return result

    def _telemetry_status(self, params, ref, fields, at, stale_after):
        result = []
        query = "SELECT observed_at,event_id FROM safety_telemetry_channels WHERE tenant=? AND site=? AND source=? AND instance=? AND scope_hash=? AND asset_ref=? AND channel=?"
        for channel, spec in sorted(fields.items()):
            row = self.conn.execute(query + " ORDER BY observed_at DESC,event_id DESC LIMIT 1", (*params, ref, channel)).fetchone()
            event = None
            conflict = False
            if row:
                event = json.loads(self.conn.execute("SELECT payload FROM safety_events WHERE tenant=? AND site=? AND id=?", (*params[:2], row["event_id"])).fetchone()[0])
                conflict = self.conn.execute("SELECT COUNT(*) FROM (" + query + " AND observed_at=? LIMIT 2)", (*params, ref, channel, row["observed_at"])).fetchone()[0] > 1
            freshness = self._freshness(event, at, stale_after)
            usable = event and freshness == "fresh-export" and not conflict
            state = event["evidence"]["state"] if usable else "unknown"
            result.append(dict(channel=channel, sensor_kind=spec["kind"], unit=spec["unit"],
                               freshness=freshness, reported_state=state, conflicting=conflict,
                               value=event["evidence"]["value"] if usable and state == "observed" else None,
                               last_observation=event["observed_at"] if event else None,
                               sensor_health="unknown", calibration="not-verified"))
        return result

    @staticmethod
    def _freshness(event, at, stale_after):
        if event is None:
            return "unknown"
        age = (at - datetime.fromisoformat(event["observed_at"])).total_seconds()
        return "clock-invalid" if age < 0 else "stale" if age > stale_after else "fresh-export"
