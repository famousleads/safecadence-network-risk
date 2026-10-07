"""Scoped offline pilot fixtures; no brokers, cameras, actuators or remote models."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from safecadence.integrations.public_safety_cli import safety
from safecadence.integrations.public_safety_import import validate_scope
from safecadence.integrations.public_safety_store import PublicSafetyEvidenceStore
from safecadence.integrations.security_catalog import catalog
from safecadence.integrations.security_import import ImportRejected
from safecadence.integrations.security_store import SecurityEvidenceStore

TIME = "2026-10-06T12:00:00+00:00"
EPOCH = 1791288000
SCOPE = {"cameras": {"entry": ["restricted"]}}
HA_SCOPE = {"entities": {"binary_sensor.door": "door", "sensor.room": "temperature"}}


def frigate(lifecycle="new", frame=EPOCH):
    return {"topic": "frigate/events", "captured_at": TIME, "retained": False,
            "payload": {"type": lifecycle, "after": {
                "id": "fixture-1", "camera": "entry", "label": "person",
                "frame_time": frame, "end_time": frame if lifecycle == "end" else None,
                "score": 0.8, "false_positive": False,
                "current_zones": ["restricted", "private-zone"], "entered_zones": ["restricted"],
                "sub_label": "PRIVATE-NAME", "recognized_license_plate": "PRIVATE-PLATE",
                "clip_url": "https://example.com/private?token=TOPSECRET",
                "attributes": {"face": "PRIVATE-FACE"}, "authorization": "TOPSECRET"}}}


def availability(state="online", captured=TIME, retained=False):
    return {"topic": "frigate/available", "captured_at": captured,
            "payload": state, "retained": retained}


def home(entity="binary_sensor.door", kind="door", state="on", unit=None):
    attrs = {"device_class": kind, "friendly_name": "PRIVATE-NAME", "token": "TOPSECRET"}
    if unit is not None:
        attrs["unit_of_measurement"] = unit
    return {"id": 42, "type": "event", "event": {
        "event_type": "state_changed", "time_fired": TIME,
        "context": {"user_id": "PRIVATE-USER"},
        "data": {"entity_id": entity, "new_state": {
            "entity_id": entity, "state": state, "attributes": attrs}}}}


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = PublicSafetyEvidenceStore(self.root / "evidence.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def register(self, source="frigate", **changes):
        args = dict(tenant="agency", site="station", source=source, instance="source-1",
                    source_version="fixture-v1", purpose="facility-safety",
                    scope=SCOPE if source == "frigate" else HA_SCOPE, stale_after=300)
        args.update(changes)
        return self.store.register(**args)

    def put(self, rows=None, source="frigate", **changes):
        path = self.root / "events.json"
        path.write_bytes(json.dumps(frigate() if rows is None else rows).encode())
        args = dict(source=source, tenant="agency", site="station", instance="source-1")
        args.update(changes)
        return self.store.import_file(path, **args)

    def events(self, **changes):
        args = dict(tenant="agency", site="station")
        args.update(changes)
        return self.store.events(**args)

    def status(self, at=TIME):
        return self.store.status(tenant="agency", site="station", as_of=at)[0]

    def test_registry_does_not_claim_live_engines(self):
        rows = catalog()
        self.assertEqual(len(rows), 32)
        self.assertEqual(sum(r["status"] == "file-import" for r in rows), 4)
        self.assertEqual(sum(r["public_safety_status"] == "scoped-file-import" for r in rows), 3)
        self.assertEqual(sum(r["public_safety_status"] == "scoped-csv-review" for r in rows), 2)
        self.assertFalse(any(r["live_connector"] or r["engine_installed"] for r in rows))

    def test_registration_required_even_for_empty_batch(self):
        with self.assertRaisesRegex(ImportRejected, "source_not_registered"):
            self.put([])
        audit = self.store.audit(tenant="agency")
        self.assertTrue(audit["chain_valid"])
        failure = next(r for r in audit["records"] if r["status"] == "rejected")
        self.assertIn("recommendation", failure)

    def test_site_and_tenant_and_instance_isolation(self):
        ids = set()
        for tenant in ("agency", "other"):
            for site in ("station", "campus"):
                for instance in ("source-1", "source-2"):
                    self.register(tenant=tenant, site=site, instance=instance)
                    self.put(tenant=tenant, site=site, instance=instance)
                rows = self.events(tenant=tenant, site=site)
                self.assertEqual(len(rows), 2)
                self.assertTrue(ids.isdisjoint(r["id"] for r in rows))
                ids.update(r["id"] for r in rows)
        self.assertEqual(self.events(site="missing"), [])

    def test_scope_cannot_be_bypassed_by_import_site(self):
        self.register()
        with self.assertRaisesRegex(ImportRejected, "source_not_registered"):
            self.put(site="other")
        self.assertEqual(self.events(), [])

    def test_presence_minimization_no_identities_or_urls_saved(self):
        self.register()
        self.put()
        event = self.events()[0]
        self.assertEqual(event["kind"], "presence")
        self.assertEqual(event["evidence"]["current_zones"], ["restricted"])
        self.assertEqual(event["severity"], "unreviewed")
        self.assertIsNone(event["confidence"])
        self.assertFalse(event["control_allowed"])
        for marker in ("TOPSECRET", "PRIVATE-NAME", "PRIVATE-PLATE", "PRIVATE-FACE", "private-zone", "https://"):
            self.assertNotIn(marker, json.dumps(event))
            self.assertNotIn(marker.encode(), (self.root / "evidence.db").read_bytes())

    def test_duplicate_replay_and_lifecycle_versions(self):
        self.register()
        self.assertEqual(self.put()["inserted"], 1)
        self.assertEqual(self.put()["duplicates"], 1)
        self.put(frigate("update", EPOCH + 10))
        self.put(frigate("end", EPOCH + 20))
        rows = self.events()
        self.assertEqual([r["evidence"]["lifecycle"] for r in rows], ["end", "update", "new"])
        self.assertEqual(len({r["source_event_id"] for r in rows}), 1)

    def test_backfilled_observation_cannot_replace_latest(self):
        self.register()
        self.put(frigate("end", EPOCH + 20))
        self.put(frigate("new", EPOCH - 20))
        self.assertEqual(self.events()[0]["evidence"]["lifecycle"], "end")

    def test_out_of_scope_batch_is_atomic_and_audited(self):
        self.register()
        bad = frigate()
        bad["payload"]["after"]["camera"] = "unauthorized"
        with self.assertRaisesRegex(ImportRejected, "camera_out_of_scope"):
            self.put([frigate(), bad])
        self.assertEqual(self.events(), [])
        self.assertTrue(any(r.get("reason") == "camera_out_of_scope" for r in self.store.audit(tenant="agency")["records"]))

    def test_unapproved_zone_rejected(self):
        self.register()
        bad = frigate()
        bad["payload"]["after"].update(current_zones=["private"], entered_zones=[])
        with self.assertRaisesRegex(ImportRejected, "zone_out_of_scope"):
            self.put(bad)

    def test_end_event_can_have_no_current_zone(self):
        self.register()
        row = frigate("end")
        row["payload"]["after"]["current_zones"] = []
        self.put(row)
        self.assertEqual(self.events()[0]["evidence"]["current_zones"], [])

    def test_frigate_commands_rejected(self):
        self.register()
        for topic in ("frigate/restart", "frigate/entry/detect/set", "other/events"):
            with self.subTest(topic=topic), self.assertRaisesRegex(ImportRejected, "unsupported_frigate_topic"):
                self.put(dict(availability(), topic=topic))

    def test_frigate_invalid_fields_matrix(self):
        self.register()
        for change in ({"score": True}, {"score": 2}, {"label": "face"},
                       {"false_positive": "no"}, {"frame_time": None},
                       {"id": "bad/id"}, {"current_zones": "restricted"}):
            row = frigate()
            row["payload"]["after"].update(change)
            with self.subTest(change=change), self.assertRaises(ImportRejected):
                self.put(row)

    def test_retained_flag_and_capture_time_validated(self):
        self.register()
        for row in (dict(availability(), retained="false"), dict(availability(), captured_at=None)):
            with self.assertRaises(ImportRejected):
                self.put(row)

    def test_reported_online_is_not_verified_live_health(self):
        self.register()
        self.put(availability())
        result = self.status()
        self.assertEqual(result["reported_source_state"], "online")
        self.assertEqual(result["freshness"], "fresh-export")
        self.assertEqual(result["sensor_health"], "unknown")
        self.assertFalse(result["live_connector"])

    def test_presence_never_implies_online_or_safe(self):
        self.register()
        self.put()
        self.assertEqual(self.status()["reported_source_state"], "unknown")
        self.assertEqual(self.status()["sensor_health"], "unknown")

    def test_retained_online_never_claims_current_availability(self):
        self.register()
        self.put(availability(retained=True))
        self.assertEqual(self.status()["reported_source_state"], "unknown")

    def test_empty_export_does_not_reset_health(self):
        self.register()
        self.put(availability("offline"))
        self.put([])
        self.assertEqual(self.status()["reported_source_state"], "offline")

    def test_stale_report_is_unknown_not_all_clear(self):
        self.register()
        self.put(availability())
        result = self.status("2026-10-06T12:10:00Z")
        self.assertEqual(result["freshness"], "stale")
        self.assertEqual(result["reported_source_state"], "unknown")

    def test_clock_ahead_is_visible_unknown(self):
        self.register()
        self.put(availability(captured="2026-10-06T12:10:00Z"))
        self.assertEqual(self.status()["freshness"], "clock-invalid")
        self.assertEqual(self.status()["reported_source_state"], "unknown")

    def test_backfilled_online_does_not_override_offline(self):
        self.register()
        self.put(availability("offline"))
        self.put(availability("online", captured="2026-10-06T11:59:00Z"))
        self.assertEqual(self.status()["reported_source_state"], "offline")

    def test_conflicting_availability_same_time_stays_unknown(self):
        self.register()
        self.put([availability("online"), availability("offline")])
        self.assertEqual(self.status()["reported_source_state"], "unknown")

    def test_scope_revision_invalidates_prior_health_but_keeps_history(self):
        self.register()
        self.put(availability())
        self.register(scope={"cameras": {"entry": ["other-zone"]}})
        self.assertEqual(self.status()["freshness"], "unknown")
        self.assertEqual(len(self.events()), 1)

    def test_source_registered_without_events_is_unknown(self):
        self.register()
        self.assertEqual(self.status()["freshness"], "unknown")
        self.assertIsNone(self.status()["latest_observation"])

    def test_home_assistant_binary_sensor(self):
        self.register("home-assistant")
        self.put(home(), source="home-assistant")
        evidence = self.events()[0]["evidence"]
        self.assertEqual(evidence["state"], "on")
        self.assertEqual(evidence["sensor_kind"], "door")
        self.assertNotIn("TOPSECRET", json.dumps(evidence))
        self.assertNotIn("PRIVATE-USER", json.dumps(evidence))

    def test_home_assistant_temperature_units_and_value(self):
        self.register("home-assistant")
        self.put(home("sensor.room", "temperature", "24.5", "C"), source="home-assistant")
        event = self.events()[0]
        self.assertEqual(event["evidence"]["value"], 24.5)
        self.assertEqual(event["evidence"]["unit"], "C")
        self.assertEqual(event["kind"], "environment")

    def test_home_assistant_unavailable_unknown_removed(self):
        self.register("home-assistant")
        for state in ("unavailable", "unknown"):
            self.put(home(state=state), source="home-assistant")
        removed = home()
        removed["event"]["data"]["new_state"] = None
        self.put(removed, source="home-assistant")
        self.assertEqual({r["evidence"]["state"] for r in self.events()}, {"unavailable", "unknown", "removed"})
        self.assertEqual(self.status()["reported_source_state"], "unknown")

    def test_fresh_door_does_not_hide_unobserved_temperature_sensor(self):
        self.register("home-assistant")
        self.put(home(), source="home-assistant")
        assets = {r["asset_ref"]: r for r in self.status()["assets"]}
        self.assertEqual(assets["binary_sensor.door"]["reported_state"], "on")
        self.assertEqual(assets["sensor.room"]["freshness"], "unknown")
        self.assertEqual(assets["sensor.room"]["sensor_health"], "unknown")

    def test_conflicting_entity_states_same_time_are_unknown(self):
        self.register("home-assistant")
        self.put([home(state="on"), home(state="off")], source="home-assistant")
        door = next(r for r in self.status()["assets"] if r["asset_ref"] == "binary_sensor.door")
        self.assertEqual(door["reported_state"], "unknown")

    def test_home_assistant_raw_event_and_jsonl(self):
        self.register("home-assistant")
        path = self.root / "events.jsonl"
        event = home()["event"]
        path.write_text(json.dumps(event) + "\n" + json.dumps(event), encoding="utf-8")
        result = self.store.import_file(path, tenant="agency", site="station", source="home-assistant", instance="source-1")
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(result["duplicates"], 1)

    def test_home_assistant_bad_state_identity_class_and_units(self):
        self.register("home-assistant")
        rows = [home(state="open"), home(kind="motion"), home(entity="binary_sensor.other"),
                home("sensor.room", "temperature", "NaN", "C"),
                home("sensor.room", "temperature", "25", "K")]
        mismatch = home()
        mismatch["event"]["data"]["new_state"]["entity_id"] = "binary_sensor.other"
        rows.append(mismatch)
        for row in rows:
            with self.subTest(row=row), self.assertRaises(ImportRejected):
                self.put(row, source="home-assistant")
        self.assertEqual(self.events(), [])

    def test_home_assistant_commands_and_unrelated_events_rejected(self):
        self.register("home-assistant")
        bad_event = home()
        bad_event["event"]["event_type"] = "call_service"
        for row in (bad_event, {"type": "call_service", "domain": "lock", "service": "unlock"}):
            with self.assertRaises(ImportRejected):
                self.put(row, source="home-assistant")

    def test_scope_domains_do_not_allow_actuators_or_people_tracking(self):
        for entity in ("lock.door", "person.faz", "device_tracker.phone", "camera.entry", "switch.alarm"):
            with self.subTest(entity=entity), self.assertRaises(ImportRejected):
                validate_scope("home-assistant", {"entities": {entity: "door"}})

    def test_scope_and_freshness_limits(self):
        for scope in ({"cameras": {}}, {"cameras": {"entry": []}},
                      {"cameras": {"entry": ["restricted", "restricted"]}},
                      {"cameras": {"entry": ["restricted"]}, "commands": True}):
            with self.assertRaises(ImportRejected):
                self.register(scope=scope)
        for stale_after in (True, 0, 86401, "300"):
            with self.assertRaises(ImportRejected):
                self.register(stale_after=stale_after)

    def test_rejected_scope_file_audited_without_source_contents(self):
        path = self.root / "scope.json"
        path.write_text('{"secret":"TOPSECRET","secret":1}', encoding="utf-8")
        with self.assertRaises(ImportRejected):
            self.store.register_file(path, tenant="agency", site="station", source="frigate", instance="source-1",
                                     source_version="fixture-v1", purpose="facility-safety")
        audit = self.store.audit(tenant="agency")
        self.assertTrue(any(r.get("reason") == "duplicate_json_key" for r in audit["records"]))
        self.assertNotIn("TOPSECRET", json.dumps(audit))

    def test_size_and_structure_limits_atomic(self):
        self.register()
        path = self.root / "bad.json"
        for data in (b"x" * (8 * 1024 * 1024 + 1), b'{"topic":1,"topic":2}', b"[]\nnot-json",
                     json.dumps([{}] * 10001).encode()):
            path.write_bytes(data)
            with self.assertRaises(ImportRejected):
                self.store.import_file(path, tenant="agency", site="station", source="frigate", instance="source-1")
        self.assertEqual(self.events(), [])

    def test_discarded_credentials_cannot_bypass_structure_limits(self):
        self.register()
        row = frigate()
        nested = "TOPSECRET"
        for _ in range(20):
            nested = {"inner": nested}
        row["payload"]["after"]["authorization"] = nested
        with self.assertRaisesRegex(ImportRejected, "nesting_limit"):
            self.put(row)
        self.assertEqual(self.events(), [])
        self.assertNotIn("TOPSECRET", json.dumps(self.store.audit(tenant="agency")))

    def test_unknown_source_and_missing_file_rejected(self):
        self.register()
        with self.assertRaises(ImportRejected):
            self.put([], source="thingsboard")
        with self.assertRaises(ImportRejected):
            self.store.import_file(self.root / "missing", source="frigate", tenant="agency", site="station", instance="source-1")

    def test_safety_observations_never_enter_vulnerability_graph(self):
        self.register()
        self.put()
        security = SecurityEvidenceStore(self.root / "evidence.db")
        try:
            self.assertEqual(security.events(tenant="agency"), [])
            self.assertEqual(security.export_graph(tenant="agency", graph_path=self.root / "graph.db"), {"nodes": 0, "edges": 0})
        finally:
            security.close()

    def test_reads_and_registration_and_import_are_audited(self):
        self.register()
        self.put()
        self.events()
        self.status()
        actions = {r["action"] for r in self.store.audit(tenant="agency")["records"]}
        self.assertTrue({"safety_register", "safety_import", "safety_events_read", "safety_status_read", "safety_audit_read"}.issubset(actions))

    def test_tampered_shared_chain_detected(self):
        self.register()
        self.store.conn.execute("UPDATE security_import_audit SET payload='{}'")
        self.store.conn.commit()
        self.assertFalse(self.store.audit(tenant="agency")["chain_valid"])

    def test_no_network_or_subprocess_required_for_operations(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")), \
             patch("subprocess.Popen", side_effect=AssertionError("process attempted")):
            self.register()
            self.put()
            self.events()
            self.status()
            self.assertTrue(self.store.audit(tenant="agency")["chain_valid"])

    def test_database_permissions_and_invalid_read_limits(self):
        self.assertEqual(os.stat(self.root / "evidence.db").st_mode & 0o777, 0o600)
        for limit in (True, 0, 10001):
            with self.assertRaises(ValueError):
                self.events(limit=limit)

    def test_cli_success_failure_and_absence_of_controls(self):
        scope_path = self.root / "scope.json"
        event_path = self.root / "events.json"
        scope_path.write_text(json.dumps(SCOPE), encoding="utf-8")
        event_path.write_text(json.dumps(frigate()), encoding="utf-8")
        prefix = ["--db", str(self.root / "cli.db")]
        context = ["--tenant", "agency", "--site", "station", "--instance", "source-1"]
        runner = CliRunner()
        register = runner.invoke(safety, prefix + ["register", "frigate"] + context + ["--source-version", "fixture-v1", "--purpose", "facility-safety", "--scope", str(scope_path)])
        self.assertEqual(register.exit_code, 0, register.output)
        imported = runner.invoke(safety, prefix + ["import", "frigate", str(event_path)] + context)
        self.assertEqual(imported.exit_code, 0, imported.output)
        bad = dict(frigate(), topic="frigate/restart")
        event_path.write_text(json.dumps(bad), encoding="utf-8")
        rejected = runner.invoke(safety, prefix + ["import", "frigate", str(event_path)] + context)
        self.assertNotEqual(rejected.exit_code, 0)
        self.assertNotIn("TOPSECRET", rejected.output)
        for command in ("lock", "unlock", "dispatch", "connect", "acknowledge"):
            self.assertNotIn(command, safety.commands)

    def test_guarded_cli_runs_full_offline_flow(self):
        scope_path = self.root / "scope.json"
        event_path = self.root / "events.json"
        scope_path.write_text(json.dumps(HA_SCOPE), encoding="utf-8")
        event_path.write_text(json.dumps(home()), encoding="utf-8")
        base = [sys.executable, "-m", "safecadence.security.local_only", "safety", "--db", str(self.root / "guarded.db")]
        context = ["--tenant", "agency", "--site", "station", "--instance", "source-1"]
        commands = [["register", "home-assistant"] + context + ["--source-version", "fixture-v1", "--purpose", "facility-safety", "--scope", str(scope_path)],
                    ["import", "home-assistant", str(event_path)] + context,
                    ["events", "--tenant", "agency", "--site", "station"],
                    ["status", "--tenant", "agency", "--site", "station"],
                    ["audit", "--tenant", "agency"]]
        for command in commands:
            result = subprocess.run(base + command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("TOPSECRET", result.stdout)
            output = json.loads(result.stdout)
            if command[0] == "audit":
                self.assertTrue(output["chain_valid"])


if __name__ == "__main__":
    unittest.main()
