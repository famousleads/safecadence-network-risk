"""Synthetic device and organization-brand evidence; no upstream engines run."""
from __future__ import annotations

import csv
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from safecadence.integrations.public_safety_cli import safety
from safecadence.integrations.public_safety_exposure import decode_exposure_csv
from safecadence.integrations.public_safety_import import validate_scope
from safecadence.integrations.public_safety_store import PublicSafetyEvidenceStore
from safecadence.integrations.security_import import ImportRejected
from safecadence.integrations.security_store import SecurityEvidenceStore

TIME = "2026-10-06T12:00:00Z"
TB_SCOPE = {"devices": {"room-1": {"telemetry": {
    "temperature": {"kind": "temperature", "unit": "C"},
    "leak": {"kind": "moisture", "unit": None}}, "alarm_types": ["high-temperature"]},
    "room-2": {"telemetry": {"door": {"kind": "door", "unit": None}}, "alarm_types": []}}}
BRAND_SCOPE = {"subject_type": "organization-brand", "authorization_ref": "case-approval-1",
               "brands": {"agency-brand": {"usernames": ["agency_official"],
                                           "platform_hosts": ["example.com"]}}}


def telemetry(**changes):
    row = dict(export_schema="netrisk-thingsboard-v1", type="telemetry", device="room-1",
               observed_at=TIME, key="temperature", value=24.5, unit="C", state="observed",
               details={"token": "TOPSECRET", "person": "PRIVATE-NAME"})
    row.update(changes)
    return row


def alarm(**changes):
    row = dict(export_schema="netrisk-thingsboard-v1", type="alarm", device="room-1",
               observed_at=TIME, alarm_type="high-temperature", alarm_id="alarm-1",
               status="ACTIVE_UNACK", source_severity="MAJOR",
               start_at="2026-10-06T11:59:00Z", end_at=None)
    row.update(changes)
    return row


def csv_bytes(source="sherlock", rows=None, **changes):
    header = ["username", "name", "url_main", "url_user", "exists", "http_status",
              "response_time_s" if source == "sherlock" else "error_reason"]
    row = dict(username="agency_official", name="Example", url_main="https://example.com/",
               url_user="https://example.com/agency_official", exists="Claimed", http_status="200",
               response_time_s="0.1", error_reason="PRIVATE-NAME token=TOPSECRET")
    row.update(changes)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(header)
    for item in rows if rows is not None else [row]:
        writer.writerow([item[k] for k in header])
    return stream.getvalue().encode()


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = PublicSafetyEvidenceStore(self.root / "evidence.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def register(self, source="thingsboard", **changes):
        args = dict(tenant="agency", site="station", source=source, instance="fixture",
                    source_version="fixture-v1", purpose="facility-safety" if source == "thingsboard" else "brand-protection",
                    scope=TB_SCOPE if source == "thingsboard" else BRAND_SCOPE)
        args.update(changes)
        return self.store.register(**args)

    def put(self, rows=None, source="thingsboard", **changes):
        path = self.root / "source-export"
        path.write_bytes(csv_bytes(source) if rows is None and source != "thingsboard" else
                         rows if isinstance(rows, bytes) else json.dumps(telemetry() if rows is None else rows).encode())
        args = dict(source=source, tenant="agency", site="station", instance="fixture")
        if source != "thingsboard":
            args["observed_at"] = TIME
        args.update(changes)
        return self.store.import_file(path, **args)

    def events(self, **changes):
        return self.store.events(tenant="agency", site="station", **changes)

    def review(self, event_id=None, **changes):
        args = dict(tenant="agency", site="station", event_id=event_id or self.events()[0]["id"],
                    decision="confirmed-brand-account", evidence_ref="local-ownership-record-1",
                    expected_revision=0, actor="brand-reviewer")
        args.update(changes)
        return self.store.review_brand(**args)

    def test_thingsboard_telemetry_minimized(self):
        self.register()
        self.assertEqual(self.put()["inserted"], 1)
        row = self.events()[0]
        self.assertEqual(row["kind"], "telemetry")
        self.assertEqual(row["evidence"]["value"], 24.5)
        self.assertEqual(row["evidence"]["unit"], "C")
        self.assertEqual(row["evidence"]["calibration"], "not-verified")
        self.assertFalse(row["control_allowed"])
        for marker in ("TOPSECRET", "PRIVATE-NAME"):
            self.assertNotIn(marker, json.dumps(row))
            self.assertNotIn(marker.encode(), (self.root / "evidence.db").read_bytes())

    def test_binary_and_unknown_telemetry(self):
        self.register()
        for row in (telemetry(key="leak", value=True, unit=None),
                    telemetry(state="unavailable", value=None), telemetry(state="unknown", value=None)):
            self.put(row)
        self.assertEqual(len(self.events()), 3)

    def test_telemetry_validation_matrix(self):
        self.register()
        changes = [dict(unit="F"), dict(unit=None), dict(value=True), dict(value="24"),
                   dict(value=10 ** 400), dict(state="unavailable"), dict(state=[]),
                   dict(device="other"), dict(key="relay"), dict(type="rpc"),
                   dict(export_schema="native"), dict(observed_at=None), dict(value=float("nan"))]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ImportRejected):
                self.put(telemetry(**change))
        self.assertEqual(self.events(), [])

    def test_boolean_sensor_not_numeric_or_string(self):
        self.register()
        for value in (1, 0, "true", None):
            with self.subTest(value=value), self.assertRaises(ImportRejected):
                self.put(telemetry(key="leak", unit=None, value=value))

    def test_alarm_lifecycle_and_source_severity_preserved(self):
        self.register()
        self.put(alarm())
        self.put(alarm(status="CLEARED_ACK", observed_at="2026-10-06T12:01:00Z",
                       end_at="2026-10-06T12:00:30Z"))
        rows = self.events()
        self.assertEqual([r["evidence"]["status"] for r in rows], ["CLEARED_ACK", "ACTIVE_UNACK"])
        self.assertEqual(rows[0]["evidence"]["source_severity"], "MAJOR")
        self.assertEqual(rows[0]["severity"], "unreviewed")
        self.assertFalse(rows[0]["evidence"]["upstream_action_allowed"])

    def test_alarm_validation_matrix(self):
        self.register()
        for change in (dict(alarm_type="other"), dict(status="acknowledge"), dict(source_severity="high"),
                       dict(alarm_id="bad/id"), dict(start_at="2026-10-07T12:00:00Z"),
                       dict(end_at="2026-10-06T11:58:00Z"), dict(end_at="2026-10-06T12:00:00.1Z")):
            with self.subTest(change=change), self.assertRaises(ImportRejected):
                self.put(alarm(**change))

    def test_alarm_fractional_timestamps_use_numeric_order(self):
        self.register()
        self.put(alarm(start_at="2026-10-06T12:00:00Z", observed_at="2026-10-06T12:00:00.1Z"))
        self.assertEqual(len(self.events()), 1)

    def test_device_scope_disallows_controls_and_tracking(self):
        for kind in ("face", "person", "lock", "location", "switch"):
            scope = {"devices": {"room": {"telemetry": {"x": {"kind": kind, "unit": None}}, "alarm_types": []}}}
            with self.subTest(kind=kind), self.assertRaises(ImportRejected):
                validate_scope("thingsboard", scope)
        for scope in ({"devices": {}}, {"devices": {"room": {"telemetry": {}, "alarm_types": []}}},
                      {"devices": {"room": {"telemetry": {}, "alarm_types": [], "rpc": True}}}):
            with self.assertRaises(ImportRejected):
                self.register(scope=scope)

    def test_thingsboard_atomic_replay_scope_and_isolation(self):
        self.register()
        with self.assertRaises(ImportRejected):
            self.put([telemetry(), telemetry(device="other")])
        self.assertEqual(self.events(), [])
        self.assertEqual(self.put()["inserted"], 1)
        self.assertEqual(self.put()["duplicates"], 1)
        self.put(telemetry(value=25))
        self.assertEqual(len(self.events()), 2)
        for change in (dict(site="other"), dict(tenant="other"), dict(instance="other")):
            with self.assertRaisesRegex(ImportRejected, "source_not_registered"):
                self.put(**change)

    def test_missing_devices_remain_unknown(self):
        self.register()
        self.put()
        status = self.store.status(tenant="agency", site="station", as_of=TIME)[0]
        assets = {row["asset_ref"]: row for row in status["assets"]}
        self.assertEqual(assets["room-1"]["freshness"], "fresh-export")
        self.assertEqual(assets["room-2"]["freshness"], "unknown")
        self.assertEqual(status["sensor_health"], "unknown")
        channels = {r["channel"]: r for r in assets["room-1"]["telemetry_channels"]}
        self.assertEqual(channels["temperature"]["value"], 24.5)
        self.assertEqual(channels["leak"]["freshness"], "unknown")
        self.assertIsNone(channels["leak"]["value"])

    def test_channel_conflicts_backfill_and_scope_changes(self):
        self.register()
        self.put(telemetry())
        self.put(telemetry(value=25))
        self.put(telemetry(value=20, observed_at="2026-10-06T11:59:00Z"))
        def channel():
            status = self.store.status(tenant="agency", site="station", as_of=TIME)[0]
            return next(r for r in status["assets"][0]["telemetry_channels"] if r["channel"] == "temperature")
        self.assertTrue(channel()["conflicting"])
        self.assertIsNone(channel()["value"])
        self.register(source_version="fixture-v2")
        self.assertEqual(channel()["freshness"], "unknown")

    def test_stale_and_future_channels_do_not_report_current_values(self):
        self.register()
        self.put()
        for time, expected in (("2026-10-06T12:10:00Z", "stale"), ("2026-10-06T11:50:00Z", "clock-invalid")):
            status = self.store.status(tenant="agency", site="station", as_of=time)[0]
            value = next(r for r in status["assets"][0]["telemetry_channels"] if r["channel"] == "temperature")
            self.assertEqual(value["freshness"], expected)
            self.assertIsNone(value["value"])

    def test_observation_time_override_denied_for_environment(self):
        self.register()
        with self.assertRaisesRegex(ImportRejected, "observation_time_override"):
            self.put(observed_at=TIME)

    def test_generic_wrappers_cannot_hide_unsupported_commands_or_scopes(self):
        self.register()
        for wrapper in ({"type": "rpc", "data": [telemetry()]},
                        {"type": "rpc", "hits": {"hits": [{"_source": telemetry()}]}}):
            with self.assertRaises(ImportRejected):
                self.put(wrapper)
        path = self.root / "scope.json"
        path.write_text(json.dumps({"type": "rpc", "data": [TB_SCOPE]}))
        with self.assertRaises(ImportRejected):
            self.store.register_file(path, tenant="agency", site="station", source="thingsboard", instance="other",
                                     source_version="fixture-v1", purpose="facility-safety")
        self.assertEqual(self.events(), [])

    def test_sherlock_and_maigret_csv_candidates_not_identities(self):
        for source in ("sherlock", "maigret"):
            self.register(source)
            self.put(source=source)
            self.assertEqual(self.put(source=source)["duplicates"], 1)
            row = self.events(source=source)[0]
            self.assertEqual(row["kind"], "brand-exposure")
            self.assertEqual(row["evidence"]["review_status"], "unreviewed")
            self.assertEqual(row["review"]["revision"], 0)
            self.assertFalse(row["review"]["identity_verified"])
            self.assertFalse(row["control_allowed"])
            self.assertIsNone(row["confidence"])
            self.assertNotIn("TOPSECRET", json.dumps(row))
            self.assertNotIn("PRIVATE-NAME", json.dumps(row))

    def test_brand_scope_requires_explicit_authority_and_organization(self):
        for scope in ({}, dict(BRAND_SCOPE, subject_type="person"),
                      dict(BRAND_SCOPE, authorization_ref=""), dict(BRAND_SCOPE, brands={}),
                      dict(BRAND_SCOPE, people=["someone"])):
            with self.assertRaises(ImportRejected):
                self.register("sherlock", scope=scope)

    def test_duplicate_username_and_wildcard_hosts_denied(self):
        duplicate = json.loads(json.dumps(BRAND_SCOPE))
        duplicate["brands"]["other"] = duplicate["brands"]["agency-brand"]
        with self.assertRaises(ImportRejected):
            self.register("sherlock", scope=duplicate)
        for value in ("*.example.com", "localhost", "127.0.0.1", "EXAMPLE.COM", "example.com:443"):
            scope = json.loads(json.dumps(BRAND_SCOPE))
            scope["brands"]["agency-brand"]["platform_hosts"] = [value]
            with self.assertRaises(ImportRejected):
                self.register("sherlock", scope=scope)

    def test_unapproved_username_or_platform_rejects_batch(self):
        self.register("sherlock")
        for changes in (dict(username="private_person"), dict(url_user="https://other.example/agency_official"),
                        dict(name="<script>"), dict(exists="Verified")):
            with self.subTest(changes=changes), self.assertRaises(ImportRejected):
                self.put(csv_bytes(**changes), source="sherlock")
        self.assertEqual(self.events(), [])

    def test_url_credentials_queries_fragments_and_unsafe_schemes_rejected(self):
        self.register("sherlock")
        urls = ["http://example.com/agency_official", "javascript:alert(1)",
                "https://user:TOPSECRET@example.com/agency_official", "https://example.com/u?token=TOPSECRET",
                "https://example.com/u#TOPSECRET", "https://example.com:443/u", "https://example.com/u%0a",
                "https://example.com\\evil/u", "https://example.com/u%20", "https://example.com/u?"]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ImportRejected):
                self.put(csv_bytes(url_user=url), source="sherlock")
        self.assertNotIn("TOPSECRET", json.dumps(self.store.audit(tenant="agency")))
        self.assertNotIn(b"TOPSECRET", (self.root / "evidence.db").read_bytes())

    def test_report_date_required_no_receipt_substitution(self):
        self.register("sherlock")
        for at in (None, "2026-10-06T12:00:00", "wrong"):
            with self.assertRaises(ImportRejected):
                self.put(source="sherlock", observed_at=at)

    def test_csv_header_count_row_limits_and_utf8(self):
        for data in (b"", b"username,username\nu,u", b"\xff", b"x" * (8 * 1024 * 1024 + 1),
                     csv_bytes().replace(b",response_time_s", b",unexpected"),
                     csv_bytes().replace(b",0.1", b",0.1,extra"),
                     csv_bytes(name="x" * 4097)):
            with self.assertRaises(ImportRejected):
                decode_exposure_csv(data, "sherlock", TIME)
        header, row = csv_bytes().splitlines()
        with self.assertRaisesRegex(ImportRejected, "record_count_limit"):
            decode_exposure_csv(header + b"\n" + (row + b"\n") * 10001, "sherlock", TIME)

    def test_bad_later_csv_row_is_atomic(self):
        self.register("sherlock")
        first = csv_bytes()
        bad_row = csv_bytes(username="other").splitlines()[1]
        with self.assertRaises(ImportRejected):
            self.put(first + bad_row + b"\n", source="sherlock")
        self.assertEqual(self.events(), [])

    def test_empty_valid_csv_is_unknown_not_successful_search(self):
        self.register("sherlock")
        result = self.put(csv_bytes(rows=[]), source="sherlock")
        self.assertEqual(result["records"], 0)
        self.assertEqual(result["sensor_health"], "unknown")
        self.assertEqual(self.store.status(tenant="agency", site="station")[0]["freshness"], "unknown")

    def test_human_review_bound_to_one_version_and_audited(self):
        self.register("sherlock")
        self.put(source="sherlock")
        review = self.review()
        self.assertEqual(review["verification"], "human-attestation")
        self.assertFalse(review["identity_verified"])
        event = self.events()[0]
        self.assertEqual(event["review"]["decision"], "confirmed-brand-account")
        self.assertEqual(review["evidence_hash"], event["evidence_hash"])
        self.assertEqual(event["evidence"]["review_status"], "unreviewed")
        self.assertTrue(self.store.audit(tenant="agency")["chain_valid"])
        self.assertTrue(any(r["action"] == "safety_brand_review" for r in self.store.audit(tenant="agency")["records"]))

    def test_review_history_revision_conflicts_and_corrections(self):
        self.register("sherlock")
        self.put(source="sherlock")
        self.review()
        with self.assertRaisesRegex(ImportRejected, "review_revision_conflict"):
            self.review(decision="not-brand-account")
        self.review(decision="not-brand-account", expected_revision=1)
        self.assertEqual(self.events()[0]["review"]["revision"], 2)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM safety_brand_reviews").fetchone()[0], 2)

    def test_review_never_carries_to_new_report_or_scope(self):
        self.register("sherlock")
        self.put(source="sherlock")
        old_id = self.events()[0]["id"]
        self.review(old_id)
        self.put(source="sherlock", observed_at="2026-10-06T12:01:00Z")
        self.assertEqual(self.events()[0]["review"]["decision"], "unreviewed")
        self.register("sherlock", source_version="fixture-v2")
        self.assertFalse(self.events()[0]["review"]["scope_current"])
        with self.assertRaisesRegex(ImportRejected, "review_scope_changed"):
            self.review(old_id, expected_revision=1)

    def test_review_cross_scope_negative_results_and_invalid_decisions_denied(self):
        self.register("sherlock")
        self.put(source="sherlock")
        event_id = self.events()[0]["id"]
        for changes in (dict(tenant="other"), dict(site="other"), dict(decision="verified-person"),
                        dict(evidence_ref="https://example.com/proof"), dict(expected_revision=True)):
            with self.assertRaises(ImportRejected):
                self.review(event_id, **changes)
        self.put(csv_bytes(exists="Available"), source="sherlock")
        negative = next(r for r in self.events() if r["evidence"]["source_status"] == "Available")
        with self.assertRaisesRegex(ImportRejected, "brand_candidate_required"):
            self.review(negative["id"])
        self.register()
        self.put()
        with self.assertRaisesRegex(ImportRejected, "brand_candidate_required"):
            self.review(next(r for r in self.events() if r["source"] == "thingsboard")["id"])

    def test_no_network_dns_process_or_browser_calls(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch("webbrowser.open", side_effect=AssertionError("browser")):
            self.register()
            self.put()
            for source in ("sherlock", "maigret"):
                self.register(source)
                self.put(source=source)
                self.review(self.events(source=source)[0]["id"])
            self.store.status(tenant="agency", site="station", as_of=TIME)
            self.assertTrue(self.store.audit(tenant="agency")["chain_valid"])

    def test_new_observations_do_not_enter_vulnerability_graph(self):
        self.register()
        self.put()
        self.register("sherlock")
        self.put(source="sherlock")
        security = SecurityEvidenceStore(self.root / "evidence.db")
        try:
            self.assertEqual(security.events(tenant="agency"), [])
            self.assertEqual(security.export_graph(tenant="agency", graph_path=self.root / "graph.db"), {"nodes": 0, "edges": 0})
        finally:
            security.close()

    def test_guarded_cli_all_five_sources_and_human_review(self):
        base = [sys.executable, "-m", "safecadence.security.local_only", "safety", "--db", str(self.root / "guarded.db")]
        context = ["--tenant", "agency", "--site", "station", "--instance", "fixture"]
        for source in ("thingsboard", "sherlock", "maigret"):
            scope = self.root / (source + "-scope.json")
            report = self.root / (source + "-export")
            scope.write_text(json.dumps(TB_SCOPE if source == "thingsboard" else BRAND_SCOPE))
            report.write_bytes(json.dumps([telemetry(), alarm()]).encode() if source == "thingsboard" else csv_bytes(source))
            register = ["register", source] + context + ["--source-version", "fixture-v1", "--purpose", "approved-purpose", "--scope", str(scope)]
            imported = ["import", source, str(report)] + context
            if source != "thingsboard":
                imported += ["--observed-at", TIME]
            for command in (register, imported):
                result = subprocess.run(base + command, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH="src"))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("TOPSECRET", result.stdout)
        events = subprocess.run(base + ["events", "--tenant", "agency", "--site", "station", "--source", "sherlock"], capture_output=True, text=True)
        self.assertEqual(events.returncode, 0, events.stderr)
        event_id = json.loads(events.stdout)[0]["id"]
        result = subprocess.run(base + ["review-brand", event_id, "--tenant", "agency", "--site", "station", "--decision", "confirmed-brand-account", "--evidence-ref", "local-record-1", "--expected-revision", "0", "--actor", "reviewer"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["verification"], "human-attestation")

    def test_cli_missing_date_and_missing_reviewer_are_errors(self):
        runner = CliRunner()
        result = runner.invoke(safety, ["review-brand", "event", "--tenant", "agency", "--site", "station"])
        self.assertNotEqual(result.exit_code, 0)
        for command in ("search", "identify", "connect", "dispatch", "rpc", "unlock"):
            self.assertNotIn(command, safety.commands)


if __name__ == "__main__":
    unittest.main()
