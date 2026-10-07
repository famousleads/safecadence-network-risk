"""Offline fixtures and process-isolated network denial tests. No external calls."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from safecadence.integrations.security_catalog import catalog
from safecadence.integrations.security_import import ImportRejected, decode, normalize, timestamp
from safecadence.integrations.security_store import SecurityEvidenceStore
from safecadence.integrations.security_updates import download, parse_update, request_for, NoRedirect
from safecadence.security.local_only import LocalPolicy

WAZUH = {"id": "1", "timestamp": "2026-10-06T10:00:00Z", "agent": {"id": "001"},
         "rule": {"level": 12, "description": "Unauthorized change"},
         "data": {"password": "TOPSECRET", "note": "token=TOPSECRET"}}
CROWDSEC = {"id": 1, "scenario": "ssh-bf", "source": {"value": "10.1.2.3"},
            "created_at": "2026-10-06T10:00:00Z"}
ZEEK = {"uid": "C1", "ts": 1791280800.0, "id.orig_h": "10.1.2.3", "id.resp_h": "10.1.2.4"}
SURICATA = {"timestamp": "2026-10-06T10:00:00Z", "event_type": "alert", "flow_id": 1,
            "src_ip": "10.1.2.3", "alert": {"signature": "Fixture test", "severity": 1}}
FIXTURES = {"wazuh": WAZUH, "crowdsec": CROWDSEC, "zeek": ZEEK, "suricata": SURICATA}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SecurityEvidenceStore(self.root / "evidence.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def do_import(self, source="wazuh", data=None, tenant="acme", instance="sensor-1"):
        path = self.root / "source.json"
        path.write_bytes(data if data is not None else json.dumps(FIXTURES[source]).encode())
        return self.store.import_file(path, source=source, tenant=tenant, instance=instance,
                                      source_version="fixture-v1")

    def test_catalog_32_distinct_and_four_imports_only(self):
        rows = catalog()
        self.assertEqual(len(rows), 32)
        self.assertEqual(len({row["backlog_id"] for row in rows}), 32)
        self.assertEqual(sum(row["status"] == "file-import" for row in rows), 4)
        self.assertFalse(any(row["live_connector"] or row["engine_installed"] for row in rows))

    def test_all_sources_import_and_replay(self):
        for source in FIXTURES:
            with self.subTest(source=source):
                self.assertEqual(self.do_import(source)["inserted"], 1)
                self.assertEqual(self.do_import(source)["duplicates"], 1)
                event = self.store.events(tenant="acme", source=source)[0]
                self.assertEqual(event["source_version"], "fixture-v1")
                self.assertIsNone(event["confidence"])
        self.assertEqual(len(self.store.events(tenant="acme")), 4)
        self.assertTrue(self.store.audit(tenant="acme")["chain_valid"])

    def test_tenant_and_instance_isolation(self):
        for tenant in ("acme", "beta"):
            for instance in ("sensor-1", "sensor-2"):
                self.do_import(tenant=tenant, instance=instance)
        a = self.store.events(tenant="acme")
        b = self.store.events(tenant="beta")
        self.assertEqual(len(a), 2)
        self.assertTrue({e["id"] for e in a}.isdisjoint({e["id"] for e in b}))
        self.assertEqual(self.store.events(tenant="missing"), [])
        self.assertEqual(len(self.store.audit(tenant="beta")["records"]), 2)

    def test_secret_redaction_preserves_hash_not_raw_secret(self):
        self.do_import()
        encoded = json.dumps(self.store.events(tenant="acme"))
        self.assertNotIn("TOPSECRET", encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertNotIn(b"TOPSECRET", (self.root / "evidence.db").read_bytes())

    def test_bad_batch_is_atomic_and_failure_audited(self):
        bad = [WAZUH, {"rule": {"level": 99}, "password": "TOPSECRET"}]
        with self.assertRaises(ImportRejected):
            self.do_import(data=json.dumps(bad).encode())
        self.assertEqual(self.store.events(tenant="acme"), [])
        audit = self.store.audit(tenant="acme")
        self.assertTrue(audit["chain_valid"])
        self.assertEqual(audit["records"][0]["status"], "rejected")
        self.assertIn("recommendation", audit["records"][0])
        self.assertNotIn("TOPSECRET", json.dumps(audit))

    def test_changed_event_keeps_both_versions(self):
        self.do_import()
        changed = dict(WAZUH, rule={"level": 15, "description": "Changed"})
        self.assertEqual(self.do_import(data=json.dumps(changed).encode())["inserted"], 1)
        self.assertEqual(len(self.store.events(tenant="acme")), 2)

    def test_empty_report_not_sensor_health(self):
        result = self.do_import(data=b"[]")
        self.assertEqual(result["records"], 0)
        self.assertEqual(result["sensor_health"], "unknown")
        status = self.store.status(tenant="acme")[0]
        self.assertEqual(status["sensor_health"], "unknown")
        self.assertFalse(status["live_connector"])

    def test_tampered_audit_detected(self):
        self.do_import()
        with self.store.conn:
            self.store.conn.execute("UPDATE security_import_audit SET payload='{}'")
        self.assertFalse(self.store.audit(tenant="acme")["chain_valid"])

    def test_missing_file_records_failure(self):
        with self.assertRaises(ImportRejected):
            self.store.import_file(self.root / "absent", source="wazuh", tenant="acme",
                                   instance="sensor-1", source_version="fixture-v1")
        self.assertEqual(self.store.audit(tenant="acme")["records"][0]["status"], "rejected")

    def test_unknown_source_even_empty_rejected(self):
        with self.assertRaises(ImportRejected):
            self.do_import(source="not-supported", data=b"[]")

    def test_context_required(self):
        with self.assertRaises(ImportRejected):
            self.do_import(tenant="")

    def test_observations_do_not_become_findings(self):
        from safecadence.graph.store import GraphStore
        self.do_import("zeek")
        self.do_import("wazuh")
        counts = self.store.export_graph(tenant="acme", graph_path=self.root / "graph.db")
        self.assertEqual(counts, {"nodes": 2, "edges": 1})
        graph = GraphStore(self.root / "graph.db")
        try:
            event = self.store.events(tenant="acme", source="wazuh")[0]
            node = graph.get_node("finding", "security:" + event["id"])
            self.assertEqual(node["attrs"]["verification"], "unverified alert")
        finally:
            graph._conn.close()

    def test_jsonl_and_indexer_export(self):
        self.assertEqual(len(decode(json.dumps(WAZUH).encode() + b"\n" + json.dumps(WAZUH).encode())), 2)
        shaped = {"hits": {"hits": [{"_source": WAZUH}]}}
        self.assertEqual(decode(json.dumps(shaped).encode()), [WAZUH])
        self.assertEqual(decode(json.dumps({"data": [CROWDSEC]}).encode()), [CROWDSEC])

    def test_invalid_inputs_matrix(self):
        for payload in (b"", b"not json", b"[1]", b"null", b'{"a":1,"a":2}',
                        b'{"x":NaN}', b"\xff", b"x" * (8 * 1024 * 1024 + 1)):
            with self.subTest(payload=payload[:40]), self.assertRaises(ImportRejected):
                decode(payload)

    def test_limits_and_schema(self):
        with self.assertRaises(ImportRejected):
            decode(json.dumps([{}] * 10001).encode())
        nested = "value"
        for _ in range(20):
            nested = {"nested": nested}
        with self.assertRaises(ImportRejected):
            self.do_import(data=json.dumps(dict(WAZUH, data=nested)).encode())
        for source in FIXTURES:
            with self.subTest(source=source), self.assertRaises(ImportRejected):
                normalize(source, {}, source_version="v1", instance="a", imported_at="now")

    def test_timestamp_requires_timezone(self):
        for value in ("2026-10-06T10:00:00", "bad", float("inf")):
            with self.subTest(value=value), self.assertRaises(ImportRejected):
                timestamp(value)
        self.assertTrue(timestamp(0).endswith("+00:00"))

    def test_severity_is_source_specific(self):
        def norm(source):
            return normalize(source, FIXTURES[source], source_version="v1", instance="a", imported_at="now")
        self.assertEqual(norm("wazuh")["severity"], "high")
        self.assertEqual(norm("suricata")["severity"], "high")
        self.assertEqual(norm("crowdsec")["severity"], "unknown")
        self.assertEqual(norm("zeek")["kind"], "observation")


class LocalGuardTests(unittest.TestCase):
    def child(self, code):
        prefix = "from safecadence.security.local_only import install_guard, EgressDenied\ninstall_guard()\n"
        result = subprocess.run([sys.executable, "-c", prefix + code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_public_and_unapproved_lan_connect_denied_before_syscall(self):
        for ip in ("8.8.8.8", "10.1.2.3", "169.254.169.254", "::ffff:8.8.8.8"):
            with self.subTest(ip=ip):
                self.child("import socket\ns=socket.socket(socket.AF_INET6 if ':' in " + repr(ip) +
                           " else socket.AF_INET)\ntry:\n s.connect((" + repr(ip) +
                           ",443))\nexcept EgressDenied:\n print('denied')\nelse:\n raise AssertionError('escape')")

    def test_dns_denied(self):
        self.child("import socket\ntry:\n socket.getaddrinfo('example.com',443)\nexcept EgressDenied:\n pass\nelse:\n raise AssertionError('escape')")

    def test_udp_and_child_process_denied(self):
        self.child("import socket,subprocess\nfor fn in (lambda: socket.socket(type=socket.SOCK_DGRAM),lambda: subprocess.run(['echo','bad'])):\n try:\n  fn()\n except EgressDenied:\n  pass\n else:\n  raise AssertionError('escape')")

    def test_loopback_communication_works(self):
        self.child("import socket\ns=socket.socket()\ns.bind(('127.0.0.1',0))\ns.listen()\nc=socket.socket()\nc.connect(s.getsockname())\na,_=s.accept()\nc.sendall(b'ok')\nassert a.recv(2)==b'ok'\na.close();c.close();s.close()")

    def test_public_listener_denied(self):
        self.child("import socket\ntry:\n socket.socket().bind(('0.0.0.0',0))\nexcept EgressDenied:\n pass\nelse:\n raise AssertionError('escape')")

    def test_local_cli_catalog_boots_under_guard(self):
        result = subprocess.run([sys.executable, "-m", "safecadence.security.local_only",
                                 "ecosystem", "catalog"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 32)

    def test_guarded_cli_import_review_audit_graph_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "wazuh.json"
            fixture.write_text(json.dumps(WAZUH))
            prefix = [sys.executable, "-m", "safecadence.security.local_only",
                      "ecosystem", "--db", str(root / "evidence.db")]
            def run(*args):
                result = subprocess.run([*prefix, *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)
            self.assertEqual(run("import", "wazuh", str(fixture), "--tenant", "acme",
                                 "--instance", "a", "--source-version", "fixture-v1")["inserted"], 1)
            self.assertEqual(len(run("events", "--tenant", "acme")), 1)
            self.assertEqual(run("events", "--tenant", "beta"), [])
            self.assertEqual(run("status", "--tenant", "acme")[0]["sensor_health"], "unknown")
            self.assertTrue(run("audit", "--tenant", "acme")["chain_valid"])
            self.assertEqual(run("graph", "--tenant", "acme", "--output", str(root / "graph.db"))["edges"], 1)

    def test_exact_internal_target_policy(self):
        policy = LocalPolicy((("192.168.4.15", 8444),))
        self.assertTrue(policy.permits("192.168.4.15", 8444))
        self.assertFalse(policy.permits("192.168.4.15", 443))
        self.assertFalse(policy.permits("192.168.4.16", 8444))
        self.assertFalse(policy.permits("api.openai.com", 443))
        for item in (("8.8.8.8", 443), ("169.254.169.254", 443), ("10.0.0.1", True)):
            with self.subTest(item=item), self.assertRaises(ValueError):
                LocalPolicy((item,))


class UpdateTests(unittest.TestCase):
    def test_request_has_only_public_date_window_not_asset_details(self):
        req = request_for("nist-nvd", at=datetime(2026, 10, 6, tzinfo=timezone.utc))
        self.assertEqual(req.get_method(), "GET")
        self.assertIsNone(req.data)
        self.assertIn("services.nvd.nist.gov/rest/json/cves/2.0?", req.full_url)
        self.assertNotIn("Authorization", req.headers)
        self.assertNotIn("apiKey", req.headers)

    def test_arbitrary_url_denied(self):
        with self.assertRaises(ImportRejected):
            request_for("https://attacker.invalid/")

    def test_redirects_denied(self):
        with self.assertRaises(ImportRejected):
            NoRedirect().redirect_request(None, None, 302, "", {}, "http://127.0.0.1")

    def test_disabled_update_does_not_open_network(self):
        opener = unittest.mock.Mock()
        with self.assertRaises(ImportRejected):
            download("nist-nvd", "unused.json", opener=opener)
        opener.open.assert_not_called()

    def test_disabled_update_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SecurityEvidenceStore(Path(tmp) / "evidence.db")
            try:
                with self.assertRaises(ImportRejected):
                    download("nist-nvd", Path(tmp) / "unused.json", store=store)
                self.assertEqual(store.audit(tenant="security-updates")["records"][0]["status"], "denied")
            finally:
                store.close()

    def test_nvd_partial_not_misrepresented(self):
        package = parse_update("nist-nvd", json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-1"}}],
                                                      "startIndex": 0, "totalResults": 2001}).encode())
        self.assertFalse(package["complete"])
        self.assertEqual(package["status"], "staged; not activated")

    def test_psirt_feed_and_xml_entity_rejection(self):
        package = parse_update("cisco-psirt", b"<rss><channel><item><title>Test advisory</title></item></channel></rss>")
        self.assertEqual(len(package["records"]), 1)
        self.assertFalse(package["complete"])
        with self.assertRaises(ImportRejected):
            parse_update("cisco-psirt", b'<!DOCTYPE rss [<!ENTITY x "bad">]><rss><channel/></rss>')

    def test_download_stages_atomic_and_audits_without_live_network(self):
        req = request_for("cisco-psirt")
        response = io.BytesIO(b"<rss><channel><item><title>Fixture</title></item></channel></rss>")
        response.status = 200
        response.geturl = lambda: req.full_url
        opener = unittest.mock.Mock()
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as tmp:
            store = SecurityEvidenceStore(Path(tmp) / "evidence.db")
            try:
                result = download("cisco-psirt", Path(tmp) / "update.json", enabled=True, opener=opener, store=store)
                self.assertTrue((Path(tmp) / "update.json").exists())
                self.assertEqual(result["status"], "staged; not activated")
                self.assertTrue(store.audit(tenant="security-updates")["chain_valid"])
            finally:
                store.close()

    def test_failed_update_preserves_previous_file(self):
        response = io.BytesIO(b"bad XML")
        response.status = 200
        response.geturl = lambda: request_for("cisco-psirt").full_url
        opener = unittest.mock.Mock()
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "update.json"
            path.write_text("last-known-good")
            with self.assertRaises(ImportRejected):
                download("cisco-psirt", path, enabled=True, opener=opener)
            self.assertEqual(path.read_text(), "last-known-good")


if __name__ == "__main__":
    unittest.main()
