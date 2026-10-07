"""Bounded offline alert/observation imports; reports never execute source text."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .security_catalog import IMPORT_SOURCES

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 10000
_SECRET = re.compile(r"password|secret|token|authorization|api[_-]?key|cookie|credential", re.I)
_TEXT_SECRET = re.compile(
    r"(?i)(bearer\s+\S+|(?:password|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+)"
)


class ImportRejected(ValueError):
    """Stable error code; never include untrusted record contents in errors."""


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def redact(obj, depth=0):
    if depth > 16:
        raise ImportRejected("nesting_limit")
    if isinstance(obj, dict):
        if len(obj) > 256:
            raise ImportRejected("field_limit")
        return {str(k)[:128]: "[REDACTED]" if _SECRET.search(str(k)) else redact(v, depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) > 1000:
            raise ImportRejected("array_limit")
        return [redact(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        return _TEXT_SECRET.sub("[REDACTED]", obj[:4096])
    if isinstance(obj, float) and not math.isfinite(obj):
        raise ImportRejected("nonfinite_number")
    return obj


def timestamp(value):
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (float, int)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(value, timezone.utc)
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        raise ImportRejected("invalid_timestamp") from None


def _text(value, fallback="", limit=512):
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        raise ImportRejected("invalid_scalar")
    return str(value)[:limit]


def _object(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ImportRejected("invalid_object")
    return value


def _json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ImportRejected("duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ImportRejected("nonfinite_number")))
    except (json.JSONDecodeError, RecursionError):
        raise ImportRejected("invalid_json") from None


def decode(data, *, unwrap=True):
    if len(data) > MAX_BYTES:
        raise ImportRejected("file_size_limit")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        raise ImportRejected("invalid_encoding") from None
    if not text:
        raise ImportRejected("empty_file")
    try:
        obj = _json(text)
    except ImportRejected as error:
        if str(error) != "invalid_json":
            raise
        obj = [_json(line) for line in text.splitlines() if line.strip()]
    if isinstance(obj, dict):
        if unwrap and "hits" in obj:  # Elasticsearch/OpenSearch supplied search export
            obj = _object(obj["hits"]).get("hits", [])
            if not isinstance(obj, list):
                raise ImportRejected("invalid_records")
            obj = [_object(hit).get("_source") for hit in obj]
        elif unwrap and isinstance(obj.get("data"), list):  # API wrapper, not Wazuh's event data
            obj = obj["data"]
        else:
            obj = [obj]
    if not isinstance(obj, list) or any(not isinstance(row, dict) for row in obj):
        raise ImportRejected("invalid_records")
    if len(obj) > MAX_RECORDS:
        raise ImportRejected("record_count_limit")
    return obj


def normalize(source, row, *, source_version, instance, imported_at):
    if source not in IMPORT_SOURCES:
        raise ImportRejected("unsupported_source")
    clean = redact(row)
    raw_hash = digest(row)
    event_id = _text(clean.get("id") or clean.get("uid") or raw_hash, limit=256)
    asset = ""
    severity = "info"
    original_severity = None
    kind = "observation"
    observed = None
    if source == "wazuh":
        rule = _object(clean.get("rule"))
        if "level" not in rule:
            raise ImportRejected("wazuh_alert_rule_required")
        if isinstance(rule["level"], (bool, float)):
            raise ImportRejected("invalid_wazuh_level")
        try:
            level = int(rule["level"])
        except (ValueError, TypeError):
            raise ImportRejected("invalid_wazuh_level") from None
        if not 0 <= level <= 16:
            raise ImportRejected("invalid_wazuh_level")
        original_severity = level
        severity = "critical" if level >= 15 else "high" if level >= 12 else "medium" if level >= 7 else "low" if level >= 4 else "info"
        title = _text(rule.get("description"), "Wazuh alert")
        agent = _object(clean.get("agent"))
        asset = _text(agent.get("id") or agent.get("name") or agent.get("ip"))
        observed = clean.get("timestamp")
        kind = "alert"
    elif source == "crowdsec":
        if not clean.get("scenario"):
            raise ImportRejected("crowdsec_scenario_required")
        title = _text(clean["scenario"])
        target = _object(clean.get("source"))
        asset = _text(target.get("value"))
        observed = clean.get("created_at") or clean.get("start_at")
        kind = "alert"
        # A detection does not establish successful compromise or justify blocking.
        severity = "unknown"
    elif source == "zeek":
        if not clean.get("uid") or "ts" not in clean:
            raise ImportRejected("zeek_uid_timestamp_required")
        title = "Zeek connection observation"
        asset = _text(clean.get("id.orig_h"))
        observed = clean["ts"]
    else:
        event_type = _text(clean.get("event_type"))
        if not event_type:
            raise ImportRejected("suricata_event_type_required")
        observed = clean.get("timestamp")
        asset = _text(clean.get("src_ip"))
        title = "Suricata " + event_type
        if event_type == "alert":
            alert = _object(clean.get("alert"))
            title = _text(alert.get("signature"), "Suricata alert")
            original_severity = alert.get("severity")
            severity = {1: "high", 2: "medium", 3: "low"}.get(original_severity, "unknown")
            kind = "alert"
    return dict(
        schema_version=1, source=source, source_version=source_version,
        instance=instance, source_event_id=event_id, observed_at=timestamp(observed),
        imported_at=imported_at, asset_ref=asset, title=title, kind=kind,
        severity=severity, original_severity=original_severity,
        confidence=None, evidence_hash=raw_hash, evidence=clean,
        limitations=["Supplied file; not a live connector or verified compromise.",
                     "Import receipt does not prove sensor health or complete coverage.",
                     "Heuristic secret redaction is not a guarantee of anonymization."],
    )
