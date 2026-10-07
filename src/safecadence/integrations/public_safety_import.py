"""Read-only, minimized camera/environmental observations from local exports."""
from __future__ import annotations

import math
import re
from datetime import datetime

from .security_import import ImportRejected, digest, timestamp
from .public_safety_exposure import EXPOSURE_SOURCES, normalize_exposure, validate_exposure_scope

SOURCES = frozenset({"frigate", "home-assistant", "thingsboard"}) | EXPOSURE_SOURCES
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_BINARY = frozenset({"door", "window", "opening", "moisture", "occupancy", "motion"})


def name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ImportRejected("invalid_source_identifier")
    return value


def object_value(value):
    if not isinstance(value, dict):
        raise ImportRejected("invalid_object")
    return value


def names(value):
    if not isinstance(value, list) or len(value) > 100:
        raise ImportRejected("invalid_scope_list")
    result = [name(item) for item in value]
    if len(set(result)) != len(result):
        raise ImportRejected("duplicate_scope_identifier")
    return result


def validate_scope(source, scope):
    object_value(scope)
    if source in EXPOSURE_SOURCES:
        return validate_exposure_scope(scope)
    if source == "thingsboard":
        if set(scope) != {"devices"}:
            raise ImportRejected("invalid_thingsboard_scope")
        devices = object_value(scope["devices"])
        if not 1 <= len(devices) <= 100:
            raise ImportRejected("invalid_device_scope")
        result = {}
        for device, fields in devices.items():
            fields = object_value(fields)
            if set(fields) != {"telemetry", "alarm_types"}:
                raise ImportRejected("invalid_device_scope")
            telemetry = object_value(fields["telemetry"])
            if len(telemetry) > 100:
                raise ImportRejected("invalid_telemetry_scope")
            clean = {}
            for key, spec in telemetry.items():
                spec = object_value(spec)
                if set(spec) != {"kind", "unit"}:
                    raise ImportRejected("invalid_telemetry_scope")
                kind, unit = spec["kind"], spec["unit"]
                if not ((kind == "temperature" and unit in ("C", "F")) or
                        (kind in _BINARY and unit is None)):
                    raise ImportRejected("unsupported_telemetry_scope")
                clean[name(key)] = dict(kind=kind, unit=unit)
            alarms = names(fields["alarm_types"])
            if not clean and not alarms:
                raise ImportRejected("empty_device_scope")
            result[name(device)] = dict(telemetry=clean, alarm_types=sorted(alarms))
        return {"devices": result}
    if source == "frigate":
        if set(scope) != {"cameras"}:
            raise ImportRejected("invalid_frigate_scope")
        cameras = object_value(scope["cameras"])
        if not 1 <= len(cameras) <= 100:
            raise ImportRejected("invalid_camera_scope")
        result = {}
        for camera, zones in cameras.items():
            allowed = names(zones)
            if not allowed:
                raise ImportRejected("zone_scope_required")
            result[name(camera)] = sorted(allowed)
        return {"cameras": result}
    if source == "home-assistant":
        if set(scope) != {"entities"}:
            raise ImportRejected("invalid_home_assistant_scope")
        entities = object_value(scope["entities"])
        if not 1 <= len(entities) <= 100:
            raise ImportRejected("invalid_entity_scope")
        result = {}
        for entity, kind in entities.items():
            name(entity)
            domain = entity.split(".")[0]
            if not ((domain == "binary_sensor" and kind in _BINARY) or
                    (domain == "sensor" and kind == "temperature")):
                raise ImportRejected("unsupported_entity_scope")
            result[entity] = kind
        return {"entities": result}
    raise ImportRejected("unsupported_safety_source")


def required_time(value):
    result = timestamp(value)
    if result is None:
        raise ImportRejected("observation_timestamp_required")
    return result


def _validate_structure(row):
    # Validate discarded fields too; credential keys must not hide deep payloads.
    pending = [(row, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 16:
            raise ImportRejected("nesting_limit")
        if isinstance(value, dict):
            if len(value) > 256:
                raise ImportRejected("field_limit")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            if len(value) > 1000:
                raise ImportRejected("array_limit")
            pending.extend((item, depth + 1) for item in value)


def _frigate(row, scope):
    # Export wrapper: topic + decoded payload + capture time, never a broker command.
    if row.get("topic") not in {"frigate/events", "frigate/available"}:
        raise ImportRejected("unsupported_frigate_topic")
    captured = required_time(row.get("captured_at"))
    retained = row.get("retained", False)
    if not isinstance(retained, bool):
        raise ImportRejected("invalid_retained_flag")
    if row["topic"] == "frigate/available":
        state = row.get("payload")
        if not isinstance(state, str) or state not in {"online", "offline", "stopped"}:
            raise ImportRejected("invalid_availability")
        return dict(source_event_id="availability:" + captured, observed_at=captured,
                    asset_ref="", kind="availability", title="Frigate reported " + state,
                    evidence={"reported_state": state, "retained": retained,
                              "captured_at": captured})
    payload = object_value(row.get("payload"))
    lifecycle = payload.get("type")
    if not isinstance(lifecycle, str) or lifecycle not in {"new", "update", "end"}:
        raise ImportRejected("invalid_frigate_lifecycle")
    after = object_value(payload.get("after"))
    camera = name(after.get("camera"))
    if camera not in scope["cameras"]:
        raise ImportRejected("camera_out_of_scope")
    # Only presence observations; omit identities, attributes, clips and source URLs.
    label = after.get("label")
    if not isinstance(label, str) or label not in {"person", "car"}:
        raise ImportRejected("unsupported_object_label")
    current = names(after.get("current_zones", []))
    entered = names(after.get("entered_zones", []))
    allowed = set(scope["cameras"][camera])
    if not allowed.intersection(current + entered):
        raise ImportRejected("zone_out_of_scope")
    score = after.get("score")
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or
                              not math.isfinite(score) or not 0 <= score <= 1):
        raise ImportRejected("invalid_object_score")
    false_positive = after.get("false_positive", False)
    if not isinstance(false_positive, bool):
        raise ImportRejected("invalid_false_positive")
    observed = required_time(after.get("end_time") if lifecycle == "end" else after.get("frame_time"))
    return dict(source_event_id=name(after.get("id")), observed_at=observed,
                asset_ref=camera, kind="presence", title=label + " presence observation",
                evidence=dict(camera=camera, label=label, lifecycle=lifecycle,
                              current_zones=sorted(allowed.intersection(current)),
                              entered_zones=sorted(allowed.intersection(entered)),
                              source_score=score, false_positive=false_positive,
                              retained=retained, captured_at=captured))


def _home_assistant(row, scope):
    if "type" in row:
        if row["type"] != "event":
            raise ImportRejected("unsupported_home_assistant_message")
        event = object_value(row.get("event"))
    else:
        event = row
    if event.get("event_type") != "state_changed":
        raise ImportRejected("unsupported_home_assistant_event")
    data = object_value(event.get("data"))
    entity = name(data.get("entity_id"))
    if entity not in scope["entities"]:
        raise ImportRejected("entity_out_of_scope")
    observed = required_time(event.get("time_fired"))
    state_obj = data.get("new_state")
    kind = scope["entities"][entity]
    evidence = dict(entity=entity, sensor_kind=kind, state="removed", value=None, unit=None)
    if state_obj is not None:
        state_obj = object_value(state_obj)
        if state_obj.get("entity_id") != entity:
            raise ImportRejected("entity_identity_mismatch")
        state = state_obj.get("state")
        if not isinstance(state, str) or len(state) > 64:
            raise ImportRejected("invalid_entity_state")
        attributes = object_value(state_obj.get("attributes", {}))
        if attributes.get("device_class") != kind:
            raise ImportRejected("sensor_class_mismatch")
        evidence["state"] = state
        if state not in {"unknown", "unavailable"}:
            if kind == "temperature":
                unit = attributes.get("unit_of_measurement")
                if not isinstance(unit, str) or unit not in {"C", "F", "\u00b0C", "\u00b0F"}:
                    raise ImportRejected("unsupported_temperature_unit")
                try:
                    value = float(state)
                except ValueError:
                    raise ImportRejected("invalid_temperature_value") from None
                if not math.isfinite(value):
                    raise ImportRejected("invalid_temperature_value")
                evidence.update(value=value, unit=unit)
            elif state not in {"on", "off"}:
                raise ImportRejected("invalid_binary_sensor_state")
    return dict(source_event_id=entity + ":" + observed, observed_at=observed,
                asset_ref=entity, kind="environment", title=kind + " state observation",
                evidence=evidence)


def _thingsboard(row, scope):
    # Our local export envelope, not an assumed native alarm/event stream API.
    if row.get("export_schema") != "netrisk-thingsboard-v1":
        raise ImportRejected("unsupported_thingsboard_export")
    device = name(row.get("device"))
    if device not in scope["devices"]:
        raise ImportRejected("device_out_of_scope")
    fields = scope["devices"][device]
    observed = required_time(row.get("observed_at"))
    if row.get("type") == "telemetry":
        key = name(row.get("key"))
        if key not in fields["telemetry"]:
            raise ImportRejected("telemetry_out_of_scope")
        spec = fields["telemetry"][key]
        if row.get("unit") != spec["unit"]:
            raise ImportRejected("telemetry_unit_mismatch")
        value = row.get("value")
        state = row.get("state")
        if state not in ("observed", "unknown", "unavailable"):
            raise ImportRejected("invalid_telemetry_state")
        if state != "observed":
            if value is not None:
                raise ImportRejected("unavailable_value_not_null")
        elif spec["kind"] == "temperature":
            if (isinstance(value, bool) or not isinstance(value, (float, int)) or
                    abs(value) > 1000000 or not math.isfinite(value)):
                raise ImportRejected("invalid_temperature_value")
        elif not isinstance(value, bool):
            raise ImportRejected("invalid_binary_telemetry")
        return dict(source_event_id=digest([device, key, observed]), observed_at=observed,
                    asset_ref=device, kind="telemetry", title=spec["kind"] + " telemetry observation",
                    evidence=dict(device=device, key=key, sensor_kind=spec["kind"],
                                  state=state, value=value, unit=spec["unit"],
                                  calibration="not-verified"))
    if row.get("type") == "alarm":
        alarm_type = name(row.get("alarm_type"))
        if alarm_type not in fields["alarm_types"]:
            raise ImportRejected("alarm_out_of_scope")
        status, severity = row.get("status"), row.get("source_severity")
        if status not in ("ACTIVE_UNACK", "ACTIVE_ACK", "CLEARED_UNACK", "CLEARED_ACK"):
            raise ImportRejected("invalid_alarm_status")
        if severity not in ("CRITICAL", "MAJOR", "MINOR", "WARNING", "INDETERMINATE"):
            raise ImportRejected("invalid_alarm_severity")
        start = required_time(row.get("start_at"))
        end = timestamp(row.get("end_at"))
        start_time, observed_time = map(datetime.fromisoformat, (start, observed))
        if start_time > observed_time or (end is not None and
                not start_time <= datetime.fromisoformat(end) <= observed_time):
            raise ImportRejected("invalid_alarm_order")
        return dict(source_event_id=name(row.get("alarm_id")), observed_at=observed,
                    asset_ref=device, kind="source-alarm", title="Reported environmental alarm",
                    evidence=dict(device=device, alarm_type=alarm_type, status=status,
                                  source_severity=severity, start_at=start, end_at=end,
                                  upstream_action_allowed=False))
    raise ImportRejected("unsupported_thingsboard_record")


def normalize(source, row, *, config, imported_at):
    if source not in SOURCES:
        raise ImportRejected("unsupported_safety_source")
    # Apply shared structural limits even to fields we deliberately do not retain.
    _validate_structure(row)
    parser = {"frigate": _frigate, "home-assistant": _home_assistant,
              "thingsboard": _thingsboard, "sherlock": normalize_exposure, "maigret": normalize_exposure}[source]
    result = parser(row, config["scope"])
    return dict(result, schema_version=1, source=source,
                source_version=config["source_version"], instance=config["instance"],
                tenant=config["tenant"], site=config["site"], purpose=config["purpose"],
                scope_hash=config["scope_hash"], imported_at=imported_at,
                evidence_hash=digest(row), severity="unreviewed", confidence=None,
                live_connector=False, control_allowed=False,
                limitations=["Supplied export; source state is not verified live health.",
                             "Advisory observation; no identity, intent or safety determination.",
                             "Source score is not a calibrated safety confidence.",
                             "Raw media, identities and arbitrary source attributes are not retained."])
