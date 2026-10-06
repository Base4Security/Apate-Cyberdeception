from apate.plugins import EventType, PluginEvent
from apate.telemetry import IoC, TelemetryRecord


def _make_event(**overrides) -> PluginEvent:
    defaults = dict(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id="op-1",
        payload={"kind": "scan", "source_ip": "203.0.113.10"},
    )
    defaults.update(overrides)
    return PluginEvent(**defaults)


def test_from_event_normalizes_interaction_with_ip_ioc():
    event = _make_event()
    record = TelemetryRecord.from_event(event)

    assert record.event_type == EventType.INTERACTION
    assert record.operation_id == "op-1"
    assert record.plugin_id == "honeypot-mock-1"
    assert record.surface == "network"
    assert record.source_event_id == event.id
    assert record.timestamp == event.timestamp
    assert record.ttp_id is None
    assert record.iocs == [IoC(type="ip", value="203.0.113.10")]
    assert record.payload == {"kind": "scan", "source_ip": "203.0.113.10"}


def test_from_event_extracts_ttp_id_regardless_of_event_type():
    event = _make_event(
        event_type=EventType.TTP_OBSERVED,
        payload={"ttp_id": "T1078", "detail": "acceso simulado"},
    )
    record = TelemetryRecord.from_event(event)

    assert record.ttp_id == "T1078"
    assert record.iocs == []  # el payload no trae ninguna clave reconocida como IoC


def test_from_event_extracts_multiple_iocs():
    event = _make_event(payload={"kind": "exfil", "hash": "deadbeef", "source_ip": "198.51.100.7"})
    record = TelemetryRecord.from_event(event)

    values = {(ioc.type, ioc.value) for ioc in record.iocs}
    assert values == {("hash", "deadbeef"), ("ip", "198.51.100.7")}


def test_from_event_unrecognized_payload_key_kept_in_raw_payload_but_not_promoted_to_ioc():
    event = _make_event(payload={"kind": "scan", "custom_field": "algo-no-mapeado"})
    record = TelemetryRecord.from_event(event)

    assert record.iocs == []
    assert record.payload["custom_field"] == "algo-no-mapeado"


def test_telemetry_record_roundtrip_to_dict_from_dict():
    event = _make_event(payload={"kind": "access", "source_ip": "198.51.100.7", "ttp_id": "T1078"})
    record = TelemetryRecord.from_event(event)

    restored = TelemetryRecord.from_dict(record.to_dict())

    assert restored.id == record.id
    assert restored.event_type == record.event_type
    assert restored.operation_id == record.operation_id
    assert restored.plugin_id == record.plugin_id
    assert restored.surface == record.surface
    assert restored.timestamp == record.timestamp
    assert restored.source_event_id == record.source_event_id
    assert restored.ttp_id == record.ttp_id
    assert restored.iocs == record.iocs
    assert restored.payload == record.payload


def test_ioc_roundtrip_to_dict_from_dict():
    ioc = IoC(type="hash", value="deadbeef")
    assert IoC.from_dict(ioc.to_dict()) == ioc
