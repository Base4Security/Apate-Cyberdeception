from apate.plugins import EventBus, EventType, PluginEvent
from apate.telemetry import IoC, JSONFileTelemetryRepository, TelemetryCollector


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


def test_handle_event_normalizes_and_persists(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    collector = TelemetryCollector(repository=repo)

    collector.handle_event(_make_event())

    events = collector.list_events("op-1")
    assert len(events) == 1
    assert events[0].plugin_id == "honeypot-mock-1"


def test_list_events_returns_events_in_order(tmp_path):
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))

    collector.handle_event(_make_event(payload={"kind": "scan"}))
    collector.handle_event(_make_event(payload={"kind": "access"}))

    kinds = [e.payload["kind"] for e in collector.list_events("op-1")]
    assert kinds == ["scan", "access"]


def test_list_events_for_unknown_operation_returns_empty(tmp_path):
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))
    assert collector.list_events("no-existe") == []


def test_list_iocs_dedupes_by_type_and_value(tmp_path):
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))

    collector.handle_event(_make_event(payload={"kind": "scan", "source_ip": "203.0.113.10"}))
    collector.handle_event(_make_event(payload={"kind": "access", "source_ip": "203.0.113.10"}))
    collector.handle_event(_make_event(payload={"kind": "exfil", "hash": "deadbeef"}))

    iocs = collector.list_iocs("op-1")
    assert iocs == [IoC(type="ip", value="203.0.113.10"), IoC(type="hash", value="deadbeef")]


def test_list_ttps_dedupes_and_sorts(tmp_path):
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))

    collector.handle_event(
        _make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"})
    )
    collector.handle_event(
        _make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"})
    )
    collector.handle_event(
        _make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"})
    )

    assert collector.list_ttps("op-1") == ["T1046", "T1078"]


def test_list_ttps_by_operation_delegates_to_repository(tmp_path):
    # Fase 4 post-BlackHat (ver docs/roadmap.md): la consulta agregada
    # cross-operacion -- el colector no la resuelve el mismo, delega
    # tal cual en el repositorio.
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))

    collector.handle_event(_make_event(operation_id="op-1", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"}))
    collector.handle_event(_make_event(operation_id="op-2", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))

    result = collector.list_ttps_by_operation(["op-1", "op-2"])

    assert result == {"op-1": ["T1078"], "op-2": ["T1046"]}


def test_list_events_by_operation_delegates_grouped_records(tmp_path):
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))
    collector.handle_event(_make_event(operation_id="op-1", payload={"kind": "one"}))
    collector.handle_event(_make_event(operation_id="op-2", payload={"kind": "two"}))

    result = collector.list_events_by_operation(["op-1", "op-2"])

    assert result["op-1"][0].payload["kind"] == "one"
    assert result["op-2"][0].payload["kind"] == "two"


def test_attach_subscribes_to_an_additional_bus(tmp_path):
    # Un mismo colector "central" puede escuchar mas de una operacion:
    # se lo construye sin bus y se lo va enganchando a medida que se
    # crean operaciones (attach), en vez de atarlo a un unico bus.
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))
    bus_op1 = EventBus()
    bus_op2 = EventBus()
    collector.attach(bus_op1)
    collector.attach(bus_op2)

    bus_op1.publish(_make_event(operation_id="op-1"))
    bus_op2.publish(_make_event(operation_id="op-2"))

    assert len(collector.list_events("op-1")) == 1
    assert len(collector.list_events("op-2")) == 1


def test_constructor_bus_argument_subscribes_immediately(tmp_path):
    bus = EventBus()
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path), bus=bus)

    bus.publish(_make_event())

    assert len(collector.list_events("op-1")) == 1
