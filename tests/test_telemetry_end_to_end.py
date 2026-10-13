from apate.core import AdversaryProfile, Narrative, Operation, OperationStatus, RulesOfEngagement
from apate.plugins import EventBus, EventType, MockHoneypotPlugin
from apate.rules import Action, ActionKind, Condition, Rule, RuleEngine
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def _make_operation() -> Operation:
    return Operation(
        name="Operacion de prueba - telemetria",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046", "T1078"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


class _InMemoryTelemetryRepository:
    """Repositorio minimo en memoria, solo para el test de convivencia
    con el RuleEngine: evita tocar el filesystem para probar que M3 y
    M4 conviven en el mismo bus sin interferirse."""

    def __init__(self) -> None:
        self._by_operation: dict[str, list] = {}

    def append(self, record) -> None:
        self._by_operation.setdefault(record.operation_id, []).append(record)

    def list_for_operation(self, operation_id: str) -> list:
        return list(self._by_operation.get(operation_id, []))


def test_mock_honeypot_deploy_and_access_end_to_end_through_collector(tmp_path):
    bus = EventBus()
    operation = _make_operation()
    repo = JSONFileTelemetryRepository(tmp_path)
    collector = TelemetryCollector(repository=repo, bus=bus)

    mock = MockHoneypotPlugin(
        plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
    )
    mock.deploy()
    mock.simulate_access(ttp_id="T1078")

    events = collector.list_events(operation.id)
    assert [e.event_type for e in events] == [
        EventType.INTERACTION,  # scan
        EventType.INTERACTION,  # access
        EventType.TTP_OBSERVED,  # ttp observada
    ]

    iocs = collector.list_iocs(operation.id)
    assert iocs[0].type == "ip"
    assert iocs[0].value == "203.0.113.10"  # IP por defecto del mock (TEST-NET-3, RFC 5737)

    assert collector.list_ttps(operation.id) == ["T1078"]

    # La telemetria persiste: un colector nuevo apuntando al mismo
    # directorio ve los mismos registros sin haber escuchado el bus.
    reloaded = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))
    assert len(reloaded.list_events(operation.id)) == 3


def test_collector_runs_in_parallel_with_rule_engine_without_interfering():
    """M4 agrega un colector en paralelo al RuleEngine de M3 sobre el
    mismo bus, sin reemplazarlo: un evento debe disparar la regla Y
    quedar registrado en la telemetria."""

    bus = EventBus()
    operation = _make_operation()

    mock = MockHoneypotPlugin(
        plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
    )
    RuleEngine(
        operation=operation,
        plugins={"honeypot-mock-1": mock},
        bus=bus,
        rules=[
            Rule(
                name="Escaneo -> activar",
                when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
                then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
            )
        ],
    )
    collector = TelemetryCollector(repository=_InMemoryTelemetryRepository(), bus=bus)

    mock.deploy()

    assert operation.status == OperationStatus.ACTIVE  # disparado por el RuleEngine (M3)
    assert len(collector.list_events(operation.id)) == 1  # registrado por el TelemetryCollector (M4)
