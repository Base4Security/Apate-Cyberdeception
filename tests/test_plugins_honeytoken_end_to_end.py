"""Caso end-to-end de M7: HoneytokenPlugin desplegado sobre una
Operation real (M1), con el RuleEngine (M3) reaccionando a un acceso
detectado por check_access() -- mismo patron usado con
MockHoneypotPlugin en tests/test_rules_end_to_end.py, pero con un
plugin real (filesystem) en vez de simulado."""

import os

from apate.core import AdversaryProfile, Narrative, Operation, OperationStatus, PluginBinding, RulesOfEngagement
from apate.plugins import EventBus, EventType, HoneytokenPlugin, PluginLifecycleState
from apate.rules import Action, ActionKind, Condition, Rule, RuleEngine


def _make_operation() -> Operation:
    return Operation(
        name="Operacion de prueba - honeytoken",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1552.001"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def test_honeytoken_access_triggers_mark_compromised_via_rule_engine(tmp_path):
    bus = EventBus()
    operation = _make_operation()
    operation.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", config={"directory": str(tmp_path)}))

    honeytoken = HoneytokenPlugin(
        plugin_id="honeytoken-1",
        surface="data",
        operation_id=operation.id,
        bus=bus,
        config={"directory": str(tmp_path)},
    )

    rule = Rule(
        name="Acceso a honeytoken-1: marcar la operacion como comprometida",
        when=Condition(event_type=EventType.INTERACTION, plugin_id="honeytoken-1", payload={"kind": "access"}),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.COMPROMISED)],
    )
    engine = RuleEngine(operation=operation, plugins={"honeytoken-1": honeytoken}, bus=bus, rules=[rule])

    operation.mark_active()
    honeytoken.deploy()
    assert honeytoken.state == PluginLifecycleState.DEPLOYED
    assert operation.status == OperationStatus.ACTIVE  # deploy() por si solo no dispara la regla

    # Simula que un atacante abrio uno de los senuelos: se fuerza el
    # atime hacia adelante en vez de confiar en que la lectura real lo
    # actualice, ya que eso depende del filesystem (ver la limitacion
    # documentada en apate/plugins/honeytoken.py) -- lo que este test
    # verifica es la reaccion del RuleEngine al evento, no el
    # comportamiento de atime del sistema operativo.
    target = tmp_path / "credenciales.csv"
    stat_result = os.stat(target)
    os.utime(target, (stat_result.st_atime + 10, stat_result.st_mtime))

    events = honeytoken.check_access()

    assert any(e.event_type == EventType.INTERACTION and e.payload["kind"] == "access" for e in events)
    assert operation.status == OperationStatus.COMPROMISED

    # Cierre: retirar el honeytoken no debe dejar archivos huerfanos.
    honeytoken.retire()
    assert list(tmp_path.iterdir()) == []
    assert honeytoken.state == PluginLifecycleState.RETIRED
