from datetime import datetime, timedelta, timezone

import pytest

from apate.core import (
    AdversaryProfile,
    ClosureCriteria,
    Narrative,
    Operation,
    OperationStatus,
    PluginBinding,
    RulesOfEngagement,
)
from apate.core.exceptions import InvalidTransitionError
from apate.plugins import DeceptionPlugin, EventBus, EventType, PluginEvent
from apate.rules import Action, ActionKind, Condition, Rule, RuleEngine, UnknownPluginError


class _RecordingPlugin(DeceptionPlugin):
    """Plugin de prueba minimo que solo registra que metodo se llamo,
    sin validar el ciclo de vida (eso ya se prueba en
    tests/test_plugins_mock.py) - aca lo que importa es que el motor
    de reglas invoque el metodo correcto sobre el plugin correcto."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.calls: list[str] = []

    def deploy(self) -> None:
        self.calls.append("deploy")

    def rotate(self) -> None:
        self.calls.append("rotate")

    def retire(self) -> None:
        self.calls.append("retire")


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        id="op-1",
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_event(**overrides) -> PluginEvent:
    defaults = dict(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id="op-1",
        payload={"kind": "scan"},
    )
    defaults.update(overrides)
    return PluginEvent(**defaults)


def _make_engine(*, operation=None, plugins=None, rules=None, bus=None):
    operation = operation or _make_operation()
    bus = bus or EventBus()
    plugins = plugins if plugins is not None else {
        "honeypot-mock-1": _RecordingPlugin(
            plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
        )
    }
    for plugin_id, plugin in plugins.items():
        if all(binding.plugin_id != plugin_id for binding in operation.plugins):
            operation.bind_plugin(PluginBinding(plugin_id=plugin_id, surface=plugin.surface))
    return RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=rules or []), operation, plugins


def test_matching_event_rule_triggers_plugin_deploy():
    rule = Rule(
        name="Escaneo -> deploy",
        when=Condition(event_type=EventType.INTERACTION, plugin_id="honeypot-mock-1", payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, plugins = _make_engine(rules=[rule])

    engine.handle_event(_make_event())

    assert plugins["honeypot-mock-1"].calls == ["deploy"]


def test_non_matching_event_does_not_trigger_actions():
    rule = Rule(
        name="Acceso -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "access"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, plugins = _make_engine(rules=[rule])

    engine.handle_event(_make_event(payload={"kind": "scan"}))

    assert plugins["honeypot-mock-1"].calls == []


def test_rule_can_trigger_multiple_actions_in_order():
    rule = Rule(
        name="Escaneo -> deploy + activar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[
            Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1"),
            Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE),
        ],
    )
    engine, operation, plugins = _make_engine(rules=[rule])

    engine.handle_event(_make_event())

    assert plugins["honeypot-mock-1"].calls == ["deploy"]
    assert operation.status == OperationStatus.ACTIVE


@pytest.mark.parametrize(
    "to_status,expected_status",
    [
        (OperationStatus.ACTIVE, OperationStatus.ACTIVE),
        (OperationStatus.CLOSED, OperationStatus.CLOSED),
    ],
)
def test_transition_action_applies_correct_operation_method(to_status, expected_status):
    rule = Rule(
        name="Transicion",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.TRANSITION, to=to_status)],
    )
    engine, operation, _ = _make_engine(rules=[rule])

    engine.handle_event(_make_event())

    assert operation.status == expected_status


def test_transition_to_compromised_requires_active_first():
    # PLANNING -> COMPROMISED no esta permitido (ver _ALLOWED_TRANSITIONS
    # en el Nucleo de Operacion); el motor no debe tragarse ese error.
    rule = Rule(
        name="Transicion invalida",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.COMPROMISED)],
    )
    engine, _, _ = _make_engine(rules=[rule])

    with pytest.raises(InvalidTransitionError):
        engine.handle_event(_make_event())


def test_action_with_no_plugin_id_targets_all_registered_plugins():
    bus = EventBus()
    operation = _make_operation()
    plugins = {
        "mock-1": _RecordingPlugin(plugin_id="mock-1", surface="network", operation_id=operation.id, bus=bus),
        "mock-2": _RecordingPlugin(plugin_id="mock-2", surface="network", operation_id=operation.id, bus=bus),
    }
    rule = Rule(
        name="Retirar todos",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.RETIRE)],
    )
    engine, _, _ = _make_engine(operation=operation, plugins=plugins, rules=[rule], bus=bus)

    engine.handle_event(_make_event(plugin_id="mock-1"))

    assert plugins["mock-1"].calls == ["retire"]
    assert plugins["mock-2"].calls == ["retire"]


def test_action_referencing_unknown_plugin_raises():
    rule = Rule(
        name="Plugin desconocido",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="no-existe")],
    )
    engine, _, _ = _make_engine(rules=[rule])

    with pytest.raises(UnknownPluginError):
        engine.handle_event(_make_event())


def test_check_closure_triggers_when_operation_is_past_due():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(end_date=datetime.now(timezone.utc) - timedelta(days=1))
    )
    rule = Rule(
        name="Cierre automatico",
        when=Condition(closure_due=True),
        then=[Action(kind=ActionKind.RETIRE), Action(kind=ActionKind.TRANSITION, to=OperationStatus.CLOSED)],
    )
    engine, _, plugins = _make_engine(operation=operation, rules=[rule])

    engine.check_closure()

    assert plugins["honeypot-mock-1"].calls == ["retire"]
    assert operation.status == OperationStatus.CLOSED


def test_check_closure_does_not_trigger_when_not_past_due():
    rule = Rule(
        name="Cierre automatico",
        when=Condition(closure_due=True),
        then=[Action(kind=ActionKind.RETIRE)],
    )
    engine, operation, plugins = _make_engine(rules=[rule])

    engine.check_closure()

    assert plugins["honeypot-mock-1"].calls == []
    assert operation.status == OperationStatus.PLANNING


def test_event_driven_rule_is_not_triggered_by_check_closure():
    rule = Rule(
        name="Solo por evento",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, plugins = _make_engine(rules=[rule])

    engine.check_closure()

    assert plugins["honeypot-mock-1"].calls == []
