"""Persistencia de disparos y rechazos del RuleEngine."""

from apate.core import AdversaryProfile, Narrative, Operation, OperationStatus, PluginBinding, RulesOfEngagement
from apate.plugins import EventBus, EventType, PluginEvent
from apate.rules import Action, ActionKind, Condition, RejectionKind, Rule, RuleEngine, SQLiteRuleDecisionRepository


def _operation() -> Operation:
    return Operation(
        name="Decisiones persistidas",
        adversary_profile=AdversaryProfile(name="APT"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )


def test_rule_decisions_survive_reinstantiating_the_repository(tmp_path):
    operation = _operation()
    repository = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    rule = Rule(
        name="Acceso observado -> activar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "access"}),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
    )
    engine = RuleEngine(
        operation=operation,
        plugins={},
        bus=EventBus(),
        rules=[rule],
        decision_repository=repository,
    )

    engine.handle_event(
        PluginEvent(
            event_type=EventType.INTERACTION,
            plugin_id="decoy-1",
            surface="network",
            operation_id=operation.id,
            payload={"kind": "access"},
        )
    )

    reloaded = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    firings = reloaded.list_firings_for_operation(operation.id)
    assert [firing.rule_name for firing in firings] == ["Acceso observado -> activar"]
    assert firings[0].actions[0].to == OperationStatus.ACTIVE


def test_rejected_decision_is_persisted(tmp_path):
    operation = _operation()
    operation.roe.forbidden_actions = ["transition"]
    repository = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    rule = Rule(
        name="Bloqueada",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
    )
    engine = RuleEngine(
        operation=operation,
        plugins={},
        bus=EventBus(),
        rules=[rule],
        decision_repository=repository,
    )

    event = PluginEvent(
        event_type=EventType.INTERACTION,
        plugin_id="decoy-1",
        surface="network",
        operation_id=operation.id,
    )
    engine.handle_event(event)

    reloaded = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    rejection = reloaded.list_rejections_for_operation(operation.id)[0]
    assert rejection.rule_name == "Bloqueada"
    assert rejection.kind == RejectionKind.ROE
    assert rejection.triggering_event_id == event.id


def test_execution_error_rejection_keeps_its_stable_kind_and_triggering_event(tmp_path):
    class FailingCapability:
        def rotate(self):
            raise RuntimeError("Docker no disponible")

    operation = _operation()
    operation.bind_plugin(PluginBinding(plugin_id="decoy-1", surface="network"))
    repository = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    engine = RuleEngine(
        operation=operation,
        plugins={"decoy-1": FailingCapability()},
        bus=EventBus(),
        rules=[
            Rule(
                name="Rotacion fallida",
                when=Condition(event_type=EventType.INTERACTION),
                then=[Action(kind=ActionKind.ROTATE, plugin_id="decoy-1")],
            )
        ],
        decision_repository=repository,
        reject_action_errors=True,
    )
    event = PluginEvent(
        event_type=EventType.INTERACTION,
        plugin_id="decoy-1",
        surface="network",
        operation_id=operation.id,
    )

    engine.handle_event(event)

    rejection = repository.list_rejections_for_operation(operation.id)[0]
    assert rejection.kind == RejectionKind.EXECUTION_ERROR
    assert rejection.triggering_event_id == event.id
