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


def _make_engine(*, operation=None, plugins=None, rules=None, bus=None, bind_plugins=True, **engine_kwargs):
    operation = operation or _make_operation()
    bus = bus or EventBus()
    plugins = plugins if plugins is not None else {
        "honeypot-mock-1": _RecordingPlugin(
            plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
        )
    }
    if bind_plugins:
        # M9: el motor solo puede apuntar a plugins vinculados a la
        # operacion (operation.plugins) -- se vinculan aca por
        # default, salvo que un test necesite explicitamente un plugin
        # "fuera de alcance" (bind_plugins=False).
        already_bound = {b.plugin_id for b in operation.plugins}
        for plugin_id in plugins:
            if plugin_id not in already_bound:
                operation.bind_plugin(PluginBinding(plugin_id=plugin_id, surface="network"))
    return (
        RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=rules or [], **engine_kwargs),
        operation,
        plugins,
    )


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

    engine.handle_event(_make_event())

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


def test_history_starts_empty():
    engine, _, _ = _make_engine()

    assert engine.history == []


def test_handle_event_appends_firing_with_rule_name_and_triggering_event_id():
    rule = Rule(
        name="Escaneo -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, _ = _make_engine(rules=[rule])
    event = _make_event()

    engine.handle_event(event)

    assert len(engine.history) == 1
    firing = engine.history[0]
    assert firing.rule_name == "Escaneo -> deploy"
    assert firing.triggering_event_id == event.id
    assert firing.actions == rule.then


def test_check_closure_appends_firing_with_no_triggering_event_id():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(end_date=datetime.now(timezone.utc) - timedelta(days=1))
    )
    rule = Rule(
        name="Cierre automatico",
        when=Condition(closure_due=True),
        then=[Action(kind=ActionKind.RETIRE)],
    )
    engine, _, _ = _make_engine(operation=operation, rules=[rule])

    engine.check_closure()

    assert len(engine.history) == 1
    assert engine.history[0].triggering_event_id is None


def test_non_matching_event_does_not_append_to_history():
    rule = Rule(
        name="Acceso -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "access"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, _ = _make_engine(rules=[rule])

    engine.handle_event(_make_event(payload={"kind": "scan"}))

    assert engine.history == []


# -- M9: Rules of Engagement (forbidden_actions/allowed_actions) ------------


def test_forbidden_action_by_kind_is_not_executed_and_is_recorded():
    operation = _make_operation(roe=RulesOfEngagement(forbidden_actions=["deploy"]))
    rule = Rule(
        name="Escaneo -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, plugins = _make_engine(operation=operation, rules=[rule])

    engine.handle_event(_make_event())

    assert plugins["honeypot-mock-1"].calls == []
    assert len(engine.rejected_actions) == 1
    assert engine.rejected_actions[0].rule_name == "Escaneo -> deploy"
    assert engine.rejected_actions[0].action.kind == ActionKind.DEPLOY
    assert "Rules of Engagement" in engine.rejected_actions[0].reason


def test_forbidden_action_by_plugin_specific_signature_only_blocks_that_plugin():
    operation = _make_operation(roe=RulesOfEngagement(forbidden_actions=["deploy:mock-1"]))
    bus = EventBus()
    plugins = {
        "mock-1": _RecordingPlugin(plugin_id="mock-1", surface="network", operation_id=operation.id, bus=bus),
        "mock-2": _RecordingPlugin(plugin_id="mock-2", surface="network", operation_id=operation.id, bus=bus),
    }
    rule = Rule(
        name="Escaneo -> deploy ambos",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[
            Action(kind=ActionKind.DEPLOY, plugin_id="mock-1"),
            Action(kind=ActionKind.DEPLOY, plugin_id="mock-2"),
        ],
    )
    engine, _, plugins = _make_engine(operation=operation, plugins=plugins, rules=[rule], bus=bus)

    engine.handle_event(_make_event())

    assert plugins["mock-1"].calls == []  # bloqueado por la signature especifica
    assert plugins["mock-2"].calls == ["deploy"]  # no mencionado en forbidden_actions
    assert len(engine.rejected_actions) == 1


def test_forbidden_transition_target_is_rejected_and_operation_keeps_its_status():
    operation = _make_operation(roe=RulesOfEngagement(forbidden_actions=["transition:active"]))
    rule = Rule(
        name="Escaneo -> activar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
    )
    engine, operation, _ = _make_engine(operation=operation, rules=[rule])

    engine.handle_event(_make_event())

    assert operation.status == OperationStatus.PLANNING
    assert len(engine.rejected_actions) == 1


def test_allowed_actions_acts_as_allowlist_only_when_non_empty():
    operation = _make_operation(roe=RulesOfEngagement(allowed_actions=["deploy"]))
    rule = Rule(
        name="Escaneo -> deploy + retirar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[
            Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1"),
            Action(kind=ActionKind.RETIRE, plugin_id="honeypot-mock-1"),
        ],
    )
    engine, _, plugins = _make_engine(operation=operation, rules=[rule])

    engine.handle_event(_make_event())

    assert plugins["honeypot-mock-1"].calls == ["deploy"]  # retire no esta en la allowlist
    assert len(engine.rejected_actions) == 1
    assert engine.rejected_actions[0].action.kind == ActionKind.RETIRE


def test_rejected_action_does_not_prevent_the_rule_from_being_recorded_in_history():
    operation = _make_operation(roe=RulesOfEngagement(forbidden_actions=["deploy"]))
    rule = Rule(
        name="Escaneo -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    engine, _, _ = _make_engine(operation=operation, rules=[rule])

    engine.handle_event(_make_event())

    assert len(engine.history) == 1
    assert engine.history[0].rule_name == "Escaneo -> deploy"


# -- M9: alcance de plugin (operation.plugins) -------------------------------


def test_action_referencing_plugin_not_bound_to_operation_raises():
    bus = EventBus()
    operation = _make_operation()
    plugins = {
        "honeypot-mock-1": _RecordingPlugin(
            plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
        )
    }
    rule = Rule(
        name="Escaneo -> deploy",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1")],
    )
    # bind_plugins=False: el plugin esta registrado en el motor pero
    # nunca se vinculo a la operacion -- exactamente el gap que M9
    # cierra (antes no habia ningun chequeo contra operation.plugins).
    engine, operation, plugins = _make_engine(
        operation=operation, plugins=plugins, rules=[rule], bus=bus, bind_plugins=False
    )

    with pytest.raises(UnknownPluginError):
        engine.handle_event(_make_event())


def test_broadcast_action_silently_excludes_plugin_not_bound_to_operation():
    bus = EventBus()
    operation = _make_operation()
    plugins = {
        "mock-1": _RecordingPlugin(plugin_id="mock-1", surface="network", operation_id=operation.id, bus=bus),
        "mock-2": _RecordingPlugin(plugin_id="mock-2", surface="network", operation_id=operation.id, bus=bus),
    }
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network"))
    # mock-2 nunca se vincula a la operacion.
    rule = Rule(
        name="Retirar todos",
        when=Condition(event_type=EventType.INTERACTION),
        then=[Action(kind=ActionKind.RETIRE)],
    )
    engine, _, _ = _make_engine(operation=operation, plugins=plugins, rules=[rule], bus=bus, bind_plugins=False)

    engine.handle_event(_make_event())

    assert plugins["mock-1"].calls == ["retire"]
    assert plugins["mock-2"].calls == []  # excluido: fuera de alcance, no lanza


# -- M9: tope de acciones por cadena de eventos ------------------------------


class _CascadingPlugin(DeceptionPlugin):
    """Plugin de prueba que al desplegarse siempre publica un nuevo
    evento de interaccion -- simula una cascada sin limite natural,
    para poder probar RuleEngine.max_actions_per_event (M9) sin
    depender de que un plugin real vuelva a fallar por estado (lo que
    cortaria la cascada por otro motivo distinto del que se quiere
    probar aca)."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.deploy_count = 0

    def deploy(self) -> None:
        self.deploy_count += 1
        self._publish(EventType.INTERACTION, {"kind": "scan"})

    def rotate(self) -> None:
        pass

    def retire(self) -> None:
        pass


def test_default_max_actions_per_event_is_fifty():
    engine, _, _ = _make_engine()
    assert engine.max_actions_per_event == 50


def test_cascade_of_actions_is_capped_by_max_actions_per_event():
    bus = EventBus()
    operation = _make_operation()
    plugin = _CascadingPlugin(plugin_id="cascading-1", surface="data", operation_id=operation.id, bus=bus)
    operation.bind_plugin(PluginBinding(plugin_id="cascading-1", surface="data"))
    rule = Rule(
        name="Escaneo -> deploy (se autoalimenta)",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.DEPLOY, plugin_id="cascading-1")],
    )
    engine = RuleEngine(
        operation=operation, plugins={"cascading-1": plugin}, bus=bus, rules=[rule], max_actions_per_event=5
    )

    engine.handle_event(_make_event(plugin_id="cascading-1"))

    assert plugin.deploy_count == 5  # se corto la cascada, no crecio sin limite
    assert len(engine.rejected_actions) >= 1
    assert "Tope de acciones" in engine.rejected_actions[-1].reason


# -- M12f: ClosureCriteria.trigger_conditions ("Gating Criteria") -----------


def test_trigger_condition_matched_by_event_closes_the_operation():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    engine, operation, _ = _make_engine(operation=operation)

    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}))

    assert operation.status == OperationStatus.CLOSED


def test_trigger_condition_not_matched_does_not_close_the_operation():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    engine, operation, _ = _make_engine(operation=operation)

    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))

    assert operation.status == OperationStatus.PLANNING


def test_trigger_condition_close_is_recorded_in_history():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    engine, operation, _ = _make_engine(operation=operation)
    event = _make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})

    engine.handle_event(event)

    assert len(engine.history) == 1
    firing = engine.history[0]
    assert firing.rule_name == "closure_criteria.trigger_conditions"
    assert firing.triggering_event_id == event.id
    assert firing.actions == [Action(kind=ActionKind.TRANSITION, to=OperationStatus.CLOSED)]


def test_trigger_condition_bypasses_roe_forbidden_transition_to_closed():
    # La excepcion documentada en el docstring del motor (M12f): a
    # diferencia de una Action de una Rule comun, el cierre por Gating
    # Criteria NO pasa por roe.permits() -- es "the unnegotiable pause
    # or conclusion to the operation" (SAC0005 del catalogo de Engage).
    operation = _make_operation(
        roe=RulesOfEngagement(forbidden_actions=["transition:closed"]),
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        ),
    )
    engine, operation, _ = _make_engine(operation=operation)

    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}))

    assert operation.status == OperationStatus.CLOSED
    assert engine.rejected_actions == []  # no se rechaza: el bypass es intencional, no un fallo


def test_regular_rule_transition_to_closed_still_respects_roe_forbidden_actions():
    # Regresion explicita (M9, sin cambios): una Rule comun con Action
    # (TRANSITION, to=CLOSED) sigue 100% gateada por RoE -- la excepcion
    # de M12f es exclusiva de ClosureCriteria.trigger_conditions, nunca
    # se filtra hacia self.rules.
    operation = _make_operation(roe=RulesOfEngagement(forbidden_actions=["transition:closed"]))
    rule = Rule(
        name="Escaneo -> cerrar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.CLOSED)],
    )
    engine, operation, _ = _make_engine(operation=operation, rules=[rule])

    engine.handle_event(_make_event())

    assert operation.status == OperationStatus.PLANNING
    assert len(engine.rejected_actions) == 1
    assert engine.rejected_actions[0].action.to == OperationStatus.CLOSED


def test_trigger_condition_matching_event_on_already_closed_operation_is_idempotent():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    operation.close()  # ya cerrada de antemano
    engine, operation, _ = _make_engine(operation=operation)

    # No debe lanzar InvalidTransitionError ni intentar cerrar de nuevo.
    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}))

    assert operation.status == OperationStatus.CLOSED
    assert engine.history == []


def test_two_trigger_conditions_matching_same_event_close_only_once():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[
                Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}),
                Condition(event_type=EventType.TTP_OBSERVED),  # tambien matchea el mismo evento
            ]
        )
    )
    engine, operation, _ = _make_engine(operation=operation)

    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}))

    assert operation.status == OperationStatus.CLOSED
    assert len(engine.history) == 1  # no un RuleFiring por cada condicion que matchea


def test_trigger_condition_close_counts_against_max_actions_per_event():
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    engine, operation, _ = _make_engine(operation=operation, max_actions_per_event=0)

    engine.handle_event(_make_event(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"}))

    assert operation.status == OperationStatus.PLANNING  # el tope corto el cierre antes de aplicarlo
    assert len(engine.rejected_actions) == 1
    assert "Tope de acciones" in engine.rejected_actions[0].reason


def test_check_closure_does_not_evaluate_trigger_conditions():
    # trigger_conditions es inherentemente event-driven (necesita el
    # evento entrante para matches_event()) -- check_closure() sigue
    # siendo exclusivamente sobre is_past_due()/end_date, sin cambios.
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    engine, operation, _ = _make_engine(operation=operation)

    engine.check_closure()

    assert operation.status == OperationStatus.PLANNING
    assert engine.history == []


def test_max_actions_per_event_none_disables_the_cap_for_a_small_chain():
    bus = EventBus()
    operation = _make_operation()
    plugin = _RecordingPlugin(plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus)
    operation.bind_plugin(PluginBinding(plugin_id="honeypot-mock-1", surface="network"))
    rule = Rule(
        name="Escaneo -> deploy + rotate + retire",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "scan"}),
        then=[
            Action(kind=ActionKind.DEPLOY, plugin_id="honeypot-mock-1"),
            Action(kind=ActionKind.ROTATE, plugin_id="honeypot-mock-1"),
            Action(kind=ActionKind.RETIRE, plugin_id="honeypot-mock-1"),
        ],
    )
    engine = RuleEngine(
        operation=operation,
        plugins={"honeypot-mock-1": plugin},
        bus=bus,
        rules=[rule],
        max_actions_per_event=None,
    )

    engine.handle_event(_make_event())

    assert plugin.calls == ["deploy", "rotate", "retire"]
    assert engine.rejected_actions == []
