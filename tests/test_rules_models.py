import pytest

from apate.core import OperationStatus
from apate.plugins import EventType
from apate.rules import Action, ActionKind, Condition, Rule, RuleDefinitionError, parse_rules


def test_condition_matches_event_by_type_plugin_and_payload():
    from apate.plugins import PluginEvent

    condition = Condition(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        payload={"kind": "scan"},
    )
    event = PluginEvent(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id="op-1",
        payload={"kind": "scan", "source_ip": "203.0.113.10"},
    )
    assert condition.matches_event(event) is True


def test_condition_does_not_match_different_plugin():
    from apate.plugins import PluginEvent

    condition = Condition(event_type=EventType.INTERACTION, plugin_id="honeypot-mock-1")
    event = PluginEvent(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-2",
        surface="network",
        operation_id="op-1",
    )
    assert condition.matches_event(event) is False


def test_condition_cannot_combine_event_type_and_closure_due():
    with pytest.raises(RuleDefinitionError):
        Condition(event_type=EventType.INTERACTION, closure_due=True)


def test_condition_requires_event_type_or_closure_due():
    with pytest.raises(RuleDefinitionError):
        Condition()


def test_action_transition_requires_to():
    with pytest.raises(RuleDefinitionError):
        Action(kind=ActionKind.TRANSITION)


def test_action_transition_rejects_invalid_target():
    # PLANNING no es un destino valido: ninguna transicion vuelve ahi.
    with pytest.raises(RuleDefinitionError):
        Action(kind=ActionKind.TRANSITION, to=OperationStatus.PLANNING)


def test_action_non_transition_rejects_to():
    with pytest.raises(RuleDefinitionError):
        Action(kind=ActionKind.DEPLOY, to=OperationStatus.ACTIVE)


# -- Action.signatures() (M9, hardening) -------------------------------------


def test_signatures_for_plugin_action_with_plugin_id():
    action = Action(kind=ActionKind.RETIRE, plugin_id="honeypot-mock-1")
    assert action.signatures() == ["retire", "retire:honeypot-mock-1"]


def test_signatures_for_plugin_action_without_plugin_id():
    action = Action(kind=ActionKind.RETIRE)
    assert action.signatures() == ["retire"]


def test_signatures_for_transition_action():
    action = Action(kind=ActionKind.TRANSITION, to=OperationStatus.CLOSED)
    assert action.signatures() == ["transition", "transition:closed"]


def test_parse_rules_from_yaml_text():
    yaml_text = """
    rules:
      - name: "Escaneo -> desplegar segundo mock y activar"
        when:
          event_type: interaction
          plugin_id: honeypot-mock-1
          payload:
            kind: scan
        then:
          - action: deploy
            plugin_id: honeypot-mock-2
          - action: transition
            to: active
    """
    rules = parse_rules(yaml_text)

    assert len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, Rule)
    assert rule.name == "Escaneo -> desplegar segundo mock y activar"
    assert rule.when.event_type == EventType.INTERACTION
    assert rule.when.payload == {"kind": "scan"}
    assert len(rule.then) == 2
    assert rule.then[0].kind == ActionKind.DEPLOY
    assert rule.then[0].plugin_id == "honeypot-mock-2"
    assert rule.then[1].kind == ActionKind.TRANSITION
    assert rule.then[1].to == OperationStatus.ACTIVE


def test_parse_rules_with_closure_due_and_wildcard_plugin():
    yaml_text = """
    rules:
      - name: "Cierre automatico"
        when:
          closure_due: true
        then:
          - action: retire
          - action: transition
            to: closed
    """
    rules = parse_rules(yaml_text)

    assert len(rules) == 1
    assert rules[0].when.closure_due is True
    assert rules[0].then[0].plugin_id is None  # sin plugin_id => todos los plugins


def test_parse_rules_empty_document_returns_empty_list():
    assert parse_rules("") == []


def test_parse_rules_missing_field_raises_rule_definition_error():
    yaml_text = """
    rules:
      - when:
          event_type: interaction
        then: []
    """
    with pytest.raises(RuleDefinitionError):
        parse_rules(yaml_text)


def test_parse_rules_unknown_action_kind_raises_rule_definition_error():
    yaml_text = """
    rules:
      - name: "Regla invalida"
        when:
          event_type: interaction
        then:
          - action: explode
    """
    with pytest.raises(RuleDefinitionError):
        parse_rules(yaml_text)


def test_parse_rules_invalid_yaml_syntax_raises_rule_definition_error():
    # Sintaxis YAML rota (corchete sin cerrar), no un problema de
    # esquema: parse_rules debe reportar esto tambien como
    # RuleDefinitionError, no dejar pasar un yaml.YAMLError crudo -
    # quien edita reglas a mano (por ejemplo desde la interfaz web de
    # M4b) solo deberia tener que atajar un tipo de excepcion.
    with pytest.raises(RuleDefinitionError):
        parse_rules("rules: [invalid")


def test_parse_rules_document_that_is_not_a_mapping_raises_rule_definition_error():
    with pytest.raises(RuleDefinitionError):
        parse_rules("- just\n- a\n- list\n")


# -- Condition.to_dict() (M12f) -----------------------------------------------


def test_condition_to_dict_from_dict_roundtrip_for_event_shaped_condition():
    condition = Condition(
        event_type=EventType.TTP_OBSERVED, plugin_id="honeypot-mock-1", payload={"ttp_id": "T1499"}
    )

    restored = Condition.from_dict(condition.to_dict())

    assert restored == condition


def test_condition_to_dict_from_dict_roundtrip_for_closure_due_condition():
    # event_type=None viaja explicito en el dict (a diferencia del YAML,
    # donde la clave simplemente se omite) -- from_dict() tiene que
    # distinguir "la clave esta pero vale None" de EventType(None), que
    # rompería.
    condition = Condition(closure_due=True)

    restored = Condition.from_dict(condition.to_dict())

    assert restored == condition
    assert condition.to_dict()["event_type"] is None
