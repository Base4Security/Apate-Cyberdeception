from datetime import datetime, timedelta, timezone

import pytest

from apate.core import (
    AdversaryProfile,
    DeceptionLevel,
    Environment,
    InvalidTransitionError,
    Narrative,
    Operation,
    OperationStatus,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
)


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(
            name="APT ficticio",
            motivation="espionaje",
            skill_level="intermediate",
            expected_ttps=["T1046", "T1078"],
        ),
        roe=RulesOfEngagement(environment=Environment.ISOLATED),
        narrative=Narrative(name="Servidor de intranet en desarrollo"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def test_operation_starts_in_planning():
    op = _make_operation()
    assert op.status == OperationStatus.PLANNING
    assert op.closed_at is None


def test_valid_transition_sequence():
    op = _make_operation()
    op.mark_active()
    assert op.status == OperationStatus.ACTIVE

    op.mark_compromised()
    assert op.status == OperationStatus.COMPROMISED

    op.close()
    assert op.status == OperationStatus.CLOSED
    assert op.closed_at is not None


def test_planning_can_close_directly():
    op = _make_operation()
    op.close()
    assert op.status == OperationStatus.CLOSED


def test_invalid_transition_raises():
    op = _make_operation()
    op.mark_active()
    with pytest.raises(InvalidTransitionError):
        # ACTIVE -> PLANNING no esta permitido: rompería la
        # trazabilidad de la operación.
        op.transition_to(OperationStatus.PLANNING)


def test_closed_operation_has_no_further_transitions():
    op = _make_operation()
    op.close()
    with pytest.raises(InvalidTransitionError):
        op.mark_active()


def test_narrative_similarity_out_of_range_raises():
    with pytest.raises(ValueError):
        Narrative(name="x", similarity_percentage=150)


def test_add_scenario_and_bind_plugin():
    op = _make_operation()
    scenario = Scenario(
        description="Detectar escaneo interno",
        related_ttps=["T1046"],
        deception_level=DeceptionLevel.BASIC,
    )
    op.add_scenario(scenario)
    op.bind_plugin(PluginBinding(plugin_id="dolost-mock", surface="network"))

    assert len(op.scenarios) == 1
    assert op.scenarios[0].description == "Detectar escaneo interno"
    assert len(op.plugins) == 1
    assert op.plugins[0].surface == "network"


def test_is_past_due():
    op = _make_operation()
    past = datetime.now(timezone.utc) - timedelta(days=1)
    op.closure_criteria.end_date = past
    assert op.is_past_due() is True

    op.close()
    # Una vez cerrada, ya no se considera "vencida pendiente de cierre".
    assert op.is_past_due() is False


def test_is_past_due_without_end_date():
    op = _make_operation()
    assert op.is_past_due() is False


def test_roundtrip_to_dict_from_dict():
    op = _make_operation()
    op.add_scenario(Scenario(description="Escenario 1", related_ttps=["T1078"]))
    op.bind_plugin(PluginBinding(plugin_id="buda-mock", surface="identity"))
    op.mark_active()

    restored = Operation.from_dict(op.to_dict())

    assert restored.id == op.id
    assert restored.name == op.name
    assert restored.status == op.status
    assert restored.adversary_profile.expected_ttps == op.adversary_profile.expected_ttps
    assert restored.roe.environment == op.roe.environment
    assert restored.narrative.name == op.narrative.name
    assert len(restored.scenarios) == 1
    assert restored.scenarios[0].description == "Escenario 1"
    assert len(restored.plugins) == 1
    assert restored.plugins[0].plugin_id == "buda-mock"
