"""Tests para apate.web._engage_preparation -- vista de "Preparacion"
(Goals Prepare/Understand de MITRE Engage, kind == "strategic")
cruzada contra los campos reales de una Operation. Unitario sobre
preparation_coverage() en aislamiento (sin HTTP) -- la integracion
(tab presente en operations/detail.html) vive en
tests/test_web_operations_preparation_tab.py."""

from datetime import datetime, timedelta, timezone

from apate.core import (
    AdversaryProfile,
    ClosureCriteria,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
    StrategicDecisions,
    StrategicObjective,
)
from apate.core.models import Environment, OperationStatus
from apate.plugins import EventType
from apate.rules.models import Condition
from apate.web._engage_preparation import NO_FIELD_ACTIVITY_IDS, preparation_coverage


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _coverage(operation, buda_panels=None, buda_tools_mounted=True) -> dict:
    rows = preparation_coverage(operation, buda_panels=buda_panels or {}, buda_tools_mounted=buda_tools_mounted)
    return {row["activity"].id: row for row in rows}


# -- Estructura general -------------------------------------------------


def test_returns_exactly_the_eight_strategic_activities_in_dataset_order():
    rows = preparation_coverage(_make_operation(), buda_panels={}, buda_tools_mounted=True)

    ids = [row["activity"].id for row in rows]
    assert ids == ["SAC0001", "SAC0002", "SAC0003", "SAC0004", "SAC0005", "SAC0006", "SAC0012", "SAC0009"]


def test_every_row_has_a_valid_status():
    rows = preparation_coverage(_make_operation(), buda_panels={}, buda_tools_mounted=True)

    for row in rows:
        assert row["status"] in ("covered", "partial", "not_covered", "no_field")
        assert row["detail"]


def test_threat_model_always_no_field_regardless_of_operation_data():
    fully_loaded = _make_operation(
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"], target_assets=["ERP"]),
    )

    coverage = _coverage(fully_loaded)

    assert coverage["SAC0009"]["status"] == "no_field"
    assert "SAC0009" in NO_FIELD_ACTIVITY_IDS


# -- SAC0001 Operational Objective -> StrategicDecisions.objectives --------


def test_operational_objective_not_covered_when_bare():
    assert _coverage(_make_operation())["SAC0001"]["status"] == "not_covered"


def test_operational_objective_partial_with_roles_but_no_objectives():
    op = _make_operation(strategic_decisions=StrategicDecisions(roles={"CTI": "Equipo"}))
    assert _coverage(op)["SAC0001"]["status"] == "partial"


def test_operational_objective_covered_with_objectives():
    op = _make_operation(strategic_decisions=StrategicDecisions(objectives=[StrategicObjective.EARLY_DETECTION]))
    row = _coverage(op)["SAC0001"]
    assert row["status"] == "covered"
    assert "Detección temprana" in row["detail"]


# -- SAC0002 Persona Creation -> perfiles de usuario (identidad/comportamiento) --


def test_persona_creation_not_covered_without_any_identity_plugin():
    assert _coverage(_make_operation())["SAC0002"]["status"] == "not_covered"


def test_persona_creation_not_covered_when_tools_not_mounted():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda"))

    row = _coverage(op, buda_tools_mounted=False)["SAC0002"]

    assert row["status"] == "not_covered"
    assert "BUDA" not in row["detail"]
    assert "DOLOS-T" not in row["detail"]


def test_persona_creation_partial_when_plugin_bound_without_profiles():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda"))

    row = _coverage(op, buda_panels={"buda-1": {"found": True, "user_profiles": []}})["SAC0002"]

    assert row["status"] == "partial"


def test_persona_creation_covered_when_profiles_present():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda"))

    row = _coverage(
        op,
        buda_panels={"buda-1": {"found": True, "user_profiles": [{"id": 1, "name": "Maria"}]}},
    )["SAC0002"]

    assert row["status"] == "covered"
    assert "1 perfil" in row["detail"]


def test_persona_creation_ignores_non_buda_bindings():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="mock"))

    assert _coverage(op)["SAC0002"]["status"] == "not_covered"


# -- SAC0003 Storyboarding -> Scenario (paso 3) -----------------------------


def test_storyboarding_not_covered_without_scenarios():
    assert _coverage(_make_operation())["SAC0003"]["status"] == "not_covered"


def test_storyboarding_partial_when_scenario_has_no_related_ttps():
    op = _make_operation()
    op.add_scenario(Scenario(description="Escenario base"))

    assert _coverage(op)["SAC0003"]["status"] == "partial"


def test_storyboarding_covered_when_scenario_has_related_ttps():
    op = _make_operation()
    op.add_scenario(Scenario(description="Escenario base", related_ttps=["T1046"]))

    assert _coverage(op)["SAC0003"]["status"] == "covered"


# -- SAC0004 Cyber Threat Intelligence -> AdversaryProfile ------------------


def test_cti_not_covered_when_profile_bare():
    assert _coverage(_make_operation())["SAC0004"]["status"] == "not_covered"


def test_cti_partial_with_only_motivation_or_notes():
    op = _make_operation(adversary_profile=AdversaryProfile(name="APT", motivation="espionaje"))
    assert _coverage(op)["SAC0004"]["status"] == "partial"


def test_cti_covered_with_expected_ttps():
    op = _make_operation(adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]))
    assert _coverage(op)["SAC0004"]["status"] == "covered"


# -- SAC0005 Gating Criteria -> ClosureCriteria -----------------------------


def test_gating_criteria_not_covered_when_empty():
    assert _coverage(_make_operation())["SAC0005"]["status"] == "not_covered"


def test_gating_criteria_partial_with_only_free_text_conditions():
    op = _make_operation(closure_criteria=ClosureCriteria(conditions=["si se detecta algo raro"]))
    assert _coverage(op)["SAC0005"]["status"] == "partial"


def test_gating_criteria_covered_with_end_date():
    op = _make_operation(closure_criteria=ClosureCriteria(end_date=datetime.now(timezone.utc) + timedelta(days=30)))
    assert _coverage(op)["SAC0005"]["status"] == "covered"


def test_gating_criteria_covered_with_trigger_conditions():
    op = _make_operation(
        closure_criteria=ClosureCriteria(trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED)])
    )
    assert _coverage(op)["SAC0005"]["status"] == "covered"


# -- SAC0006 After-Action Review -> informe post-operacion (M6) ------------


def test_after_action_review_not_covered_while_planning():
    assert _coverage(_make_operation())["SAC0006"]["status"] == "not_covered"


def test_after_action_review_partial_while_active():
    op = _make_operation()
    op.mark_active()
    assert _coverage(op)["SAC0006"]["status"] == "partial"


def test_after_action_review_covered_once_closed():
    op = _make_operation()
    op.mark_active()
    op.close()
    assert _coverage(op)["SAC0006"]["status"] == "covered"


# -- SAC0012 Engagement Environment -> RulesOfEngagement.environment -------


def test_engagement_environment_partial_with_default_isolated_and_no_constraints():
    row = _coverage(_make_operation())["SAC0012"]
    assert row["status"] == "partial"


def test_engagement_environment_covered_when_environment_is_not_isolated():
    op = _make_operation(roe=RulesOfEngagement(environment=Environment.NEAR_PRODUCTION))
    row = _coverage(op)["SAC0012"]
    assert row["status"] == "covered"
    assert "Cercano a producción" in row["detail"]


def test_engagement_environment_covered_with_roe_constraints_even_if_isolated():
    op = _make_operation(roe=RulesOfEngagement(forbidden_actions=["deploy:*"]))
    assert _coverage(op)["SAC0012"]["status"] == "covered"


# -- Higiene de nombres (function-first, ver test_web_function_first_naming.py) --


def test_no_detail_text_mentions_branded_tool_names():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda"))
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", plugin_kind="dolost"))

    rows = preparation_coverage(op, buda_panels={}, buda_tools_mounted=False)

    for row in rows:
        assert "BUDA" not in row["detail"]
        assert "DOLOS-T" not in row["detail"]
