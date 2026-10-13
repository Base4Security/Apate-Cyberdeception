"""Tests para los campos de M10 (apate.core.models) - alineacion
completa del modelo con la metodologia CTI-a-ciberengano, ver
docs/analisis-metodologia-cti.md y la seccion M10 de docs/roadmap.md.

Cubre los dataclasses nuevos/extendidos (roundtrip to_dict/from_dict)
y, sobre todo, que una operacion persistida en disco ANTES de M10 (sin
ninguno de estos campos) siga cargando sin explotar via
JSONFileOperationRepository -- son cambios aditivos, no deberian
romper compatibilidad hacia atras."""

import json

import pytest

from apate.core import (
    AdversaryProfile,
    ClosureCriteria,
    DeceptionEffect,
    Environment,
    JSONFileOperationRepository,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
    StrategicDecisions,
    StrategicObjective,
)


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M10",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(environment=Environment.ISOLATED),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


# -- AdversaryProfile.target_assets ------------------------------------------


def test_adversary_profile_target_assets_roundtrip():
    profile = AdversaryProfile(name="APT ficticio", target_assets=["ERP", "AD"])
    restored = AdversaryProfile.from_dict(profile.to_dict())
    assert restored.target_assets == ["ERP", "AD"]


def test_adversary_profile_target_assets_defaults_to_empty_list():
    assert AdversaryProfile(name="x").target_assets == []


# -- StrategicDecisions / StrategicObjective ---------------------------------


def test_strategic_decisions_roundtrip():
    decisions = StrategicDecisions(
        objectives=[StrategicObjective.EARLY_DETECTION, StrategicObjective.ATTRIBUTION],
        roles={"CTI": "Equipo de inteligencia", "SOC/IR": "Equipo de respuesta"},
        resource_estimate="2 analistas part-time durante 3 meses",
    )

    restored = StrategicDecisions.from_dict(decisions.to_dict())

    assert restored.objectives == [StrategicObjective.EARLY_DETECTION, StrategicObjective.ATTRIBUTION]
    assert restored.roles == {"CTI": "Equipo de inteligencia", "SOC/IR": "Equipo de respuesta"}
    assert restored.resource_estimate == "2 analistas part-time durante 3 meses"


def test_strategic_decisions_defaults_are_empty():
    decisions = StrategicDecisions()
    assert decisions.objectives == []
    assert decisions.roles == {}
    assert decisions.resource_estimate == ""


def test_strategic_objective_rejects_values_outside_the_five_categories():
    # objectives esta restringido a las 5 categorias del paper (enum),
    # no texto libre -- un valor fuera de esa lista cerrada debe
    # rechazarse, no aceptarse silenciosamente como string.
    with pytest.raises(ValueError):
        StrategicDecisions.from_dict({"objectives": ["no-es-una-categoria-valida"]})


def test_all_five_paper_categories_are_valid_objectives():
    # Las cinco categorias que exige el paper (Pacheco & Staino):
    # deteccion temprana, recoleccion de inteligencia,
    # disuasion/desgaste, atribucion, validacion de controles.
    assert {o.value for o in StrategicObjective} == {
        "early_detection",
        "intelligence_collection",
        "deterrence_attrition",
        "attribution",
        "controls_validation",
    }


def test_operation_has_strategic_decisions_by_default():
    op = _make_operation()
    assert op.strategic_decisions == StrategicDecisions()


# -- PluginBinding.scenario_id + DeceptionEffect -----------------------------


def test_plugin_binding_scenario_id_and_effect_roundtrip():
    binding = PluginBinding(
        plugin_id="honeytoken-1",
        surface="data",
        scenario_id="scenario-42",
        effect=DeceptionEffect(
            expected_adversary_belief="El archivo contiene credenciales reales",
            expected_adversary_action="Intentar usarlas para moverse lateralmente",
            success_metric="Alerta de uso de credencial sintetica en menos de 5 minutos",
        ),
    )

    restored = PluginBinding.from_dict(binding.to_dict())

    assert restored.scenario_id == "scenario-42"
    assert restored.effect.expected_adversary_belief == "El archivo contiene credenciales reales"
    assert restored.effect.expected_adversary_action == "Intentar usarlas para moverse lateralmente"
    assert restored.effect.success_metric == "Alerta de uso de credencial sintetica en menos de 5 minutos"


def test_plugin_binding_scenario_id_defaults_to_none():
    binding = PluginBinding(plugin_id="mock-1", surface="network")
    assert binding.scenario_id is None
    assert binding.effect == DeceptionEffect()


def test_plugin_binding_does_not_validate_scenario_id_against_operation():
    # Documentado en el docstring de PluginBinding: el dataclass no
    # tiene visibilidad de la Operation que lo contiene, asi que un
    # scenario_id que no existe en ningun lado no rompe nada al
    # construir el binding -- la resolucion (y el "no encontrado") se
    # maneja en Operation.find_scenario().
    binding = PluginBinding(plugin_id="mock-1", surface="network", scenario_id="no-existe")
    op = _make_operation()
    op.bind_plugin(binding)

    assert op.find_scenario(binding.scenario_id) is None


def test_operation_find_scenario_resolves_bound_scenario():
    op = _make_operation()
    scenario = Scenario(description="Detectar escaneo interno", related_ttps=["T1046"])
    op.add_scenario(scenario)
    op.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", scenario_id=scenario.id))

    resolved = op.find_scenario(op.plugins[0].scenario_id)

    assert resolved is scenario


def test_operation_find_scenario_with_none_returns_none():
    op = _make_operation()
    assert op.find_scenario(None) is None


# -- Narrative.psychological_impact ------------------------------------------


def test_narrative_psychological_impact_roundtrip():
    narrative = Narrative(name="x", psychological_impact="sesgo de urgencia")
    restored = Narrative.from_dict(narrative.to_dict())
    assert restored.psychological_impact == "sesgo de urgencia"


def test_narrative_psychological_impact_defaults_to_empty_string():
    assert Narrative(name="x").psychological_impact == ""


# -- Roundtrip completo de Operation con todos los campos de M10 ------------


def test_operation_roundtrip_includes_all_m10_fields():
    op = _make_operation(
        adversary_profile=AdversaryProfile(name="APT ficticio", target_assets=["ERP"]),
        narrative=Narrative(name="Narrativa base", psychological_impact="sesgo de confirmacion"),
        strategic_decisions=StrategicDecisions(
            objectives=[StrategicObjective.DETERRENCE_ATTRITION],
            roles={"Legal": "Asesoria juridica"},
            resource_estimate="1 analista",
        ),
    )
    scenario = Scenario(description="Escenario 1", related_ttps=["T1078"])
    op.add_scenario(scenario)
    op.bind_plugin(
        PluginBinding(
            plugin_id="buda-mock",
            surface="identity",
            scenario_id=scenario.id,
            effect=DeceptionEffect(success_metric="TTP observada dentro del plazo"),
        )
    )

    restored = Operation.from_dict(op.to_dict())

    assert restored.adversary_profile.target_assets == ["ERP"]
    assert restored.narrative.psychological_impact == "sesgo de confirmacion"
    assert restored.strategic_decisions.objectives == [StrategicObjective.DETERRENCE_ATTRITION]
    assert restored.strategic_decisions.roles == {"Legal": "Asesoria juridica"}
    assert restored.plugins[0].scenario_id == scenario.id
    assert restored.plugins[0].effect.success_metric == "TTP observada dentro del plazo"


# -- Compatibilidad hacia atras: operaciones persistidas antes de M10 -------


def _legacy_operation_dict() -> dict:
    """Un dict con exactamente la forma que produce Operation.to_dict()
    ANTES de M10 -- sin target_assets, sin strategic_decisions, sin
    scenario_id/effect en los plugins, sin psychological_impact. No se
    genera llamando a to_dict() actual (eso probaria el codigo nuevo
    contra si mismo): se escribe a mano para fijar el formato real que
    ya hay en disco desde M1-M9."""

    return {
        "id": "op-legacy-1",
        "name": "Operacion legacy pre-M10",
        "status": "active",
        "adversary_profile": {
            "name": "APT ficticio",
            "motivation": "espionaje",
            "skill_level": "intermediate",
            "expected_ttps": ["T1046", "T1078"],
            "notes": "perfil cargado antes de M10",
        },
        "roe": {
            "environment": "isolated",
            "allowed_actions": [],
            "forbidden_actions": [],
            "legal_constraints": [],
            "escalation_contact": "",
        },
        "narrative": {
            "name": "Narrativa legacy",
            "description": "",
            "similarity_percentage": 100,
            "story_elements": [],
        },
        "scenarios": [
            {
                "id": "scenario-legacy-1",
                "description": "Escenario legacy",
                "related_ttps": ["T1046"],
                "deception_level": "basic",
            }
        ],
        "plugins": [
            {
                "plugin_id": "honeytoken-1",
                "surface": "data",
                "config": {"directory": "/tmp/legacy"},
            }
        ],
        "closure_criteria": {"end_date": None, "conditions": []},
        "created_at": "2025-01-01T00:00:00+00:00",
        "updated_at": "2025-01-01T00:00:00+00:00",
        "closed_at": None,
        # nota: sin la clave "strategic_decisions" en absoluto -- asi
        # es como quedo cualquier archivo <id>.json escrito antes de M10.
    }


def test_from_dict_on_legacy_operation_does_not_raise_and_fills_defaults():
    op = Operation.from_dict(_legacy_operation_dict())

    assert op.adversary_profile.target_assets == []
    assert op.narrative.psychological_impact == ""
    assert op.strategic_decisions == StrategicDecisions()
    assert op.plugins[0].scenario_id is None
    assert op.plugins[0].effect == DeceptionEffect()
    # el resto del contenido legacy se preserva igual
    assert op.name == "Operacion legacy pre-M10"
    assert op.adversary_profile.expected_ttps == ["T1046", "T1078"]
    assert op.scenarios[0].description == "Escenario legacy"
    assert op.plugins[0].plugin_id == "honeytoken-1"


def test_json_file_repository_loads_legacy_operation_from_disk(tmp_path):
    legacy_path = tmp_path / "op-legacy-1.json"
    legacy_path.write_text(json.dumps(_legacy_operation_dict()), encoding="utf-8")

    repo = JSONFileOperationRepository(tmp_path)
    op = repo.get("op-legacy-1")

    assert op.strategic_decisions == StrategicDecisions()
    assert op.plugins[0].scenario_id is None

    # Guardar de nuevo (con los campos nuevos ya presentes, aunque
    # vacios) y volver a cargar tiene que seguir funcionando igual --
    # confirma que el archivo se "migra" de forma transparente al
    # primer save(), sin pasos manuales.
    repo.save(op)
    reloaded = repo.get("op-legacy-1")
    assert json.loads(legacy_path.read_text(encoding="utf-8"))["strategic_decisions"] == {
        "objectives": [],
        "roles": {},
        "resource_estimate": "",
    }
    assert reloaded.strategic_decisions == StrategicDecisions()
