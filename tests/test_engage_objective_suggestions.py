"""Tests para apate.engage.suggest_activities_for_objectives() --
segunda mejora del backlog de Engage post-M12: sugerencia de
actividades a partir del objetivo estrategico (paso 2), funcion
hermana de suggest_activities() (M12d, TTPs).

Contra el dataset real (apate/data/engage_objective_suggestions.json),
igual que test_engage_suggestions.py con el suyo -- probarlo contra
los datos reales confirma que la resolucion objetivo->approach->
actividad funciona sobre lo que el archivo realmente tiene, no sobre
un mock. A diferencia de ese dataset, este es un juicio interpretativo
de APATE (ver _meta del archivo y el docstring de
apate.engage.suggestions) -- los tests confirman que la resolucion
tecnica funciona, no que el juicio interpretativo en si sea 'correcto'
(no hay una fuente oficial contra la que validarlo)."""

from apate.core.models import StrategicObjective
from apate.engage import Activity, get_activity, list_activities, suggest_activities_for_objectives

# Los cinco valores reales de StrategicObjective (apate.core.models) --
# el dataset tiene que cubrir los cinco, ni mas ni menos.
_ALL_OBJECTIVES = {o.value for o in StrategicObjective}


def test_suggest_activities_for_objectives_with_empty_list_returns_empty_list():
    assert suggest_activities_for_objectives([]) == []


def test_suggest_activities_for_objectives_ignores_unknown_objective():
    assert suggest_activities_for_objectives(["objetivo-inventado"]) == []


def test_suggest_activities_for_objectives_returns_real_activity_objects():
    result = suggest_activities_for_objectives(["early_detection"])
    assert result
    for activity in result:
        assert isinstance(activity, Activity)
        assert activity.kind == "engagement"


def test_every_real_strategic_objective_is_covered_by_the_dataset():
    # Chequeo de integridad: si StrategicObjective suma/saca un valor
    # sin actualizar engage_objective_suggestions.json, este test lo
    # marca -- mismo criterio que el chequeo de tacticas de
    # test_engage_suggestions.py.
    for objective in _ALL_OBJECTIVES:
        result = suggest_activities_for_objectives([objective])
        assert result, f"objetivo estrategico real {objective!r} no sugirio ninguna actividad"


def test_early_detection_maps_to_expose_detect_approach():
    result = suggest_activities_for_objectives(["early_detection"])
    expected = {a.id for a in list_activities(approach_id="EAP0002", kind="engagement")}
    assert {a.id for a in result} == expected


def test_intelligence_collection_maps_to_expose_collect_approach():
    result = suggest_activities_for_objectives(["intelligence_collection"])
    expected = {a.id for a in list_activities(approach_id="EAP0001", kind="engagement")}
    assert {a.id for a in result} == expected


def test_controls_validation_maps_to_affect_prevent_approach():
    result = suggest_activities_for_objectives(["controls_validation"])
    expected = {a.id for a in list_activities(approach_id="EAP0003", kind="engagement")}
    assert {a.id for a in result} == expected


def test_deterrence_attrition_maps_to_direct_and_disrupt_approaches():
    result = suggest_activities_for_objectives(["deterrence_attrition"])
    expected = {a.id for a in list_activities(approach_id="EAP0004", kind="engagement")} | {
        a.id for a in list_activities(approach_id="EAP0005", kind="engagement")
    }
    assert {a.id for a in result} == expected


def test_attribution_maps_to_motivate_and_collect_approaches():
    result = suggest_activities_for_objectives(["attribution"])
    expected = {a.id for a in list_activities(approach_id="EAP0007", kind="engagement")} | {
        a.id for a in list_activities(approach_id="EAP0001", kind="engagement")
    }
    assert {a.id for a in result} == expected


def test_deduplicates_activities_shared_across_two_objectives():
    # intelligence_collection y attribution comparten el Approach
    # Expose/Collect (EAP0001) -- las actividades de ese approach no
    # deberian aparecer duplicadas al pasar los dos objetivos juntos.
    result = suggest_activities_for_objectives(["intelligence_collection", "attribution"])
    result_ids = [a.id for a in result]
    assert len(result_ids) == len(set(result_ids))


def test_no_strategic_kind_activities_ever_suggested():
    # Las actividades "strategic" (Prepare/Understand) son de nivel
    # operacion, no de un plugin puntual -- no tienen que aparecer acá
    # aunque algun approach_id del dataset este mal tipeado.
    for objective in _ALL_OBJECTIVES:
        result = suggest_activities_for_objectives([objective])
        assert all(activity.kind == "engagement" for activity in result)


def test_result_activities_resolve_via_get_activity():
    result = suggest_activities_for_objectives(["controls_validation"])
    for activity in result:
        assert get_activity(activity.id) == activity
