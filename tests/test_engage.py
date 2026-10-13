"""Tests para apate.engage (M12a) - catalogo de MITRE Engage, ver
docs/analisis-engage-integral.md y src/apate/data/mitre_engage_matrix.json.

Contra el dataset real (no mockeado): el catalogo es un archivo de
datos versionado, con IDs/nombres/descripciones tomados literal del
repo publico oficial de MITRE Engage y la relacion Goal->Approach->
Activity cruzada contra la matriz visual real (ver el campo _meta del
propio JSON) -- probarlo contra el dataset real es lo que confirma que
la carga y las consultas funcionan sobre esos datos concretos, no
sobre un fixture inventado."""

from apate.engage import Activity, Approach, Goal, get_activity, list_activities, list_approaches, list_goals


# -- list_goals() ------------------------------------------------------


def test_list_goals_returns_all_five():
    goals = list_goals()
    assert len(goals) == 5
    assert all(isinstance(g, Goal) for g in goals)
    assert {g.name for g in goals} == {"Prepare", "Understand", "Expose", "Affect", "Elicit"}


def test_list_goals_kind_distinguishes_strategic_from_engagement():
    goals = list_goals()
    strategic = {g.name for g in goals if g.kind == "strategic"}
    engagement = {g.name for g in goals if g.kind == "engagement"}
    assert strategic == {"Prepare", "Understand"}
    assert engagement == {"Expose", "Affect", "Elicit"}


def test_list_goals_returns_a_copy_not_shared_state():
    first = list_goals()
    first.pop()
    assert len(list_goals()) == 5


# -- list_approaches() ---------------------------------------------------


def test_list_approaches_without_filter_returns_all_nine():
    approaches = list_approaches()
    assert len(approaches) == 9
    assert all(isinstance(a, Approach) for a in approaches)


def test_list_approaches_filters_by_goal_id():
    # EGO0002 = Affect -> Prevent/Direct/Disrupt (ver matriz real).
    affect_approaches = list_approaches(goal_id="EGO0002")
    assert {a.name for a in affect_approaches} == {"Prevent", "Direct", "Disrupt"}
    assert all(a.goal_id == "EGO0002" for a in affect_approaches)


def test_list_approaches_with_unknown_goal_id_returns_empty():
    assert list_approaches(goal_id="no-existe-este-goal") == []


def test_list_approaches_returns_a_copy_not_shared_state():
    first = list_approaches()
    first.pop()
    assert len(list_approaches()) == 9


# -- list_activities() ----------------------------------------------------


def test_list_activities_without_filter_returns_all_31():
    activities = list_activities()
    assert len(activities) == 31
    assert all(isinstance(a, Activity) for a in activities)


def test_list_activities_filters_by_kind():
    engagement = list_activities(kind="engagement")
    strategic = list_activities(kind="strategic")
    assert len(engagement) == 23
    assert len(strategic) == 8
    assert all(a.kind == "engagement" for a in engagement)
    assert all(a.kind == "strategic" for a in strategic)


def test_list_activities_filters_by_approach_id():
    # EAP0001 = Collect: API Monitoring/Network Monitoring/System
    # Activity Monitoring, mas cualquier otra activity multi-approach
    # que tambien incluya Collect (Software Manipulation, EAC0014).
    collect_activities = list_activities(approach_id="EAP0001")
    assert {a.id for a in collect_activities} == {"EAC0001", "EAC0002", "EAC0003", "EAC0014"}
    assert all("EAP0001" in a.approach_ids for a in collect_activities)


def test_list_activities_filters_by_approach_id_and_kind_together():
    # Ambos filtros son independientes y se aplican juntos: SAP0001
    # (Plan, strategic) no deberia devolver nada al pedir kind=engagement.
    assert list_activities(approach_id="SAP0001", kind="engagement") == []
    assert len(list_activities(approach_id="SAP0001", kind="strategic")) > 0


def test_list_activities_with_unknown_approach_id_returns_empty():
    assert list_activities(approach_id="no-existe-este-approach") == []


def test_list_activities_returns_a_copy_not_shared_state():
    first = list_activities()
    first.pop()
    assert len(list_activities()) == 31


# -- get_activity() ---------------------------------------------------------


def test_get_activity_with_valid_id():
    activity = get_activity("EAC0005")
    assert activity is not None
    assert activity.name == "Lures"
    assert activity.kind == "engagement"


def test_get_activity_with_invalid_id_returns_none():
    assert get_activity("EAC9999-no-existe") is None


# -- actividad con mas de un approach (M12a, pedido explicito) --------------


def test_lures_activity_belongs_to_three_approaches():
    lures = get_activity("EAC0005")
    assert lures is not None
    assert len(lures.approach_ids) == 3
    assert set(lures.approach_ids) == {"EAP0002", "EAP0004", "EAP0005"}

    approach_names = {a.id: a.name for a in list_approaches()}
    assert {approach_names[aid] for aid in lures.approach_ids} == {"Detect", "Direct", "Disrupt"}


# -- integridad del dataset (chequeo cruzado, no del contenido en si) ------


def test_every_approach_goal_id_resolves_to_a_known_goal():
    known_goal_ids = {g.id for g in list_goals()}
    for approach in list_approaches():
        assert approach.goal_id in known_goal_ids, f"{approach.id} ({approach.name}) referencia un goal_id desconocido"


def test_every_activity_approach_id_resolves_to_a_known_approach():
    known_approach_ids = {a.id for a in list_approaches()}
    for activity in list_activities():
        missing = set(activity.approach_ids) - known_approach_ids
        assert not missing, f"{activity.id} ({activity.name}) referencia approach_ids desconocidos: {missing}"


def test_activity_kind_matches_the_kind_of_its_goals():
    # Ninguna activity "engagement" deberia colgar de un approach de un
    # goal "strategic", y viceversa -- confirma que no hay mezcla entre
    # las dos mitades de la matriz (Prepare/Understand vs.
    # Expose/Affect/Elicit).
    goal_kind_by_approach_id = {a.id: next(g.kind for g in list_goals() if g.id == a.goal_id) for a in list_approaches()}
    for activity in list_activities():
        for approach_id in activity.approach_ids:
            assert goal_kind_by_approach_id[approach_id] == activity.kind, (
                f"{activity.id} ({activity.name}, kind={activity.kind}) referencia el approach "
                f"{approach_id} de un goal de kind distinto"
            )
