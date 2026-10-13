"""Tests de integracion web para el selector de actividades de MITRE
Engage (M12c) en el formulario de "Vincular plugin" -- ver
docs/analisis-engage-integral.md y apate.engage.

Sigue el mismo patron que tests/test_web_operations_m10.py/
test_web_operations_attack.py: postea al formulario real via el
`client` de tests/conftest.py, sin mockear nada."""

from apate.engage import get_activity, list_activities


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12c",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- formulario --------------------------------------------------------


def test_detail_page_lists_engagement_activities_grouped_by_goal(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    text = response.data.decode()
    # Goals de tipo "engagement" presentes.
    assert "Expose" in text
    assert "Affect" in text
    assert "Elicit" in text
    # Goals "strategic" filtrados -- no deberian aparecer como grupo
    # del selector (aunque "Prepare"/"Understand" no colisionan con
    # ningun otro texto de la pagina, se busca el patron de opcion).
    for activity in list_activities(kind="engagement"):
        assert f'value="{activity.id}"' in text
        assert activity.name in text
    for activity in list_activities(kind="strategic"):
        assert f'value="{activity.id}"' not in text


def test_detail_page_does_not_offer_strategic_activities_as_checkboxes(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    # Ninguna de las 8 strategic activities (Prepare/Understand)
    # aparece como opcion marcable -- son de nivel operacion, no de un
    # PluginBinding puntual.
    for activity in list_activities(kind="strategic"):
        assert f'name="engage_activity_ids" value="{activity.id}"' not in text


# -- POST /operations/<id>/plugins -----------------------------------------


def test_add_plugin_binding_with_engage_activities(client, app):
    operation_id = _create_operation(client)
    lures = get_activity("EAC0005")
    api_monitoring = get_activity("EAC0001")

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "surface": "data",
            "engage_activity_ids": [lures.id, api_monitoring.id],
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    binding = operation.plugins[0]
    assert set(binding.effect.engage_activity_ids) == {lures.id, api_monitoring.id}


def test_add_plugin_binding_without_engage_activities_defaults_to_empty_list(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "mock-1", "surface": "network"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.engage_activity_ids == []


def test_add_plugin_binding_deduplicates_repeated_engage_activity_ids(client, app):
    # "Lures" pertenece a 3 Approaches (Detect/Direct/Disrupt) y puede
    # aparecer repetido en el <select> si se marca bajo mas de uno --
    # el servidor no deberia guardar duplicados.
    operation_id = _create_operation(client)
    lures = get_activity("EAC0005")

    client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "surface": "data",
            "engage_activity_ids": [lures.id, lures.id, lures.id],
        },
        follow_redirects=False,
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.engage_activity_ids == [lures.id]


# -- integracion end-to-end: detalle muestra el nombre resuelto -----------


def test_linked_plugin_shows_resolved_activity_names_in_detail_page(client, app):
    operation_id = _create_operation(client)
    lures = get_activity("EAC0005")

    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "honeytoken-1", "surface": "data", "engage_activity_ids": [lures.id]},
        follow_redirects=True,
    )

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"Lures" in response.data
    # El id crudo tambien queda accesible (title="EAC0005"), pero el
    # nombre resuelto es lo que se muestra como texto visible.
    assert f'title="{lures.id}"'.encode() in response.data
