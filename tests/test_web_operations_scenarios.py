"""Tests para la via web de creacion de Scenario dentro de una
operacion (M12b, ver docs/roadmap.md seccion M12) -- hasta este hito
la unica forma de agregar un escenario era programatica (ej.
examples/quickstart.py), lo que dejaba el <select> de `scenario_id`
del formulario de "vincular plugin" (M10) siempre vacio.

Sigue el mismo patron que tests/test_web_operations_m10.py: postea al
formulario real via el `client` de tests/conftest.py (APATE_MOUNT_
EXTERNAL_TOOLS=False), sin mockear nada -- esta ruta no depende de
DOLOS-T/BUDA en absoluto."""


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12b",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- formulario en detail.html -----------------------------------------


def test_detail_page_includes_add_scenario_form(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert f'action="/operations/{operation_id}/scenarios"'.encode() in response.data
    assert b'name="description"' in response.data
    assert b'name="related_ttps"' in response.data
    assert b'name="catalog_related_ttps"' in response.data
    assert b'name="deception_level"' in response.data
    # Los 4 valores reales de DeceptionLevel, no 3 (ver M5).
    for level in [b"none", b"basic", b"complete", b"impossible"]:
        assert level in response.data
    for label in ["Sin engaño", "Básico", "Completo", "Imposible"]:
        assert label.encode("utf-8") in response.data


def test_add_scenario_combines_catalog_and_free_ttps_without_losing_external_values(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={
            "description": "Cobertura mixta",
            "catalog_related_ttps": ["T1046", "T1078"],
            "related_ttps": "T1078, T9999.777",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    scenario = app.config["OPERATION_REPOSITORY"].get(operation_id).scenarios[0]
    assert scenario.related_ttps == ["T1046", "T1078", "T9999.777"]
    assert b"T9999.777" in response.data


# -- POST /operations/<id>/scenarios -------------------------------------


def test_add_scenario_creates_and_persists(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Detectar escaneo interno", "related_ttps": "T1046, T1078", "deception_level": "complete"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data
    assert b"Detectar escaneo interno" in response.data

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert len(operation.scenarios) == 1
    scenario = operation.scenarios[0]
    assert scenario.description == "Detectar escaneo interno"
    assert scenario.related_ttps == ["T1046", "T1078"]
    assert scenario.deception_level.value == "complete"


def test_add_scenario_defaults_to_basic_deception_level(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Escenario sin nivel explicito"},
        follow_redirects=True,
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.scenarios[0].deception_level.value == "basic"


def test_add_scenario_without_related_ttps_defaults_to_empty_list(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Escenario sin TTPs"},
        follow_redirects=True,
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.scenarios[0].related_ttps == []


def test_add_scenario_with_empty_description_is_rejected(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "", "related_ttps": "T1046"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.scenarios == []


def test_add_scenario_with_blank_description_is_rejected(client, app):
    # Solo espacios: se recorta y se trata como vacio, no como contenido real.
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "   "},
        follow_redirects=True,
    )

    assert b"flash-error" in response.data
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.scenarios == []


def test_add_scenario_with_invalid_deception_level_is_rejected(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Escenario valido", "deception_level": "not-a-real-level"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.scenarios == []


def test_add_scenario_404_for_unknown_operation(client):
    response = client.post(
        "/operations/no-existe/scenarios", data={"description": "x"}
    )
    assert response.status_code == 404


def test_add_scenario_twice_appends_both(client, app):
    operation_id = _create_operation(client)

    client.post(f"/operations/{operation_id}/scenarios", data={"description": "Primero"})
    client.post(f"/operations/{operation_id}/scenarios", data={"description": "Segundo"})

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert [s.description for s in operation.scenarios] == ["Primero", "Segundo"]


# -- Integracion: el <select> de scenario_id deja de estar vacio ------------


def test_scenario_id_select_lists_real_scenarios_when_linking_a_plugin(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Detectar escaneo interno", "related_ttps": "T1046"},
        follow_redirects=True,
    )
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    scenario = operation.scenarios[0]

    # El <select> del formulario de "vincular plugin" (M10) ahora tiene
    # que ofrecer el escenario recien creado como opcion real.
    detail_response = client.get(f"/operations/{operation_id}")
    assert f'<option value="{scenario.id}">Detectar escaneo interno</option>'.encode() in detail_response.data

    link_response = client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "surface": "data",
            "scenario_id": scenario.id,
            "expected_adversary_belief": "Cree que son credenciales reales",
            "expected_adversary_action": "Las usa para moverse lateralmente",
            "success_metric": "Alerta en menos de 5 minutos",
        },
        follow_redirects=True,
    )
    assert link_response.status_code == 200

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    binding = operation.plugins[0]
    assert binding.scenario_id == scenario.id
    # Y la operacion resuelve el vinculo end-to-end, via el mismo
    # helper que ya usan las vistas (Operation.find_scenario()).
    assert operation.find_scenario(binding.scenario_id).description == "Detectar escaneo interno"

    # Se refleja tambien en la tabla de plugins vinculados del detalle.
    final_detail = client.get(f"/operations/{operation_id}")
    assert b"Detectar escaneo interno" in final_detail.data


def test_scenario_select_prefills_from_query_param(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Detección de acceso SSH", "related_ttps": "T1021"},
        follow_redirects=True,
    )
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    scenario = operation.scenarios[0]

    response = client.get(
        f"/operations/{operation_id}",
        query_string={"prefill_scenario_id": scenario.id},
    )

    assert response.status_code == 200
    assert f'value="{scenario.id}" selected'.encode() in response.data


def test_scenario_select_without_prefill_query_does_not_preselect_any_scenario(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Detección de acceso SSH", "related_ttps": "T1021"},
        follow_redirects=True,
    )
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    scenario = operation.scenarios[0]

    response = client.get(f"/operations/{operation_id}")
    assert response.status_code == 200
    assert f'value="{scenario.id}" selected'.encode() not in response.data
