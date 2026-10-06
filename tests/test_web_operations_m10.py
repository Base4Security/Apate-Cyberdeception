"""Tests de integracion web para los campos de M10 (paso 1/2/4/5 de la
metodologia) expuestos en apate.web.blueprints.operations -- ver
docs/analisis-metodologia-cti.md y la seccion M10 de docs/roadmap.md.

Sigue el mismo patron que tests/test_web_operations.py (helper
_create_operation posteando al formulario real, sin mockear nada)."""

from apate.core.models import Scenario


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M10",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        target_assets="ERP, Active Directory",
        environment="isolated",
        objectives=["early_detection", "attribution"],
        roles="CTI: Equipo de inteligencia\nSOC/IR: Equipo de respuesta\nlinea sin dos puntos",
        resource_estimate="2 analistas part-time",
        narrative_name="Narrativa base",
        narrative_description="desc",
        psychological_impact="sesgo de confirmacion",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- formulario de creacion ---------------------------------------------


def test_new_operation_form_includes_m10_fields(client):
    response = client.get("/operations/new")

    assert response.status_code == 200
    assert b'name="target_assets"' in response.data
    assert b'name="objectives"' in response.data
    # El valor crudo sigue viajando en el checkbox (value="early_detection",
    # lo que postea create_operation()) -- solo el texto que lee el
    # operador cambia a la etiqueta legible (apate.web._enum_labels).
    assert b'value="early_detection"' in response.data
    assert "Detección temprana".encode("utf-8") in response.data
    assert b'name="roles"' in response.data
    assert b'name="resource_estimate"' in response.data
    assert b'name="psychological_impact"' in response.data


def test_create_operation_saves_m10_fields_to_repository(client, app):
    operation_id = _create_operation(client)

    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)

    assert operation.adversary_profile.target_assets == ["ERP", "Active Directory"]
    assert [o.value for o in operation.strategic_decisions.objectives] == ["early_detection", "attribution"]
    assert operation.strategic_decisions.roles == {
        "CTI": "Equipo de inteligencia",
        "SOC/IR": "Equipo de respuesta",
    }
    assert operation.strategic_decisions.resource_estimate == "2 analistas part-time"
    assert operation.narrative.psychological_impact == "sesgo de confirmacion"


def test_create_operation_displays_m10_fields_in_detail_page(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"ERP" in response.data
    assert b"Active Directory" in response.data
    # Etiquetas legibles (apate.web._enum_labels), no el valor crudo del
    # enum -- confirma el hallazgo real corregido: "early_detection" no
    # debe aparecer como texto visible en la vista de detalle.
    assert "Detección temprana".encode("utf-8") in response.data
    assert "Atribución".encode("utf-8") in response.data
    assert b"early_detection" not in response.data
    assert b"Equipo de inteligencia" in response.data
    assert b"2 analistas part-time" in response.data
    assert b"sesgo de confirmacion" in response.data


def test_create_operation_without_m10_fields_uses_defaults(client, app):
    # Ningun campo de M10 es obligatorio: un formulario que no los
    # manda (ej. un cliente HTTP viejo, o alguien que deja todo en
    # blanco) tiene que seguir creando la operacion, no romper con un
    # 500 -- mismo criterio "aditivo" que from_dict().
    form = dict(
        name="Operacion minima",
        adversary_name="Actor",
        adversary_skill_level="unknown",
        environment="isolated",
        narrative_name="Narrativa",
    )
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302

    operation_id = response.headers["Location"].rsplit("/", 1)[-1]
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)

    assert operation.adversary_profile.target_assets == []
    assert operation.strategic_decisions.objectives == []
    assert operation.strategic_decisions.roles == {}
    assert operation.narrative.psychological_impact == ""


# -- vincular plugin (scenario_id + DeceptionEffect) -------------------------


def test_add_plugin_binding_form_lists_operation_scenarios(client, app):
    operation_id = _create_operation(client)
    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)
    scenario = Scenario(description="Detectar escaneo interno", related_ttps=["T1046"])
    operation.add_scenario(scenario)
    repo.save(operation)

    response = client.get(f"/operations/{operation_id}")

    assert f'value="{scenario.id}"'.encode() in response.data
    assert b"Detectar escaneo interno" in response.data


def test_add_plugin_binding_persists_scenario_id_and_effect(client, app):
    operation_id = _create_operation(client)
    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)
    scenario = Scenario(description="Detectar escaneo interno", related_ttps=["T1046"])
    operation.add_scenario(scenario)
    repo.save(operation)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "surface": "data",
            "scenario_id": scenario.id,
            "expected_adversary_belief": "El archivo contiene credenciales reales",
            "expected_adversary_action": "Usarlas para moverse lateralmente",
            "success_metric": "Alerta en menos de 5 minutos",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = repo.get(operation_id)
    assert len(operation.plugins) == 1
    binding = operation.plugins[0]
    assert binding.plugin_id == "honeytoken-1"
    assert binding.scenario_id == scenario.id
    assert binding.effect.expected_adversary_belief == "El archivo contiene credenciales reales"
    assert binding.effect.expected_adversary_action == "Usarlas para moverse lateralmente"
    assert binding.effect.success_metric == "Alerta en menos de 5 minutos"

    detail_response = client.get(f"/operations/{operation_id}")
    assert b"Detectar escaneo interno" in detail_response.data
    assert b"El archivo contiene credenciales reales" in detail_response.data
    assert b"Alerta en menos de 5 minutos" in detail_response.data


def test_add_plugin_binding_without_scenario_selected_leaves_it_none(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "mock-1", "surface": "network", "scenario_id": ""},
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].scenario_id is None
    assert operation.plugins[0].effect.expected_adversary_belief == ""


def test_add_plugin_binding_404_for_unknown_operation(client):
    response = client.post(
        "/operations/no-existe/plugins", data={"plugin_id": "mock-1", "surface": "network"}
    )
    assert response.status_code == 404
