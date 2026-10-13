"""Tests para apate.web._enum_labels -- hallazgo real del usuario:
StrategicObjective/Environment/EventType se mostraban con su valor
crudo (snake_case) en varias vistas, leyendose como nombre de
variable en vez de una frase.

Cobertura en dos niveles: unitario sobre las funciones puras del
modulo (mapeo correcto + fallback al valor crudo si no esta cubierto),
e integracion confirmando que las plantillas renderizan la etiqueta
legible, no el valor crudo -- para Environment y EventType (los sitios
que StrategicObjective ya cubre tests/test_web_operations_m10.py, que
se actualizo con este mismo hallazgo)."""

from apate.plugins import EventType, PluginEvent
from apate.web._enum_labels import (
    deception_level_label,
    outcome_label,
    resource_status_label,
    strategic_objective_label,
    tactic_label,
    environment_label,
    event_type_label,
    operation_status_label,
)


# -- Funciones puras (unitario) ----------------------------------------


def test_strategic_objective_label_known_values():
    assert strategic_objective_label("early_detection") == "Detección temprana"
    assert strategic_objective_label("intelligence_collection") == "Recolección de inteligencia"
    assert strategic_objective_label("deterrence_attrition") == "Disuasión y desgaste"
    assert strategic_objective_label("attribution") == "Atribución"
    assert strategic_objective_label("controls_validation") == "Validación de controles"


def test_environment_label_known_values():
    assert environment_label("isolated") == "Aislado"
    assert environment_label("near_production") == "Cercano a producción"
    assert environment_label("production") == "Producción"
    assert environment_label("playground") == "Playground"


def test_event_type_label_known_values():
    assert event_type_label("interaction") == "Interacción"
    assert event_type_label("ttp_observed") == "TTP observada"


def test_deception_level_label_known_values():
    assert deception_level_label("none") == "Sin engaño"
    assert deception_level_label("basic") == "Básico"
    assert deception_level_label("complete") == "Completo"
    assert deception_level_label("impossible") == "Imposible"


def test_tactic_label_known_values():
    assert tactic_label("collection") == "Recolección"
    assert tactic_label("command-and-control") == "Comando y control"
    assert tactic_label("credential-access") == "Acceso a credenciales"
    assert tactic_label("defense-evasion") == "Evasión de defensas"
    assert tactic_label("discovery") == "Descubrimiento"
    assert tactic_label("execution") == "Ejecución"
    assert tactic_label("exfiltration") == "Exfiltración"
    assert tactic_label("impact") == "Impacto"
    assert tactic_label("initial-access") == "Acceso inicial"
    assert tactic_label("lateral-movement") == "Movimiento lateral"
    assert tactic_label("persistence") == "Persistencia"
    assert tactic_label("privilege-escalation") == "Escalada de privilegios"
    assert tactic_label("resource-development") == "Desarrollo de recursos"


def test_operational_labels_known_values():
    assert operation_status_label("planning") == "En preparación"
    assert operation_status_label("active") == "Activa"
    assert operation_status_label("compromised") == "Comprometida"
    assert operation_status_label("closed") == "Cerrada"
    assert resource_status_label("pending") == "Pendiente"
    assert resource_status_label("archived") == "Archivada"
    assert outcome_label("success") == "Completada"


def test_unmapped_value_falls_back_to_raw_value_instead_of_crashing():
    # Un miembro de enum nuevo sin actualizar el diccionario no debe
    # romper la plantilla -- degradado a mostrar el valor crudo.
    assert strategic_objective_label("some_new_objective") == "some_new_objective"
    assert environment_label("some_new_environment") == "some_new_environment"
    assert event_type_label("some_new_event") == "some_new_event"
    assert tactic_label("some_new_tactic") == "some_new_tactic"
    assert operation_status_label("some_new_status") == "some_new_status"
    assert resource_status_label("some_new_status") == "some_new_status"
    assert outcome_label("some_new_outcome") == "some_new_outcome"
    assert deception_level_label("some_new_level") == "some_new_level"


def test_operation_lists_translate_status_but_preserve_machine_values(client):
    _create_operation(client)
    text = client.get("/operations/").get_data(as_text=True)
    assert 'data-status="planning"' in text
    assert 'badge-planning">En preparación</span>' in text
    assert '>planning</span>' not in text


# -- Environment: value crudo en el formulario, texto traducido visible -----


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba enum labels",
        adversary_name="APT ficticio",
        environment="near_production",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_environment_select_shows_translated_text_but_keeps_raw_value(client):
    response = client.get("/operations/new")
    text = response.data.decode()

    # El <select> tiene que seguir posteando el valor crudo real...
    assert 'value="near_production"' in text
    assert 'value="isolated"' in text
    # ...pero el texto que lee el operador esta traducido.
    assert "Cercano a producción" in text
    assert "Aislado" in text


def test_operation_detail_shows_translated_environment_not_raw_value(client):
    operation_id = _create_operation(client, environment="near_production")

    response = client.get(f"/operations/{operation_id}")

    assert "Cercano a producción".encode("utf-8") in response.data
    assert b"near_production" not in response.data


# -- EventType: telemetria/Playground muestran la etiqueta, no el valor crudo -


def _seed_ttp_observed_event(collector, operation_id: str) -> None:
    collector.handle_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id="honeypot-mock-1",
            surface="network",
            operation_id=operation_id,
            payload={"ttp_id": "T1078"},
        )
    )


def test_telemetry_detail_shows_translated_event_type_not_raw_value(client, app):
    _seed_ttp_observed_event(app.config["TELEMETRY_COLLECTOR"], "op-enum-labels")

    response = client.get("/telemetry/op-enum-labels")

    assert "TTP observada".encode("utf-8") in response.data
    assert b"ttp_observed" not in response.data


def test_playground_attacker_view_shows_translated_event_type(client, app):
    from apate.playground.events import PLAYGROUND_PLUGIN_ID

    operation_id = _create_operation(client)
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id=PLAYGROUND_PLUGIN_ID,
            surface="network",
            operation_id=operation_id,
            payload={"ttp_id": "T1078", "source": "attacker"},
        )
    )

    response = client.get(f"/playground/{operation_id}/attacker")

    assert "TTP observada".encode("utf-8") in response.data
    assert b"ttp_observed" not in response.data


def test_playground_defender_view_shows_translated_event_type(client, app):
    operation_id = _create_operation(client)
    _seed_ttp_observed_event(app.config["TELEMETRY_COLLECTOR"], operation_id)

    response = client.get(f"/playground/{operation_id}/defender")

    assert "TTP observada".encode("utf-8") in response.data
    assert b"ttp_observed" not in response.data
