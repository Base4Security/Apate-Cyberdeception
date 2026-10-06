from apate.core import PluginBinding, Scenario
from apate.plugins import EventType, PluginEvent
from apate.telemetry import TelemetryRecord


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_list_operations_empty_returns_200(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b"Plantilla: inici" in response.data


def test_new_operation_form_returns_200(client):
    response = client.get("/operations/new")
    assert response.status_code == 200


def test_create_operation_redirects_to_detail(client):
    operation_id = _create_operation(client)
    response = client.get(f"/operations/{operation_id}")
    assert response.status_code == 200


def test_list_operations_shows_created_operation(client):
    _create_operation(client, name="Operacion Q1")
    response = client.get("/operations/")
    assert b"Operacion Q1" in response.data


def test_operation_detail_shows_profile_and_status(client):
    operation_id = _create_operation(client, adversary_name="Actor de ejemplo")
    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"Actor de ejemplo" in response.data
    assert b"T1046" in response.data
    assert b"planning" in response.data


def test_operation_detail_shows_scoped_metrics_with_source_and_period(client, app):
    operation_id = _create_operation(client)
    app.config["TELEMETRY_COLLECTOR"].repository.append(
        TelemetryRecord.from_event(
            PluginEvent(
                event_type=EventType.TTP_OBSERVED,
                operation_id=operation_id,
                plugin_id="buda-profile-1",
                surface="identity",
                payload={"ttp_id": "T1078", "source_ip": "203.0.113.10"},
            )
        )
    )

    text = client.get(f"/operations/{operation_id}").get_data(as_text=True)

    assert 'id="operation-metrics"' in text
    assert "Alcance: solo esta operaci&oacute;n" in text
    # La atribucion de fuente sigue estando; dentro de la propia app decir
    # "Telemetria <producto>" era redundante (fase 4 del renombre).
    assert "Fuente: Telemetr&iacute;a" in text
    assert "per&iacute;odo: historial completo" in text
    assert "APATE: 1" in text
    assert "no es un score" in text


def test_detail_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe")
    assert response.status_code == 404


def test_transition_404_for_unknown_operation(client):
    response = client.post("/operations/no-existe/transition", data={"to": "active"})
    assert response.status_code == 404


def test_transition_to_active_updates_status(client):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "active"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"badge-active" in response.data


def test_invalid_transition_flashes_error_and_keeps_status(client):
    operation_id = _create_operation(client)

    # PLANNING -> COMPROMISED no esta permitido (ver _ALLOWED_TRANSITIONS
    # en el Nucleo de Operacion): la UI debe mostrar el error, no
    # romper con un 500, y la operacion debe seguir en planning.
    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "compromised"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert b"badge-planning" in response.data


def test_transition_with_unknown_target_flashes_error(client):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "not-a-real-status"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data


def _create_closed_operation(client, **overrides):
    operation_id = _create_operation(client, **overrides)
    client.post(f"/operations/{operation_id}/transition", data={"to": "closed"})
    return operation_id


def test_report_flashes_error_for_non_closed_operation(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/report", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert b"solo est" in response.data


def test_report_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe/report")
    assert response.status_code == 404


def test_report_markdown_is_the_default_format(client):
    operation_id = _create_closed_operation(client, adversary_name="Actor de ejemplo", expected_ttps=["T1046", "T1078"])

    response = client.get(f"/operations/{operation_id}/report")

    assert response.status_code == 200
    assert response.mimetype == "text/markdown"
    assert "attachment" in response.headers["Content-Disposition"]
    assert b"T1046" in response.data
    assert b"# Informe post-operaci" in response.data


def test_report_json_format(client):
    operation_id = _create_closed_operation(client, expected_ttps=["T1046", "T1078"])

    response = client.get(f"/operations/{operation_id}/report?format=json")

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["operation_id"] == operation_id
    assert payload["operation_status"] == "closed"
    assert set(payload["ttps_not_observed"]) == {"T1046", "T1078"}


def test_report_stix_format(client):
    """Exportación STIX 2.1 (cierre del paso 6/7 de la metodología,
    ver docstring de `apate.reporting.stix`) -- mismo `format=` que
    json/pdf/markdown en la misma ruta, no una ruta nueva."""

    operation_id = _create_closed_operation(client, expected_ttps=["T1046", "T1078"])

    response = client.get(f"/operations/{operation_id}/report?format=stix")

    assert response.status_code == 200
    assert response.mimetype == "application/stix+json"
    assert "stix" in response.headers["Content-Disposition"]
    payload = response.get_json()
    assert payload["type"] == "bundle"
    types = {obj["type"] for obj in payload["objects"]}
    assert "attack-pattern" in types
    assert "report" in types


def test_report_stix_format_only_available_for_closed_operations(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/report?format=stix", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-error" in response.data


def test_detail_page_shows_stix_download_button_only_when_closed(client):
    open_operation_id = _create_operation(client)
    response = client.get(f"/operations/{open_operation_id}")
    assert b'Descargar <abbr title="Structured Threat Information Expression">STIX</abbr>' not in response.data

    closed_operation_id = _create_closed_operation(client)
    response = client.get(f"/operations/{closed_operation_id}")
    assert b'Descargar <abbr title="Structured Threat Information Expression">STIX</abbr>' in response.data


def test_detail_page_shows_report_buttons_only_when_closed(client):
    open_operation_id = _create_operation(client)
    response = client.get(f"/operations/{open_operation_id}")
    assert b"Descargar Markdown" not in response.data

    closed_operation_id = _create_closed_operation(client)
    response = client.get(f"/operations/{closed_operation_id}")
    assert b"Descargar Markdown" in response.data
    assert b"Descargar JSON" in response.data


def test_operation_detail_links_to_filtered_telemetry(client, app):
    operation_id = _create_operation(client, adversary_name="APT vinculado")
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    scenario = Scenario(id="escenario-link", description="Escenario identidad")
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="buda-identity-1",
            plugin_kind="buda",
            surface="identity",
            scenario_id=scenario.id,
            config={"narrative_id": 123},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation_id}").data.decode()

    assert "telemetry/" + operation_id in text
    assert f"plugin_id=buda-identity-1" in text
    assert f"scenario_id={scenario.id}" in text
    assert f"surface=identity" in text
