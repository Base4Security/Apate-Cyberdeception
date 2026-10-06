"""Tests de integracion web para "esperado vs. observado" (M14f) en
playground/defender.html -- ver docs/roadmap.md seccion M14f.

Mismo patron que tests/test_web_operations_ttp_heatmap.py (heatmap de
TTPs, M13a) y tests/test_web_operations_m10.py (vincular plugin, M10):
no se reimplementa la clasificacion de status ni el parseo del
formulario de "vincular plugin" -- se ejercita el mismo camino real
(generate_report()/_ttp_heatmap(), ahora compartida via
apate.web._ttp_presentation) via el `client` real."""

from apate.plugins import EventType, PluginEvent


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion Playground M14f",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _bind_plugin(client, operation_id, **overrides):
    data = dict(plugin_id="mock-1", surface="network")
    data.update(overrides)
    response = client.post(f"/operations/{operation_id}/plugins", data=data, follow_redirects=False)
    assert response.status_code == 302


def _seed_ttp_observed(app, operation_id: str, ttp_id: str) -> None:
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id="honeypot-mock-1",
            surface="network",
            operation_id=operation_id,
            payload={"ttp_id": ttp_id},
        )
    )


def _cell_classes(text: str, ttp_id: str) -> str:
    """Extrae el atributo class= completo de la celda de esa tecnica,
    identificada por su id dentro del title= del div.ttp-cell -- mismo
    helper que tests/test_web_operations_ttp_heatmap.py."""

    idx = text.index(f'>{ttp_id}<')
    div_start = text.rindex('<div class="ttp-cell', 0, idx)
    div_tag_end = text.index(">", div_start)
    return text[div_start:div_tag_end]


# -- Heatmap "esperado vs. observado", sin gate de CLOSED -------------------


def test_defender_view_shows_expected_vs_observed_heatmap_on_active_operation(client):
    # A diferencia de operations/detail.html (M13a, solo CLOSED), la
    # vista de defensor del Playground la muestra en cualquier estado
    # -- la operacion recien creada queda en PLANNING.
    operation_id = _create_operation(client, expected_ttps=["T1078"])

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"Esperado vs. observado" in response.data
    assert b'class="ttp-heatmap"' in response.data


def test_defender_view_heatmap_classifies_the_same_way_as_operations_detail(client, app):
    # No reimplementa la logica de clasificacion -- mismo resultado
    # sobre el mismo OperationReport que ya cubre
    # test_web_operations_ttp_heatmap.py::test_ttp_heatmap_classifies_matched_not_observed_and_unexpected_cells.
    operation_id = _create_operation(client, expected_ttps=["T1078", "T1005"])
    _seed_ttp_observed(app, operation_id, "T1078")  # esperada y observada -> matched
    # T1005 esperada pero nunca observada -> not-observed
    _seed_ttp_observed(app, operation_id, "T1057")  # observada, no esperada -> unexpected

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "ttp-cell-matched" in _cell_classes(text, "T1078")
    assert "ttp-cell-not-observed" in _cell_classes(text, "T1005")
    assert "ttp-cell-unexpected" in _cell_classes(text, "T1057")


def test_defender_view_heatmap_appears_before_raw_events_section(client, app):
    operation_id = _create_operation(client, expected_ttps=["T1078"])
    _seed_ttp_observed(app, operation_id, "T1078")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert text.index("Esperado vs. observado") < text.index("<h2>Eventos")


# -- Plan por plugin vinculado -----------------------------------------------


def test_defender_view_shows_plugin_plan_with_scenario_and_engage_activities(client):
    operation_id = _create_operation(client)
    response = client.get(f"/operations/{operation_id}")
    assert response.status_code == 200

    add_scenario_response = client.post(
        f"/operations/{operation_id}/scenarios",
        data={"description": "Detectar escaneo interno", "related_ttps": "T1046", "deception_level": "basic"},
        follow_redirects=False,
    )
    assert add_scenario_response.status_code == 302

    scenario_id = client.application.config["OPERATION_REPOSITORY"].get(operation_id).scenarios[0].id

    _bind_plugin(
        client,
        operation_id,
        plugin_id="honeytoken-1",
        surface="data",
        scenario_id=scenario_id,
        expected_adversary_belief="El archivo contiene credenciales reales",
        expected_adversary_action="Usarlas para moverse lateralmente",
        success_metric="Alerta en menos de 5 minutos",
    )

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"honeytoken-1" in response.data
    assert b"Detectar escaneo interno" in response.data
    assert b"El archivo contiene credenciales reales" in response.data
    assert b"Usarlas para moverse lateralmente" in response.data
    assert b"Alerta en menos de 5 minutos" in response.data


def test_defender_view_without_plugin_bindings_says_so_explicitly(client):
    # Mismo criterio que M12i con escenarios vacios: la seccion lo dice
    # explicito, no se omite en silencio.
    operation_id = _create_operation(client)

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"no tiene ning" in response.data
    assert b"capacidades vinculadas" in response.data


# -- Independiente de si hay una sesion de Playground activa ----------------


def test_defender_view_shows_expected_vs_observed_without_active_playground_session(client):
    # Las decisiones ahora se consultan en SQLite aun sin una
    # PlaygroundSession activa; el heatmap sigue dependiendo de la
    # telemetría persistida, no de la sesión.
    operation_id = _create_operation(client, expected_ttps=["T1078"])

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "decisiones persistidas" in text
    assert "Esperado vs. observado" in text
    assert 'class="ttp-heatmap"' in text
