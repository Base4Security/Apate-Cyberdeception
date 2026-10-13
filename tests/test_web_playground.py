from unittest.mock import patch

from apate.core import PluginBinding
from apate.playground.events import PLAYGROUND_PLUGIN_ID
from apate.plugins import MockHoneypotPlugin, PluginLifecycleState

_RULE_YAML = """
rules:
  - name: "Login honeypot -> activar"
    when:
      event_type: interaction
      payload:
        kind: ssh_connection
    then:
      - action: transition
        to: active
"""


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion Playground",
        adversary_name="APT ficticio",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    return response.headers["Location"].rsplit("/", 1)[-1]


def _make_checkout(tmp_path):
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return checkout


def test_playground_index_returns_200(client):
    response = client.get("/playground/")
    assert response.status_code == 200


def test_playground_index_shows_created_operation(client):
    _create_operation(client, name="Operacion visible")
    response = client.get("/playground/")
    assert b"Operacion visible" in response.data


def test_playground_index_uses_operational_cards_without_changing_start_contract(client):
    operation_id = _create_operation(client, name="Operacion en tarjeta")
    text = client.get("/playground/").get_data(as_text=True)

    assert 'class="playground-operation-grid"' in text
    assert 'class="panel playground-operation-card' in text
    assert f'action="/playground/{operation_id}/start"' in text
    assert f'id="playground-level-{operation_id}" name="level"' in text
    assert "ninguna operaci&oacute;n se inicia sola" in text
    assert "ejecuci&amp;oacute;n" not in text
    assert "Sin recursos de Playground en ejecuci&oacute;n" in text
    assert "Atacante</a>" in text and "Defensor</a>" in text


def test_attacker_view_returns_200_for_operation_without_events(client):
    operation_id = _create_operation(client)
    response = client.get(f"/playground/{operation_id}/attacker")
    assert response.status_code == 200
    assert b"no hay acciones del contenedor atacante" in response.data


def test_attacker_view_explains_that_an_active_session_is_required(client):
    operation_id = _create_operation(client)

    response = client.get(f"/playground/{operation_id}/attacker")

    assert response.status_code == 200
    assert b"Falta una sesi" in response.data


def test_run_attacker_rejects_second_click_globally(client, app, tmp_path):
    operation_id = _create_operation(client)
    other_operation_id = _create_operation(client, name="Otra operación")
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)
    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})
        client.post(f"/playground/{other_operation_id}/start", data={"level": "basic"})

    socketio = app.extensions["socketio"]
    with patch.object(socketio, "start_background_task") as background:
        first = client.post(f"/playground/{operation_id}/attacker/run", follow_redirects=True)
        second = client.post(f"/playground/{other_operation_id}/attacker/run", follow_redirects=True)

    assert first.status_code == 200
    assert b"Atacante iniciado en segundo plano" in first.data
    assert second.status_code == 200
    assert b"El atacante ya est" in second.data
    assert background.call_count == 1


def test_attacker_background_streams_events_and_marks_the_run_completed(client, app, tmp_path):
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)
    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    from apate.web.blueprints import playground as playground_module

    def stream(_config, on_line):
        on_line("  MITRE ATT&CK  |  T1595.003\n")
        on_line("  Tactic        |  Reconnaissance\n")
        on_line("  Technique     |  Active Scanning\n")

    with patch.object(app.extensions["socketio"], "start_background_task", side_effect=lambda target, *args: target(*args)):
        with patch.object(playground_module, "run_attacker_script_streaming", side_effect=stream):
            response = client.post(f"/playground/{operation_id}/attacker/run", follow_redirects=True)

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Última corrida terminada" in body
    assert "T1595.003" in body
    assert app.config["PLAYGROUND_ATTACKER_RUN"]["status"] == "completed"


def test_defender_view_returns_200_and_reports_no_active_session(client):
    operation_id = _create_operation(client)
    response = client.get(f"/playground/{operation_id}/defender")
    assert response.status_code == 200
    assert b"decisiones persistidas" in response.data


def test_playground_views_share_switcher_and_defender_has_structured_sections(client):
    operation_id = _create_operation(client)
    attacker = client.get(f"/playground/{operation_id}/attacker").get_data(as_text=True)
    defender = client.get(f"/playground/{operation_id}/defender").get_data(as_text=True)

    assert 'class="playground-view-switcher"' in attacker
    assert 'aria-current="page"' in attacker
    assert 'id="attacker-actions-title"' in attacker
    assert 'class="playground-view-switcher"' in defender
    assert 'aria-label="Resumen de observaci&oacute;n"' in defender
    assert 'class="playground-section-nav"' in defender
    for section in ("live", "expected", "plan", "coverage", "decisions", "raw"):
        assert f'id="playground-{section}"' in defender


def test_attacker_view_404_for_unknown_operation(client):
    response = client.get("/playground/no-existe/attacker")
    assert response.status_code == 404


def test_start_without_playground_path_configured_flashes_error(client, app):
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = None

    response = client.post(
        f"/playground/{operation_id}/start", data={"level": "basic"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert operation_id not in app.config["PLAYGROUND_SESSIONS"]


def test_start_with_invalid_level_flashes_error(client, app, tmp_path):
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    response = client.post(
        f"/playground/{operation_id}/start", data={"level": "no-es-un-nivel"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data


def test_start_success_registers_session_and_flashes(client, app, tmp_path):
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack") as mock_start:
        response = client.post(
            f"/playground/{operation_id}/start", data={"level": "complete"}, follow_redirects=True
        )

    assert response.status_code == 200
    assert b"flash-success" in response.data
    assert mock_start.call_count == 1
    assert operation_id in app.config["PLAYGROUND_SESSIONS"]

    index_response = client.get("/playground/")
    assert b"activo" in index_response.data


def test_real_app_playground_session_registers_binding_and_executes_deploy_rule(client, app, tmp_path):
    operation_id = _create_operation(client)
    repository = app.config["OPERATION_REPOSITORY"]
    operation = repository.get(operation_id)
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="mock"))
    repository.save(operation)
    client.post(
        "/rules/",
        data={
            "rules_text": """
rules:
  - name: \"Conexion SSH -> desplegar mock\"
    when:
      event_type: interaction
      payload:
        kind: ssh_connection
    then:
      - action: deploy
        plugin_id: mock-1
""",
        },
    )
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        response = client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    assert response.status_code == 302
    session = app.config["PLAYGROUND_SESSIONS"][operation_id]
    session.bridge.ingest_elastic_hit(
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}
    )

    plugin = session.engine.plugins["mock-1"]
    assert isinstance(plugin, MockHoneypotPlugin)
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_stop_removes_session_and_flashes(client, app, tmp_path):
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})
    assert operation_id in app.config["PLAYGROUND_SESSIONS"]

    with patch("apate.web.blueprints.playground.stop_stack") as mock_stop:
        response = client.post(f"/playground/{operation_id}/stop", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-success" in response.data
    assert mock_stop.call_count == 1
    assert operation_id not in app.config["PLAYGROUND_SESSIONS"]


def test_attacker_view_only_shows_events_sourced_from_attacker_container(client, app):
    operation_id = _create_operation(client)
    collector = app.config["TELEMETRY_COLLECTOR"]
    bus_events = [
        dict(plugin_id=PLAYGROUND_PLUGIN_ID, payload={"kind": "sql_injection", "source": "attacker"}),
        dict(plugin_id=PLAYGROUND_PLUGIN_ID, payload={"kind": "ssh_connection", "source": "elastic"}),
    ]
    from apate.plugins.base import EventType, PluginEvent

    for overrides in bus_events:
        collector.handle_event(
            PluginEvent(
                event_type=EventType.INTERACTION,
                surface="network",
                operation_id=operation_id,
                **overrides,
            )
        )

    response = client.get(f"/playground/{operation_id}/attacker")

    assert response.status_code == 200
    assert b"sql_injection" in response.data
    assert b"ssh_connection" not in response.data


def test_defender_view_shows_rule_engine_decisions_after_session_event(client, app, tmp_path):
    operation_id = _create_operation(client)
    client.post("/rules/", data={"rules_text": _RULE_YAML})
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    session = app.config["PLAYGROUND_SESSIONS"][operation_id]
    session.bridge.ingest_elastic_hit(
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}
    )

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"Login honeypot -&gt; activar" in response.data or b"Login honeypot -> activar" in response.data
    assert b"203.0.113.10" in response.data


def test_defender_view_shows_roe_rejected_actions_from_active_session(client, app, tmp_path):
    operation_id = _create_operation(client)
    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)
    operation.roe.forbidden_actions = ["retire"]
    repo.save(operation)
    client.post(
        "/rules/",
        data={
            "rules_text": """
rules:
  - name: \"Retiro bloqueado\"
    when:
      event_type: interaction
      payload:
        kind: ssh_connection
    then:
      - action: retire
        plugin_id: playground-1
""",
        },
    )
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    session = app.config["PLAYGROUND_SESSIONS"][operation_id]
    session.bridge.ingest_elastic_hit({"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.11"}})

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"Acciones rechazadas" in response.data
    assert b"Retiro bloqueado" in response.data
    assert b"Prohibida por Rules of Engagement" in response.data
    assert b"RoE" in response.data


def test_defender_view_fetches_and_ingests_new_elastic_hits(client, app, tmp_path):
    # Gap real cerrado tras la verificacion manual pendiente desde M5
    # (ver docs/roadmap.md y apate/playground/session.py):
    # fetch_and_ingest_elastic() nunca se llamaba desde ningun lado de
    # la app real -- solo el contenedor atacante llegaba a la vista de
    # defensor. Este test confirma que visitar la vista de defensor con
    # una sesion activa consulta Elasticsearch de verdad (via
    # PlaygroundSession.fetch_elastic_events()) e ingiere lo que
    # encuentra, sin que el operador tenga que hacer nada aparte.
    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    fake_hits = [{"_source": {"event_type": "ssh_connection", "source_ip": "198.51.100.7"}}]
    with patch("apate.playground.events.fetch_recent_hits", return_value=fake_hits) as mock_fetch:
        response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert mock_fetch.called
    assert b"198.51.100.7" in response.data


def test_defender_view_survives_unreachable_elasticsearch(client, app, tmp_path):
    # La contraparte del test anterior: si Elasticsearch no responde
    # (stack recien arrancado, ES todavia no healthy, o apagado del
    # todo), la vista de defensor tiene que seguir respondiendo 200 con
    # un flash de error -- no un 500 -- mismo criterio que start()/
    # stop() ya aplican a PlaygroundError.
    from apate.playground.exceptions import PlaygroundCommandError

    operation_id = _create_operation(client)
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})

    with patch(
        "apate.playground.events.fetch_recent_hits",
        side_effect=PlaygroundCommandError("Elasticsearch no disponible"),
    ):
        response = client.get(f"/playground/{operation_id}/defender", follow_redirects=True)

    assert response.status_code == 200
    assert "No se pudo consultar Elasticsearch".encode("utf-8") in response.data
