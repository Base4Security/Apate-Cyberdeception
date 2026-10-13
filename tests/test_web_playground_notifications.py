"""Tests para las notificaciones en tiempo real del modo Playground
(M13f) -- ver docs/roadmap.md seccion M13f.

Fuente real, no simulada: el mismo `EventBus` que ya arma
`PlaygroundSession.create()` (con `RuleEngine`/`TelemetryCollector`
suscriptos) -- `session.bridge.ingest_elastic_hit(...)` es el mismo
mecanismo que ya ejercita test_web_playground.py para alimentar la
vista de defensor, no un evento fabricado para este test puntual.

Usa `flask_socketio.SocketIOTestClient` contra el namespace propio de
APATE ('/playground', ver apate.web.blueprints.playground) -- requiere
`namespaces="*"` en la instancia de `SocketIO` (M13f, apate.web),
confirmado necesario de forma empirica: python-socketio por defecto
solo acepta conexiones al namespace por defecto ('/') si no se declara
explicitamente que acepta cualquiera."""

from unittest.mock import patch

from flask_socketio import SocketIOTestClient

_RULE_YAML = """
rules:
  - name: "Escaneo -> activar"
    when:
      event_type: interaction
      payload:
        kind: scan
    then:
      - action: transition
        to: active
"""


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion Playground M13f",
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


def _start_playground(client, app, operation_id, tmp_path):
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)
    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation_id}/start", data={"level": "basic"})


def test_notification_emitted_when_active_session_receives_a_real_event(client, app, tmp_path):
    operation_id = _create_operation(client)
    _start_playground(client, app, operation_id, tmp_path)

    socketio = app.extensions["socketio"]
    test_client = SocketIOTestClient(app, socketio, namespace="/playground")

    session = app.config["PLAYGROUND_SESSIONS"][operation_id]
    session.bridge.ingest_elastic_hit({"_source": {"event_type": "scan", "source_ip": "203.0.113.5"}})

    received = test_client.get_received(namespace="/playground")

    assert len(received) == 1
    assert received[0]["name"] == "playground_event"
    payload = received[0]["args"][0]
    assert payload["operation_id"] == operation_id
    assert payload["event_type"] == "interaction"
    assert payload["triggered_rules"] == []


def test_notification_includes_the_triggered_rule_name_when_a_rule_matches(client, app, tmp_path):
    client.post("/rules/", data={"rules_text": _RULE_YAML})
    operation_id = _create_operation(client)
    _start_playground(client, app, operation_id, tmp_path)

    socketio = app.extensions["socketio"]
    test_client = SocketIOTestClient(app, socketio, namespace="/playground")

    session = app.config["PLAYGROUND_SESSIONS"][operation_id]
    session.bridge.ingest_elastic_hit({"_source": {"event_type": "scan", "source_ip": "203.0.113.5"}})

    received = test_client.get_received(namespace="/playground")
    payload = received[0]["args"][0]

    assert payload["triggered_rules"] == ["Escaneo -> activar"]
    # Confirma contra la fuente real, no solo el payload emitido -- el
    # RuleFiring en si sigue en engine.history como siempre.
    assert [f.rule_name for f in session.engine.history] == ["Escaneo -> activar"]


def test_no_notification_without_any_active_playground_session(client, app):
    # Sin _start_session() de por medio no existe ninguna suscripcion
    # -- conectarse al namespace no dispara nada por si solo, y no hay
    # ningun bus real al que publicarle un evento para esta operacion.
    operation_id = _create_operation(client)
    socketio = app.extensions["socketio"]
    test_client = SocketIOTestClient(app, socketio, namespace="/playground")

    assert test_client.get_received(namespace="/playground") == []
    assert operation_id not in app.config["PLAYGROUND_SESSIONS"]


def test_no_notification_for_an_operation_that_never_had_a_session_even_if_another_one_is_active(
    client, app, tmp_path
):
    # Dos operaciones: se arranca Playground solo para la primera --
    # confirma que la ausencia de notificacion no es "nunca funciona",
    # sino especificamente "sin sesion propia, no hay nada que emitir"
    # para la segunda, mientras la primera si tiene una suscripcion real.
    active_operation_id = _create_operation(client, name="Con sesion activa")
    idle_operation_id = _create_operation(client, name="Sin sesion")
    _start_playground(client, app, active_operation_id, tmp_path)

    assert active_operation_id in app.config["PLAYGROUND_SESSIONS"]
    assert idle_operation_id not in app.config["PLAYGROUND_SESSIONS"]
