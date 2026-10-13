"""Puentes de telemetría externa configurables (primera de una tanda de
tres tareas para ampliar el ecosistema de herramientas que APATE
orquesta). Ver docstring de `apate.core.models.ExternalTelemetrySource`/
`apate.telemetry.external_bridge` para el diseño completo."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from apate.core import AdversaryProfile, ExternalTelemetrySource, Narrative, Operation, RulesOfEngagement


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación con telemetría externa"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


# -- Sección en el tab de Capacidades ----------------------------------------


def test_tab_shows_empty_state_without_any_bridge(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Puentes de telemetr" in text
    assert "Todav" in text and "no hay ninguna fuente" in text


def test_tab_lists_existing_bridge(client, app):
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo",
            elastic_url="http://localhost:9200",
            index="tpot-*",
            field_mapping={"ttp_id": "mitre.technique_id", "detail": "message"},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "T-Pot demo" in text
    assert "tpot-*" in text
    assert "http://localhost:9200" in text
    assert "ttp_id" in text
    assert "Nunca" in text  # last_fetch_at nunca seteado


def test_tab_shows_last_fetch_timestamp_when_present(client, app):
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo",
            elastic_url="http://localhost:9200",
            index="tpot-*",
            last_fetch_at=datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc),
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "2026-08-21T10:00:00" in text
    assert "Nunca" not in text.split("Puentes de telemetr")[1].split("Agregar fuente")[0]


# -- Agregar fuente (POST) ----------------------------------------------------


def test_add_telemetry_bridge_creates_source(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/telemetry-bridges",
        data={
            "name": "T-Pot demo",
            "elastic_url": "http://localhost:9200",
            "index": "tpot-*",
            "surface": "host",
            "timestamp_field": "event.created",
            "field_mapping": "ttp_id: mitre.technique_id\ndetail: message",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert len(saved.telemetry_bridges) == 1
    source = saved.telemetry_bridges[0]
    assert source.name == "T-Pot demo"
    assert source.elastic_url == "http://localhost:9200"
    assert source.index == "tpot-*"
    assert source.surface == "host"
    assert source.timestamp_field == "event.created"
    assert source.field_mapping == {"ttp_id": "mitre.technique_id", "detail": "message"}


def test_add_telemetry_bridge_defaults_surface_and_timestamp_field(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    client.post(
        f"/operations/{operation.id}/telemetry-bridges",
        data={
            "name": "X",
            "elastic_url": "http://x",
            "index": "y*",
            "field_mapping": "detail: message",
        },
    )

    source = app.config["OPERATION_REPOSITORY"].get(operation.id).telemetry_bridges[0]
    assert source.surface == "network"
    assert source.timestamp_field == "@timestamp"


def test_add_telemetry_bridge_requires_name_url_and_index(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/telemetry-bridges",
        data={"name": "", "elastic_url": "", "index": "", "field_mapping": "detail: message"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).telemetry_bridges == []


def test_add_telemetry_bridge_requires_at_least_one_mapping(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/telemetry-bridges",
        data={"name": "X", "elastic_url": "http://x", "index": "y*", "field_mapping": ""},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).telemetry_bridges == []


def test_add_telemetry_bridge_redirects_to_plugins_tab(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/telemetry-bridges",
        data={"name": "X", "elastic_url": "http://x", "index": "y*", "field_mapping": "detail: message"},
        follow_redirects=False,
    )

    assert response.headers["Location"].endswith("#tab-plugins")


# -- Consultar ahora (POST fetch) ---------------------------------------------


def test_fetch_telemetry_bridge_ingests_and_persists_events(client, app):
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*", field_mapping={"detail": "message"}
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id

    fake_hits = [{"_source": {"message": "conexión detectada"}}]
    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=fake_hits):
        response = client.post(
            f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch", follow_redirects=False
        )

    assert response.status_code == 302
    events = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert len(events) == 1
    assert events[0].payload["detail"] == "conexión detectada"


def test_fetch_telemetry_bridge_updates_last_fetch_at(client, app):
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*", field_mapping={"detail": "message"}
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id
    assert operation.telemetry_bridges[0].last_fetch_at is None

    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=[]):
        client.post(f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch")

    updated = app.config["OPERATION_REPOSITORY"].get(operation.id).telemetry_bridges[0]
    assert updated.last_fetch_at is not None


def test_fetch_telemetry_bridge_since_uses_last_fetch_at(client, app):
    operation = _operation()
    previous_fetch = datetime(2026, 8, 20, 0, 0, tzinfo=timezone.utc)
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo",
            elastic_url="http://localhost:9200",
            index="tpot-*",
            field_mapping={"detail": "message"},
            last_fetch_at=previous_fetch,
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id

    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=[]) as mock_fetch:
        client.post(f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch")

    assert mock_fetch.call_args.kwargs["since"] == previous_fetch


def test_fetch_telemetry_bridge_flashes_error_on_connection_failure(client, app):
    from apate.playground.exceptions import PlaygroundCommandError

    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*", field_mapping={"detail": "message"}
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id

    with patch(
        "apate.telemetry.external_bridge.fetch_recent_hits",
        side_effect=PlaygroundCommandError("no se pudo conectar"),
    ):
        response = client.post(
            f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch", follow_redirects=True
        )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    # No se actualiza last_fetch_at si la consulta fallo.
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).telemetry_bridges[0].last_fetch_at is None


def test_fetch_telemetry_bridge_404_for_unknown_source(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(f"/operations/{operation.id}/telemetry-bridges/no-existe/fetch")

    assert response.status_code == 404


def test_fetch_telemetry_bridge_runs_rules(client, app, monkeypatch):
    from pathlib import Path

    from apate.core import ExternalTelemetrySource, PluginBinding
    from apate.plugins import DolosTPlugin, EventType, PluginLifecycleState

    operation = _operation()
    operation.bind_plugin(
        PluginBinding(
            plugin_id="network-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "decoy-1"}]},
        )
    )
    source = ExternalTelemetrySource(
        name="Fuente que dispara reglas",
        elastic_url="http://localhost:9200",
        surface="network",
        index="logs-*",
        field_mapping={"detail": "message"},
    )
    operation.add_telemetry_bridge(source)
    app.config["OPERATION_REPOSITORY"].save(operation)
    Path(app.config["APATE_RULES_PATH"]).write_text(
        f"""rules:
  - name: Activar desde puente externo
    when:
      event_type: interaction
      plugin_id: {source.id}
      payload:
        detail: conexión detectada
    then:
      - action: rotate
        plugin_id: network-1
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "apate.telemetry.external_bridge.fetch_recent_hits",
        lambda **kwargs: [{"_source": {"message": "conexión detectada"}}],
    )
    restored = []
    rotations = []

    def restore(plugin):
        restored.append(plugin.plugin_id)
        plugin.state = PluginLifecycleState.DEPLOYED

    def rotate(plugin):
        rotations.append(plugin.plugin_id)
        plugin._publish(EventType.INTERACTION, {"kind": "rotate"})

    monkeypatch.setattr(DolosTPlugin, "restore_deployed_state", restore)
    monkeypatch.setattr(DolosTPlugin, "rotate", rotate)

    response = client.post(f"/operations/{operation.id}/telemetry-bridges/{source.id}/fetch")

    assert response.status_code == 302
    assert restored == ["network-1"]
    assert rotations == ["network-1"]
    # Un solo registro: el evento del puente. El `rotate` que dispara la
    # regla es una accion del ciclo de vida y la telemetria del adversario
    # ya no la guarda -- E3 de docs/improvements.md.
    records = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert [r.payload.get("detail") for r in records] == ["conexión detectada"]


def test_fetch_telemetry_bridge_rejects_unavailable_rule_action_without_500(client, app, monkeypatch):
    from pathlib import Path

    operation = _operation()
    source = ExternalTelemetrySource(
        name="Fuente con regla rechazada",
        elastic_url="http://localhost:9200",
        index="logs-*",
        field_mapping={"detail": "message"},
    )
    operation.add_telemetry_bridge(source)
    app.config["OPERATION_REPOSITORY"].save(operation)
    Path(app.config["APATE_RULES_PATH"]).write_text(
        f"""rules:
  - name: Acción inexistente rechazada
    when:
      event_type: interaction
      plugin_id: {source.id}
    then:
      - action: rotate
        plugin_id: no-existe
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "apate.telemetry.external_bridge.fetch_recent_hits",
        lambda **kwargs: [{"_source": {"message": "conexión detectada"}}],
    )

    response = client.post(
        f"/operations/{operation.id}/telemetry-bridges/{source.id}/fetch",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "no pudo actuar" in response.get_data(as_text=True)
    rejections = app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation.id)
    assert [rejection.rule_name for rejection in rejections] == ["Acción inexistente rechazada"]


def test_fetch_telemetry_bridge_logs_operator_action(client, app):
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*", field_mapping={"detail": "message"}
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id

    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=[]):
        client.post(f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch")

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert any(a.action == "telemetry_bridge_fetch" for a in actions)


# -- Correlación gratuita con la infraestructura existente -------------------


def test_ingested_ttp_shows_up_in_existing_ttp_report(client, app):
    """El puente no reimplementa nada de correlación -- lo que ya
    existe (generate_report()/compare_ttps()) lo toma directo de
    TelemetryCollector.list_ttps(), que ya recibe el ttp_id mapeado."""

    from apate.reporting import generate_report

    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1110.001"]))
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo",
            elastic_url="http://localhost:9200",
            index="tpot-*",
            field_mapping={"ttp_id": "mitre.technique_id"},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    source_id = operation.telemetry_bridges[0].id

    fake_hits = [{"_source": {"mitre": {"technique_id": "T1110.001"}}}]
    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=fake_hits):
        client.post(f"/operations/{operation.id}/telemetry-bridges/{source_id}/fetch")

    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    report = generate_report(saved, app.config["TELEMETRY_COLLECTOR"])
    assert "T1110.001" in report.matched_ttps
