"""Ingesta periódica unificada de actividad externa por operación."""

from apate.core import PluginBinding, Scenario
from apate.plugins import buda_plugin as buda_module
from apate.plugins import dolost_plugin as dolost_module


def _create_operation(client, app, name: str):
    response = client.post(
        "/operations/new",
        data={"name": name, "adversary_name": "APT", "narrative_name": "Narrativa"},
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]
    return app.config["OPERATION_REPOSITORY"].get(operation_id)


def test_poll_unifies_buda_and_dolost_in_operation_telemetry(client, app, monkeypatch):
    operation = _create_operation(client, app, "Operación unificada")
    scenario = Scenario(description="Acceso inicial", id="scenario-1")
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="identity-1",
            plugin_kind="buda",
            surface="identity",
            scenario_id=scenario.id,
            config={"narrative_id": 41},
        )
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="network-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            config={"decoys": [{"Hostname": "ssh-decoy"}]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    monkeypatch.setattr(
        buda_module,
        "drain_events",
        lambda narrative_id: [
            {"kind": "credential_use", "detail": "Uso simulado", "narrative_id": narrative_id}
        ],
    )
    monkeypatch.setattr(
        dolost_module,
        "get_structured_events",
        lambda: [{"kind": "observable_ip", "detail": "203.0.113.9", "decoy": "ssh-decoy"}],
    )

    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True
    published = service.poll_once()

    assert {event.plugin_id for event in published} == {"identity-1", "network-1"}
    persisted = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert {event.plugin_id for event in persisted} == {"identity-1", "network-1"}
    assert len(service.live_events(operation.id)) == 2


def test_poll_reuses_dolost_adapter_to_deduplicate_snapshots(client, app, monkeypatch):
    operation = _create_operation(client, app, "Operación con snapshot")
    operation.bind_plugin(
        PluginBinding(
            plugin_id="network-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "ssh-decoy"}]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    monkeypatch.setattr(
        dolost_module,
        "get_structured_events",
        lambda: [{"kind": "observable_ip", "detail": "203.0.113.9", "decoy": "ssh-decoy"}],
    )
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True

    assert len(service.poll_once()) == 1
    assert service.poll_once() == []
    assert len(app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)) == 1


def test_poll_fails_closed_for_shared_buda_narrative(client, app, monkeypatch):
    calls = []
    monkeypatch.setattr(buda_module, "drain_events", lambda narrative_id: calls.append(narrative_id) or [])
    for name in ("Operación uno", "Operación dos"):
        operation = _create_operation(client, app, name)
        operation.bind_plugin(
            PluginBinding(
                plugin_id=f"identity-{operation.id}",
                plugin_kind="buda",
                surface="identity",
                config={"narrative_id": 7},
            )
        )
        app.config["OPERATION_REPOSITORY"].save(operation)
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True

    assert service.poll_once() == []
    assert calls == []
    assert "atribución ambigua" in service.status()["last_error"]


def test_poll_runs_rules_and_persists_telemetry_once(client, app, monkeypatch):
    from pathlib import Path

    from apate.core import OperationStatus, PluginBinding
    from apate.plugins import BudaPlugin, EventType, PluginEvent

    operation = _create_operation(client, app, "Operación con reglas autónomas")
    operation.bind_plugin(PluginBinding(plugin_id="identity-1", plugin_kind="buda", surface="identity"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    Path(app.config["APATE_RULES_PATH"]).write_text(
        """rules:
  - name: Activar ante uso de credencial
    when:
      event_type: interaction
      plugin_id: identity-1
      payload:
        kind: credential_use
    then:
      - action: transition
        to: active
""",
        encoding="utf-8",
    )

    def publish_activity(plugin):
        event = plugin._publish(EventType.INTERACTION, {"kind": "credential_use"})
        return [event]

    monkeypatch.setattr(BudaPlugin, "check_activity", publish_activity)
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True
    service.rules_enabled = True

    assert len(service.poll_once()) == 1
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).status is OperationStatus.ACTIVE
    records = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert len(records) == 1


def test_poll_continues_after_a_rule_failure(client, app, monkeypatch):
    from pathlib import Path

    from apate.core import PluginBinding
    from apate.plugins import BudaPlugin, DolosTPlugin, EventType, PluginEvent

    operation = _create_operation(client, app, "Operación tolerante a errores")
    operation.bind_plugin(PluginBinding(plugin_id="identity-1", plugin_kind="buda", surface="identity"))
    operation.bind_plugin(
        PluginBinding(
            plugin_id="network-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "decoy-1"}]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    Path(app.config["APATE_RULES_PATH"]).write_text(
        """rules:
  - name: Acción inválida no detiene el sondeo
    when:
      event_type: interaction
      plugin_id: identity-1
    then:
      - action: rotate
        plugin_id: inexistente
""",
        encoding="utf-8",
    )

    def identity_activity(plugin):
        event = plugin._publish(EventType.INTERACTION, {"kind": "credential_use"})
        return [event]

    def network_activity(plugin):
        event = plugin._publish(EventType.INTERACTION, {"kind": "connection"})
        return [event]

    monkeypatch.setattr(BudaPlugin, "check_activity", identity_activity)
    monkeypatch.setattr(DolosTPlugin, "check_activity", network_activity)
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True
    service.rules_enabled = True

    events = service.poll_once()

    assert [event.plugin_id for event in events] == ["identity-1", "network-1"]
    assert service.status()["last_error"].startswith("regla/Acción inválida no detiene el sondeo:")
    records = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert {record.plugin_id for record in records} == {"identity-1", "network-1"}
    rejections = app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation.id)
    assert len(rejections) == 1


def test_poll_rule_rotates_a_cached_target_and_persists_its_firing(client, app, monkeypatch):
    from pathlib import Path

    from apate.core import PluginBinding
    from apate.plugins import BudaPlugin, DolosTPlugin, EventType

    operation = _create_operation(client, app, "Operación con acción entre capacidades")
    operation.bind_plugin(PluginBinding(plugin_id="identity-1", plugin_kind="buda", surface="identity"))
    operation.bind_plugin(
        PluginBinding(
            plugin_id="network-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "decoy-1"}]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    Path(app.config["APATE_RULES_PATH"]).write_text(
        """rules:
  - name: Rotar decoy ante uso de credencial
    when:
      event_type: interaction
      plugin_id: identity-1
    then:
      - action: rotate
        plugin_id: network-1
""",
        encoding="utf-8",
    )
    rotations = []

    def identity_activity(plugin):
        return [plugin._publish(EventType.INTERACTION, {"kind": "credential_use"})]

    def rotate(plugin):
        assert plugin.state.value == "deployed"
        rotations.append(plugin.plugin_id)
        plugin._publish(EventType.INTERACTION, {"kind": "rotate"})

    def unexpected_restore(_plugin):
        raise AssertionError("el sondeo no debe reconciliar un adaptador cacheado")

    monkeypatch.setattr(BudaPlugin, "check_activity", identity_activity)
    monkeypatch.setattr(DolosTPlugin, "restore_deployed_state", unexpected_restore)
    monkeypatch.setattr(DolosTPlugin, "rotate", rotate)
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True

    assert [event.plugin_id for event in service.poll_once()] == ["identity-1"]
    assert rotations == ["network-1"]
    firings = app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operation.id)
    assert [firing.rule_name for firing in firings] == ["Rotar decoy ante uso de credencial"]


def test_poll_skips_unscoped_dolost_collector(client, app, monkeypatch):
    operation = _create_operation(client, app, "Operación sin inventario")
    operation.bind_plugin(
        PluginBinding(plugin_id="network-1", plugin_kind="dolost", surface="network")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    monkeypatch.setattr(dolost_module, "get_structured_events", lambda: [{"kind": "observable_ip"}])
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True

    assert service.poll_once() == []
    assert "sin decoys correlacionables" in service.status()["last_error"]
