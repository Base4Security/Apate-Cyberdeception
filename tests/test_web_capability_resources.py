"""`capability_state()`/`capability_resources()` (`apate.web._deception_path`)
-- extraidas de la logica que `build_deception_path()` ya tenia inline
para que `apate.web._operation_tree` (arbol de la operacion) la reuse.
Ver docstring de esas funciones."""

from datetime import datetime, timezone
from unittest.mock import patch

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.plugins import EventType
from apate.telemetry import TelemetryRecord
from apate.web._deception_path import build_deception_path, capability_resources, capability_state


def test_capability_state_dolost_active_when_any_decoy_is_up():
    state = capability_state(
        "dolost",
        "dolost-1",
        dolost_panels={"dolost-1": {"decoys": [{"up": False}, {"up": True}]}},
        buda_panels={},
        honeytoken_panels={},
        observed=False,
    )
    assert state == "active"


def test_capability_state_observed_wins_over_deployment_state():
    state = capability_state(
        "dolost",
        "dolost-1",
        dolost_panels={"dolost-1": {"decoys": [{"up": False}]}},
        buda_panels={},
        honeytoken_panels={},
        observed=True,
    )
    assert state == "observed"


def test_capability_resources_buda_key_is_profile_id_not_name():
    """Regresion: `resource_id` real (`buda_plugin.py`) usa el id numerico
    del `UserProfile` (`f"profile:{profile_id}"`), no su nombre -- si
    `capability_resources()` alguna vez usa el nombre como `key`, la
    correlacion evento->recurso de `build_deception_path()` se rompe en
    silencio (el evento queda colgado del nodo de la capacidad en vez
    del recurso puntual)."""

    items = capability_resources(
        "buda",
        binding=PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"),
        dolost_panels={},
        buda_panels={"buda-1": {"is_running": True, "user_profiles": [{"id": 42, "name": "Ana Torres", "role": "IT"}]}},
        honeytoken_panels={},
    )
    assert items == [{"kind": "profile", "key": "42", "label": "Ana Torres", "state": "active", "detail": "IT"}]


def test_deception_path_still_correlates_buda_event_to_profile_resource_after_extraction():
    operation = Operation(
        name="Operación con perfil",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))
    event = TelemetryRecord(
        event_type=EventType.INTERACTION,
        operation_id=operation.id,
        plugin_id="buda-1",
        surface="identity",
        timestamp=datetime.now(timezone.utc),
        source_event_id="source-1",
        resource_id="profile:42",
        payload={"detail": "Actividad simulada"},
    )
    buda_panels = {"buda-1": {"is_running": True, "user_profiles": [{"id": 42, "name": "Ana Torres", "role": "IT"}]}}

    path = build_deception_path(operation, [event], dolost_panels={}, buda_panels=buda_panels, honeytoken_panels={})

    relations = {(edge["source"], edge["target"], edge["relation"]) for edge in path["edges"]}
    resource_id = "resource:buda-1:profile:42"
    assert any(node["id"] == resource_id and node["label"] == "Ana Torres" for node in path["nodes"])
    assert (resource_id, f"event:{event.id}", "observado por") in relations


def test_capability_resources_dolost_falls_back_to_binding_config_without_panel_data():
    items = capability_resources(
        "dolost",
        binding=PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", config={"decoys": [{"Hostname": "srv-finanzas"}]}),
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
    )
    assert items == [
        {"kind": "decoy", "key": "srv-finanzas", "label": "srv-finanzas", "state": "planned", "detail": "Configurado; estado no disponible"}
    ]


def test_capability_resources_unknown_kind_returns_nothing():
    assert (
        capability_resources(
            "mock",
            binding=PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"),
            dolost_panels={},
            buda_panels={},
            honeytoken_panels={},
        )
        == []
    )


def test_scenario_with_bound_capability_still_renders_after_extraction(client, app):
    """No-regresion de integracion: la pagina de detalle sigue armando
    el camino de engano (y ahora tambien el arbol) sin romper con datos
    reales de escenario+binding, tras extraer capability_state()/
    capability_resources()."""

    operation = Operation(
        name="Operación de regresión",
        adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1078"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    scenario = Scenario(description="Acceso inicial", related_ttps=["T1078"])
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200


def test_canarytoken_state_distinguishes_configured_from_deployed():
    configured = capability_state(
        "canarytoken",
        "canarytoken-1",
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        canarytoken_panels={"canarytoken-1": {"configured": True, "deployed": False}},
        observed=False,
    )
    deployed = capability_state(
        "canarytoken",
        "canarytoken-1",
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        canarytoken_panels={"canarytoken-1": {"configured": True, "deployed": True}},
        observed=False,
    )

    assert configured == "deployed"
    assert deployed == "active"


def test_opencanary_state_preserves_docker_unknown_from_not_deployed():
    unknown = capability_state(
        "opencanary",
        "opencanary-1",
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        opencanary_panels={
            "opencanary-1": {"configured": True, "deployed": False, "docker_available": False}
        },
        observed=False,
    )
    not_deployed = capability_state(
        "opencanary",
        "opencanary-1",
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        opencanary_panels={
            "opencanary-1": {"configured": True, "deployed": False, "docker_available": True}
        },
        observed=False,
    )

    assert unknown == "unknown"
    assert not_deployed == "deployed"


def test_canarytoken_resource_uses_real_token_key_without_secret():
    binding = PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data")
    items = capability_resources(
        "canarytoken",
        binding,
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        canarytoken_panels={
            "canarytoken-1": {
                "configured": True,
                "deployed": True,
                "token": "tok-1",
                "hostname": "tok-1.example",
                "token_type": "dns",
                "auth_token": "nunca-mostrar",
            }
        },
    )

    assert items == [
        {
            "kind": "canarytoken",
            "key": "tok-1",
            "label": "tok-1.example",
            "state": "active",
            "detail": "Miga Canarytoken · dns",
        }
    ]
    assert "nunca-mostrar" not in str(items)


def test_opencanary_resource_exposes_services_with_unknown_docker_state():
    binding = PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network")
    items = capability_resources(
        "opencanary",
        binding,
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        opencanary_panels={
            "opencanary-1": {
                "configured": True,
                "deployed": False,
                "docker_available": False,
                "container_status": None,
                "services": {"ssh": {"enabled": True, "port": 2222}},
            }
        },
    )

    assert items == [
        {
            "kind": "opencanary",
            "key": "opencanary-1",
            "label": "ssh:2222",
            "state": "unknown",
            "detail": "Docker no disponible; estado del contenedor desconocido.",
        }
    ]


def test_deception_path_correlates_new_plugin_events_to_real_resources():
    operation = Operation(
        name="Operación con recursos nuevos",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    operation.plugins.extend(
        [
            PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data"),
            PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network"),
        ]
    )
    events = [
        TelemetryRecord(
            event_type=EventType.INTERACTION,
            operation_id=operation.id,
            plugin_id="canarytoken-1",
            surface="data",
            source_event_id="source-canarytoken",
            resource_id="canarytoken:tok-1",
            timestamp=datetime.now(timezone.utc),
        ),
        TelemetryRecord(
            event_type=EventType.INTERACTION,
            operation_id=operation.id,
            plugin_id="opencanary-1",
            surface="network",
            source_event_id="source-opencanary",
            resource_id="opencanary:opencanary-1",
            timestamp=datetime.now(timezone.utc),
        ),
    ]
    path = build_deception_path(
        operation,
        events,
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
        canarytoken_panels={
            "canarytoken-1": {
                "configured": True,
                "deployed": True,
                "token": "tok-1",
                "token_type": "dns",
            }
        },
        opencanary_panels={
            "opencanary-1": {
                "configured": True,
                "deployed": True,
                "docker_available": True,
                "container_status": "running",
                "services": {"ssh": {"enabled": True, "port": 2222}},
            }
        },
    )

    relations = {(edge["source"], edge["target"]) for edge in path["edges"]}
    assert ("resource:canarytoken-1:canarytoken:tok-1", f"event:{events[0].id}") in relations
    assert ("resource:opencanary-1:opencanary:opencanary-1", f"event:{events[1].id}") in relations


def test_operation_detail_no_longer_marks_new_plugin_resources_not_applicable(client, app):
    operation = Operation(
        name="Operación con Canarytokens y OpenCanary",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    operation.plugins.extend(
        [
            PluginBinding(
                plugin_id="canarytoken-1",
                plugin_kind="canarytoken",
                surface="data",
                config={
                    "base_url": "http://canary.local/root",
                    "token_type": "dns",
                    "memo": "Portal proveedores",
                    "email": "soc@example.test",
                    "token": "tok-1",
                    "auth_token": "secret-auth-value-unique",
                    "hostname": "tok-1.example",
                },
            ),
            PluginBinding(
                plugin_id="opencanary-1",
                plugin_kind="opencanary",
                surface="network",
                config={"services": {"ssh": {"enabled": True, "port": 2222}}},
            ),
        ]
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(
        "apate.web.blueprints.operations._opencanary_container_status",
        return_value={"docker_available": False, "status": None, "up": None},
    ):
        text = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "tok-1.example" in text
    assert "ssh:2222" in text
    assert "Estado desconocido" in text
    assert "No aplica para este tipo de capacidad" not in text
    assert "decoys / OpenCanary" in text
    assert "honeytokens / Canarytokens" in text
    assert "secret-auth-value-unique" not in text
