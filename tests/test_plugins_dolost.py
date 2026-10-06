"""Tests para DolosTPlugin (M8c) - ver apate.plugins.dolost_plugin.

Sin Docker real: se mockean las funciones de DOLOS-T que el adaptador
llama directo (`deploy_collector`/`deploy_decoy`/`clean_decoy`/
`get_structured_events`, todas importadas por nombre dentro del modulo
del adaptador) y los metodos de `_docker_manager` que usa `rotate()`
-- estos tests verifican la logica del adaptador (estado, payloads,
deduplicacion), no el comportamiento real de DOLOS-T/Docker."""

import pytest

from apate.plugins import DolosTPlugin, EventBus, EventType, PluginLifecycleState, PluginStateError
from apate.plugins import dolost_plugin as dolost_plugin_module

_DECOY = {"Hostname": "ssh-decoy", "IP": "10.0.0.5"}


def _make_plugin(bus: EventBus = None, **config_overrides) -> DolosTPlugin:
    config = dict(config_overrides)
    return DolosTPlugin(
        plugin_id="dolost-1",
        surface="red",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
        config=config,
    )


@pytest.fixture
def dolost_calls(monkeypatch):
    """Reemplaza las funciones de DOLOS-T por dobles que solo
    registran la llamada, y los metodos de _docker_manager usados por
    rotate() -- ninguno de los dos requiere Docker corriendo."""

    calls = {"deploy_collector": [], "deploy_decoy": [], "clean_decoy": [], "stop": [], "start": [],
              "clean_container": [], "clean_networks": []}

    monkeypatch.setattr(dolost_plugin_module, "deploy_collector", lambda: calls["deploy_collector"].append(True))
    monkeypatch.setattr(dolost_plugin_module, "deploy_decoy", lambda decoy: calls["deploy_decoy"].append(decoy))
    monkeypatch.setattr(dolost_plugin_module, "clean_decoy", lambda decoy: calls["clean_decoy"].append(decoy))
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "stop", lambda container_id: calls["stop"].append(container_id)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "start", lambda container_id: calls["start"].append(container_id)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "clean_container", lambda name: calls["clean_container"].append(name)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "clean_networks", lambda: calls["clean_networks"].append(True)
    )
    return calls


# -- deploy() -----------------------------------------------------------


def test_deploy_without_decoys_only_deploys_collector(dolost_calls):
    plugin = _make_plugin()
    plugin.deploy()

    assert len(dolost_calls["deploy_collector"]) == 1
    assert dolost_calls["deploy_decoy"] == []


def test_deploy_with_decoys_deploys_collector_and_each_decoy(dolost_calls):
    plugin = _make_plugin(decoys=[_DECOY, {"Hostname": "ftp-decoy"}])
    plugin.deploy()

    assert len(dolost_calls["deploy_collector"]) == 1
    assert dolost_calls["deploy_decoy"] == [_DECOY, {"Hostname": "ftp-decoy"}]


def test_deploy_emits_interaction_event_with_decoy_count(dolost_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    _make_plugin(bus=bus, decoys=[_DECOY]).deploy()

    assert len(received) == 1
    assert received[0].payload["kind"] == "deploy"
    assert received[0].payload["decoy_count"] == 1


def test_deploy_sets_state_to_deployed(dolost_calls):
    plugin = _make_plugin()
    plugin.deploy()
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_deploy_twice_raises_plugin_state_error(dolost_calls):
    plugin = _make_plugin()
    plugin.deploy()
    with pytest.raises(PluginStateError):
        plugin.deploy()


# -- rotate() -------------------------------------------------------------


def test_rotate_before_deploy_raises_plugin_state_error(dolost_calls):
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


def test_rotate_stops_and_starts_each_configured_decoy(dolost_calls):
    plugin = _make_plugin(decoys=[_DECOY])
    plugin.deploy()

    plugin.rotate()

    assert dolost_calls["stop"] == ["DolosT-ssh-decoy"]
    assert dolost_calls["start"] == ["DolosT-ssh-decoy"]


def test_rotate_keeps_deployed_state_and_emits_event(dolost_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, decoys=[_DECOY])
    plugin.deploy()
    received.clear()

    plugin.rotate()

    assert plugin.state == PluginLifecycleState.DEPLOYED
    assert len(received) == 1
    assert received[0].payload["kind"] == "rotate"


# -- retire() ---------------------------------------------------------------


def test_retire_before_deploy_raises_plugin_state_error(dolost_calls):
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_cleans_each_decoy_and_the_collector(dolost_calls):
    plugin = _make_plugin(decoys=[_DECOY])
    plugin.deploy()

    plugin.retire()

    assert dolost_calls["clean_decoy"] == [_DECOY]
    assert dolost_calls["clean_container"] == ["Collector"]
    assert len(dolost_calls["clean_networks"]) == 1


def test_retire_sets_state_to_retired_and_emits_event(dolost_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    received.clear()

    plugin.retire()

    assert plugin.state == PluginLifecycleState.RETIRED
    assert received[0].payload["kind"] == "retire"


def test_retire_twice_raises_plugin_state_error(dolost_calls):
    plugin = _make_plugin()
    plugin.deploy()
    plugin.retire()
    with pytest.raises(PluginStateError):
        plugin.retire()


# -- check_activity() --------------------------------------------------------


def test_check_activity_before_deploy_raises_plugin_state_error(dolost_calls, monkeypatch):
    monkeypatch.setattr(dolost_plugin_module, "get_structured_events", lambda: [])
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.check_activity()


def test_check_activity_publishes_interaction_for_events_without_ttp_id(dolost_calls, monkeypatch):
    raw_event = {
        "kind": "network_connection",
        "detail": "Connection observed",
        "ttp_id": None,
        "source_ip": "203.0.113.5",
        "decoy": "ssh-decoy",
        "timestamp": "2026-01-01T00:00:00",
    }
    monkeypatch.setattr(dolost_plugin_module, "get_structured_events", lambda: [raw_event])

    bus = EventBus()
    interactions = []
    ttps = []
    bus.subscribe(EventType.INTERACTION, interactions.append)
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus, decoys=[_DECOY])
    plugin.deploy()
    interactions.clear()
    published = plugin.check_activity()

    assert len(published) == 1
    assert len(interactions) == 1
    assert ttps == []
    assert interactions[0].payload["source_ip"] == "203.0.113.5"
    assert interactions[0].resource_id == "decoy:ssh-decoy"
    # ttp_id=None se filtra del payload (el adaptador descarta claves
    # con valor None antes de publicar).
    assert "ttp_id" not in interactions[0].payload


def test_check_activity_publishes_ttp_observed_when_ttp_id_present(dolost_calls, monkeypatch):
    raw_event = {"kind": "exploit_attempt", "detail": "...", "ttp_id": "T1190", "decoy": "ssh-decoy"}
    monkeypatch.setattr(dolost_plugin_module, "get_structured_events", lambda: [raw_event])

    bus = EventBus()
    ttps = []
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    plugin.check_activity()

    assert len(ttps) == 1
    assert ttps[0].payload["ttp_id"] == "T1190"


def test_check_activity_does_not_republish_the_same_event_twice(dolost_calls, monkeypatch):
    # get_structured_events() no drena -- relee el mismo snapshot en
    # cada llamada, asi que sin deduplicacion esto se publicaria en
    # cada poll (ver docstring de DolosTPlugin).
    raw_event = {"kind": "decoy_usage", "detail": "Activity 'login' recorded", "ttp_id": None, "decoy": "ssh-decoy"}
    monkeypatch.setattr(dolost_plugin_module, "get_structured_events", lambda: [raw_event])

    plugin = _make_plugin()
    plugin.deploy()

    first = plugin.check_activity()
    second = plugin.check_activity()

    assert len(first) == 1
    assert second == []


def test_check_activity_publishes_new_events_on_later_polls(dolost_calls, monkeypatch):
    first_event = {"kind": "decoy_usage", "detail": "login", "ttp_id": None, "decoy": "ssh-decoy"}
    second_event = {"kind": "decoy_usage", "detail": "logout", "ttp_id": None, "decoy": "ssh-decoy"}

    events_by_call = [[first_event], [first_event, second_event]]
    monkeypatch.setattr(dolost_plugin_module, "get_structured_events", lambda: events_by_call.pop(0))

    plugin = _make_plugin()
    plugin.deploy()

    first = plugin.check_activity()
    second = plugin.check_activity()

    assert len(first) == 1
    assert len(second) == 1
    assert second[0].payload["detail"] == "logout"
