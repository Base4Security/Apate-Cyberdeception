"""Tests para `apate.plugins.opencanary_plugin.OpenCanaryPlugin`. Ver
docstring del módulo para el diseño completo."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from apate.plugins import EventBus, EventType, OpenCanaryPlugin, PluginStateError
from apate.plugins.opencanary_client import OpenCanaryHit


def _make_plugin(bus: EventBus = None, **config_overrides) -> OpenCanaryPlugin:
    config = {"services": {"ssh": {"enabled": True, "port": 2222}}}
    config.update(config_overrides)
    return OpenCanaryPlugin(
        plugin_id="opencanary-1",
        surface="network",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
        config=config,
    )


def _collect(bus: EventBus, event_type: EventType) -> list:
    collected = []
    bus.subscribe(event_type, collected.append)
    return collected


# -- deploy() -------------------------------------------------------------


def test_deploy_calls_deploy_container_with_container_name_convention():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="abc123") as mock_deploy:
        plugin.deploy()

    mock_deploy.assert_called_once_with(
        name="OpenCanary-opencanary-1",
        node_id="opencanary-1",
        services={"ssh": {"enabled": True, "port": 2222}},
        network_mode="bridge",
    )
    assert plugin.state == "deployed"


def test_deploy_uses_configured_node_id_and_network_mode():
    plugin = _make_plugin(node_id="mi-nodo", network_mode="host")
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x") as mock_deploy:
        plugin.deploy()

    assert mock_deploy.call_args.kwargs["node_id"] == "mi-nodo"
    assert mock_deploy.call_args.kwargs["network_mode"] == "host"


def test_deploy_without_services_still_deploys_with_empty_dict():
    plugin = _make_plugin(services={})
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x") as mock_deploy:
        plugin.deploy()

    assert mock_deploy.call_args.kwargs["services"] == {}
    assert plugin.state == "deployed"


def test_deploy_sets_last_checked_at_cursor():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"), patch(
        "apate.plugins.opencanary_plugin.time"
    ) as mock_time:
        mock_time.time.return_value = 1000.0
        plugin.deploy()

    assert plugin.config["last_checked_at"] == 1000.0


def test_deploy_publishes_interaction_with_enabled_service_list():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    plugin = _make_plugin(bus)
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    assert len(interactions) == 1
    assert interactions[0].payload["services"] == ["ssh"]
    assert interactions[0].resource_id == "opencanary:opencanary-1"


def test_deploy_twice_raises_plugin_state_error():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()
        with pytest.raises(PluginStateError):
            plugin.deploy()


def test_deploy_propagates_docker_error_without_marking_deployed():
    from apate.plugins.exceptions import OpenCanaryError

    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", side_effect=OpenCanaryError("puerto ocupado")):
        with pytest.raises(OpenCanaryError):
            plugin.deploy()
    assert plugin.state == "created"


# -- rotate(): stop+start real, a diferencia de Canarytokens ----------------


def test_rotate_calls_restart_container():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.restart_container") as mock_restart:
        plugin.rotate()

    mock_restart.assert_called_once_with(name="OpenCanary-opencanary-1")
    assert plugin.state == "deployed"


def test_rotate_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


# -- retire() ---------------------------------------------------------------


def test_retire_calls_stop_and_remove_and_clears_cursor():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.stop_and_remove_container") as mock_stop:
        plugin.retire()

    mock_stop.assert_called_once_with(name="OpenCanary-opencanary-1")
    assert "last_checked_at" not in plugin.config
    assert plugin.state == "retired"


def test_retire_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


# -- check_activity(): polling + cursor persistido ---------------------------


_HIT = OpenCanaryHit(
    logtype=4002,
    local_time="2024-01-01 00:00:00",
    src_host="203.0.113.5",
    src_port=51390,
    dst_host=None,
    dst_port=2222,
    node_id="opencanary-1",
    logdata={"USERNAME": "fakeuser", "PASSWORD": ""},
)


def test_check_activity_publishes_one_event_per_hit():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[_HIT]):
        events = plugin.check_activity()

    assert len(events) == 1
    assert events[0].payload["source_ip"] == "203.0.113.5"
    assert events[0].payload["logdata"]["USERNAME"] == "fakeuser"
    assert events[0].resource_id == "opencanary:opencanary-1"


def test_check_activity_passes_persisted_cursor_to_fetch_logs():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()
    plugin.config["last_checked_at"] = 500.0

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[]) as mock_fetch:
        plugin.check_activity()

    assert mock_fetch.call_args.kwargs["since"] == 500.0


def test_check_activity_updates_cursor_to_now_after_call():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[]), patch(
        "apate.plugins.opencanary_plugin.time"
    ) as mock_time:
        mock_time.time.return_value = 2000.0
        plugin.check_activity()

    assert plugin.config["last_checked_at"] == 2000.0


def test_check_activity_without_ttp_id_stays_interaction():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[_HIT]):
        events = plugin.check_activity()

    assert events[0].event_type == EventType.INTERACTION
    assert "ttp_id" not in events[0].payload


def test_check_activity_with_ttp_id_becomes_ttp_observed():
    plugin = _make_plugin(ttp_id="T1110.001")
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[_HIT]):
        events = plugin.check_activity()

    assert events[0].event_type == EventType.TTP_OBSERVED
    assert events[0].payload["ttp_id"] == "T1110.001"


def test_check_activity_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.check_activity()


def test_check_activity_no_hits_returns_empty_list():
    plugin = _make_plugin()
    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        plugin.deploy()

    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[]):
        events = plugin.check_activity()

    assert events == []
