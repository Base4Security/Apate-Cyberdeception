"""Tests para `apate.plugins.canarytoken_plugin.CanarytokenPlugin`. Ver
docstring del módulo para el diseño completo."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from apate.plugins import CanarytokenPlugin, EventBus, EventType, PluginStateError
from apate.plugins.canarytoken_client import CanarytokenCreated, CanarytokenHit
from apate.plugins.exceptions import CanarytokenAPIError, PluginConfigError


def _make_plugin(bus: EventBus = None, **config_overrides) -> CanarytokenPlugin:
    config = {
        "base_url": "http://localhost:8082/rootpath",
        "token_type": "dns",
        "memo": "Nota de prueba",
        "email": "soc@example.com",
    }
    config.update(config_overrides)
    return CanarytokenPlugin(
        plugin_id="canarytoken-1",
        surface="data",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
        config=config,
    )


def _collect(bus: EventBus, event_type: EventType) -> list:
    collected = []
    bus.subscribe(event_type, collected.append)
    return collected


_CREATED = CanarytokenCreated(token="tok-1", auth_token="secret-auth-abc123", token_url="http://x/y", hostname="tok-1.local")


# -- deploy() -----------------------------------------------------------


def test_deploy_creates_token_and_stores_identity_in_config():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED) as mock_create:
        plugin.deploy()

    assert plugin.config["token"] == "tok-1"
    assert plugin.config["auth_token"] == "secret-auth-abc123"
    assert plugin.config["token_url"] == "http://x/y"
    assert plugin.config["hostname"] == "tok-1.local"
    assert plugin.state == "deployed"
    mock_create.assert_called_once_with(
        "http://localhost:8082/rootpath", token_type="dns", memo="Nota de prueba", email="soc@example.com", extra_fields=None
    )


def test_deploy_passes_extra_fields_through():
    plugin = _make_plugin(extra_fields={"redirect_url": "https://example.com"})
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED) as mock_create:
        plugin.deploy()

    assert mock_create.call_args.kwargs["extra_fields"] == {"redirect_url": "https://example.com"}


def test_deploy_publishes_interaction_without_auth_token_in_payload():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    plugin = _make_plugin(bus)
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    assert len(interactions) == 1
    assert "secret-auth-abc123" not in repr(interactions[0].payload)
    assert interactions[0].resource_id == "canarytoken:tok-1"


def test_deploy_without_base_url_raises_plugin_config_error():
    plugin = _make_plugin(base_url=None)
    with pytest.raises(PluginConfigError, match="base_url"):
        plugin.deploy()


def test_deploy_missing_memo_and_email_reports_both_in_one_error():
    plugin = _make_plugin(memo=None, email=None)
    with pytest.raises(PluginConfigError) as exc_info:
        plugin.deploy()
    assert "memo" in str(exc_info.value)
    assert "email" in str(exc_info.value)


def test_deploy_twice_raises_plugin_state_error():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()
        with pytest.raises(PluginStateError):
            plugin.deploy()


def test_deploy_propagates_canarytoken_api_error():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", side_effect=CanarytokenAPIError("falló")):
        with pytest.raises(CanarytokenAPIError):
            plugin.deploy()
    assert plugin.state == "created"  # no quedó a medio desplegar


# -- rotate(): sin equivalente natural, documentado ---------------------


def test_rotate_does_not_change_state():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()
    plugin.rotate()
    assert plugin.state == "deployed"


def test_rotate_publishes_interaction_explaining_no_native_equivalent():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    plugin = _make_plugin(bus)
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()
    interactions.clear()

    plugin.rotate()

    assert len(interactions) == 1
    assert interactions[0].payload["kind"] == "rotate"
    assert "no tiene forma de regenerar" in interactions[0].payload["detail"]


def test_rotate_makes_no_http_call():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()
    with patch("apate.plugins.canarytoken_plugin.delete_token") as mock_delete, patch(
        "apate.plugins.canarytoken_plugin.fetch_hits"
    ) as mock_fetch:
        plugin.rotate()
    mock_delete.assert_not_called()
    mock_fetch.assert_not_called()


def test_rotate_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


# -- retire() -------------------------------------------------------------


def test_retire_deletes_token_and_clears_identity_from_config():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.delete_token") as mock_delete:
        plugin.retire()

    mock_delete.assert_called_once_with("http://localhost:8082/rootpath", token="tok-1", auth_token="secret-auth-abc123")
    assert "token" not in plugin.config
    assert "auth_token" not in plugin.config
    assert plugin.state == "retired"


def test_retire_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_propagates_api_error_without_clearing_config():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.delete_token", side_effect=CanarytokenAPIError("falló")):
        with pytest.raises(CanarytokenAPIError):
            plugin.retire()
    # Sigue "deployed" con su identidad intacta -- no se borró nada si el borrado remoto falló.
    assert plugin.config.get("token") == "tok-1"
    assert plugin.state == "deployed"


# -- check_hits(): polling + deduplicación por cursor ------------------


_HIT_OLD = CanarytokenHit(time_of_hit=100.0, source_ip="203.0.113.1", input_channel="DNS", token_type="dns", is_tor_relay=False, useragent="")
_HIT_NEW = CanarytokenHit(time_of_hit=200.0, source_ip="203.0.113.2", input_channel="DNS", token_type="dns", is_tor_relay=True, useragent="curl/8.0")


def test_check_hits_without_since_publishes_all_hits():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_OLD, _HIT_NEW]):
        events = plugin.check_hits()

    assert len(events) == 2


def test_check_hits_with_since_skips_already_seen_hits():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_OLD, _HIT_NEW]):
        events = plugin.check_hits(since=100.0)

    assert len(events) == 1
    assert events[0].payload["time_of_hit"] == 200.0


def test_check_hits_updates_last_hit_time_cursor_in_config():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_OLD, _HIT_NEW]):
        plugin.check_hits()

    assert plugin.config["last_hit_time"] == 200.0


def test_check_hits_no_new_hits_keeps_cursor():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_OLD]):
        plugin.check_hits(since=500.0)

    assert plugin.config["last_hit_time"] == 500.0


def test_check_hits_without_ttp_id_configured_stays_interaction():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_NEW]):
        events = plugin.check_hits()

    assert events[0].event_type == EventType.INTERACTION
    assert "ttp_id" not in events[0].payload


def test_check_hits_with_ttp_id_configured_becomes_ttp_observed():
    plugin = _make_plugin(ttp_id="T1590.002")
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_NEW]):
        events = plugin.check_hits()

    assert events[0].event_type == EventType.TTP_OBSERVED
    assert events[0].payload["ttp_id"] == "T1590.002"


def test_check_hits_payload_never_contains_auth_token():
    plugin = _make_plugin()
    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        plugin.deploy()

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[_HIT_NEW]):
        events = plugin.check_hits()

    assert "secret-auth-abc123" not in repr(events[0].payload)


def test_check_hits_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.check_hits()


# -- restore_deployed_state() --------------------------------------------


def test_restore_deployed_state_with_stored_identity_sets_deployed():
    plugin = _make_plugin(token="tok-1", auth_token="a")
    plugin.restore_deployed_state()
    assert plugin.state == "deployed"


def test_restore_deployed_state_without_identity_raises():
    plugin = _make_plugin()
    with pytest.raises(PluginConfigError):
        plugin.restore_deployed_state()


def test_restore_deployed_state_makes_no_http_call():
    plugin = _make_plugin(token="tok-1", auth_token="a")
    with patch("apate.plugins.canarytoken_plugin.fetch_hits") as mock_fetch, patch(
        "apate.plugins.canarytoken_plugin.create_token"
    ) as mock_create:
        plugin.restore_deployed_state()
    mock_fetch.assert_not_called()
    mock_create.assert_not_called()
