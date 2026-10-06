import pytest

from apate.plugins import EventBus, EventType, MockHoneypotPlugin, PluginLifecycleState, PluginStateError


def _make_plugin(bus: EventBus = None, **overrides) -> MockHoneypotPlugin:
    defaults = dict(
        plugin_id="honeypot-mock",
        surface="network",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
    )
    defaults.update(overrides)
    return MockHoneypotPlugin(**defaults)


def test_deploy_emits_scan_interaction_event():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    _make_plugin(bus=bus).deploy()

    assert len(received) == 1
    assert received[0].payload["kind"] == "scan"


def test_deploy_sets_state_to_deployed():
    plugin = _make_plugin()
    plugin.deploy()
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_deploy_twice_raises_plugin_state_error():
    plugin = _make_plugin()
    plugin.deploy()
    with pytest.raises(PluginStateError):
        plugin.deploy()


def test_simulate_access_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.simulate_access()


def test_simulate_access_emits_interaction_and_ttp_observed_events():
    bus = EventBus()
    interactions = []
    ttps = []
    bus.subscribe(EventType.INTERACTION, interactions.append)
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    interactions.clear()  # descartar el evento de scan del deploy()
    plugin.simulate_access(ttp_id="T1078")

    assert len(interactions) == 1
    assert interactions[0].payload["kind"] == "access"
    assert len(ttps) == 1
    assert ttps[0].payload["ttp_id"] == "T1078"


def test_rotate_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


def test_rotate_after_deploy_emits_interaction_event_and_keeps_deployed_state():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    received.clear()
    plugin.rotate()

    assert len(received) == 1
    assert received[0].payload["kind"] == "rotate"
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_retire_after_deploy_emits_interaction_event_and_sets_retired_state():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    received.clear()
    plugin.retire()

    assert len(received) == 1
    assert received[0].payload["kind"] == "retire"
    assert plugin.state == PluginLifecycleState.RETIRED


def test_retire_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_twice_raises_plugin_state_error():
    plugin = _make_plugin()
    plugin.deploy()
    plugin.retire()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_events_carry_plugin_id_surface_and_operation_id():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, plugin_id="honeypot-mock-2", surface="network", operation_id="op-99")
    plugin.deploy()

    event = received[0]
    assert event.plugin_id == "honeypot-mock-2"
    assert event.surface == "network"
    assert event.operation_id == "op-99"


def test_end_to_end_bus_subscriber_receives_mock_events():
    # Simula como el motor de reglas (M3) va a consumir el bus: un unico
    # suscriptor viendo la secuencia completa de eventos de una operacion.
    bus = EventBus()
    seen = []
    bus.subscribe(EventType.INTERACTION, lambda e: seen.append((e.event_type, e.payload.get("kind"))))
    bus.subscribe(EventType.TTP_OBSERVED, lambda e: seen.append((e.event_type, e.payload.get("ttp_id"))))

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    plugin.simulate_access(ttp_id="T1078")
    plugin.retire()

    assert seen == [
        (EventType.INTERACTION, "scan"),
        (EventType.INTERACTION, "access"),
        (EventType.TTP_OBSERVED, "T1078"),
        (EventType.INTERACTION, "retire"),
    ]
