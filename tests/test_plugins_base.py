import pytest

from apate.core import PluginBinding
from apate.plugins import (
    DeceptionPlugin,
    EventBus,
    EventType,
    PluginEvent,
    PluginLifecycleState,
    PluginStateError,
    sanitize_payload_text,
)


class _DummyPlugin(DeceptionPlugin):
    """Subclase concreta minima, misma estructura que MockHoneypotPlugin,
    usada solo para ejercitar el contrato de DeceptionPlugin en aislamiento."""

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        self._publish(EventType.INTERACTION, {"kind": "deploy"})
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        self._publish(EventType.INTERACTION, {"kind": "rotate"})

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        self._publish(EventType.INTERACTION, {"kind": "retire"})
        self.state = PluginLifecycleState.RETIRED


def _make_plugin(bus: EventBus = None, **overrides) -> _DummyPlugin:
    defaults = dict(
        plugin_id="dummy-1",
        surface="network",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
    )
    defaults.update(overrides)
    return _DummyPlugin(**defaults)


def test_deception_plugin_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        DeceptionPlugin(plugin_id="x", surface="network", operation_id="op-1", bus=EventBus())


def test_incomplete_subclass_cannot_be_instantiated():
    # Le falta implementar retire(): el ABC debe rechazar la instanciacion.
    class _Incomplete(DeceptionPlugin):
        def deploy(self) -> None:
            pass

        def rotate(self) -> None:
            pass

    with pytest.raises(TypeError):
        _Incomplete(plugin_id="x", surface="network", operation_id="op-1", bus=EventBus())


def test_plugin_starts_in_created_state():
    plugin = _make_plugin()
    assert plugin.state == PluginLifecycleState.CREATED


def test_from_binding_copies_plugin_id_surface_and_config():
    binding = PluginBinding(plugin_id="dolost-mock", surface="network", config={"source_ip": "10.0.0.1"})
    bus = EventBus()

    plugin = _DummyPlugin.from_binding(binding, operation_id="op-42", bus=bus)

    assert plugin.plugin_id == "dolost-mock"
    assert plugin.surface == "network"
    assert plugin.operation_id == "op-42"
    assert plugin.config == {"source_ip": "10.0.0.1"}


def test_event_bus_publish_calls_subscribed_handler():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()

    assert len(received) == 1
    assert received[0].event_type == EventType.INTERACTION


def test_event_bus_publish_calls_multiple_handlers_in_order():
    bus = EventBus()
    order = []
    bus.subscribe(EventType.INTERACTION, lambda e: order.append("first"))
    bus.subscribe(EventType.INTERACTION, lambda e: order.append("second"))

    _make_plugin(bus=bus).deploy()

    assert order == ["first", "second"]


def test_event_bus_publish_with_no_subscribers_does_not_raise():
    bus = EventBus()
    # No hay ningun subscribe() previo: publish() debe ser un no-op silencioso,
    # porque el motor de reglas (M3) puede todavia no existir al emitirse el evento.
    _make_plugin(bus=bus).deploy()


def test_event_bus_only_calls_handlers_for_matching_event_type():
    bus = EventBus()
    received = []
    bus.subscribe(EventType.TTP_OBSERVED, received.append)

    _make_plugin(bus=bus).deploy()  # solo emite INTERACTION

    assert received == []


def test_plugin_event_roundtrip_to_dict_from_dict():
    event = PluginEvent(
        event_type=EventType.TTP_OBSERVED,
        plugin_id="dummy-1",
        surface="network",
        operation_id="op-1",
        resource_id="decoy:srv-1",
        payload={"ttp_id": "T1078"},
    )

    restored = PluginEvent.from_dict(event.to_dict())

    assert restored.id == event.id
    assert restored.event_type == event.event_type
    assert restored.plugin_id == event.plugin_id
    assert restored.surface == event.surface
    assert restored.operation_id == event.operation_id
    assert restored.resource_id == "decoy:srv-1"
    assert restored.payload == event.payload
    assert restored.timestamp == event.timestamp


def test_require_state_raises_plugin_state_error_on_mismatch():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        # Todavia esta CREATED, no DEPLOYED: rotate() no es valido aca.
        plugin.rotate()


# -- sanitize_payload_text() (seccion 3.4 del contrato de plugins) ----------


def test_sanitize_payload_text_leaves_short_text_unchanged():
    assert sanitize_payload_text("hola") == "hola"


def test_sanitize_payload_text_truncates_long_text():
    long_text = "a" * 3000

    result = sanitize_payload_text(long_text)

    assert len(result) < 3000
    assert result.startswith("a" * 2000)
    assert "truncado" in result
    assert "3000" in result


def test_sanitize_payload_text_respects_custom_max_length():
    result = sanitize_payload_text("abcdefghij", max_length=5)

    assert result.startswith("abcde")
    assert "truncado" in result


def test_sanitize_payload_text_boundary_exact_length_not_truncated():
    exact = "a" * 2000
    assert sanitize_payload_text(exact) == exact


def test_sanitize_payload_text_passes_through_non_string_types():
    assert sanitize_payload_text(42) == 42
    assert sanitize_payload_text(True) is True
    assert sanitize_payload_text(None) is None
    payload = {"nested": "dict"}
    assert sanitize_payload_text(payload) is payload
