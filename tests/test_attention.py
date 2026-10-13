"""Señales deterministas y casos no pueden cruzar operaciones ni actuar solos."""

import pytest

from apate.attention import AttentionService, SQLiteAttentionRepository
from apate.plugins.base import EventType, PluginEvent
from apate.telemetry import SQLiteTelemetryRepository, TelemetryCollector


def _services(tmp_path):
    telemetry = SQLiteTelemetryRepository(tmp_path / "telemetry.db")
    attention = SQLiteAttentionRepository(tmp_path / "attention.db")
    service = AttentionService(attention, telemetry)
    collector = TelemetryCollector(repository=telemetry, attention_evaluator=service.on_record)
    return service, collector


def _event(operation_id="op-1", plugin_id="honeyuser-1"):
    return PluginEvent(event_type=EventType.INTERACTION, operation_id=operation_id,
                       plugin_id=plugin_id, surface="identity", resource_id="S-1-5-21-1001",
                       payload={"kind": "honeyuser_authentication_success", "source_ip": "203.0.113.20"})


def test_rule_evaluates_only_after_persist_and_deduplicates_evidence(tmp_path):
    service, collector = _services(tmp_path)
    collector.handle_event(_event())
    collector.handle_event(_event())
    signals = service.repository.list_signals("op-1")
    events = collector.list_events("op-1")
    assert len(signals) == 1
    assert signals[0].origin == "rule"
    assert {item.value for item in signals[0].evidence} == {event.id for event in events}
    assert signals[0].status == "open"


def test_manual_transition_and_case_constraints(tmp_path):
    service, collector = _services(tmp_path)
    collector.handle_event(_event())
    collector.handle_event(_event(operation_id="op-2"))
    event_id = collector.list_events("op-1")[0].id
    with pytest.raises(ValueError, match="operación"):
        service.create_manual("op-2", title="manual", description="", severity="medium",
                              event_ids=[event_id], note="", operator="fede")
    manual = service.create_manual("op-1", title="manual", description="", severity="medium",
                                   event_ids=[event_id], note="", operator="fede")
    with pytest.raises(ValueError, match="nota"):
        service.transition_signal("op-1", manual.id, "resolve")
    assert service.transition_signal("op-1", manual.id, "acknowledge").status == "acknowledged"
    assert service.transition_signal("op-1", manual.id, "resolve", note="investigado").status == "resolved"
    with pytest.raises(KeyError):
        service.repository.get_signal("op-2", manual.id)

    case = service.create_case("op-1", title="revisión", description="", signal_ids=[manual.id])
    with pytest.raises(ValueError, match="otro caso"):
        service.create_case("op-1", title="doble", description="", signal_ids=[manual.id])
    with pytest.raises(ValueError, match="operación"):
        service.update_case_signals("op-1", case.id, add=[service.repository.list_signals("op-2")[0].id])
