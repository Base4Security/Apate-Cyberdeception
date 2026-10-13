"""Tests para `apate.telemetry.external_bridge.ExternalTelemetryBridge`
(puente de telemetría externo configurable, primera de una tanda de
tres tareas para ampliar el ecosistema de herramientas que APATE
orquesta). Ver docstring del módulo para el diseño completo."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from apate.core import ExternalTelemetrySource
from apate.playground.exceptions import PlaygroundCommandError
from apate.plugins.base import EventBus, EventType, PluginEvent
from apate.telemetry.exceptions import ExternalTelemetryError
from apate.telemetry.external_bridge import ExternalTelemetryBridge


def _source(**overrides) -> ExternalTelemetrySource:
    defaults = dict(
        name="T-Pot demo",
        elastic_url="http://localhost:9200",
        index="tpot-*",
        field_mapping={"ttp_id": "mitre.technique_id", "detail": "message", "source_ip": "src_ip"},
    )
    defaults.update(overrides)
    return ExternalTelemetrySource(**defaults)


def _bridge(source=None, bus=None, operation_id="op-1") -> ExternalTelemetryBridge:
    return ExternalTelemetryBridge(source=source or _source(), bus=bus or EventBus(), operation_id=operation_id)


def _collect(bus: EventBus, event_type: EventType) -> list[PluginEvent]:
    collected: list[PluginEvent] = []
    bus.subscribe(event_type, collected.append)
    return collected


# -- ingest_hit(): mapeo declarativo -----------------------------------------


def test_maps_flat_fields_by_declared_mapping():
    bridge = _bridge(_source(field_mapping={"detail": "message", "source_ip": "src_ip"}))
    hit = {"_source": {"message": "conexión SSH", "src_ip": "203.0.113.20"}}

    event = bridge.ingest_hit(hit)

    assert event is not None
    assert event.payload["detail"] == "conexión SSH"
    assert event.payload["source_ip"] == "203.0.113.20"


def test_maps_dotted_nested_fields():
    bridge = _bridge(_source(field_mapping={"ttp_id": "mitre.technique_id"}))
    hit = {"_source": {"mitre": {"technique_id": "T1110.001"}}}

    event = bridge.ingest_hit(hit)

    assert event.payload["ttp_id"] == "T1110.001"


def test_ttp_id_present_produces_ttp_observed_event():
    bridge = _bridge(_source(field_mapping={"ttp_id": "mitre.technique_id"}))
    hit = {"_source": {"mitre": {"technique_id": "T1110.001"}}}

    event = bridge.ingest_hit(hit)

    assert event.event_type == EventType.TTP_OBSERVED


def test_no_ttp_id_produces_interaction_event():
    bridge = _bridge(_source(field_mapping={"detail": "message"}))
    hit = {"_source": {"message": "algo pasó"}}

    event = bridge.ingest_hit(hit)

    assert event.event_type == EventType.INTERACTION


def test_unmapped_source_fields_are_ignored():
    """Solo se copia lo que el mapeo declara -- ni transformación ni
    "copiar todo lo que haya"."""

    bridge = _bridge(_source(field_mapping={"detail": "message"}))
    hit = {"_source": {"message": "algo", "campo_no_mapeado": "no debería aparecer"}}

    event = bridge.ingest_hit(hit)

    assert "campo_no_mapeado" not in event.payload
    assert set(event.payload) == {"detail", "source"}


def test_mapped_field_absent_in_source_is_simply_missing_from_payload():
    bridge = _bridge(_source(field_mapping={"detail": "message", "ttp_id": "mitre.technique_id"}))
    hit = {"_source": {"message": "algo"}}  # sin mitre.technique_id

    event = bridge.ingest_hit(hit)

    assert "ttp_id" not in event.payload
    assert event.payload["detail"] == "algo"


def test_no_mapped_fields_resolve_returns_none_without_publishing():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    bridge = _bridge(_source(field_mapping={"detail": "message"}), bus=bus)
    hit = {"_source": {"otro_campo": "x"}}  # 'message' ausente

    event = bridge.ingest_hit(hit)

    assert event is None
    assert interactions == []


def test_hit_without_valid_source_returns_none_without_raising():
    bridge = _bridge()
    assert bridge.ingest_hit({"no_source_key": True}) is None
    assert bridge.ingest_hit("no es un dict") is None


# -- event.plugin_id / surface / operation_id --------------------------------


def test_event_uses_source_id_as_plugin_id():
    source = _source()
    bridge = _bridge(source, operation_id="op-42")
    event = bridge.ingest_hit({"_source": {"message": "x"}})

    assert event.plugin_id == source.id
    assert event.operation_id == "op-42"


def test_event_uses_source_declared_surface():
    bridge = _bridge(_source(surface="identity"))
    event = bridge.ingest_hit({"_source": {"message": "x"}})

    assert event.surface == "identity"


def test_two_different_sources_produce_events_with_different_plugin_ids():
    """Una Operacion puede tener mas de una fuente externa -- cada una
    necesita un identificador distinto para poder filtrarse/correlacionarse
    por separado."""

    bus = EventBus()
    source_a = _source(name="Fuente A")
    source_b = _source(name="Fuente B")
    event_a = _bridge(source_a, bus=bus).ingest_hit({"_source": {"message": "x"}})
    event_b = _bridge(source_b, bus=bus).ingest_hit({"_source": {"message": "y"}})

    assert event_a.plugin_id != event_b.plugin_id


# -- Publicación real en el bus ----------------------------------------------


def test_ingest_hit_publishes_to_the_bus():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    bridge = _bridge(bus=bus)

    bridge.ingest_hit({"_source": {"message": "x"}})

    assert len(interactions) == 1


def test_ingest_hits_processes_several_in_order_skipping_unmapped():
    bridge = _bridge(_source(field_mapping={"detail": "message"}))
    hits = [
        {"_source": {"message": "primero"}},
        {"_source": {"otro": "sin mapeo"}},  # se descarta
        {"_source": {"message": "tercero"}},
    ]

    events = bridge.ingest_hits(hits)

    assert [e.payload["detail"] for e in events] == ["primero", "tercero"]


# -- Sanitización (sección 3.4 del contrato) ---------------------------------


def test_long_mapped_text_is_truncated():
    bridge = _bridge(_source(field_mapping={"detail": "message"}))
    long_text = "a" * 3000

    event = bridge.ingest_hit({"_source": {"message": long_text}})

    assert len(event.payload["detail"]) < 3000
    assert "truncado" in event.payload["detail"]


# -- fetch_and_ingest(): cliente compartido + traducción de excepciones -----


def test_fetch_and_ingest_queries_and_translates():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)
    fake_hits = [{"_source": {"message": "conexión"}}]

    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=fake_hits) as mock_fetch:
        bridge = _bridge(_source(field_mapping={"detail": "message"}))
        events = bridge.fetch_and_ingest(since=since)

    assert len(events) == 1
    assert events[0].payload["detail"] == "conexión"
    mock_fetch.assert_called_once()
    _, kwargs = mock_fetch.call_args
    assert kwargs["since"] == since
    assert kwargs["index"] == "tpot-*"
    assert kwargs["elastic_url"] == "http://localhost:9200"


def test_fetch_and_ingest_passes_the_configured_timestamp_field():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)

    with patch("apate.telemetry.external_bridge.fetch_recent_hits", return_value=[]) as mock_fetch:
        bridge = _bridge(_source(timestamp_field="event.created"))
        bridge.fetch_and_ingest(since=since)

    assert mock_fetch.call_args.kwargs["timestamp_field"] == "event.created"


def test_fetch_and_ingest_wraps_connection_error_in_external_telemetry_error():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)

    with patch(
        "apate.telemetry.external_bridge.fetch_recent_hits",
        side_effect=PlaygroundCommandError("no se pudo conectar"),
    ):
        bridge = _bridge()
        with pytest.raises(ExternalTelemetryError):
            bridge.fetch_and_ingest(since=since)
