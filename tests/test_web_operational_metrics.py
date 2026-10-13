"""Métricas operacionales descriptivas sobre datos reales de APATE."""

from datetime import datetime, timedelta, timezone

from apate.core import (
    AdversaryProfile,
    DeceptionEffect,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
)
from apate.plugins import EventType, PluginEvent
from apate.telemetry import TelemetryRecord
from apate.web._operational_metrics import (
    build_operation_metrics,
    build_portfolio_operational_metrics,
)


def _operation(name="Operación", **overrides):
    defaults = dict(
        name=name,
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078", "T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _record(operation_id, plugin_id, payload, *, timestamp=None):
    return TelemetryRecord.from_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED if payload.get("ttp_id") else EventType.INTERACTION,
            operation_id=operation_id,
            plugin_id=plugin_id,
            surface="identity" if plugin_id.startswith("identity") else "network",
            payload=payload,
            timestamp=timestamp or datetime.now(timezone.utc),
        )
    )


def test_operation_metrics_cross_model_with_normalized_telemetry():
    operation = _operation()
    operation.bind_plugin(
        PluginBinding(
            plugin_id="identity-1",
            plugin_kind="buda",
            surface="identity",
            effect=DeceptionEffect(measured_outcome="Se observó interacción"),
        )
    )
    operation.bind_plugin(
        PluginBinding(plugin_id="network-1", plugin_kind="dolost", surface="network")
    )
    records = [
        _record(operation.id, "identity-1", {"ttp_id": "T1078", "source_ip": "203.0.113.10"}),
        _record(operation.id, "network-1", {"kind": "scan", "source_ip": "203.0.113.10"}),
        _record(operation.id, "network-1", {"ttp_id": "T1110", "hash": "abc"}),
    ]

    metrics = build_operation_metrics(operation, records, telemetry_source="SQLiteTelemetryRepository")

    assert metrics["event_count"] == 3
    assert metrics["ioc_count"] == 2  # IP repetida + hash
    assert metrics["observed_ttp_count"] == 2
    assert metrics["matched_ttp_count"] == 1
    assert metrics["unexpected_ttp_count"] == 1
    assert metrics["measured_effect_count"] == 1
    assert metrics["provider_counts"] == [{"provider": "APATE", "count": 3}]


def test_operation_metrics_empty_state_is_explicit_and_not_synthetic():
    metrics = build_operation_metrics(_operation(), [], telemetry_source="JSONFileTelemetryRepository")

    assert metrics["event_count"] == 0
    assert metrics["matched_ttp_count"] == 0
    assert metrics["expected_ttp_count"] == 2
    assert metrics["first_observed_at"] is None
    assert metrics["provider_counts"] == []


def test_portfolio_metrics_use_global_distinct_values_and_operation_rows():
    first = _operation("Primera")
    second = _operation("Segunda")
    moment = datetime(2026, 8, 19, tzinfo=timezone.utc)
    records = {
        first.id: [
            _record(first.id, "mock-1", {"ttp_id": "T1078", "source_ip": "203.0.113.10"}, timestamp=moment)
        ],
        second.id: [
            _record(
                second.id,
                "mock-2",
                {"ttp_id": "T1078", "source_ip": "203.0.113.10"},
                timestamp=moment + timedelta(minutes=5),
            )
        ],
    }

    metrics = build_portfolio_operational_metrics(
        [first, second], records, telemetry_source="SQLiteTelemetryRepository"
    )

    assert metrics["operation_count"] == 2
    assert metrics["operations_with_telemetry"] == 2
    assert metrics["event_count"] == 2
    assert metrics["observed_ttp_count"] == 1
    assert metrics["ioc_count"] == 1
    assert [row["operation_name"] for row in metrics["rows"]] == ["Primera", "Segunda"]
    assert metrics["first_observed_at"] == moment
    assert metrics["last_observed_at"] == moment + timedelta(minutes=5)
