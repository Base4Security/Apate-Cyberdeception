"""Métricas descriptivas desde el dominio y Telemetría de APATE.

No calcula scores ni interpreta resultados humanos. Los conteos de
telemetría usan todo el historial persistido disponible; los conteos del
modelo son una fotografía del estado actual de cada ``Operation``.
"""

from __future__ import annotations

from collections import Counter

from ..core.models import Operation

_PROVIDER_LABELS = {
    "buda": "APATE",
    "dolost": "APATE",
    "honeytoken": "APATE",
    "mock": "APATE",
}


def _binding_kind(binding) -> str:
    if binding.plugin_kind:
        return binding.plugin_kind
    return binding.plugin_id.casefold().split("-", 1)[0]


def _provider_for_event(operation: Operation, event) -> str:
    binding = next((item for item in operation.plugins if item.plugin_id == event.plugin_id), None)
    if binding is not None:
        return _PROVIDER_LABELS.get(_binding_kind(binding), "APATE")
    prefix = event.plugin_id.casefold().split("-", 1)[0]
    return _PROVIDER_LABELS.get(prefix, "APATE")


def build_operation_metrics(operation: Operation, records: list, *, telemetry_source: str) -> dict:
    """Resume una operación sin consultar proveedores vendorizados."""

    observed_ttps = {record.ttp_id for record in records if record.ttp_id}
    expected_ttps = set(operation.adversary_profile.expected_ttps)
    iocs = {(ioc.type, ioc.value) for record in records for ioc in record.iocs}
    measured_effect_count = sum(bool(binding.effect.measured_outcome) for binding in operation.plugins)
    evidence_by_plugin = {binding.plugin_id: {record.id for record in records if record.plugin_id == binding.plugin_id}
                          for binding in operation.plugins}
    evidenced_effect_count = sum(
        bool(binding.effect.measured_outcome)
        and bool(set(binding.effect.evidence_event_ids) & evidence_by_plugin[binding.plugin_id])
        for binding in operation.plugins
    )
    timestamps = [record.timestamp for record in records]
    provider_counts = Counter(_provider_for_event(operation, record) for record in records)
    return {
        "operation_id": operation.id,
        "operation_name": operation.name,
        "status": operation.status.value,
        "event_count": len(records),
        "ioc_count": len(iocs),
        "observed_ttp_count": len(observed_ttps),
        "expected_ttp_count": len(expected_ttps),
        "matched_ttp_count": len(expected_ttps & observed_ttps),
        "unexpected_ttp_count": len(observed_ttps - expected_ttps),
        "binding_count": len(operation.plugins),
        "measured_effect_count": measured_effect_count,
        "evidenced_effect_count": evidenced_effect_count,
        "effects_awaiting_evidence_count": measured_effect_count - evidenced_effect_count,
        "provider_counts": [
            {"provider": provider, "count": count}
            for provider, count in sorted(provider_counts.items())
        ],
        "first_observed_at": min(timestamps) if timestamps else None,
        "last_observed_at": max(timestamps) if timestamps else None,
        "telemetry_source": telemetry_source,
        "_observed_ttps": observed_ttps,
        "_iocs": iocs,
    }


def build_portfolio_operational_metrics(
    operations: list[Operation], records_by_operation: dict[str, list], *, telemetry_source: str
) -> dict:
    """Agrega métricas operacionales conservando filas por operación."""

    rows = [
        build_operation_metrics(
            operation,
            records_by_operation.get(operation.id, []),
            telemetry_source=telemetry_source,
        )
        for operation in operations
    ]
    all_records = [
        record
        for operation in operations
        for record in records_by_operation.get(operation.id, [])
    ]
    provider_counts = Counter(
        _provider_for_event(operation, record)
        for operation in operations
        for record in records_by_operation.get(operation.id, [])
    )
    timestamps = [record.timestamp for record in all_records]
    return {
        "operation_count": len(operations),
        "operations_with_telemetry": sum(row["event_count"] > 0 for row in rows),
        "event_count": len(all_records),
        "ioc_count": len({ioc for row in rows for ioc in row["_iocs"]}),
        "observed_ttp_count": len({ttp for row in rows for ttp in row["_observed_ttps"]}),
        "measured_effect_count": sum(row["measured_effect_count"] for row in rows),
        "evidenced_effect_count": sum(row["evidenced_effect_count"] for row in rows),
        "effects_awaiting_evidence_count": sum(row["effects_awaiting_evidence_count"] for row in rows),
        "first_observed_at": min(timestamps) if timestamps else None,
        "last_observed_at": max(timestamps) if timestamps else None,
        "telemetry_source": telemetry_source,
        "provider_counts": [
            {"provider": provider, "count": count}
            for provider, count in sorted(provider_counts.items())
        ],
        "rows": [
            {key: value for key, value in row.items() if not key.startswith("_")}
            for row in rows
        ],
    }
