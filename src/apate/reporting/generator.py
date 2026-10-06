"""Generador del informe post-operacion (M6) - documento de diseno,
seccion 4.3.

Compara AdversaryProfile.expected_ttps (paso 1 de la metodologia,
Nucleo de Operacion) contra TelemetryCollector.list_ttps() (M4) para
identificar discrepancias, y agrega los IoCs recolectados
(TelemetryCollector.list_iocs()). No agrega logica de negocio nueva a
M1/M4 -- solo compara lo que ya exponen.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

from ..core.models import Operation
from ..telemetry.collector import TelemetryCollector
from .models import OperationReport, PluginEffectSummary


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TTPComparison(NamedTuple):
    """Fase 4 post-BlackHat (ver docs/roadmap.md): el resultado de
    comparar dos conjuntos de TTPs, extraido de generate_report() para
    que apate.web._portfolio.build_portfolio() lo reuse sin tener que
    construir un OperationReport completo -- que exige pasar por
    telemetry.list_ttps() operacion por operacion -- por cada
    operacion del portafolio."""

    matched_ttps: list[str]
    ttps_not_observed: list[str]
    unexpected_ttps: list[str]


def compare_ttps(expected_ttps, observed_ttps) -> TTPComparison:
    """Compara dos colecciones de IDs de TTP (esperadas vs.
    observadas) por conjuntos. Pura logica de comparacion, sin
    dependencia de Operation/TelemetryCollector -- generate_report()
    la usa con los TTPs de una sola operacion, build_portfolio() con
    los de una consulta agregada cross-operacion."""

    expected_set = set(expected_ttps)
    observed_set = set(observed_ttps)
    return TTPComparison(
        matched_ttps=sorted(expected_set & observed_set),
        ttps_not_observed=sorted(expected_set - observed_set),
        unexpected_ttps=sorted(observed_set - expected_set),
    )


def plugin_effect_summaries(operation: Operation) -> list[PluginEffectSummary]:
    """Comparacion planificado vs. medido del efecto de engaño (paso 4
    de la metodologia) para cada `PluginBinding` de `operation` --
    Fase 2 post-BlackHat (ver docs/roadmap.md). No depende de
    telemetria (a diferencia de las TTPs de `generate_report()`): es
    directamente lo que ya esta cargado en cada `DeceptionEffect`, asi
    que `generate_report()` y `generate_workshop_kit()` la comparten
    tal cual en vez de recalcularla cada uno por su lado."""

    return [
        PluginEffectSummary(
            plugin_id=binding.plugin_id,
            expected_adversary_belief=binding.effect.expected_adversary_belief,
            expected_adversary_action=binding.effect.expected_adversary_action,
            success_metric=binding.effect.success_metric,
            measured_outcome=binding.effect.measured_outcome,
            measured_at=binding.effect.measured_at,
            measured_by=binding.effect.measured_by,
            evidence_event_ids=list(binding.effect.evidence_event_ids),
        )
        for binding in operation.plugins
    ]


def generate_report(operation: Operation, telemetry: TelemetryCollector) -> OperationReport:
    """Arma el informe post-operacion para `operation` a partir de los
    registros ya normalizados por `telemetry` (M4). No filtra por
    estado de la Operacion -- tiene sentido generar un informe
    intermedio sobre una operacion todavia activa -- aunque el caso de
    uso principal (roadmap M6) es el cierre."""

    expected_ttps = sorted(set(operation.adversary_profile.expected_ttps))
    observed_ttps = telemetry.list_ttps(operation.id)  # ya viene ordenado y deduplicado

    comparison = compare_ttps(expected_ttps, observed_ttps)

    return OperationReport(
        operation_id=operation.id,
        operation_name=operation.name,
        operation_status=operation.status.value,
        generated_at=_utcnow(),
        expected_ttps=expected_ttps,
        observed_ttps=observed_ttps,
        matched_ttps=comparison.matched_ttps,
        ttps_not_observed=comparison.ttps_not_observed,
        unexpected_ttps=comparison.unexpected_ttps,
        iocs=telemetry.list_iocs(operation.id),
        event_count=len(telemetry.list_events(operation.id)),
        plugin_effects=plugin_effect_summaries(operation),
    )
