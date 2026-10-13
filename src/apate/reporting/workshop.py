"""Generador del kit de taller colaborativo (M12i) - documento de
diseno, seccion 4.3; pasos 3/4 de la metodologia CTI-a-ciberengano.

A diferencia de `generate_report()` (M6, informe de lo ya observado),
este kit es material de trabajo para completar durante el taller --
no exige que la Operacion este cerrada ni que haya telemetria cargada.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..core.models import Operation
from ..telemetry.collector import TelemetryCollector
from .generator import generate_report, plugin_effect_summaries
from .models import WorkshopKit


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_workshop_kit(operation: Operation, telemetry: Optional[TelemetryCollector] = None) -> WorkshopKit:
    """Arma el kit de taller para `operation`. Si se pasa `telemetry`,
    reusa `generate_report()` (M6) tal cual para el heatmap de TTPs --
    no se recalcula esa comparacion de cero; si no se pasa (operacion
    todavia en planificacion, o sin TelemetryCollector a mano), el
    heatmap se degrada a listar solo `AdversaryProfile.expected_ttps`,
    sin comparacion contra lo observado.

    `plugin_effects` (Fase 2 post-BlackHat) no depende de esa rama: se
    calcula igual haya o no telemetria (reusando `report.plugin_effects`
    cuando `generate_report()` ya lo calculo, para no repetir el
    trabajo)."""

    if telemetry is not None:
        report = generate_report(operation, telemetry)
        expected_ttps = report.expected_ttps
        observed_ttps = report.observed_ttps
        matched_ttps = report.matched_ttps
        ttps_not_observed = report.ttps_not_observed
        unexpected_ttps = report.unexpected_ttps
        plugin_effects = report.plugin_effects
    else:
        expected_ttps = sorted(set(operation.adversary_profile.expected_ttps))
        observed_ttps = None
        matched_ttps = None
        ttps_not_observed = None
        unexpected_ttps = None
        plugin_effects = plugin_effect_summaries(operation)

    return WorkshopKit(
        operation_id=operation.id,
        operation_name=operation.name,
        operation_status=operation.status.value,
        generated_at=_utcnow(),
        adversary_profile=operation.adversary_profile,
        scenarios=list(operation.scenarios),
        expected_ttps=expected_ttps,
        observed_ttps=observed_ttps,
        matched_ttps=matched_ttps,
        ttps_not_observed=ttps_not_observed,
        unexpected_ttps=unexpected_ttps,
        plugin_effects=plugin_effects,
    )
