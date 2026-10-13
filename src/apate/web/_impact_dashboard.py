"""Adaptación de datos reales para el centro de impacto.

La composición visual de ``impact.html`` no conoce repositorios ni modelos.
Este módulo reúne una sola lectura agrupada de telemetría, reutiliza el
heatmap de portafolio y entrega exactamente la forma que consume la vista.
No genera informes por operación: la pantalla puede permanecer abierta sin
convertir una consulta de tablero en trabajo de reporting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..i18n import gettext as _
from ._portfolio import build_portfolio


_DELTA_WINDOW = timedelta(hours=1)
# Filas del flujo de actividad: medido a 1920x1080, ocho llenan el panel sin
# desbordar la pantalla (el criterio de aceptacion de esta vista).
_ACTIVITY_ROWS = 8


def _format_count(value: int) -> str:
    """Formatea conteos grandes con el separador habitual de la interfaz."""

    return f"{value:,}".replace(",", ".")


def _delta_last_hour(records: list, *, now: datetime) -> str:
    """Compara la última hora con la anterior solo si ambas son medibles.

    Un porcentaje necesita un denominador real. Si no hay eventos en alguna
    ventana, se omite el detalle en vez de presentar un ``0 %`` aparente.
    """

    current_start = now - _DELTA_WINDOW
    previous_start = current_start - _DELTA_WINDOW
    current = sum(record.timestamp >= current_start for record in records)
    previous = sum(previous_start <= record.timestamp < current_start for record in records)
    if current == 0 or previous == 0:
        return ""
    percentage = round((current - previous) * 100 / previous)
    sign = "+" if percentage > 0 else ""
    return _("%(sign)s%(percentage)s %% última hora", sign=sign, percentage=percentage)


def _infrastructure(operations, statuses: dict[str, dict]) -> list[dict]:
    """Consolida el estado ya calculado para listados de operaciones."""

    decoys = {key: sum(statuses.get(op.id, {}).get("decoys", {}).get(key, 0) for op in operations) for key in ("up", "down", "unknown")}
    narratives = {
        key: sum(statuses.get(op.id, {}).get("narratives", {}).get(key, 0) for op in operations)
        for key in ("running", "configured")
    }
    honeytokens = {
        key: sum(statuses.get(op.id, {}).get("honeytokens", {}).get(key, 0) for op in operations)
        for key in ("deployed", "configured")
    }
    decoy_total = sum(decoys.values())
    decoy_status = "unknown" if decoys["unknown"] else "down" if decoys["down"] else "up"
    mounted = all(statuses.get(op.id, {}).get("buda_available", False) for op in operations) if operations else False
    dependency_status = "up" if mounted and not decoys["unknown"] else "unknown"
    return [
        {
            "label": _("Decoys de red"),
            "value": f"{decoys['up']} / {decoy_total}",
            "status": decoy_status,
            "detail": _("En ejecución / configurados") if decoy_total else _("Sin decoys configurados"),
        },
        {
            "label": _("Narrativas activas"),
            "value": str(narratives["running"]),
            "status": "up" if narratives["running"] else "unknown",
            "detail": _("%(count)s configuradas", count=narratives["configured"]),
        },
        {
            "label": _("Honeytokens desplegados"),
            "value": f"{honeytokens['deployed']} / {honeytokens['configured']}",
            "status": "up" if honeytokens["deployed"] else "unknown",
            "detail": _("Disponibles / configurados") if honeytokens["configured"] else _("Sin honeytokens configurados"),
        },
        {
            "label": _("Dependencias externas"),
            "value": _("Disponibles") if dependency_status == "up" else _("Sin determinar"),
            "status": dependency_status,
            "detail": _("Docker y BUDA consultados") if dependency_status == "up" else _("No se pudo consultar una dependencia"),
        },
    ]


def impact_dashboard_data(operations, telemetry, decision_repository, deployment_status: dict[str, dict], *, now: datetime | None = None) -> dict:
    """Devuelve la forma visual del centro a partir de datos persistidos."""

    current_time = now or datetime.now(timezone.utc)
    operation_ids = [operation.id for operation in operations]
    records_by_operation = telemetry.list_events_by_operation(operation_ids) if operation_ids else {}
    portfolio = build_portfolio(operations, telemetry, records_by_operation=records_by_operation)
    records = sorted(
        (record for operation_records in records_by_operation.values() for record in operation_records),
        key=lambda record: record.timestamp,
        reverse=True,
    )
    heatmap = [
        {
            "tactic": column["tactic"],
            "cells": [
                {"id": cell["technique"].id, "name": cell["technique"].name, "status": cell["status"]}
                for cell in column["cells"]
            ],
        }
        for column in portfolio["ttp_heatmap"]["columns"]
    ]
    metrics = portfolio["operational_metrics"]
    matched_ttps = sum(
        cell["matched_count"]
        for column in portfolio["ttp_heatmap"]["columns"]
        for cell in column["cells"]
    )
    firings = decision_repository.list_firings_for_operations(operation_ids)

    return {
        "is_mock": False,
        "generated_at": _("Datos consolidados a las %(time)s", time=current_time.strftime("%H:%M UTC")),
        "heatmap": heatmap,
        "metrics": [
            {"label": _("Eventos"), "value": _format_count(metrics["event_count"]), "detail": _delta_last_hour(records, now=current_time)},
            {"label": _("TTPs observadas"), "value": _format_count(metrics["observed_ttp_count"]), "detail": _("%(count)s coincidentes", count=matched_ttps) if matched_ttps else ""},
            {"label": "IoCs", "value": _format_count(metrics["ioc_count"]), "detail": _("En %(count)s operaciones", count=metrics["operations_with_telemetry"]) if metrics["ioc_count"] else ""},
            {"label": _("Reglas disparadas"), "value": _format_count(len(firings)), "detail": _("Decisiones persistidas") if firings else ""},
            {"label": _("Capacidades"), "value": _format_count(sum(len(operation.plugins) for operation in operations)), "detail": _("En %(count)s operaciones", count=len(operations)) if operations else ""},
        ],
        "activity": [
            {
                "time": record.timestamp.astimezone(timezone.utc).strftime("%H:%M:%S"),
                "severity": "high" if record.ttp_id else "medium",
                "source": record.plugin_id,
                "message": record.payload.get("detail") or _("%(event_type)s observada", event_type=record.event_type.value),
            }
            for record in records[:_ACTIVITY_ROWS]
        ],
        "infrastructure": _infrastructure(operations, deployment_status),
    }
