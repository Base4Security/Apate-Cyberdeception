"""Presentación de actividad persistida para listado y detalle de operaciones."""

from __future__ import annotations

from ..audit import OperatorAction
from ..core import Operation, OperationStatus
from ..i18n import gettext as _


def recent_rule_firings(operations: list[Operation], decision_repository, limit: int = 5) -> list[dict]:
    """Devuelve las últimas decisiones persistidas, incluso tras reiniciar."""

    names_by_id = {operation.id: operation.name for operation in operations}
    return [
        {
            "operation_name": names_by_id.get(operation_id, operation_id),
            "operation_id": operation_id,
            "firing": firing,
        }
        for operation_id, firing in decision_repository.list_recent_firings(limit)
    ]


def operation_timeline(
    operation: Operation, telemetry_records: list, operator_actions: list[OperatorAction], rule_firings: list
) -> list[dict]:
    """Combina fuentes reales sin afirmar causalidad entre ellas.

    Cada fila conserva su fuente. Las decisiones del motor se leen de su
    repositorio, por lo que sobreviven a la sesión de Playground.
    """

    entries = [
        {
            "timestamp": operation.created_at,
            "source": "operation",
            "title": _("Operación creada"),
            "detail": _("Estado inicial: %(status)s", status=OperationStatus.PLANNING.value),
        }
    ]
    if operation.updated_at != operation.created_at:
        entries.append(
            {
                "timestamp": operation.updated_at,
                "source": "operation",
                "title": _("Última actualización persistida"),
                "detail": _("Estado actual: %(status)s", status=operation.status.value),
            }
        )
    entries.extend(
        {
            "timestamp": action.timestamp,
            "source": "manual",
            "title": _("%(action)s · %(outcome)s", action=action.action, outcome=action.outcome),
            "detail": _("%(operator)s: %(detail)s", operator=action.operator, detail=action.detail),
        }
        for action in operator_actions
    )
    entries.extend(
        {
            "timestamp": event.timestamp,
            "source": "telemetry",
            "title": _("%(event_type)s · %(plugin_id)s", event_type=event.event_type.value, plugin_id=event.plugin_id),
            "detail": _("TTP: %(ttp_id)s", ttp_id=event.ttp_id) if event.ttp_id else event.surface,
        }
        for event in telemetry_records
    )
    entries.extend(
        {
            "timestamp": firing.timestamp,
            "source": "rules",
            "title": _("Regla disparada: %(rule_name)s", rule_name=firing.rule_name),
            "detail": ", ".join(action.kind.value for action in firing.actions),
        }
        for firing in rule_firings
    )
    return sorted(entries, key=lambda entry: entry["timestamp"], reverse=True)
