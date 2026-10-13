"""Ayuda para construir y enganchar `RuleEngine` con el mismo orden en todo el camino.

Se evita repetir wiring entre rutas HTTP y el servicio de ingesta:
1) bus con `TelemetryCollector` central,
2) carga de reglas globales,
3) guardado de operación luego de cualquier transición por regla.

Todos los consumidores usan este módulo para que un cambio de orden no se
dispare una sola vez en un código y otra sea olvidada en otro.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from flask import current_app, has_request_context, request

from ..core.models import Operation
from ..plugins import DeceptionPlugin, EventBus, EventType
from ..rules import RuleDefinitionError, RuleEngine, parse_rules


def build_rule_bus(operation_id=None) -> EventBus:
    """Crea un `EventBus` efímero y lo conecta al `TelemetryCollector`."""

    bus = EventBus()
    operation_id = operation_id or ((request.view_args or {}).get("operation_id") if has_request_context() else None)
    executor = current_app.config.get("OPERATION_EXECUTOR")
    if operation_id and executor and executor.managed(operation_id):
        from ..ledger.evidence import EvidenceBus
        bus = EvidenceBus(executor.ledger, operation_id, bus)
    current_app.config["TELEMETRY_COLLECTOR"].attach(bus)
    return bus


def build_rule_engine(
    *,
    operation: Operation,
    bus: EventBus,
    plugins: Mapping[str, DeceptionPlugin],
) -> RuleEngine | None:
    """Crea el `RuleEngine` para una operación en el contexto indicado."""

    rules_path = Path(current_app.config["APATE_RULES_PATH"])
    executor = current_app.config["OPERATION_EXECUTOR"]
    managed = executor.managed(operation.id)
    if not managed and current_app.config.get("APATE_GOVERNED_EXECUTION_REQUIRED", False):
        return None
    if managed:
        from ..ledger.plugins import ApprovedPlugin, approved_plugins
        from ..ledger import LedgerError
        try:
            plan, operation = executor.snapshot(operation.id)
            rules = parse_rules(plan["payload"]["content"]["rules"]["content"])
            supplied = dict(plugins)
            plugins = approved_plugins(executor, operation.id, bus)
            for identifier, plugin in supplied.items():
                if isinstance(plugin, ApprovedPlugin) and plugin.plan["id"] == plan["id"]:
                    plugins[identifier] = plugin
        except LedgerError as error:
            current_app.logger.warning("No se ejecutan reglas adoptadas: %s", error.code)
            return None
    else:
        try:
            rules = parse_rules(rules_path.read_text(encoding="utf-8"))
        except (OSError, RuleDefinitionError) as exc:
            current_app.logger.warning("No se evaluaron reglas para la operación '%s': %s", operation.id, exc)
            return None

    return RuleEngine(
        operation=operation,
        plugins=dict(plugins),
        bus=bus,
        rules=rules,
        decision_repository=current_app.config["RULE_DECISION_REPOSITORY"],
        # Las entradas autónomas no deben perder telemetría ni convertir un
        # rechazo de regla en un 500. El motor directo conserva su modo
        # estricto por defecto para las pruebas de contrato.
        reject_action_errors=True,
        operation_executor=executor,
        approved_plan_id=plan["id"] if managed else None,
    )


def attach_operation_save_listener(bus: EventBus, operation: Operation) -> None:
    """Registra guardado de la operación luego de eventos del motor.

    Debe suscribirse después del `RuleEngine` para preservar el orden
    `collector -> motor -> guardado`: en caso de disparo por evento, la
    modificación ya quedó aplicada y registrada en la historia del motor.
    """

    if current_app.config["OPERATION_EXECUTOR"].managed(operation.id):
        return

    def _persist_after_rules(_: object) -> None:
        # Se conserva el orden histórico del objetivo: telemetría -> regla ->
        # operación persiste. Si el motor no transiciona, no cambia nada.
        if not current_app.config["OPERATION_EXECUTOR"].managed(operation.id):
            current_app.config["OPERATION_REPOSITORY"].save(operation)

    bus.subscribe(EventType.INTERACTION, _persist_after_rules)
    bus.subscribe(EventType.TTP_OBSERVED, _persist_after_rules)


__all__ = ["build_rule_bus", "build_rule_engine", "attach_operation_save_listener"]
