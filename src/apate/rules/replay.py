"""Reproduce eventos guardados sin proveedores externos ni persistencia."""

from __future__ import annotations

import hashlib

from ..core.models import Operation
from ..plugins.base import EventBus, PluginEvent
from ..telemetry.models import TelemetryRecord
from .engine import RuleEngine
from .models import parse_rules


class _ReplayPlugin:
    """El motor invoca el contrato real, pero aquí solo se registra la intención."""

    def __init__(self, plugin_id: str, attempts: list[dict]) -> None:
        self.plugin_id = plugin_id
        self.attempts = attempts

    def deploy(self) -> None:
        self.attempts.append({"plugin_id": self.plugin_id, "action": "deploy"})

    def rotate(self) -> None:
        self.attempts.append({"plugin_id": self.plugin_id, "action": "rotate"})

    def retire(self) -> None:
        self.attempts.append({"plugin_id": self.plugin_id, "action": "retire"})


def replay_rules(operation: Operation, records: list[TelemetryRecord], rules_text: str,
                 *, max_events: int = 1000) -> dict:
    """Usa las guardas del RuleEngine real sobre una copia de la operación."""

    if max_events < 1:
        raise ValueError("Debe reproducirse al menos un evento.")
    rules = parse_rules(rules_text)
    copy = Operation.from_dict(operation.to_dict())
    attempts: list[dict] = []
    plugins = {binding.plugin_id: _ReplayPlugin(binding.plugin_id, attempts) for binding in copy.plugins}
    bus = EventBus()
    engine = RuleEngine(operation=copy, plugins=plugins, bus=bus, rules=rules,
                        decision_repository=None, reject_action_errors=True)
    selected = records[:max_events]
    for record in selected:
        if record.operation_id != operation.id:
            raise ValueError("La telemetría no pertenece a esta operación.")
        bus.publish(PluginEvent(event_type=record.event_type, plugin_id=record.plugin_id,
                                surface=record.surface, operation_id=record.operation_id,
                                resource_id=record.resource_id, payload=dict(record.payload),
                                id=record.source_event_id, timestamp=record.timestamp))
    return {"operation_id": operation.id, "rule_revision": hashlib.sha256(rules_text.encode("utf-8")).hexdigest(),
            "input_count": len(selected), "truncated": len(records) > max_events,
            "firings": [{"rule_name": firing.rule_name, "triggering_event_id": firing.triggering_event_id,
                         "actions": [action.signatures() for action in firing.actions]} for firing in engine.history],
            "rejections": [{"rule_name": rejection.rule_name, "triggering_event_id": rejection.triggering_event_id,
                            "kind": rejection.kind.value, "action": rejection.action.signatures()}
                           for rejection in engine.rejected_actions],
            "plugin_attempts": attempts, "simulated_final_status": copy.status.value}
