"""Motor de evaluacion de reglas (M3).

Consume los eventos del bus de M2 en tiempo real: se suscribe a si
mismo (`handle_event`) para `interaction` y `ttp_observed` en el
constructor, asi que cada evento publicado por un plugin se contrasta
contra las reglas cargadas de forma sincronica, en el mismo hilo que lo
publico. La unica condicion que no llega por el bus es el cierre
automatico por vencimiento (`closure_due`, ligado a
Operation.is_past_due()): como todavia no hay un bus asincrono ni un
scheduler, se evalua mediante `check_closure()`, que el operador (o un
loop simple) llama periodicamente.

Deterministico y auditable a proposito (seccion 8 del documento de
diseno): no hay inferencia ni heuristica, solo el match explicito de
cada regla cargada contra el evento o el estado de la operacion.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..core.models import Operation, OperationStatus
from ..plugins.base import DeceptionPlugin, EventBus, EventType, PluginEvent
from .exceptions import UnknownPluginError
from .models import Action, ActionKind, Rule

# Mapea el destino de una accion 'transition' al metodo de Operation
# que aplica esa transicion. Action ya valida en su __post_init__ que
# 'to' sea una de estas tres claves, asi que el lookup no necesita
# manejar un caso por defecto.
_TRANSITION_METHODS = {
    OperationStatus.ACTIVE: "mark_active",
    OperationStatus.COMPROMISED: "mark_compromised",
    OperationStatus.CLOSED: "close",
}


class RuleEngine:
    """Evalua reglas condicion-accion contra los eventos del bus de M2 y
    el estado de la Operacion, y dispara las acciones correspondientes
    sobre los plugins registrados y/o sobre las transiciones de estado
    de la Operacion."""

    def __init__(
        self,
        *,
        operation: Operation,
        plugins: dict[str, DeceptionPlugin],
        bus: EventBus,
        rules: list[Rule],
        max_actions_per_event: int = 50,
    ) -> None:
        if max_actions_per_event < 1:
            raise ValueError("max_actions_per_event debe ser positivo")
        self.operation = operation
        for plugin_id, plugin in plugins.items():
            if plugin.plugin_id != plugin_id or plugin.operation_id != operation.id:
                raise ValueError(f"Plugin registrado fuera de la operación: '{plugin_id}'")
        self.plugins = plugins
        self.bus = bus
        self.rules = list(rules)
        self.max_actions_per_event = max_actions_per_event
        self.rejected_actions: list[tuple[str, Action, str]] = []
        self._chain_depth = 0
        self._actions_in_chain = 0
        bus.subscribe(EventType.INTERACTION, self.handle_event)
        bus.subscribe(EventType.TTP_OBSERVED, self.handle_event)

    def handle_event(self, event: PluginEvent) -> None:
        """Punto de entrada para eventos del bus. Tambien puede llamarse
        directamente (sin pasar por un EventBus real) para probar el
        motor en aislamiento."""

        if event.operation_id != self.operation.id or event.plugin_id not in {
            binding.plugin_id for binding in self.operation.plugins
        }:
            return
        self._enter_chain()
        try:
            for rule in self.rules:
                if rule.when.event_type is not None and rule.when.matches_event(event):
                    self._execute(rule)
        finally:
            self._exit_chain()

    def check_closure(self, *, now: Optional[datetime] = None) -> None:
        """Evalua las reglas basadas en el estado de la Operacion (hoy,
        solo el cierre automatico por vencimiento). Pensado para
        llamarse desde un loop de polling simple, ya que
        is_past_due() no llega como evento del bus."""

        self._enter_chain()
        try:
            is_past_due = self.operation.is_past_due(now=now)
            for rule in self.rules:
                if rule.when.closure_due and rule.when.matches_closure(is_past_due=is_past_due):
                    self._execute(rule)
        finally:
            self._exit_chain()

    def _enter_chain(self) -> None:
        if self._chain_depth == 0:
            self._actions_in_chain = 0
        self._chain_depth += 1

    def _exit_chain(self) -> None:
        self._chain_depth -= 1

    def _execute(self, rule: Rule) -> None:
        for action in rule.then:
            self._run_action(action)

    def _run_action(self, action: Action) -> None:
        if not self.operation.roe.permits(*action.signatures()):
            self.rejected_actions.append(("roe", action, "Prohibida por Rules of Engagement"))
            return
        if self._actions_in_chain >= self.max_actions_per_event:
            self.rejected_actions.append(("cascade_limit", action, "Límite de acciones por cadena"))
            return
        self._actions_in_chain += 1
        if action.kind == ActionKind.TRANSITION:
            getattr(self.operation, _TRANSITION_METHODS[action.to])()
            return
        for plugin in self._resolve_targets(action.plugin_id):
            getattr(plugin, action.kind.value)()

    def _resolve_targets(self, plugin_id: Optional[str]) -> list[DeceptionPlugin]:
        in_scope = {binding.plugin_id for binding in self.operation.plugins}
        if plugin_id is None:
            return [plugin for pid, plugin in self.plugins.items() if pid in in_scope]
        if plugin_id not in self.plugins or plugin_id not in in_scope:
            raise UnknownPluginError(
                f"La regla referencia un plugin no registrado o no vinculado: '{plugin_id}'."
            )
        return [self.plugins[plugin_id]]
