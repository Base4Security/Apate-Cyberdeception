"""Motor de evaluacion de reglas (M3; hardening en M9).

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

Guardas de M9 (hardening, misma seccion 8 del diseno) aplicadas antes
de ejecutar cualquier Action -- ver _run_action():

1. **Rules of Engagement.** `operation.roe.permits(*action.signatures())`
   se consulta antes de cada accion. Una accion prohibida no se
   ejecuta, no lanza una excepcion (no se quiere que un bloqueo de
   politica tire abajo el flujo de quien disparo el evento, por
   ejemplo un plugin.deploy() de un tercero), y queda registrada en
   `rejected_actions` ademas de loguearse -- "rechazarla y dejar
   constancia, no fallar en silencio".
2. **Alcance de plugin.** Una accion con `plugin_id` explicito solo
   puede apuntar a un plugin registrado en el motor (`self.plugins`,
   como ya validaba `UnknownPluginError` desde M3) *y* vinculado a la
   operacion (`operation.plugins`, un `PluginBinding` por plugin) --
   esto ultimo no estaba garantizado estructuralmente antes de M9:
   nada impedia que `self.plugins` tuviera una instancia bajo un
   plugin_id que la Operacion nunca registro. Fuera de alcance en
   cualquiera de los dos sentidos levanta UnknownPluginError (error de
   configuracion, no de politica: se prefiere fallar fuerte). Una
   accion sin `plugin_id` (`None`, "todos los plugins registrados")
   se degrada en cambio a filtrar los que no esten vinculados a la
   operacion, sin lanzar -- no se quiere que un plugin mal vinculado
   bloquee el "retirar todos y cerrar" del cierre automatico (M3);
   igual queda logueado.
3. **Tope de acciones por cadena de eventos.** Defensa en profundidad,
   no reemplaza el filtro por plugin_id de Condition (M3) que evita
   que una regla se autodispare con el mismo evento: ese fix resuelve
   el caso puntual de auto-disparo directo, pero no un ciclo mas largo
   (regla A dispara una accion sobre un plugin que al ejecutarse
   publica un evento nuevo, que dispara la regla B, que dispara otra
   accion que publica otro evento...). `max_actions_per_event`
   (default 50, configurable, `None` desactiva el limite) cuenta
   acciones ejecutadas a lo largo de toda una cadena de llamadas
   anidadas de handle_event()/check_closure() -- no se resetea en
   cada llamada recursiva, solo cuando una llamada externa nueva
   arranca en profundidad 0 -- y rechaza (mismo mecanismo que el punto
   1) las acciones que excedan el tope, cortando la cascada antes de
   arriesgar un RecursionError.

**Excepcion unica a la guarda 1 (M12f): `ClosureCriteria.trigger_conditions`.**
`handle_event()` tambien evalua, ademas de `self.rules`, las
`Condition` de `self.operation.closure_criteria.trigger_conditions`
(el "Gating Criteria" del paso 2 de la metodologia, SAC0005 en el
catalogo de MITRE Engage -- ver `apate/data/mitre_engage_matrix.json`
y el docstring de `ClosureCriteria`). Si una matchea, la operacion se
cierra **sin pasar por `roe.permits()`**: es la unica accion de todo
el motor que ignora esa guarda a proposito. La definicion oficial de
SAC0005 es "the unnegotiable pause or conclusion to the operation" --
un freno de seguridad decidido de antemano en la planificacion no
tiene sentido que una `RulesOfEngagement` pensada para acotar acciones
discrecionales del motor pueda vetarlo; seria perverso que
`forbidden_actions` bloqueara justo el limite duro que la
planificacion marco como innegociable. Las otras dos guardas (2 y 3)
siguen aplicando igual: el cierre por Gating Criteria consume cupo de
`max_actions_per_event`/`_actions_in_chain` (circuit-breaker de
ingenieria, no decision de politica) y queda registrado en
`self.history` como cualquier otro disparo, para que nunca sea un
cierre silencioso sin rastro auditable. `check_closure()` no cambia:
`trigger_conditions` es inherentemente event-driven (necesita el
evento entrante para `matches_event()`), a diferencia de
`closure_due`/`is_past_due()`, que es estado agregado sin eventos.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from ..core.models import Operation, OperationStatus
from ..i18n import gettext as _
from ..plugins.base import DeceptionPlugin, EventBus, EventType, PluginEvent
from .exceptions import UnknownPluginError
from .models import Action, ActionKind, RejectedAction, RejectionKind, Rule, RuleFiring
from .repository import SQLiteRuleDecisionRepository

logger = logging.getLogger(__name__)

# Mapea el destino de una accion 'transition' al metodo de Operation
# que aplica esa transicion. Action ya valida en su __post_init__ que
# 'to' sea una de estas tres claves, asi que el lookup no necesita
# manejar un caso por defecto.
_TRANSITION_METHODS = {
    OperationStatus.ACTIVE: "mark_active",
    OperationStatus.COMPROMISED: "mark_compromised",
    OperationStatus.CLOSED: "close",
}

# Defensa en profundidad (M9): tope por defecto de acciones ejecutadas
# a lo largo de una misma cadena de eventos. Generoso frente a
# cualquier escenario legitimo actual (una regla dispara, como mucho,
# un puñado de acciones), pero finito para frenar una cascada antes de
# acercarse al limite de recursion de Python (~1000 frames; cada nivel
# de cascada consume varios frames via bus.publish -> handle_event).
_DEFAULT_MAX_ACTIONS_PER_EVENT = 50


class RuleEngine:
    """Evalua reglas condicion-accion contra los eventos del bus de M2 y
    el estado de la Operacion, y dispara las acciones correspondientes
    sobre los plugins registrados y/o sobre las transiciones de estado
    de la Operacion -- sujeto a las guardas de M9 descriptas en el
    docstring del modulo."""

    def __init__(
        self,
        *,
        operation: Operation,
        plugins: dict[str, DeceptionPlugin],
        bus: EventBus,
        rules: list[Rule],
        max_actions_per_event: Optional[int] = _DEFAULT_MAX_ACTIONS_PER_EVENT,
        decision_repository: Optional[SQLiteRuleDecisionRepository] = None,
        reject_action_errors: bool = False,
        operation_executor=None,
        approved_plan_id=None,
    ) -> None:
        self.operation = operation
        self.plugins = plugins
        self.bus = bus
        self.rules = list(rules)
        self.max_actions_per_event = max_actions_per_event
        self.decision_repository = decision_repository
        self.reject_action_errors = reject_action_errors
        self.operation_executor = operation_executor
        self.approved_plan_id = approved_plan_id
        # Copias en memoria de las decisiones de esta instancia. Si hay
        # repositorio, la fuente duradera queda en SQLite.
        self.history: list[RuleFiring] = []
        # Acciones rechazadas por RoE o por el tope de cascada (M9) --
        # ver RejectedAction en rules/models.py.
        self.rejected_actions: list[RejectedAction] = []
        self._chain_depth = 0
        self._actions_in_chain = 0
        bus.subscribe(EventType.INTERACTION, self.handle_event)
        bus.subscribe(EventType.TTP_OBSERVED, self.handle_event)

    def handle_event(self, event: PluginEvent) -> None:
        """Punto de entrada para eventos del bus. Tambien puede llamarse
        directamente (sin pasar por un EventBus real) para probar el
        motor en aislamiento."""

        self._enter_chain()
        try:
            managed = self.operation_executor is not None and self.operation_executor.managed(self.operation.id)
            if managed:
                evidence_id = (event.provenance or {}).get("ledger_evidence_id")
                if evidence_id:
                    from ..ledger.repository import LedgerError
                    evidence = self.operation_executor.ledger.record(self.operation.id, evidence_id)
                    normalized = event.to_dict()
                    normalized.pop("provenance", None)
                    if evidence["payload"].get("category") not in {"observation", "lifecycle"} or evidence["payload"].get("event") != normalized:
                        raise LedgerError("invalid_event_provenance_reference")
                else:
                    from ..ledger.evidence import OperationEvidence
                    record, admitted = OperationEvidence(self.operation_executor.ledger).ingest(self.operation.id, event)
                    if not admitted:
                        return
                    event.provenance = dict(event.provenance or {}, ledger_evidence_id=record["id"])
                if self.approved_plan_id is None or self.operation_executor.ledger.operation(self.operation.id)["active_plan_id"] != self.approved_plan_id or not self.operation_executor.observe(self.operation.id, event):
                    return
            for rule in self.rules:
                if rule.when.event_type is not None and rule.when.matches_event(event):
                    self._execute(rule, triggering_event_id=event.id)
            if not managed:
                self._check_closure_trigger_conditions(event)
        finally:
            self._exit_chain()

    def check_closure(self, *, now: Optional[datetime] = None) -> None:
        """Evalua las reglas basadas en el estado de la Operacion (hoy,
        solo el cierre automatico por vencimiento). Pensado para
        llamarse desde un loop de polling simple, ya que
        is_past_due() no llega como evento del bus."""

        self._enter_chain()
        try:
            if self.operation_executor is not None and self.operation_executor.managed(self.operation.id):
                if self.approved_plan_id is None or self.operation_executor.ledger.operation(self.operation.id)["active_plan_id"] != self.approved_plan_id or not self.operation_executor.observe(self.operation.id):
                    return
            is_past_due = self.operation.is_past_due(now=now)
            for rule in self.rules:
                if rule.when.closure_due and rule.when.matches_closure(is_past_due=is_past_due):
                    self._execute(rule, triggering_event_id=None)
        finally:
            self._exit_chain()

    def _check_closure_trigger_conditions(self, event: PluginEvent) -> None:
        """Evalua ClosureCriteria.trigger_conditions (M12f) contra el
        evento entrante -- ver el docstring del modulo sobre por que
        esto vive aparte de self.rules (bypass de roe.permits()) y por
        que solo se llama desde handle_event(), nunca check_closure()."""

        if self.operation.status == OperationStatus.CLOSED:
            return  # idempotencia: ya cerrada, no hay nada que evaluar
        for condition in self.operation.closure_criteria.trigger_conditions:
            if condition.matches_event(event):
                # Una sola condicion alcanza para cerrar -- si mas de una
                # matchea el mismo evento, no tiene sentido intentar
                # cerrar dos veces (Operation.close() ya es idempotente
                # a nivel de status, pero igual evita un segundo
                # RuleFiring redundante en el historial).
                self._close_by_gating_criteria(triggering_event_id=event.id)
                return

    def _close_by_gating_criteria(self, *, triggering_event_id: str) -> None:
        close_action = Action(kind=ActionKind.TRANSITION, to=OperationStatus.CLOSED)
        # Deliberadamente SIN operation.roe.permits(): ver "Excepcion
        # unica a la guarda 1" en el docstring del modulo. El tope de
        # cascada (guarda 3) si sigue aplicando -- es un circuit-breaker
        # de ingenieria, no una decision de politica.
        if self.max_actions_per_event is not None and self._actions_in_chain >= self.max_actions_per_event:
            self._reject(
                "closure_criteria.trigger_conditions",
                close_action,
                f"Tope de acciones por cadena de eventos alcanzado ({self.max_actions_per_event}).",
                kind=RejectionKind.CASCADE_LIMIT,
                triggering_event_id=triggering_event_id,
            )
            return
        self._actions_in_chain += 1
        self.operation.close()
        self._record_firing(
            RuleFiring(
                rule_name="closure_criteria.trigger_conditions",
                actions=[close_action],
                triggering_event_id=triggering_event_id,
            )
        )

    def _enter_chain(self) -> None:
        # handle_event()/check_closure() pueden re-entrar de forma
        # recursiva y sincronica (una accion despliega un plugin, que
        # publica un evento, que vuelve a llamar a handle_event() antes
        # de que la llamada externa original retorne). El contador de
        # acciones solo se resetea cuando una llamada NO anidada
        # arranca (profundidad 0 -> 1): en cualquier reentrada, sigue
        # acumulando sobre la misma cadena.
        self._chain_depth += 1
        if self._chain_depth == 1:
            self._actions_in_chain = 0

    def _exit_chain(self) -> None:
        self._chain_depth -= 1

    def _execute(self, rule: Rule, *, triggering_event_id: Optional[str]) -> None:
        for action in rule.then:
            try:
                self._run_action(
                    action,
                    rule_name=rule.name,
                    triggering_event_id=triggering_event_id,
                )
            except Exception as exc:
                if not self.reject_action_errors:
                    raise
                self._reject(
                    rule.name,
                    action,
                    f"No se pudo ejecutar: {type(exc).__name__}: {exc}",
                    kind=RejectionKind.EXECUTION_ERROR,
                    triggering_event_id=triggering_event_id,
                )
        self._record_firing(
            RuleFiring(rule_name=rule.name, actions=list(rule.then), triggering_event_id=triggering_event_id)
        )

    def _run_action(
        self,
        action: Action,
        *,
        rule_name: str,
        triggering_event_id: Optional[str],
    ) -> None:
        if self.operation_executor is not None and self.operation_executor.managed(self.operation.id):
            from ..ledger import LedgerError
            if self.max_actions_per_event is not None and self._actions_in_chain >= self.max_actions_per_event:
                raise LedgerError("cascade_limit")
            self._actions_in_chain += 1
            if action.kind == ActionKind.TRANSITION:
                if action.to != OperationStatus.CLOSED:
                    raise LedgerError("approved_activation_required")
                plan, definition = self.operation_executor.snapshot(self.operation.id)
                if not plan["payload"]["content"]["execution_policy"]["autonomous"]:
                    raise LedgerError("autonomous_not_approved")
                if not definition.roe.permits(*action.signatures()):
                    raise LedgerError("roe")
                state = self.operation_executor.ledger.operation(self.operation.id)
                if state["state"] in {"closing", "closed"}:
                    return
                self.operation_executor.ledger.stop(self.operation.id, target="closing",
                    expected_revision=state["revision"], reason="approved_rule_closure", actor="system:rules")
                return
            for plugin in self._resolve_targets(action.plugin_id):
                # Mismo evento/regla/capacidad produce una sola orden durable.
                # El enlace registra procedencia; no demuestra causalidad.
                key = f"rule:{triggering_event_id or 'closure_due'}:{rule_name}:{action.kind.value}:{plugin.plugin_id}"
                plugin.execute_managed(action.kind.value, idempotency_key=key, autonomous=True,
                    input_event_id=triggering_event_id, rule_name=rule_name)
            return
        if not self.operation.roe.permits(*action.signatures()):
            self._reject(
                rule_name,
                action,
                f"Prohibida por Rules of Engagement: {action.signatures()}",
                kind=RejectionKind.ROE,
                triggering_event_id=triggering_event_id,
            )
            return

        if self.max_actions_per_event is not None and self._actions_in_chain >= self.max_actions_per_event:
            self._reject(
                rule_name,
                action,
                f"Tope de acciones por cadena de eventos alcanzado ({self.max_actions_per_event}).",
                kind=RejectionKind.CASCADE_LIMIT,
                triggering_event_id=triggering_event_id,
            )
            return
        self._actions_in_chain += 1

        if action.kind == ActionKind.TRANSITION:
            getattr(self.operation, _TRANSITION_METHODS[action.to])()
            return
        for plugin in self._resolve_targets(action.plugin_id):
            getattr(plugin, action.kind.value)()

    def _reject(
        self,
        rule_name: str,
        action: Action,
        reason: str,
        *,
        kind: RejectionKind,
        triggering_event_id: Optional[str],
    ) -> None:
        rejection = RejectedAction(
            rule_name=rule_name,
            action=action,
            reason=reason,
            kind=kind,
            triggering_event_id=triggering_event_id,
        )
        self.rejected_actions.append(rejection)
        if self.decision_repository is not None:
            self.decision_repository.append_rejection(self.operation.id, rejection)
        logger.warning("Regla '%s': accion %s no ejecutada -- %s", rule_name, action.signatures(), reason)

    def _record_firing(self, firing: RuleFiring) -> None:
        self.history.append(firing)
        if self.decision_repository is not None:
            self.decision_repository.append_firing(self.operation.id, firing)

    def _resolve_targets(self, plugin_id: Optional[str]) -> list[DeceptionPlugin]:
        operation_plugin_ids = {binding.plugin_id for binding in self.operation.plugins}

        if plugin_id is None:
            in_scope: list[DeceptionPlugin] = []
            for pid, plugin in self.plugins.items():
                if pid in operation_plugin_ids:
                    in_scope.append(plugin)
                else:
                    logger.warning(
                        "Plugin '%s' registrado en el motor pero no vinculado a la operacion "
                        "(operation.plugins): excluido de una accion sobre 'todos los plugins'.",
                        pid,
                    )
            return in_scope

        if plugin_id not in self.plugins:
            raise UnknownPluginError(
                _(
                    "La regla referencia un plugin no registrado en el motor: '%(plugin_id)s'.",
                    plugin_id=plugin_id,
                )
            )
        if plugin_id not in operation_plugin_ids:
            raise UnknownPluginError(
                _(
                    "La regla referencia el plugin '%(plugin_id)s': esta registrado en el motor "
                    "pero no vinculado a la operacion (operation.plugins) -- fuera de alcance.",
                    plugin_id=plugin_id,
                )
            )
        return [self.plugins[plugin_id]]
