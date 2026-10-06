"""K1/K2 locales: autorización, reserva, intento y recibo antes/después del efecto.

La transacción nunca abarca la llamada remota. Una reclamación confirmada
puede continuar después de una parada; una reclamación nueva ya no puede
comenzar. Los adaptadores no se repiten automáticamente después de una caída.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..core import Operation
from .repository import LedgerError, RecordDraft, RecordReference, digest, json_snapshot, text_required


@dataclass(frozen=True)
class ExecutionPrincipal:
    """Resultado de autenticación del transporte, nunca datos del formulario.

    Un administrador local puede proporcionar este contexto desde Python.
    La capa web lo vuelve a obtener del proveedor en K1 y en K2.
    """

    actor: str
    operation_ids: frozenset[str]
    team_id: str | None = None
    administrator: bool = False
    autonomous: bool = False
    machine: bool = False


def validate_policy(policy: dict, operation_id: str) -> None:
    if not isinstance(policy, dict) or type(policy.get("contract")) is not int or policy.get("contract") != 1:
        raise LedgerError("execution_policy_required")
    if policy.get("budget_window") != operation_id:
        raise LedgerError("operation_budget_window_required")
    if type(policy.get("modification_limit")) is not int or policy["modification_limit"] < 0:
        raise LedgerError("invalid_modification_limit")
    if type(policy.get("max_attempts")) is not int or not 1 <= policy["max_attempts"] <= 100:
        raise LedgerError("invalid_attempt_limit")
    if type(policy.get("autonomous")) is not bool:
        raise LedgerError("explicit_autonomous_policy_required")
    if "query_limit" in policy and (type(policy["query_limit"]) is not int or policy["query_limit"] < 0):
        raise LedgerError("invalid_query_limit")
    if "query_autonomous" in policy and type(policy["query_autonomous"]) is not bool:
        raise LedgerError("explicit_query_autonomy_required")


class OperationExecutor:
    """Única autoridad de despacho para operaciones explícitamente adoptadas."""

    def __init__(self, ledger, authorize: Callable[[str], ExecutionPrincipal]):
        self.ledger = ledger
        self.authorize = authorize

    def managed(self, operation_id: str) -> bool:
        try:
            self.ledger.operation(operation_id)
        except LedgerError as error:
            if error.code == "operation_not_found":
                return False
            raise
        return True

    def _context(self, connection, operation_id: str, plan_id: str | None = None):
        operation = self.ledger._operation(connection, operation_id)
        identifier = plan_id or operation["active_plan_id"]
        if identifier is None:
            raise LedgerError("active_approved_plan_required")
        plan = self.ledger._record(connection, operation_id, identifier, "plan")
        approval = self.ledger._approval(connection, operation_id, identifier)
        if approval is None or approval["payload"]["plan_digest"] != plan["digest"]:
            raise LedgerError("exact_approval_required")
        content = plan["payload"]["content"]
        validate_policy(content.get("execution_policy"), operation_id)
        return operation, plan, Operation.from_dict(content["operation"])

    def query(self, operation_id, source_id, callback, **kwargs):
        from .queries import OperationQueries
        return OperationQueries(self).run(operation_id, source_id, callback, **kwargs)

    def snapshot(self, operation_id: str) -> tuple[dict, Operation]:
        with self.ledger._connection() as connection:
            connection.execute("BEGIN")
            _, plan, operation = self._context(connection, operation_id)
            return plan, operation

    def _principal(self, operation_id: str, operation: Operation, policy: dict) -> ExecutionPrincipal:
        principal = self.authorize(operation_id)
        if not isinstance(principal, ExecutionPrincipal):
            raise LedgerError("authenticated_principal_required")
        text_required(principal.actor)
        if operation_id not in principal.operation_ids:
            raise LedgerError("identity_scope")
        if principal.autonomous:
            if not policy["autonomous"]:
                raise LedgerError("autonomous_not_approved")
        elif not principal.machine and not principal.administrator and (operation.team_id is None or principal.team_id != operation.team_id):
            authority = getattr(self.ledger, "authorization_policy", None)
            delegated = getattr(authority, "permits_delegated_operation", None)
            if delegated is None or not delegated(principal.actor, operation_id):
                raise LedgerError("identity_team")
        return principal

    def _root_limit(self, connection, operation_id: str, policy: dict) -> int:
        # El primer plan de ejecución activado fija la ventana de toda la
        # operación. Revisar, cancelar o fallar nunca devuelve reservas.
        row = connection.execute("SELECT plan_id FROM records WHERE operation_id=? AND kind='activation' ORDER BY sequence", (operation_id,)).fetchall()
        for activation in row:
            plan = self.ledger._record(connection, operation_id, activation[0], "plan")
            previous = plan["payload"]["content"].get("execution_policy")
            if previous:
                validate_policy(previous, operation_id)
                if previous["modification_limit"] != policy["modification_limit"]:
                    raise LedgerError("budget_window_immutable")
                return previous["modification_limit"]
        raise LedgerError("active_approved_plan_required")

    def _put(self, connection, operation_id, draft, actor):
        self.ledger._validate_fact(connection, operation_id, draft)
        return self.ledger._insert(connection, operation_id, draft, actor)

    @staticmethod
    def _ref(operation_id, kind, identifier):
        return RecordReference(operation_id, kind, identifier)

    def _commands(self, connection, operation_id):
        return [self.ledger._record(connection, operation_id, row[0], "command") for row in
            connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='command' ORDER BY sequence", (operation_id,)).fetchall()]

    def _attempts(self, connection, operation_id, command_id):
        return [self.ledger._record(connection, operation_id, row[0], "attempt") for row in
            connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='attempt' AND command_id=? ORDER BY attempt_number", (operation_id, command_id)).fetchall()]

    def _receipts(self, connection, operation_id, attempt_id):
        return [self.ledger._record(connection, operation_id, row[0], "receipt") for row in
            connection.execute("SELECT r.id FROM records r JOIN record_refs f ON f.operation_id=r.operation_id AND f.record_id=r.id WHERE r.operation_id=? AND r.kind='receipt' AND f.role='attempt' AND f.target_id=? ORDER BY r.sequence", (operation_id, attempt_id)).fetchall()]

    def _stop_due(self, connection, operation_id, operation, plan, definition, event=None):
        due = definition.is_past_due() or (event is not None and any(c.matches_event(event) for c in definition.closure_criteria.trigger_conditions))
        if due and operation["state"] in {"preparation", "active", "paused"}:
            self.ledger._stop_in_transaction(connection, operation_id, operation, "closing", "approved_stop_criterion", "system:stop")
            operation["state"] = "closing"
        return due

    def _session_valid(self, connection, operation_id, capability_id, parameters):
        session = parameters.get("execution_session")
        if session is None:
            return True
        if parameters.get("subaction") != "step" or type(parameters.get("step")) is not int or type(parameters.get("cycle")) is not int:
            return False
        rows = connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='receipt' ORDER BY sequence DESC", (operation_id,)).fetchall()
        for row in rows:
            record = self.ledger._record(connection, operation_id, row[0], "receipt")
            attempt = self.ledger._record(connection, operation_id, record["references"]["attempt"]["record_id"], "attempt")
            command = self.ledger._record(connection, operation_id, attempt["references"]["command"]["record_id"], "command")
            state = record["payload"].get("adapter_state")
            if command["payload"].get("capability_id") == capability_id and state:
                plan = self.ledger._record(connection, operation_id, command["plan_id"], "plan")
                from .descriptors import descriptor_for
                from datetime import date
                descriptor = descriptor_for(plan, capability_id)
                return (descriptor["kind"] == "buda" and 0 <= parameters["step"] < len(descriptor["steps"])
                    and 0 <= parameters["cycle"] < descriptor["cycles"]
                    and date.fromisoformat(descriptor["end_date"]) >= date.today()
                    and state.get("state") == "deployed" and state.get("config", {}).get("_execution_session") == session
                    and state.get("descriptor_digest") == parameters.get("descriptor_digest"))
        return False

    def _adapter_guards(self, plan, binding, action, parameters):
        from .descriptors import MANAGED_KINDS, descriptor_for
        from ..plugins.registry import PluginRegistry
        kind = PluginRegistry.resolve_binding_kind(binding) if binding else None
        if kind not in MANAGED_KINDS:
            return {}
        try:
            descriptor = descriptor_for(plan, binding.plugin_id)
        except LedgerError:
            return {"adapter_descriptor": False}
        valid = not parameters
        if kind == "dolost" and parameters:
            valid = set(parameters) == {"hostname", "subaction"} and parameters["hostname"] in {d["Hostname"] for d in descriptor["decoys"]} and parameters["subaction"] in {"deploy": {"deploy"}, "rotate": {"start"}, "retire": {"stop", "undeploy"}}.get(action, set())
        elif kind == "playground" and parameters:
            valid = action == "rotate" and parameters == {"subaction": "attacker"}
        elif kind == "buda" and parameters:
            valid = action == "rotate" and set(parameters) == {"subaction", "step", "cycle", "execution_session", "descriptor_digest"} and parameters["subaction"] == "step"
        guards = {"adapter_descriptor": descriptor["kind"] == kind, "adapter_parameters": valid}
        if kind == "buda" and action != "retire":
            from datetime import date
            guards["worker_autonomy"] = plan["payload"]["content"]["execution_policy"]["autonomous"]
            guards["narrative_deadline"] = date.fromisoformat(descriptor["end_date"]) >= date.today()
        return guards

    def observe(self, operation_id: str, event=None) -> bool:
        """La parada de seguridad precede a cualquier regla del evento."""
        if event is not None and event.operation_id != operation_id:
            raise LedgerError("cross_operation_event")
        with self.ledger._connection(write=True) as connection:
            state, plan, definition = self._context(connection, operation_id)
            self._stop_due(connection, operation_id, state, plan, definition, event)
            return state["state"] == "active"

    def admit(self, operation_id: str, *, expected_plan_id: str, capability_id: str,
              action: str, idempotency_key: str, parameters=None, purpose="ordinary", resource_command_id=None,
              input_event_id=None, rule_name=None) -> dict:
        """K1: decisión y orden/reserva inseparables; rechazos también durables."""
        text_required(idempotency_key)
        parameters = json_snapshot(parameters or {})
        failure = None
        command = None
        with self.ledger._connection(write=True) as connection:
            state, plan, definition = self._context(connection, operation_id)
            policy = plan["payload"]["content"]["execution_policy"]
            principal = self._principal(operation_id, definition, policy)
            self._stop_due(connection, operation_id, state, plan, definition)
            from ..extensions import check_ledger_policy
            check_ledger_policy(self.ledger, "admit", operation=definition, plan=plan,
                principal=principal, capability_id=capability_id, action=action, purpose=purpose)
            old = connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='command' AND idempotency_key=?", (operation_id, idempotency_key)).fetchone()
            if old:
                command = self.ledger._record(connection, operation_id, old[0], "command")
                expected = (expected_plan_id, capability_id, action, parameters, purpose, resource_command_id)
                actual = (command["plan_id"], command["payload"]["capability_id"], command["payload"]["action"], command["payload"]["parameters"], command["payload"]["purpose"], command["payload"].get("resource_command_id"))
                if expected != actual:
                    raise LedgerError("idempotency_conflict")
                return command
            binding = definition.find_plugin_binding(capability_id)
            limit = self._root_limit(connection, operation_id, policy)
            used = len(self._commands(connection, operation_id))
            guards = {"version": plan["id"] == expected_plan_id,
                "state": state["state"] == "active" if purpose == "ordinary" else state["state"] in {"active", "paused", "closing", "closed"},
                "purpose": purpose in {"ordinary", "cleanup"},
                "action": action in {"deploy", "rotate", "retire"} and (purpose == "ordinary" or action == "retire"),
                "controlled": binding is not None,
                "roe": definition.roe.permits(action, f"{action}:{capability_id}"),
                "budget": used < limit,
                "resource": purpose == "ordinary"}
            if purpose == "cleanup" and resource_command_id:
                source = self.ledger._record(connection, operation_id, resource_command_id, "command")
                source_plan = self.ledger._record(connection, operation_id, source["plan_id"], "plan")
                original_binding = Operation.from_dict(source_plan["payload"]["content"]["operation"]).find_plugin_binding(capability_id)
                same_binding = original_binding is not None and binding is not None and digest(original_binding.to_dict()) == digest(binding.to_dict())
                guards["resource"] = same_binding and source["payload"].get("capability_id") == capability_id and source["payload"].get("action") == "deploy" and bool(self._attempts(connection, operation_id, source["id"]))
            # Evitar dos invocaciones concurrentes de la misma capacidad.
            busy = False
            for pending_id in self.ledger._pending(connection, operation_id):
                pending = self.ledger._record(connection, operation_id, pending_id, "command")
                if pending["payload"].get("capability_id") == capability_id:
                    busy = True
            guards["capability_idle"] = not busy
            guards["execution_session"] = self._session_valid(connection, operation_id, capability_id, parameters)
            guards.update(self._adapter_guards(plan, binding, action, parameters))
            references = {}
            if input_event_id is not None:
                from .evidence import OperationEvidence
                evidence = OperationEvidence(self.ledger).find_event(operation_id, input_event_id)
                guards["persisted_input"] = evidence is not None
                if evidence:
                    references["input"] = self._ref(operation_id, "evidence", evidence["id"])
            failure = next((key for key, passed in guards.items() if not passed), None)
            decision = self._put(connection, operation_id, RecordDraft("decision", {
                "outcome": "rejected" if failure else "accepted", "action": action, "purpose": purpose,
                "guards": guards, "scope": {"capability_id": capability_id}, "reason": failure,
                "execution_contract": 1, "rule_name": rule_name,
                "rules_sha256": plan["payload"]["content"]["rules"]["sha256"] if rule_name else None}, plan["id"], references), principal.actor)
            if failure is None:
                command = self._put(connection, operation_id, RecordDraft("command", {
                    "capability_id": capability_id, "action": action, "parameters": parameters,
                    "max_attempts": policy["max_attempts"], "idempotency_key": idempotency_key,
                    "purpose": purpose, "resource_command_id": resource_command_id,
                    "budget_window": operation_id, "reserved_units": 1, "execution_contract": 1},
                    plan["id"], {"decision": self._ref(operation_id, "decision", decision["id"])}), principal.actor)
        if failure:
            raise LedgerError(f"admission_{failure}")
        return command

    def claim(self, operation_id: str, command_id: str, *, retry=False, reconciliation_note=None) -> dict:
        """K2: no hay llamada externa sin número durable, finito y único."""
        failure = None
        attempt = None
        with self.ledger._connection(write=True) as connection:
            command = self.ledger._record(connection, operation_id, command_id, "command")
            state, active, definition = self._context(connection, operation_id)
            policy = active["payload"]["content"]["execution_policy"]
            principal = self._principal(operation_id, definition, policy)
            self._stop_due(connection, operation_id, state, active, definition)
            from ..extensions import check_ledger_policy
            check_ledger_policy(self.ledger, "claim", operation=definition, plan=active,
                principal=principal, capability_id=command["payload"]["capability_id"],
                action=command["payload"]["action"], purpose=command["payload"]["purpose"])
            purpose = command["payload"].get("purpose")
            if command["payload"].get("execution_contract") != 1:
                failure = "unmanaged_command"
            elif command_id not in self.ledger._pending(connection, operation_id):
                failure = "already_disposed"
            elif command["plan_id"] != active["id"]:
                failure = "stale_command_version"
            elif purpose == "ordinary" and state["state"] != "active":
                failure = "operation_stopped"
            elif purpose == "cleanup" and state["state"] not in {"active", "paused", "closing", "closed"}:
                failure = "operation_stopped"
            elif not definition.roe.permits(command["payload"]["action"], f"{command['payload']['action']}:{command['payload']['capability_id']}"):
                failure = "roe"
            elif not self._session_valid(connection, operation_id, command["payload"]["capability_id"], command["payload"]["parameters"]):
                failure = "execution_session_stopped"
            if not failure:
                guards = self._adapter_guards(active, definition.find_plugin_binding(command["payload"]["capability_id"]), command["payload"]["action"], command["payload"]["parameters"])
                failure = next((key for key, passed in guards.items() if not passed), None)
            attempts = self._attempts(connection, operation_id, command_id)
            if not failure and attempts:
                receipts = self._receipts(connection, operation_id, attempts[-1]["id"])
                if not retry:
                    failure = "explicit_retry_required"
                elif not receipts or receipts[-1]["payload"]["outcome"] == "unknown":
                    # Nunca adivinar que un worker murió por un timeout.
                    failure = "reconciliation_required"
                elif receipts[-1]["payload"]["outcome"] != "failed":
                    failure = "already_invoked"
                elif not isinstance(reconciliation_note, str) or not reconciliation_note.strip():
                    failure = "retry_reason_required"
            if not failure and len(attempts) >= command["payload"]["max_attempts"]:
                failure = "attempt_limit"
            if not failure:
                attempt = self._put(connection, operation_id, RecordDraft("attempt", {
                    "number": len(attempts) + 1, "execution_contract": 1,
                    "retry_reason": reconciliation_note}, command["plan_id"],
                    {"command": self._ref(operation_id, "command", command_id)}), principal.actor)
            else:
                self._put(connection, operation_id, RecordDraft("decision", {
                    "outcome": "rejected", "action": command["payload"]["action"],
                    "purpose": command["payload"].get("purpose", "ordinary"),
                    "guards": {"claim": False}, "scope": {"command_id": command_id},
                    "reason": failure, "stage": "K2", "execution_contract": 1},
                    command["plan_id"], {"command": self._ref(operation_id, "command", command_id)}), principal.actor)
        if failure:
            raise LedgerError(failure)
        return attempt

    def finish(self, operation_id: str, attempt_id: str, *, outcome: str, adapter_state=None, detail_code=None):
        """Recibo y disposición juntos; sin convertir aceptación en confirmación."""
        with self.ledger._connection(write=True) as connection:
            attempt = self.ledger._record(connection, operation_id, attempt_id, "attempt")
            if self._receipts(connection, operation_id, attempt_id):
                raise LedgerError("receipt_already_recorded")
            command_id = attempt["references"]["command"]["record_id"]
            receipt = self._put(connection, operation_id, RecordDraft("receipt", {
                "outcome": outcome, "adapter_state": adapter_state, "detail_code": detail_code,
                "execution_contract": 1}, attempt["plan_id"],
                {"attempt": self._ref(operation_id, "attempt", attempt_id)}), "system:executor")
            if outcome in {"accepted", "confirmed"}:
                self._put(connection, operation_id, RecordDraft("disposition", {
                    "outcome": "completed", "meaning": "adapter_invocation_returned", "execution_contract": 1},
                    attempt["plan_id"], {"command": self._ref(operation_id, "command", command_id)}), "system:executor")
            if self.ledger._operation(connection, operation_id)["state"] == "closed":
                from .evidence import OperationEvidence
                OperationEvidence(self.ledger)._addendum(connection, operation_id, receipt)
            return receipt

    def abandon(self, operation_id: str, command_id: str, *, reason: str):
        """Conciliación administrativa explícita; no prueba retiro del recurso."""
        text_required(reason)
        with self.ledger._connection(write=True) as connection:
            command = self.ledger._record(connection, operation_id, command_id, "command")
            _, plan, definition = self._context(connection, operation_id)
            principal = self._principal(operation_id, definition, plan["payload"]["content"]["execution_policy"])
            if not principal.administrator:
                raise LedgerError("administrator_required")
            return self._put(connection, operation_id, RecordDraft("disposition", {
                "outcome": "abandoned", "reason": reason, "external_effect": "unknown", "execution_contract": 1},
                command["plan_id"], {"command": self._ref(operation_id, "command", command_id)}), principal.actor)

    def reconcile_failed(self, operation_id: str, command_id: str, *, reason: str, executor_quiescent: bool):
        """Permite reintento solo tras constancia explícita de conciliación.

        La declaración la firma administración. No se infiere quiescencia de
        una edad, reinicio o timeout, ni se presenta como medición automática.
        """
        text_required(reason)
        if executor_quiescent is not True:
            raise LedgerError("executor_quiescence_required")
        with self.ledger._connection(write=True) as connection:
            command = self.ledger._record(connection, operation_id, command_id, "command")
            _, plan, definition = self._context(connection, operation_id)
            principal = self._principal(operation_id, definition, plan["payload"]["content"]["execution_policy"])
            if not principal.administrator or principal.autonomous:
                raise LedgerError("administrator_required")
            if command_id not in self.ledger._pending(connection, operation_id):
                raise LedgerError("already_disposed")
            attempts = self._attempts(connection, operation_id, command_id)
            if not attempts:
                raise LedgerError("claimed_attempt_required")
            receipts = self._receipts(connection, operation_id, attempts[-1]["id"])
            if receipts and receipts[-1]["payload"]["outcome"] not in {"unknown", "failed"}:
                raise LedgerError("already_invoked")
            return self._put(connection, operation_id, RecordDraft("receipt", {
                "outcome": "failed", "execution_contract": 1, "reason": reason,
                "executor_quiescent": True, "basis": "administrator_attestation",
                "adapter_state": None}, command["plan_id"],
                {"attempt": self._ref(operation_id, "attempt", attempts[-1]["id"])}), principal.actor)

    def invoke(self, operation_id, command, callback, *, retry=False, reconciliation_note=None, state_capture=None):
        attempt = self.claim(operation_id, command["id"], retry=retry, reconciliation_note=reconciliation_note)
        try:
            result = callback()
        except Exception as error:
            # Un error no demuestra que no hubo efecto remoto. Queda pendiente
            # hasta conciliación; no se publica el mensaje con posibles secretos.
            self.finish(operation_id, attempt["id"], outcome="unknown", detail_code=type(error).__name__,
                adapter_state=state_capture() if state_capture else None)
            raise
        self.finish(operation_id, attempt["id"], outcome="accepted", adapter_state=state_capture() if state_capture else None)
        return result

    def run(self, operation_id, *, expected_plan_id, capability_id, action, idempotency_key,
            callback, parameters=None, purpose="ordinary", resource_command_id=None, state_capture=None,
            input_event_id=None, rule_name=None):
        command = self.admit(operation_id, expected_plan_id=expected_plan_id,
            capability_id=capability_id, action=action, idempotency_key=idempotency_key,
            parameters=parameters, purpose=purpose, resource_command_id=resource_command_id,
            input_event_id=input_event_id, rule_name=rule_name)
        return self.invoke(operation_id, command, callback, state_capture=state_capture)

    def status(self, operation_id):
        """Metadatos de recuperación; no devuelve configuración descifrada."""
        from .queries import OperationQueries
        query_status = OperationQueries(self).status(operation_id)
        with self.ledger._connection() as connection:
            connection.execute("BEGIN")
            state = self.ledger._operation(connection, operation_id)
            commands = self._commands(connection, operation_id)
            policy = None
            if state["active_plan_id"]:
                policy = self.ledger._record(connection, operation_id, state["active_plan_id"], "plan")["payload"]["content"].get("execution_policy")
            limit = self._root_limit(connection, operation_id, policy) if policy else None
            return {**query_status, "operation_id": operation_id, "state": state["state"],
                "active_plan_id": state["active_plan_id"], "reserved_modifications": len(commands),
                "modification_limit": limit, "remaining_modifications": max(0, limit - len(commands)) if limit is not None else None,
                "physical_verification": "external_evidence_required",
                "pending": [{"command_id": c["id"], "plan_id": c["plan_id"],
                    "capability_id": c["payload"]["capability_id"], "action": c["payload"]["action"],
                    "attempts": len(self._attempts(connection, operation_id, c["id"])),
                    "max_attempts": c["payload"]["max_attempts"]} for c in commands
                    if c["id"] in self.ledger._pending(connection, operation_id)]}
