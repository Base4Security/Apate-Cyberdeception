"""Casos de uso de despliegue compartibles por la UI y una API futura."""

from __future__ import annotations

from datetime import datetime
from copy import copy
import uuid
from typing import Any, Mapping, Optional

from ..i18n import gettext as _
from .connector import DeploymentConnector
from .exceptions import DeploymentExecutionError, DeploymentValidationError
from .models import DeploymentPlan, DeploymentRecord, DeploymentStatus, DeploymentTarget
from .repository import DeploymentRepository


class DeploymentService:
    """Coordina conectores sin depender de Flask ni de un transporte HTTP."""

    def __init__(
        self,
        *,
        repository: DeploymentRepository,
        connectors: Mapping[str, DeploymentConnector],
        operation_executor=None,
    ) -> None:
        self.repository = repository
        self.connectors = dict(connectors)
        self.operation_executor = operation_executor

    def _managed(self, operation_id):
        managed = self.operation_executor is not None and self.operation_executor.managed(operation_id)
        if not managed and getattr(self.operation_executor, "governed_required", False):
            from ..ledger import LedgerError
            raise LedgerError("governed_operation_required")
        return managed

    def managed_poll(self, record, *, bus, checkpoints, executor=None):
        isolated = copy(self)
        isolated.operation_executor = executor or self.operation_executor
        isolated._poll_bus = bus
        isolated._poll_checkpoints = checkpoints
        plan = self.repository.get_plan(record.plan_id)
        return isolated._managed_call("poll", plan, record=record)

    def _managed_call(self, action, plan, *, record=None, now=None, recovery_command=None, recovery_reason=None):
        """Congela destino, parámetros, credencial administrativa y recurso.

        La bóveda operativa de contraseñas generadas sigue siendo persistente;
        solo la credencial del destino se resuelve desde el plan aprobado.
        """
        from ..ledger import LedgerError
        from ..ledger.repository import digest, json_snapshot
        from ..ledger.deployment import FrozenDeploymentRepository, FrozenCredentialStore
        executor = self.operation_executor
        version, definition = executor.snapshot(plan.operation_id)
        items = version["payload"]["content"].get("external_resource_versions", {}).get("items", [])
        approved = next((item["snapshot"] for item in items if item["kind"] == "deployment_plan" and item["id"] == plan.id), None)
        if approved is None or digest(approved) != digest(plan.to_dict()):
            raise LedgerError("approved_deployment_plan_required")
        frozen_plan = DeploymentPlan.from_dict(json_snapshot(approved))
        if record is None:
            record = self.repository.find_record_for_plan(plan.id)
        if definition.find_plugin_binding(frozen_plan.plugin_id) is None:
            raise LedgerError("controlled_capability_required")
        frozen_record = None
        if record is not None:
            # Un JSON editable no puede redirigir una rotación/retiro hacia
            # otro recurso. Usar el último recibo del registro o la importación
            # explícitamente revisada en este plan.
            for fact in reversed(executor.ledger.history(plan.operation_id)):
                state = fact["payload"].get("adapter_state") if fact["kind"] == "receipt" else None
                if state and state.get("deployment_record", {}).get("id") == record.id:
                    frozen_record = DeploymentRecord.from_dict(state["deployment_record"])
                    break
            if frozen_record is None:
                imported = next((item["snapshot"] for item in items if item["kind"] == "deployment_record" and item["id"] == record.id), None)
                if imported is None:
                    raise LedgerError("approved_resource_required")
                frozen_record = DeploymentRecord.from_dict(json_snapshot(imported))
            if frozen_record.plan_id != frozen_plan.id or frozen_record.operation_id != frozen_plan.operation_id:
                raise LedgerError("resource_plan_mismatch")
        connector = copy(self._connector(frozen_plan.connector_kind))
        if frozen_plan.connector_kind not in {"active-directory-honeyuser", "filesystem-honeyfile"}:
            raise LedgerError("adapter_not_frozen")
        if frozen_plan.target.credential_ref:
            reference = frozen_plan.target.credential_ref
            credential = next((item["snapshot"] for item in items if item["kind"] == "target_credential" and item["id"] == reference), None)
            if credential is None or not hasattr(connector, "_credentials"):
                raise LedgerError("credential_snapshot_required")
            connector._credentials = FrozenCredentialStore(reference, credential, connector._credentials)
        isolated = DeploymentService(repository=FrozenDeploymentRepository(self.repository, frozen_plan, frozen_record),
            connectors={frozen_plan.connector_kind: connector})
        params = {"deployment_plan_id": frozen_plan.id, "deployment_plan_sha256": digest(approved)}
        if action == "retry":
            # Este método antiguo no acredita conciliación. La recuperación B
            # requiere el endpoint explícito, que conserva la misma orden.
            raise LedgerError("explicit_command_recovery_required")
        if action == "refresh":
            # Consulta; no consume unidades de modificación ni implica efecto.
            return executor.query(plan.operation_id, frozen_plan.plugin_id, lambda: isolated.refresh(frozen_record.id), purpose="reconcile")
        if action == "poll":
            from .active_directory import HoneyuserEventMonitor
            return executor.query(plan.operation_id, frozen_plan.plugin_id,
                lambda: HoneyuserEventMonitor(connector=connector, checkpoint_repository=self._poll_checkpoints).poll(frozen_record, frozen_plan, self._poll_bus))
        kind = {"execute": "deploy", "rotate": "rotate", "retire": "retire"}[action]
        purpose = "ordinary"
        source = None
        if kind == "retire" and executor.ledger.operation(plan.operation_id)["state"] in {"paused", "closing", "closed"}:
            purpose = "cleanup"
            for fact in reversed(executor.ledger.history(plan.operation_id)):
                if fact["kind"] == "command" and fact["payload"].get("parameters", {}).get("deployment_plan_id") == plan.id and fact["payload"].get("action") == "deploy":
                    source = fact["id"]
                    break
        key = f"deployment:execute:{plan.id}" if action == "execute" else f"deployment:{action}:{uuid.uuid4()}"
        def invoke():
            if recovery_command is not None and kind == "deploy" and frozen_record is not None:
                result = isolated.retry(frozen_record.id)
            else:
                result = isolated.execute(frozen_plan.id, now=now) if action == "execute" else getattr(isolated, action)(frozen_record.id)
            if result.status in {DeploymentStatus.FAILED, DeploymentStatus.DEGRADED}:
                raise LedgerError("deployment_effect_unknown")
            return result
        capture = lambda: {"deployment_record": isolated.repository.record} if isolated.repository.record else None
        if recovery_command is not None:
            expected = {"deployment_plan_id": frozen_plan.id, "deployment_plan_sha256": digest(approved)}
            if recovery_command["plan_id"] != version["id"] or recovery_command["payload"]["parameters"] != expected or recovery_command["payload"]["capability_id"] != frozen_plan.plugin_id:
                raise LedgerError("resource_plan_mismatch")
            return executor.invoke(plan.operation_id, recovery_command, invoke, retry=True,
                reconciliation_note=recovery_reason, state_capture=capture)
        return executor.run(plan.operation_id, expected_plan_id=version["id"], capability_id=frozen_plan.plugin_id,
            action=kind, idempotency_key=key, parameters=params, purpose=purpose, resource_command_id=source,
            callback=invoke, state_capture=capture)

    def retry_command(self, operation_id, command_id, *, reason):
        from ..ledger import LedgerError
        command = self.operation_executor.ledger.record(operation_id, command_id)
        if command["kind"] != "command":
            raise LedgerError("command_required")
        plan_id = command["payload"].get("parameters", {}).get("deployment_plan_id")
        if not plan_id:
            raise LedgerError("approved_deployment_plan_required")
        plan = self.repository.get_plan(plan_id)
        if plan.operation_id != operation_id:
            raise LedgerError("resource_plan_mismatch")
        action = {"deploy": "execute", "rotate": "rotate", "retire": "retire"}.get(command["payload"]["action"])
        if action is None:
            raise LedgerError("invalid_command")
        record = self.repository.find_record_for_plan(plan_id)
        return self._managed_call(action, plan, record=record, recovery_command=command, recovery_reason=reason)

    def _connector(self, kind: str) -> DeploymentConnector:
        connector = self.connectors.get(kind)
        if connector is None:
            raise DeploymentValidationError(
                _("No hay un conector de despliegue registrado para '%(kind)s'.", kind=kind)
            )
        return connector

    def connector_manifest(self, kind: str) -> dict[str, object]:
        """Describe el contrato instalado sin abrir una conexión externa."""
        return self._connector(kind).contract().to_dict()

    def prepare(
        self,
        *,
        operation_id: str,
        plugin_id: str,
        target: DeploymentTarget,
        configuration: dict[str, Any],
    ) -> DeploymentPlan:
        connector = self._connector(target.connector_kind)
        connector.validate(target, configuration)
        plan = connector.plan(
            operation_id=operation_id,
            plugin_id=plugin_id,
            target=target,
            configuration=dict(configuration),
        )
        expected = (operation_id, plugin_id, target.id, target.connector_kind)
        actual = (plan.operation_id, plan.plugin_id, plan.target_id, plan.connector_kind)
        if actual != expected or plan.target != target:
            raise DeploymentValidationError(
                _("El conector devolvió un plan fuera del alcance solicitado.")
            )
        self.repository.save_plan(plan)
        return plan

    def execute(
        self,
        plan_id: str,
        *,
        now: Optional[datetime] = None,
    ) -> DeploymentRecord:
        plan = self.repository.get_plan(plan_id)
        if self._managed(plan.operation_id):
            return self._managed_call("execute", plan, now=now)
        existing = self.repository.find_record_for_plan(plan_id)
        if existing is not None and existing.status is not DeploymentStatus.PLANNED:
            return existing

        plan = self.repository.get_plan(plan_id)
        if plan.is_expired(now=now):
            raise DeploymentValidationError(_("El plan de despliegue venció; generá uno nuevo."))

        connector = self._connector(plan.connector_kind)
        record = existing or DeploymentRecord.from_plan(plan)
        if existing is None:
            self.repository.save_record(record)
        record.transition_to(DeploymentStatus.APPLYING)
        self.repository.save_record(record)
        try:
            result = connector.deploy(plan)
            if result.status not in {
                DeploymentStatus.ACTIVE,
                DeploymentStatus.DEGRADED,
                DeploymentStatus.FAILED,
            }:
                raise DeploymentValidationError(
                    _("El conector devolvió un estado inválido después de desplegar: %(status)s.", status=result.status.value)
                )
            record.apply_result(result)
            self.repository.save_record(record)
            return record
        except Exception as exc:
            if record.status is DeploymentStatus.APPLYING:
                record.transition_to(DeploymentStatus.FAILED)
                record.last_error = str(exc)
                record.detail = str(exc)
                self.repository.save_record(record)
            if isinstance(exc, DeploymentValidationError):
                raise
            raise DeploymentExecutionError(
                _("Falló la ejecución del plan de despliegue '%(plan_id)s': %(detail)s", plan_id=plan_id, detail=exc)
            ) from exc

    def refresh(self, record_id: str) -> DeploymentRecord:
        record = self.repository.get_record(record_id)
        plan = self.repository.get_plan(record.plan_id)
        if self._managed(record.operation_id):
            return self._managed_call("refresh", plan, record=record)
        result = self._connector(record.connector_kind).status(record, plan)
        if result.status not in {
            DeploymentStatus.ACTIVE,
            DeploymentStatus.DEGRADED,
            DeploymentStatus.FAILED,
            DeploymentStatus.RETIRED,
        }:
            raise DeploymentValidationError(
                _("El conector devolvió un estado inválido al consultar: %(status)s.", status=result.status.value)
            )
        record.apply_result(result)
        self.repository.save_record(record)
        return record

    def retry(self, record_id: str) -> DeploymentRecord:
        """Reintenta explícitamente un despliegue fallido o degradado.

        ``execute()`` conserva su idempotencia y nunca repite por accidente.
        Esta operación separada expresa la intención del operador y reutiliza
        el mismo plan confirmado; el conector debe reconciliar el recurso.
        """

        record = self.repository.get_record(record_id)
        if self._managed(record.operation_id):
            return self._managed_call("retry", self.repository.get_plan(record.plan_id), record=record)
        if record.status not in {DeploymentStatus.FAILED, DeploymentStatus.DEGRADED}:
            raise DeploymentValidationError(
                _(
                    "Solo se puede reintentar un despliegue fallido o degradado; estado actual: %(status)s.",
                    status=record.status.value,
                )
            )
        plan = self.repository.get_plan(record.plan_id)
        connector = self._connector(record.connector_kind)
        record.transition_to(DeploymentStatus.APPLYING)
        self.repository.save_record(record)
        try:
            result = connector.deploy(plan)
            if result.status not in {
                DeploymentStatus.ACTIVE,
                DeploymentStatus.DEGRADED,
                DeploymentStatus.FAILED,
            }:
                raise DeploymentValidationError(
                    _("El conector devolvió un estado inválido después del reintento: %(status)s.", status=result.status.value)
                )
            record.apply_result(result)
            self.repository.save_record(record)
            return record
        except Exception as exc:
            if record.status is DeploymentStatus.APPLYING:
                record.transition_to(DeploymentStatus.FAILED)
                record.last_error = str(exc)
                record.detail = str(exc)
                self.repository.save_record(record)
            if isinstance(exc, DeploymentValidationError):
                raise
            raise DeploymentExecutionError(
                _("Falló el reintento del despliegue '%(record_id)s': %(detail)s", record_id=record_id, detail=exc)
            ) from exc

    def rotate(self, record_id: str) -> DeploymentRecord:
        record = self.repository.get_record(record_id)
        plan = self.repository.get_plan(record.plan_id)
        if self._managed(record.operation_id):
            return self._managed_call("rotate", plan, record=record)
        record.transition_to(DeploymentStatus.ROTATING)
        self.repository.save_record(record)
        try:
            result = self._connector(record.connector_kind).rotate(record, plan)
            if result.status not in {
                DeploymentStatus.ACTIVE,
                DeploymentStatus.DEGRADED,
                DeploymentStatus.FAILED,
            }:
                raise DeploymentValidationError(
                    _("El conector devolvió un estado inválido después de rotar: %(status)s.", status=result.status.value)
                )
            record.apply_result(result)
            self.repository.save_record(record)
            return record
        except Exception as exc:
            if record.status is DeploymentStatus.ROTATING:
                record.transition_to(DeploymentStatus.FAILED)
                record.last_error = str(exc)
                record.detail = str(exc)
                self.repository.save_record(record)
            if isinstance(exc, DeploymentValidationError):
                raise
            raise DeploymentExecutionError(
                _("Falló la rotación del despliegue '%(record_id)s': %(detail)s", record_id=record_id, detail=exc)
            ) from exc

    def retire(self, record_id: str) -> DeploymentRecord:
        record = self.repository.get_record(record_id)
        plan = self.repository.get_plan(record.plan_id)
        if self._managed(record.operation_id):
            return self._managed_call("retire", plan, record=record)
        record.transition_to(DeploymentStatus.RETIRING)
        self.repository.save_record(record)
        try:
            result = self._connector(record.connector_kind).retire(record, plan)
            if result.status not in {
                DeploymentStatus.RETIRED,
                DeploymentStatus.DEGRADED,
                DeploymentStatus.FAILED,
            }:
                raise DeploymentValidationError(
                    _("El conector devolvió un estado inválido después de retirar: %(status)s.", status=result.status.value)
                )
            record.apply_result(result)
            self.repository.save_record(record)
            return record
        except Exception as exc:
            if record.status is DeploymentStatus.RETIRING:
                record.transition_to(DeploymentStatus.FAILED)
                record.last_error = str(exc)
                record.detail = str(exc)
                self.repository.save_record(record)
            if isinstance(exc, DeploymentValidationError):
                raise
            raise DeploymentExecutionError(
                _("Falló el retiro del despliegue '%(record_id)s': %(detail)s", record_id=record_id, detail=exc)
            ) from exc
