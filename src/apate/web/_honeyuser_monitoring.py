"""Sondeo periódico de honeyusers activos hacia telemetría y reglas."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from ..deployment import DeploymentStatus
from ..plugins.operation import build_operation_plugins
from ._rule_engine_runtime import attach_operation_save_listener, build_rule_bus, build_rule_engine

_LOG = logging.getLogger(__name__)


class HoneyuserMonitoringService:
    """Mantiene el puente AD -> EventBus sin conservar buses entre ciclos."""

    def __init__(self, app, *, enabled: bool, interval_seconds: float = 30.0,
                 reconcile_interval_seconds: float = 300.0) -> None:
        self._app = app
        self.enabled = enabled
        self.interval_seconds = max(5.0, float(interval_seconds))
        self.reconcile_interval_seconds = max(30.0, float(reconcile_interval_seconds))
        self._stop = threading.Event()
        self._poll_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last_poll: datetime | None = None
        self._last_success: datetime | None = None
        self._last_error: str | None = None
        self._record_status: dict[str, dict[str, str | None]] = {}

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="apate-honeyuser-monitor",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        # Esperar un intervalo evita que el arranque quede condicionado por
        # la disponibilidad de todos los controladores de dominio.
        while not self._stop.wait(self.interval_seconds):
            self.poll_once()

    def poll_once(self) -> int:
        """Sondea todos los registros elegibles; un DC caído no frena otros."""

        total = 0
        with self._poll_lock, self._app.app_context():
            self._last_poll = datetime.now(timezone.utc)
            self._last_error = None
            all_successful = True
            records = self._app.config["DEPLOYMENT_REPOSITORY"]
            for operation in self._app.config["OPERATION_REPOSITORY"].list():
                if self._app.config.get("APATE_GOVERNED_EXECUTION_REQUIRED", False) and not self._app.config["OPERATION_EXECUTOR"].managed(operation.id):
                    continue
                for record in records.list_records_for_operation(operation.id):
                    if record.connector_kind != "active-directory-honeyuser" or record.status not in {
                        DeploymentStatus.ACTIVE,
                        DeploymentStatus.DEGRADED,
                    }:
                        continue
                    try:
                        state = self._record_status.setdefault(record.id, {})
                        last_refresh = state.get("last_refresh")
                        due = not last_refresh or (
                            datetime.now(timezone.utc) - datetime.fromisoformat(last_refresh)
                        ).total_seconds() >= self.reconcile_interval_seconds
                        if due:
                            try:
                                service = self._app.config["DEPLOYMENT_SERVICE"]
                                from copy import copy
                                if callable(getattr(service, "_managed", None)) and service._managed(operation.id):
                                    service = copy(service)
                                    service.operation_executor = self._query_executor(operation.id)
                                gate = getattr(self._app.config.get("OPERATION_PLAN_SERVICE"), "adoption_gate", None)
                                executor = self._app.config.get("OPERATION_EXECUTOR")
                                job = gate.enter(operation.id, kind="legacy:AD-refresh", actor="system:monitor") if gate and (executor is None or not executor.managed(operation.id)) else None
                                try:
                                    refreshed = service.refresh(record.id)
                                finally:
                                    if job:
                                        gate.finish(job)
                                state["last_refresh"] = datetime.now(timezone.utc).isoformat()
                                state["last_refresh_error"] = None
                                state["last_refresh_status"] = refreshed.status.value
                            except Exception as exc:
                                all_successful = False
                                state["last_refresh_error"] = type(exc).__name__
                                self._last_error = f"{operation.id}/{record.id}: refresh/{type(exc).__name__}"
                                _LOG.warning("Falló la reconciliación de honeyuser %s", self._last_error, exc_info=True)
                        total += len(self._poll_record_with_status(operation, record))
                    except Exception as exc:
                        all_successful = False
                        self._last_error = f"{operation.id}/{record.id}: {type(exc).__name__}"
                        _LOG.warning("Falló el sondeo de honeyuser %s", self._last_error, exc_info=True)
            if all_successful:
                self._last_success = datetime.now(timezone.utc)
        return total

    def poll_record(self, operation, record):
        """Sondeo inmediato serializado con el ciclo automático."""

        with self._poll_lock, self._app.app_context():
            return self._poll_record_with_status(operation, record)

    def _poll_record_with_status(self, operation, record):
        """Guarda la frescura y el resultado de esta fuente concreta."""

        state = self._record_status.setdefault(record.id, {})
        state["last_poll"] = datetime.now(timezone.utc).isoformat()
        try:
            events = self._poll_record_unlocked(operation, record)
        except Exception as exc:
            state["last_error"] = type(exc).__name__
            raise
        state["last_success"] = datetime.now(timezone.utc).isoformat()
        state["last_error"] = None
        return events

    def _poll_record_unlocked(self, operation, record):
        plan = self._app.config["DEPLOYMENT_REPOSITORY"].get_plan(record.plan_id)
        bus = build_rule_bus(operation.id)
        engine = build_rule_engine(
            operation=operation,
            bus=bus,
            plugins=build_operation_plugins(operation, bus),
        )
        if engine is not None:
            attach_operation_save_listener(bus, operation)
        executor = self._app.config["OPERATION_EXECUTOR"]
        if executor.managed(operation.id):
            return self._app.config["DEPLOYMENT_SERVICE"].managed_poll(record, bus=bus,
                checkpoints=self._app.config["HONEYUSER_EVENT_MONITOR"]._checkpoints,
                executor=self._query_executor(operation.id))
        gate = self._app.config["OPERATION_PLAN_SERVICE"].adoption_gate
        job = gate.enter(operation.id, kind="legacy:AD-poll", actor="system:monitor")
        try:
            return self._app.config["HONEYUSER_EVENT_MONITOR"].poll(record, plan, bus)
        finally:
            gate.finish(job)

    def _query_executor(self, operation_id):
        from ..ledger import ExecutionPrincipal, OperationExecutor
        return OperationExecutor(self._app.config["OPERATION_LEDGER"], lambda op:
            ExecutionPrincipal("system:AD-monitor", frozenset({operation_id}), autonomous=True))

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_seconds": self.interval_seconds,
            "reconcile_interval_seconds": self.reconcile_interval_seconds,
            "last_poll": self._last_poll.isoformat() if self._last_poll else None,
            "last_success": self._last_success.isoformat() if self._last_success else None,
            "last_error": self._last_error,
            "records": {record_id: state.copy() for record_id, state in self._record_status.items()},
        }
