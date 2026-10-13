"""Lotes BUDA finitos e inmutables, con una reserva por acción WinRM."""

from __future__ import annotations

from datetime import date
import threading
import uuid

from ..plugins.base import EventType, PluginLifecycleState
from .execution import ExecutionPrincipal, OperationExecutor
from .repository import LedgerError, digest

_workers = {}
_workers_lock = threading.Lock()


def execute_step(step):
    import winrm
    response = winrm.Session(step["server"], auth=(step["username"], step["password"])).run_ps(step["command"])
    if response.status_code != 0:
        raise LedgerError("buda_remote_command_failed")
    return response.status_code


class BudaAdapter:
    def __init__(self, facade, descriptor):
        self.facade = facade
        self.plugin = facade.plugin
        self.descriptor = descriptor
        self.descriptor_digest = digest(descriptor)
        self.worker = None

    def call(self, action, parameters=None):
        parameters = parameters or {}
        if parameters.get("subaction") == "step":
            index = parameters["step"]
            if type(index) is not int or not 0 <= index < len(self.descriptor["steps"]):
                raise LedgerError("approved_buda_step_required")
            if date.fromisoformat(self.descriptor["end_date"]) < date.today():
                raise LedgerError("buda_narrative_expired")
            result = execute_step(self.descriptor["steps"][index])
            # Es actividad generada por el defensor, no una TTP del adversario.
            self.plugin._publish(EventType.INTERACTION, {"kind": "buda_command_executed",
                "step": index, "exit_code": result, "source": "defender_simulation"},
                resource_id=f"buda-step:{self.descriptor_digest}:{index}")
            return result
        if action in {"deploy", "rotate"}:
            policy = self.facade.plan["payload"]["content"]["execution_policy"]
            if not policy["autonomous"]:
                raise LedgerError("autonomous_buda_worker_not_approved")
            if date.fromisoformat(self.descriptor["end_date"]) < date.today():
                raise LedgerError("buda_narrative_expired")
            self._interrupt_wait()
            self.plugin.config["_execution_session"] = str(uuid.uuid4())
            self.plugin.state = PluginLifecycleState.DEPLOYED
        else:
            # Detiene futuras admisiones de ese lote; no deshace comandos
            # PowerShell ni cancela una llamada remota ya reclamada.
            self._interrupt_wait()
            self.plugin.config.pop("_execution_session", None)
            self.plugin.state = PluginLifecycleState.RETIRED
        self.plugin._publish(EventType.INTERACTION,
            {"kind": action, "adapter": "buda", "meaning": "local_batch_control"})

    def after(self, action):
        if action not in {"deploy", "rotate"}:
            return
        session = self.plugin.config["_execution_session"]
        self.worker = threading.Thread(target=self.run_batch, args=(session,), daemon=True,
            name="apate-buda-" + session)
        with _workers_lock:
            _workers[session] = {"event": threading.Event(), "thread": self.worker}
        try:
            self.worker.start()
        except Exception:
            with _workers_lock:
                _workers.pop(session, None)
            raise

    def _interrupt_wait(self):
        with _workers_lock:
            worker = _workers.get(self.plugin.config.get("_execution_session"))
            if worker:
                worker["event"].set()

    def run_batch(self, session):
        try:
            self._run_batch(session)
        finally:
            with _workers_lock:
                _workers.pop(session, None)

    def _run_batch(self, session):
        executor = OperationExecutor(self.facade.executor.ledger, lambda op: ExecutionPrincipal(
            "system:buda", frozenset({op}), autonomous=True))
        operation_id = self.plugin.operation_id
        plan_id = self.facade.plan["id"]
        interval = self.descriptor["interval_seconds"]
        for cycle in range(self.descriptor["cycles"]):
            for index in range(len(self.descriptor["steps"])):
                parameters = {"subaction": "step", "step": index, "cycle": cycle,
                    "execution_session": session, "descriptor_digest": self.descriptor_digest}
                try:
                    executor.run(operation_id, expected_plan_id=plan_id, capability_id=self.plugin.plugin_id,
                        action="rotate", parameters=parameters,
                        idempotency_key=f"buda:{session}:{cycle}:{index}", callback=lambda parameters=parameters: self.call("rotate", parameters))
                except Exception:
                    # Incertidumbre o rechazo termina el lote; ningún replay.
                    return
                if interval and (index + 1 < len(self.descriptor["steps"]) or cycle + 1 < self.descriptor["cycles"]):
                    with _workers_lock:
                        worker = _workers.get(session)
                        event = worker["event"] if worker else threading.Event()
                    if event.wait(interval):
                        return

    def observe(self, **kwargs):
        # Los eventos de este adaptador provienen del lote anterior, nunca
        # de drain_events() global ni de la Narrative editable.
        return []
