"""Adaptadores que ejecutan configuración congelada mediante K1/K2."""

from __future__ import annotations

import uuid

from ..plugins.base import PluginLifecycleState
from ..plugins.registry import PluginRegistry
from .execution import ExecutionPrincipal, OperationExecutor
from .repository import LedgerError, digest, json_snapshot

# No declarar conformidad de un adaptador que relee objetos globales o usa
# imágenes mutables. Continúa visible para observar, pero no para actuar.
SUPPORTED_CONTROL = frozenset({"mock", "honeytoken", "canarytoken", "opencanary", "dolost", "buda", "playground"})


class ApprovedPlugin:
    """Fachada con el mismo objeto para acción manual y reglas reentrantes."""

    def __init__(self, executor, plan, binding, plugin):
        object.__setattr__(self, "executor", executor)
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "plugin", plugin)
        object.__setattr__(self, "binding_digest", digest(binding.to_dict()))
        object.__setattr__(self, "kind", PluginRegistry.resolve_binding_kind(binding))
        from .evidence import EvidenceBus
        if not isinstance(plugin._bus, EvidenceBus):
            plugin.replace_bus(EvidenceBus(executor.ledger, plugin.operation_id, plugin._bus))
        from .descriptors import MANAGED_KINDS, descriptor_for
        descriptor = descriptor_for(plan, binding.plugin_id) if self.kind in MANAGED_KINDS else None
        object.__setattr__(self, "descriptor", descriptor)
        # El estado operativo procede del recibo cifrado, nunca del editor.
        for record in reversed(executor.ledger.history(plugin.operation_id)):
            state = record["payload"].get("adapter_state") if record["kind"] == "receipt" else None
            if state and state.get("binding_digest") == self.binding_digest and (descriptor is None or state.get("descriptor_digest") == digest(descriptor)):
                plugin.config = json_snapshot(state["config"])
                plugin.state = PluginLifecycleState(state["state"])
                if plugin.state == PluginLifecycleState.DEPLOYED and self.kind == "honeytoken":
                    plugin.restore_deployed_state()
                break
        object.__setattr__(self, "effective_config", json_snapshot(plugin.config))
        object.__setattr__(self, "effective_state", plugin.state)
        if descriptor:
            from .buda_adapter import BudaAdapter
            from .docker_adapter import DockerAdapter
            object.__setattr__(self, "adapter", BudaAdapter(self, descriptor) if self.kind == "buda" else DockerAdapter(self, descriptor))
        else:
            object.__setattr__(self, "adapter", None)

    def __getattr__(self, name):
        return getattr(self.plugin, name)

    def __setattr__(self, name, value):
        # Las rutas anteriores fuerzan estado de ciclo de vida para lectura.
        # Esto nunca modifica la autoridad de K1 ni la configuración aprobada.
        setattr(self.plugin, name, value)

    def _capture(self):
        config = json_snapshot(self.plugin.config)
        directory = getattr(self.plugin, "_created_directory", None)
        if directory is not None:
            config["_apate_created_directory"] = True
        object.__setattr__(self, "effective_config", json_snapshot(config))
        object.__setattr__(self, "effective_state", self.plugin.state)
        return {"binding_digest": self.binding_digest, "descriptor_digest": digest(self.descriptor) if self.descriptor else None,
            "config": config, "state": self.plugin.state.value}

    def _call(self, action, parameters=None):
        self.plugin.config = json_snapshot(self.effective_config)
        self.plugin.state = self.effective_state
        if action in {"rotate", "retire"} and self.effective_state != PluginLifecycleState.DEPLOYED and not (self.adapter and action == "retire" and self.plugin.config.get("_managed_resources")):
            raise LedgerError("recorded_deployment_required")
        if self.adapter:
            return self.adapter.call(action, parameters)
        if self.kind == "honeytoken" and action in {"rotate", "retire"}:
            self.plugin.restore_deployed_state()
        return getattr(self.plugin, action)()

    def execute_managed(self, action, *, idempotency_key=None, autonomous=False, parameters=None,
                        input_event_id=None, rule_name=None):
        if self.kind not in SUPPORTED_CONTROL:
            raise LedgerError("adapter_not_frozen")
        executor = self.executor
        if autonomous:
            executor = OperationExecutor(executor.ledger, lambda op: ExecutionPrincipal(
                "system:rules", frozenset({op}), autonomous=True))
        operation_id = self.plugin.operation_id
        # Desplegar otra vez la misma capacidad es un reintento, aun después
        # de revisar el plan. Una nueva generación necesita un ID nuevo.
        key = f"plugin:deploy:{self.plugin_id}" if action == "deploy" and not parameters else idempotency_key or f"plugin:{action}:{uuid.uuid4()}"
        state = executor.ledger.operation(operation_id)
        purpose = "ordinary"
        source = None
        if action == "retire" and state["state"] in {"paused", "closing", "closed"}:
            purpose = "cleanup"
            for record in reversed(executor.ledger.history(operation_id)):
                if record["kind"] == "command" and record["payload"].get("capability_id") == self.plugin_id and record["payload"].get("action") == "deploy" and record["payload"].get("parameters") == {}:
                    source = record["id"]
                    break
        result = executor.run(operation_id, expected_plan_id=self.plan["id"],
            capability_id=self.plugin_id, action=action, idempotency_key=key,
            callback=lambda: self._call(action, parameters), purpose=purpose, parameters=parameters,
            resource_command_id=source, state_capture=self._capture,
            input_event_id=input_event_id, rule_name=rule_name)
        if self.kind == "buda" and not parameters:
            self.adapter.after(action)
        return result

    def retry_command(self, command_id, *, reason):
        if self.kind not in SUPPORTED_CONTROL:
            raise LedgerError("adapter_not_frozen")
        command = self.executor.ledger.record(self.operation_id, command_id)
        if command["kind"] != "command" or command["plan_id"] != self.plan["id"] or command["payload"]["capability_id"] != self.plugin_id or (command["payload"]["parameters"] and not self.adapter):
            raise LedgerError("resource_plan_mismatch")
        result = self.executor.invoke(self.operation_id, command, lambda: self._call(command["payload"]["action"], command["payload"]["parameters"]),
            retry=True, reconciliation_note=reason, state_capture=self._capture)
        if self.kind == "buda" and not command["payload"]["parameters"]:
            self.adapter.after(command["payload"]["action"])
        return result

    def deploy(self):
        return self.execute_managed("deploy")

    def rotate(self):
        return self.execute_managed("rotate")

    def retire(self):
        return self.execute_managed("retire")

    def check_access(self):
        """Observar no autoriza la reescritura automática usada en modo antiguo."""
        if self.kind != "honeytoken":
            raise LedgerError("unsupported_observation")
        self.plugin.config = json_snapshot(self.effective_config)
        return self.executor.query(self.operation_id, self.plugin_id, lambda: self.plugin.check_access(rearm=False))

    def check_activity(self, **kwargs):
        self.plugin.config = json_snapshot(self.effective_config)
        callback = (lambda: self.adapter.observe(**kwargs)) if self.adapter else (lambda: self.plugin.check_activity(**kwargs))
        return self.executor.query(self.operation_id, self.plugin_id, callback)

    def restore_deployed_state(self):
        if not self.adapter:
            return self.plugin.restore_deployed_state()
        self.plugin.state = self.effective_state


def approved_plugins(executor, operation_id, bus):
    plan, operation = executor.snapshot(operation_id)
    result = {}
    for binding in operation.plugins:
        kind = PluginRegistry.resolve_binding_kind(binding)
        if kind is None:
            raise LedgerError("unregistered_approved_adapter")
        plugin = PluginRegistry.get(kind).from_binding(binding, operation_id=operation_id, bus=bus)
        result[binding.plugin_id] = ApprovedPlugin(executor, plan, binding, plugin)
    return result
