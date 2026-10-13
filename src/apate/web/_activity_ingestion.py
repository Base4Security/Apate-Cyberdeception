"""Captura periódica de actividad externa hacia Telemetría.

El servicio conserva una instancia de adaptador por binding para mantener
la deduplicación de DOLOS-T entre sondeos. Cada evento sigue entrando por
``EventBus`` y ``TelemetryCollector``; el buffer en memoria solo alimenta
la vista En vivo y nunca reemplaza al registro persistido.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

from flask import Flask

from ..plugins import (
    BudaPlugin,
    DolosTPlugin,
    EventBus,
    PluginEvent,
    PluginLifecycleState,
)
from ..core.models import OperationStatus
from ..i18n import gettext as _
from ..plugins.operation import build_operation_plugins
from ._rule_engine_runtime import attach_operation_save_listener, build_rule_bus, build_rule_engine

_LOG = logging.getLogger(__name__)
_SUPPORTED_KINDS = {"buda", "dolost"}


def _binding_kind(binding) -> str:
    """Resuelve documentos anteriores a ``plugin_kind`` sin adivinar más."""

    if binding.plugin_kind:
        return binding.plugin_kind
    prefix = binding.plugin_id.casefold().split("-", 1)[0]
    return prefix if prefix in _SUPPORTED_KINDS else ""


class ActivityIngestionService:
    """Sondea adaptadores externos y evalúa su telemetría de forma aislada."""

    def __init__(
        self,
        app: Flask,
        *,
        enabled: bool,
        rules_enabled: bool = True,
        interval_seconds: float = 5.0,
        max_live_events: int = 500,
    ) -> None:
        self._app = app
        self.enabled = enabled
        self.rules_enabled = rules_enabled
        self.interval_seconds = max(float(interval_seconds), 0.1)
        self._live_events: deque[PluginEvent] = deque(maxlen=max_live_events)
        self._plugins: dict[tuple[str, str], tuple[str, Any]] = {}
        self._state_lock = threading.Lock()
        self._poll_lock = threading.Lock()
        self._stop = threading.Event()
        self._running = False
        self._last_poll: datetime | None = None
        self._last_success: datetime | None = None
        self._last_error = ""

    def start(self, socketio) -> None:
        """Inicia un único worker daemon mediante Flask-SocketIO."""

        if not self.enabled or self._running:
            return
        self._running = True
        socketio.start_background_task(self._run)

    def stop(self) -> None:
        """Señala detención; se usa principalmente en pruebas."""

        self._stop.set()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                with self._app.app_context():
                    self.poll_once()
                self._stop.wait(self.interval_seconds)
        finally:
            self._running = False

    def poll_once(self) -> list[PluginEvent]:
        """Captura una ronda y aísla fallos por binding, proveedor o regla."""

        if not self.enabled:
            return []
        with self._poll_lock:
            now = datetime.now(timezone.utc)
            with self._state_lock:
                self._last_poll = now
                self._last_error = ""

            operations = self._app.config["OPERATION_REPOSITORY"].list()
            executor = self._app.config["OPERATION_EXECUTOR"]
            approved = []
            for operation in operations:
                if self._app.config.get("APATE_GOVERNED_EXECUTION_REQUIRED", False) and not executor.managed(operation.id):
                    continue
                if executor.managed(operation.id):
                    try:
                        approved_plan, operation = executor.snapshot(operation.id)
                    except Exception:
                        continue
                approved.append(operation)
            candidates = [
                (operation, binding, _binding_kind(binding))
                for operation in approved
                for binding in operation.plugins
                if _binding_kind(binding) in _SUPPORTED_KINDS
            ]
            conflicts = self._conflicting_bindings([item for item in candidates if not executor.managed(item[0].id)])
            published: list[PluginEvent] = []
            operation_runtimes: dict[str, tuple[EventBus, dict, Any]] = {}
            active_keys: set[tuple[str, str]] = set()
            for operation, binding, kind in candidates:
                key = (operation.id, binding.plugin_id)
                if key in conflicts:
                    self._record_error(_("%(kind)s/%(plugin_id)s: atribución ambigua", kind=kind, plugin_id=binding.plugin_id))
                    continue
                if kind == "dolost" and not binding.config.get("decoys"):
                    # Un collector global sin decoys no permite asignar sus
                    # observaciones a una operación concreta con integridad.
                    self._record_error(_("%(kind)s/%(plugin_id)s: sin decoys correlacionables", kind=kind, plugin_id=binding.plugin_id))
                    continue
                active_keys.add(key)
                job = None
                try:
                    with self._app.app_context():
                        job = None
                        gate = self._app.config["OPERATION_PLAN_SERVICE"].adoption_gate
                        if not executor.managed(operation.id):
                            job = gate.enter(operation.id, kind="legacy:activity-poll", actor="system:ingest")
                        plugin = self._plugin_for(operation.id, binding, kind)
                        engine = self._prepare_operation_runtime(
                            operation=operation,
                            runtimes=operation_runtimes,
                        )
                        if executor.managed(operation.id):
                            plugin = operation_runtimes[operation.id][1][binding.plugin_id]
                        rejection_count = len(engine.rejected_actions) if engine is not None else 0
                        try:
                            events = plugin.check_activity()
                        finally:
                            if job:
                                gate.finish(job)
                except Exception as exc:  # un proveedor o regla no detiene a los demás
                    if job:
                        gate.finish(job, unknown=True)
                    message = f"{kind}/{binding.plugin_id}: {type(exc).__name__}"
                    self._record_error(message)
                    _LOG.warning("Falló la ingesta de actividad %s", message, exc_info=True)
                    continue
                if engine is not None and len(engine.rejected_actions) > rejection_count:
                    rejection = engine.rejected_actions[-1]
                    self._record_error(f"regla/{rejection.rule_name}: {rejection.reason}")
                published.extend(events)

            for key in list(self._plugins):
                if key not in active_keys:
                    del self._plugins[key]

            if published:
                with self._state_lock:
                    self._live_events.extend(published)
            self._check_closures()
            with self._state_lock:
                self._last_success = datetime.now(timezone.utc)
            return published

    def _check_closures(self) -> None:
        """Evalúa el cierre automático por vencimiento -- E7 de
        docs/improvements.md.

        `RuleEngine.check_closure()` no tenía ningún invocador en código de
        producción: sus únicas apariciones fuera de la definición eran
        docstrings. El formulario expone `end_date`, el dashboard lista
        "próximos cierres" y `ClosureCriteria` lo valida, pero la operación
        no se cerraba nunca. Es el mismo patrón que la verificación manual
        de M5 encontró en `fetch_and_ingest_elastic()`.

        Se engancha acá porque es el único latido que ya existe. A
        diferencia del sondeo de actividad, recorre **todas** las
        operaciones y no solo las que tienen bindings BUDA/DOLOS-T: el
        vencimiento no depende de ninguna capacidad.

        No cambia la semántica del motor: sigue cerrando solo si el
        operador escribió una regla `closure_due`, que es el mecanismo
        explícito y auditable que el editor de reglas ya ofrece. Sin esa
        regla, `end_date` sigue siendo informativo.
        """

        if not self.rules_enabled:
            return
        for operation in self._app.config["OPERATION_REPOSITORY"].list():
            executor = self._app.config["OPERATION_EXECUTOR"]
            if executor.managed(operation.id):
                try:
                    executor.observe(operation.id)
                except Exception:
                    pass
                continue
            if operation.status == OperationStatus.CLOSED:
                continue
            # Sin fecha, o todavía en plazo, `check_closure()` no puede
            # hacer nada: `is_past_due()` devuelve False y ninguna regla
            # `closure_due` matchea. Se saltea para no parsear reglas ni
            # construir capacidades de cada operación en cada ciclo.
            if operation.closure_criteria.end_date is None or not operation.is_past_due():
                continue
            try:
                with self._app.app_context():
                    bus = build_rule_bus()
                    plugins = build_operation_plugins(operation, bus)
                    engine = build_rule_engine(operation=operation, bus=bus, plugins=plugins)
                    if engine is None:
                        continue
                    engine.check_closure()
                    if engine.history or engine.rejected_actions:
                        # Solo se guarda si el motor decidió algo, para no
                        # reescribir cada operación vencida en cada ciclo.
                        self._app.config["OPERATION_REPOSITORY"].save(operation)
            except Exception as exc:  # una operación no detiene a las demás
                message = f"cierre/{operation.id}: {type(exc).__name__}"
                self._record_error(message)
                _LOG.warning("Falló el chequeo de cierre %s", message, exc_info=True)

    def _prepare_operation_runtime(self, *, operation, runtimes):
        """Asigna un bus nuevo por operación y por ciclo de sondeo.

        `EventBus` no permite desuscribirse. El bus, motor y listeners viven
        solo durante `poll_once()` para no acumular suscripciones ni capturar
        una operación vieja. El adaptador se conserva para mantener su
        deduplicación, pero se reconecta al bus nuevo antes de emitir.
        """

        runtime = runtimes.get(operation.id)
        if runtime is None:
            bus = build_rule_bus(operation.id)
            supplied: dict = {}
            for operation_binding in operation.plugins:
                kind = _binding_kind(operation_binding)
                if kind not in _SUPPORTED_KINDS or operation_binding.plugin_id in supplied:
                    continue
                supplied[operation_binding.plugin_id] = self._plugin_for(
                    operation.id,
                    operation_binding,
                    kind,
                )
            for cached_plugin in supplied.values():
                cached_plugin.replace_bus(bus)

            plugins: dict = dict(supplied)
            engine = None
            if self.rules_enabled:
                plugins = build_operation_plugins(
                    operation,
                    bus,
                    supplied=supplied,
                )
                engine = build_rule_engine(operation=operation, bus=bus, plugins=plugins)
                if engine is not None:
                    attach_operation_save_listener(bus, operation)
            runtimes[operation.id] = (bus, plugins, engine)
        else:
            _, _, engine = runtime
        return engine

    def _conflicting_bindings(self, candidates: list[tuple[Any, Any, str]]) -> set[tuple[str, str]]:
        """Falla cerrado cuando una fuente pertenece a más de una operación."""

        owners: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for operation, binding, kind in candidates:
            key = (operation.id, binding.plugin_id)
            if kind == "buda" and binding.config.get("narrative_id") is not None:
                resources = [("buda", str(binding.config["narrative_id"]))]
            elif kind == "dolost":
                resources = [
                    ("dolost", str(decoy["Hostname"]).casefold())
                    for decoy in binding.config.get("decoys", [])
                    if decoy.get("Hostname")
                ]
            else:
                resources = []
            for resource in resources:
                owners.setdefault(resource, []).append(key)
        return {
            key
            for resource_owners in owners.values()
            if len(set(resource_owners)) > 1
            for key in resource_owners
        }

    def _record_error(self, message: str) -> None:
        with self._state_lock:
            self._last_error = message

    def _plugin_for(self, operation_id: str, binding, kind: str):
        executor = self._app.config["OPERATION_EXECUTOR"]
        if executor.managed(operation_id):
            from ..ledger import ExecutionPrincipal, OperationExecutor
            from ..ledger.plugins import approved_plugins
            autonomous = OperationExecutor(executor.ledger, lambda op:
                ExecutionPrincipal("system:activity-ingest", frozenset({operation_id}), autonomous=True))
            return approved_plugins(autonomous, operation_id, build_rule_bus(operation_id))[binding.plugin_id]
        signature = json.dumps(binding.to_dict(), sort_keys=True, default=str)
        key = (operation_id, binding.plugin_id)
        cached = self._plugins.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]

        bus = EventBus()
        plugin_class = BudaPlugin if kind == "buda" else DolosTPlugin
        plugin = plugin_class.from_binding(binding, operation_id=operation_id, bus=bus)
        # La fuente externa ya tiene su propio estado persistente. El
        # adaptador efímero se reconcilia solo para habilitar lectura;
        # no se ejecuta deploy/rotate/retire desde este servicio.
        plugin.state = PluginLifecycleState.DEPLOYED
        self._plugins[key] = (signature, plugin)
        return plugin

    def live_events(self, operation_id: str) -> list[PluginEvent]:
        """Snapshot reciente del proceso, separado del historial SQLite."""

        with self._state_lock:
            return [event for event in self._live_events if event.operation_id == operation_id]

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "enabled": self.enabled,
                "rules_enabled": self.rules_enabled,
                "running": self._running,
                "interval_seconds": self.interval_seconds,
                "last_poll": self._last_poll.isoformat() if self._last_poll else None,
                "last_success": self._last_success.isoformat() if self._last_success else None,
                "last_error": self._last_error,
            }
