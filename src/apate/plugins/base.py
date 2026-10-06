"""Contrato mínimo de plugins y bus local de eventos de Apate Core."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from ..core.models import PluginBinding
from .exceptions import PluginStateError


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventType(str, Enum):
    """Tipos de evento que un plugin puede publicar (seccion 4.3 del
    documento de diseno)."""

    INTERACTION = "interaction"
    TTP_OBSERVED = "ttp_observed"


@dataclass
class PluginEvent:
    """Evento normalizado emitido por un plugin al bus. El payload es
    intencionalmente libre (dict) porque cada plugin/superficie
    observa cosas distintas; la telemetria (M4) es la que lo
    normaliza mas adelante a un formato comun de IoC/TTP."""

    event_type: EventType
    plugin_id: str
    surface: str
    operation_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "plugin_id": self.plugin_id,
            "surface": self.surface,
            "operation_id": self.operation_id,
            "payload": dict(self.payload),
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PluginEvent":
        return cls(
            id=data.get("id", _new_id()),
            event_type=EventType(data["event_type"]),
            plugin_id=data["plugin_id"],
            surface=data["surface"],
            operation_id=data["operation_id"],
            payload=dict(data.get("payload", {})),
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


class EventBus:
    """Bus de eventos sincronico e in-process (seccion 4.3 del
    documento de diseno). Sin colas, hilos ni async: el flujo evento
    -> handler debe poder leerse a simple vista, en linea con el
    enfoque de bajo riesgo y trazabilidad de la seccion 8. Se
    comparte una misma instancia entre todos los plugins de una
    misma operacion."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Callable[[PluginEvent], None]]] = {}

    def subscribe(self, event_type: EventType, handler: Callable[[PluginEvent], None]) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)

    def publish(self, event: PluginEvent) -> None:
        # Publicar sin suscriptores para ese tipo de evento no es un
        # error: el emisor no debe depender de si hay o no un
        # consumidor todavia (el motor de reglas de M3 puede no
        # existir aun en el momento en que se publica).
        for handler in self._subscribers.get(event.event_type, []):
            handler(event)


class PluginLifecycleState(str, Enum):
    """Ciclo de vida de un plugin desplegado, analogo a
    OperationStatus en el Nucleo de Operacion (M1)."""

    CREATED = "created"
    DEPLOYED = "deployed"
    RETIRED = "retired"


class DeceptionPlugin(ABC):
    """Contrato para una capacidad de engaño integrada con Apate Core."""

    def __init__(
        self,
        *,
        plugin_id: str,
        surface: str,
        operation_id: str,
        bus: EventBus,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        self.plugin_id = plugin_id
        self.surface = surface
        self.operation_id = operation_id
        self.config = dict(config or {})
        self.state = PluginLifecycleState.CREATED
        self._bus = bus

    @classmethod
    def from_binding(
        cls, binding: PluginBinding, *, operation_id: str, bus: EventBus
    ) -> "DeceptionPlugin":
        """Construye el plugin a partir de un PluginBinding ya
        registrado en la Operacion (paso 4 de la metodologia:
        seleccion y configuracion de plugins a activar)."""

        return cls(
            plugin_id=binding.plugin_id,
            surface=binding.surface,
            operation_id=operation_id,
            bus=bus,
            config=binding.config,
        )

    @abstractmethod
    def deploy(self) -> None:
        """Despliega el plugin. La implementacion debe validar el
        estado con _require_state() y dejarlo en DEPLOYED al
        terminar."""

    @abstractmethod
    def rotate(self) -> None:
        """Rota el plugin (nueva identidad/senuelo, misma narrativa).
        Solo valido si el plugin esta DEPLOYED; no cambia el estado."""

    @abstractmethod
    def retire(self) -> None:
        """Retira el plugin. Solo valido si esta DEPLOYED; deja el
        estado en RETIRED."""

    def _require_state(self, expected: PluginLifecycleState, *, action: str) -> None:
        """Valida el estado antes de ejecutar una accion de ciclo de
        vida. Centralizar esto (en vez de repetir el chequeo en cada
        implementacion) es lo que evita que un plugin quede en un
        estado inconsistente frente al motor de reglas (M3)."""

        if self.state is not expected:
            raise PluginStateError(
                f"No se puede ejecutar '{action}' en estado "
                f"'{self.state.value}' (se esperaba '{expected.value}')."
            )

    def _publish(self, event_type: EventType, payload: dict[str, Any]) -> PluginEvent:
        event = PluginEvent(
            event_type=event_type,
            plugin_id=self.plugin_id,
            surface=self.surface,
            operation_id=self.operation_id,
            payload=payload,
        )
        self._bus.publish(event)
        return event
