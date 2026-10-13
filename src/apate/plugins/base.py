"""Capa de integracion por plugins - documento de diseno, seccion 4.3.

Define el contrato estandar (deploy()/rotate()/retire()) y el bus de
eventos (interaction/ttp_observed) que cualquier herramienta de
engano debe implementar para integrarse con APATE. Este contrato se
mantiene deliberadamente minimo y generico porque no solo lo usa el
plugin mock de M2: es el mismo que implementaran el plugin de
honeytokens (M7) y los adaptadores reales de DOLOS-T y BUDA (M8), y
no se quiere tener que rediseñarlo cuando esas integraciones existan.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Optional

from ..core.models import PluginBinding
from ..i18n import gettext as _
from .exceptions import PluginStateError

if TYPE_CHECKING:
    # Solo para el tipo de plugin_description mas abajo -- importar
    # .registry de verdad aca crearia un ciclo (registry.py ya importa
    # DeceptionPlugin de este modulo).
    from .registry import PluginDescription


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
    resource_id: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    provenance: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "event_type": self.event_type.value,
            "plugin_id": self.plugin_id,
            "surface": self.surface,
            "operation_id": self.operation_id,
            "resource_id": self.resource_id,
            "payload": dict(self.payload),
            "timestamp": self.timestamp.isoformat(),
        }
        if self.provenance is not None:
            value["provenance"] = dict(self.provenance)
        return value

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PluginEvent":
        return cls(
            id=data.get("id", _new_id()),
            event_type=EventType(data["event_type"]),
            plugin_id=data["plugin_id"],
            surface=data["surface"],
            operation_id=data["operation_id"],
            resource_id=data.get("resource_id"),
            payload=dict(data.get("payload", {})),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            provenance=dict(data["provenance"]) if data.get("provenance") is not None else None,
        )


# Valores de `payload["kind"]` con los que los plugins marcan una accion
# del ciclo de vida ejecutada por el operador (o por el motor de reglas),
# no una interaccion del adversario -- E3 de docs/improvements.md.
#
# Los seis plugins ya seguian esta convencion; lo que faltaba era que
# alguien la usara. Se deja aca, junto al contrato de PluginEvent, para
# que no quede como un string suelto dentro de la telemetria, y con un
# test que verifica que cada plugin la respeta.
#
# Deliberadamente NO se introduce un `EventType.LIFECYCLE`: estos eventos
# tienen que seguir viajando por el bus como INTERACTION para que el motor
# de reglas los siga viendo (una regla puede querer reaccionar a un
# despliegue). Lo que cambia es solo que la telemetria del adversario deja
# de guardarlos -- el registro de lo que hizo el operador ya vive donde
# corresponde, en apate.audit.OperatorAction.
LIFECYCLE_PAYLOAD_KINDS = frozenset({"deploy", "rotate", "retire"})


def is_lifecycle_event(event: PluginEvent) -> bool:
    """True si el evento describe una accion del ciclo de vida de una
    capacidad en vez de actividad observada del adversario."""

    return event.payload.get("kind") in LIFECYCLE_PAYLOAD_KINDS


def sanitize_payload_text(value: Any, *, max_length: int = 2000) -> Any:
    """Trunca texto largo antes de que entre a un `payload` de
    `PluginEvent` -- ver docs/plugin-event-contract.md seccion 3.4
    ("contenido sin sanitizar proveniente de una fuente no confiable...
    al menos truncarlo/escaparlo"). No hace falta escapar HTML aca: los
    templates de `apate.web` ya renderizan `payload` con el autoescape
    de Jinja (nunca `|safe`) y el inspector JS usa `textContent`, nunca
    `innerHTML` -- lo que falta cubrir es el LARGO, no la inyeccion,
    porque un evento de telemetria termina persistido en disco
    (`TelemetryCollector`) y mostrado entero en la UI sin limite
    propio.

    Deliberadamente no forma parte del contrato obligatorio de
    `DeceptionPlugin._publish()` (un plugin propio, con contenido que
    APATE ya controla en gran medida, decide si lo necesita) pero SI la
    usan los puentes de telemetria que traducen contenido de una fuente
    externa que APATE no controla (`apate.playground.events.
    PlaygroundEventBridge`, `apate.telemetry.external_bridge.
    ExternalTelemetryBridge`) -- ahi el contenido es, por definicion,
    no confiable.

    Solo trunca `str`; cualquier otro tipo (int, bool, lista, dict...)
    se devuelve tal cual -- no es una funcion de sanitizacion general,
    es especificamente para el caso de texto libre potencialmente
    enorme (un `message`/`command` completo de un log externo)."""

    if not isinstance(value, str) or len(value) <= max_length:
        return value
    return f"{value[:max_length]}... (truncado, {len(value)} caracteres originales)"


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
    """Contrato estandar de capacidades (seccion 4.3 del documento de
    diseno; paso 6 de la metodologia CTI-a-ciberengano) que cualquier
    herramienta de engano debe implementar para integrarse con APATE:
    DOLOS-T y BUDA en M8, honeytokens en M7, terceros del corpus OSS
    despues."""

    # Fase 5 post-BlackHat (ver docs/roadmap.md, apate.plugins.registry):
    # metadata legible de catalogo (M13i) que la subclase declara sobre
    # si misma. None por defecto -- un plugin de terceros descubierto
    # via entry point que no la declare no rompe el catalogo,
    # PluginRegistry.describe() arma una descripcion de respaldo.
    plugin_description: ClassVar[Optional["PluginDescription"]] = None

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
                _(
                    "No se puede ejecutar '%(action)s' en estado '%(state)s' "
                    "(se esperaba '%(expected)s').",
                    action=action,
                    state=self.state.value,
                    expected=expected.value,
                )
            )

    def replace_bus(self, bus: EventBus) -> None:
        """Reemplaza el `EventBus` de publicación del plugin.

        Se usa cuando un mismo plugin vive en más de un ciclo de vida de
        recolección (por ejemplo, un servicio de ingesta por polling en el
        cual los suscriptores no se pueden eliminar): en vez de crear un plugin
        nuevo, se conserva el estado local y se actualiza el bus activo.
        """

        self._bus = bus

    def _publish(
        self,
        event_type: EventType,
        payload: dict[str, Any],
        *,
        resource_id: Optional[str] = None,
    ) -> PluginEvent:
        event = PluginEvent(
            event_type=event_type,
            plugin_id=self.plugin_id,
            surface=self.surface,
            operation_id=self.operation_id,
            resource_id=resource_id,
            payload=payload,
        )
        self._bus.publish(event)
        return event
