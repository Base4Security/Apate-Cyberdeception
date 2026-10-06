"""Colector central de telemetria (M4) - documento de diseno, seccion
4.3.

Se suscribe al mismo EventBus de M2 que ya consume el RuleEngine de
M3, en paralelo y sin reemplazarlo: por cada evento interaction/
ttp_observed lo normaliza a un TelemetryRecord y lo persiste via
TelemetryRepository, consultable por operacion. Es "central" en el
sentido de que una misma instancia puede escuchar varias operaciones
a la vez (ver attach()): el bus es por operacion (M2), pero el
colector no tiene por que serlo, ya que cada registro normalizado ya
incluye su operation_id. Sirve de entrada para el informe
post-operacion (M6) y, mas adelante, para la interfaz web (M4b) - en
este hito el acceso sigue siendo programatico.
"""

from __future__ import annotations

from typing import Optional

from ..plugins.base import EventBus, EventType, PluginEvent
from .models import IoC, TelemetryRecord
from .repository import TelemetryRepository


class TelemetryCollector:
    """Normaliza y persiste los eventos del bus, y expone las consultas
    minimas que M6 (retroalimentacion CTI) y M4b (interfaz web) van a
    necesitar: eventos, IoCs y TTPs observadas por operacion."""

    def __init__(self, *, repository: TelemetryRepository, bus: Optional[EventBus] = None) -> None:
        self.repository = repository
        if bus is not None:
            self.attach(bus)

    def attach(self, bus: EventBus) -> None:
        """Suscribe el colector a un EventBus adicional (por ejemplo, el
        de una nueva operacion). Un mismo TelemetryCollector puede
        escuchar varias operaciones simultaneas."""

        bus.subscribe(EventType.INTERACTION, self.handle_event)
        bus.subscribe(EventType.TTP_OBSERVED, self.handle_event)

    def handle_event(self, event: PluginEvent) -> None:
        """Punto de entrada para eventos del bus. Tambien puede llamarse
        directamente (sin pasar por un EventBus real) para probar el
        colector en aislamiento."""

        self.repository.append(TelemetryRecord.from_event(event))

    def list_events(self, operation_id: str) -> list[TelemetryRecord]:
        """Todos los registros normalizados de una operacion, en el
        orden en que se observaron."""

        return self.repository.list_for_operation(operation_id)

    def list_iocs(self, operation_id: str) -> list[IoC]:
        """IoCs distintos observados en la operacion (deduplicados por
        tipo+valor), en el orden en que se observaron por primera
        vez."""

        seen: set[tuple[str, str]] = set()
        result: list[IoC] = []
        for record in self.list_events(operation_id):
            for ioc in record.iocs:
                key = (ioc.type, ioc.value)
                if key not in seen:
                    seen.add(key)
                    result.append(ioc)
        return result

    def list_ttps(self, operation_id: str) -> list[str]:
        """IDs de TTP distintos observados en la operacion, ordenados
        alfabeticamente."""

        return sorted({r.ttp_id for r in self.list_events(operation_id) if r.ttp_id is not None})
