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

from ..plugins.base import EventBus, EventType, PluginEvent, is_lifecycle_event
from .models import IoC, TelemetryRecord
from .repository import TelemetryRepository


class TelemetryCollector:
    """Normaliza y persiste los eventos del bus, y expone las consultas
    minimas que M6 (retroalimentacion CTI) y M4b (interfaz web) van a
    necesitar: eventos, IoCs y TTPs observadas por operacion."""

    def __init__(self, *, repository: TelemetryRepository, bus: Optional[EventBus] = None, attention_evaluator=None) -> None:
        self.repository = repository
        self.attention_evaluator = attention_evaluator
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
        colector en aislamiento.

        **Descarta las acciones del ciclo de vida** (E3 de
        docs/improvements.md): un deploy/rotate/retire ejecutado por el
        operador no es actividad del adversario, y guardarlo aca
        contaminaba todo lo que se deriva de esta telemetria -- los KPI de
        la operacion, los contadores de Telemetria, el Centro de impacto,
        el informe post-operacion y, sobre todo, el estado "observed" del
        arbol y del camino de engano, que se calcula como "existe algun
        registro para este plugin_id" y por lo tanto pintaba una capacidad
        recien desplegada como si el adversario ya la hubiera tocado.

        El evento sigue viajando por el bus (el motor de reglas lo ve
        igual); lo que hace el operador ya queda auditado aparte, en
        apate.audit.OperatorAction."""

        if is_lifecycle_event(event):
            return
        record = TelemetryRecord.from_event(event)
        self.repository.append(record)
        if self.attention_evaluator is not None:
            self.attention_evaluator(record)

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

    def list_ttps_by_operation(self, operation_ids: list[str]) -> dict[str, list[str]]:
        """Fase 4 post-BlackHat (ver docs/roadmap.md): la misma consulta
        que list_ttps(), pero para varias operaciones en una sola
        llamada -- delega en el repositorio para que el backend real
        (JSON o SQLite) decida como resolverla de forma eficiente. Ver
        TelemetryRepository.list_ttps_by_operation() para el contrato
        completo."""

        return self.repository.list_ttps_by_operation(operation_ids)

    def list_events_by_operation(self, operation_ids: list[str]) -> dict[str, list[TelemetryRecord]]:
        """Registros completos de varias operaciones, agrupados por ID."""

        return self.repository.list_for_operations(operation_ids)
