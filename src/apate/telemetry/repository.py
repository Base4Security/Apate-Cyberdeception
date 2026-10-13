"""Persistencia de telemetria (M4).

Misma filosofia que JSONFileOperationRepository (M1): un archivo JSON
por operacion, sin infraestructura adicional. A diferencia del
repositorio de operaciones (un objeto por archivo), aca cada archivo
contiene la lista completa de TelemetryRecord de esa operacion, porque
una operacion genera muchos registros de telemetria a lo largo de su
ciclo de vida, no uno solo.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from .models import TelemetryRecord
from ..atomic_write import write_text_atomically


class TelemetryRepository(ABC):
    """Contrato que cualquier backend de persistencia de telemetria debe
    cumplir."""

    @abstractmethod
    def append(self, record: TelemetryRecord) -> None:
        """Agrega un registro normalizado a la operacion a la que
        pertenece (record.operation_id)."""

    @abstractmethod
    def list_for_operation(self, operation_id: str) -> list[TelemetryRecord]:
        """Devuelve todos los registros de una operacion, en el orden en
        que se agregaron. Lista vacia si la operacion no tiene
        telemetria registrada todavia."""

    @abstractmethod
    def list_ttps_by_operation(self, operation_ids: list[str]) -> dict[str, list[str]]:
        """Fase 4 post-BlackHat (ver docs/roadmap.md): TTPs distintas
        observadas por cada operacion en `operation_ids`, en una sola
        llamada -- la consulta agregada cross-operacion que el
        Portafolio (M13g) necesitaba y que hasta ahora resolvia
        iterando `list_for_operation()` una vez por operacion (un
        archivo JSON completo por vez). Cada valor viene ordenado
        alfabeticamente, mismo criterio que `TelemetryCollector.
        list_ttps()`; una operacion sin ninguna TTP observada no
        aparece como clave (no aparece con lista vacia). Parte del
        contrato -- no solo de `SQLiteTelemetryRepository` -- para que
        quien llama (`TelemetryCollector`/`apate.web._portfolio`) no
        tenga que saber que backend tiene atras; `JSONFileTelemetryRepository`
        la resuelve iterando (correcta, no mas eficiente que antes),
        `SQLiteTelemetryRepository` con una unica consulta SQL real."""

    @abstractmethod
    def list_for_operations(self, operation_ids: list[str]) -> dict[str, list[TelemetryRecord]]:
        """Registros completos agrupados por operación en una llamada.

        Solo aparecen claves con registros. El orden dentro de cada lista
        es el de inserción, igual que en ``list_for_operation()``.
        """


class JSONFileTelemetryRepository(TelemetryRepository):
    """Guarda los registros de cada operacion como un array JSON en
    '<operation_id>.json' dentro de un directorio. append() hace un
    read-modify-write completo del archivo: simple y suficiente para
    el volumen de eventos de esta etapa (documento de diseno,
    secciones 1 y 8)."""

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def append(self, record: TelemetryRecord) -> None:
        records = self.list_for_operation(record.operation_id)
        records.append(record)
        path = self._path_for(record.operation_id)
        write_text_atomically(path, json.dumps([r.to_dict() for r in records], indent=2, ensure_ascii=False))

    def list_for_operation(self, operation_id: str) -> list[TelemetryRecord]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [TelemetryRecord.from_dict(d) for d in data]

    def list_ttps_by_operation(self, operation_ids: list[str]) -> dict[str, list[str]]:
        # Un archivo JSON completo por operacion, igual que list_for_
        # operation() -- este backend no gana nada de una consulta
        # "agregada" en si (sigue siendo N lecturas de disco), pero
        # cumple el mismo contrato que SQLiteTelemetryRepository para
        # que quien llama no tenga que distinguir el backend real.
        result: dict[str, list[str]] = {}
        for operation_id in operation_ids:
            ttps = sorted({r.ttp_id for r in self.list_for_operation(operation_id) if r.ttp_id is not None})
            if ttps:
                result[operation_id] = ttps
        return result

    def list_for_operations(self, operation_ids: list[str]) -> dict[str, list[TelemetryRecord]]:
        result = {}
        for operation_id in operation_ids:
            records = self.list_for_operation(operation_id)
            if records:
                result[operation_id] = records
        return result
