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
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from .models import TelemetryRecord


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
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", operation_id):
            raise ValueError("Identificador de operación inválido para persistencia local")
        return self._dir / f"{operation_id}.json"

    def append(self, record: TelemetryRecord) -> None:
        records = self.list_for_operation(record.operation_id)
        records.append(record)
        path = self._path_for(record.operation_id)
        path.write_text(
            json.dumps([r.to_dict() for r in records], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def list_for_operation(self, operation_id: str) -> list[TelemetryRecord]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [TelemetryRecord.from_dict(d) for d in data]
