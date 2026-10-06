"""Persistencia del Nucleo de Operacion.

Se define una interfaz abstracta (OperationRepository) y una primera
implementacion basada en archivos JSON. Permite cambiar la persistencia
de operaciones sin modificar el modelo de dominio.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Union

from .exceptions import OperationNotFoundError
from .models import Operation


class OperationRepository(ABC):
    """Contrato que cualquier backend de persistencia debe cumplir."""

    @abstractmethod
    def save(self, operation: Operation) -> None:
        """Crea o actualiza una operacion (upsert por id)."""

    @abstractmethod
    def get(self, operation_id: str) -> Operation:
        """Levanta OperationNotFoundError si no existe."""

    @abstractmethod
    def list(self) -> Iterator[Operation]:
        """Itera todas las operaciones almacenadas."""

    @abstractmethod
    def delete(self, operation_id: str) -> None:
        """Levanta OperationNotFoundError si no existe."""


class JSONFileOperationRepository(OperationRepository):
    """Guarda cada operacion como un archivo '<id>.json' dentro de un
    directorio. Simple, legible a simple vista, y sin dependencias
    externas - coherente con el enfoque minimalista y de bajo riesgo
    del proyecto (documento de diseno, secciones 1 y 8)."""

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", operation_id):
            raise ValueError("Identificador de operación inválido para persistencia local")
        return self._dir / f"{operation_id}.json"

    def save(self, operation: Operation) -> None:
        path = self._path_for(operation.id)
        path.write_text(
            json.dumps(operation.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, operation_id: str) -> Operation:
        path = self._path_for(operation_id)
        if not path.exists():
            raise OperationNotFoundError(operation_id)
        return Operation.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> Iterator[Operation]:
        for path in sorted(self._dir.glob("*.json")):
            yield Operation.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def delete(self, operation_id: str) -> None:
        path = self._path_for(operation_id)
        if not path.exists():
            raise OperationNotFoundError(operation_id)
        path.unlink()
