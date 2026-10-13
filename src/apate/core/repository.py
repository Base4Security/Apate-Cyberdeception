"""Persistencia del Nucleo de Operacion.

Se define una interfaz abstracta (OperationRepository) y una primera
implementacion basada en archivos JSON, suficiente para M1. El motor
de reglas (M3), la telemetria (M4) y el modo Playground (M5) dependen
de esta interfaz, no de la implementacion concreta, para poder migrar
a otro backend (por ejemplo SQLite) sin tocar el resto del sistema.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Union

from .exceptions import OperationNotFoundError
from .models import Operation
from ..atomic_write import write_text_atomically
import logging

_logger = logging.getLogger(__name__)


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

    #: Archivos que el ultimo `list()` no pudo leer, como `(nombre, motivo)`.
    #: La interfaz lo consulta para decirlo en pantalla en vez de que una
    #: operacion desaparezca sin explicacion.
    unreadable: list[tuple[str, str]]

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self.unreadable = []

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def save(self, operation: Operation) -> None:
        path = self._path_for(operation.id)
        write_text_atomically(path, json.dumps(operation.to_dict(), indent=2, ensure_ascii=False))

    def get(self, operation_id: str) -> Operation:
        path = self._path_for(operation_id)
        if not path.exists():
            raise OperationNotFoundError(operation_id)
        return Operation.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> Iterator[Operation]:
        """Las operaciones legibles. **Un archivo roto no tumba el listado.**

        Antes, un solo JSON ilegible -- truncado por una escritura
        interrumpida, editado a mano, o con un valor de enum que dejo de
        existir -- hacia que esto propagara. Y como el context processor de la
        navegacion consume `list()` en **cada render de plantilla**, el
        resultado era 500 en *todas* las rutas, incluida la que se usaria para
        arreglarlo: una operacion rota dejaba la instalacion inutilizable.

        Ahora se saltea y se anota en `unreadable`, para que la interfaz pueda
        decir cuantas no pudo leer. Saltear en silencio seria peor que fallar:
        el operador veria desaparecer una operacion sin ninguna explicacion.
        """

        self.unreadable = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                yield Operation.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.unreadable.append((path.name, str(error)))
                _logger.warning("No se pudo leer la operacion %s: %s", path.name, error)

    def delete(self, operation_id: str) -> None:
        path = self._path_for(operation_id)
        if not path.exists():
            raise OperationNotFoundError(operation_id)
        path.unlink()
