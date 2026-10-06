"""Persistencia de `OperatorAction` (Fase 1 post-BlackHat) -- mismo
patron que `apate.telemetry.repository`: un archivo JSON por
operacion, lectura/escritura completa (sin locking, sin indice),
suficiente para el volumen real de acciones manuales de una operacion
(deploy/rotate/retire/start/stop, no un flujo de alta frecuencia)."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from .models import AuditVerification, OperatorAction
from ..atomic_write import write_text_atomically
from ..file_lock import exclusive_file_lock


class OperatorActionRepository(ABC):
    """Contrato minimo: agregar una accion, listar las de una
    operacion. Mismo par de metodos que `TelemetryRepository`, a
    proposito -- son el mismo tipo de dato (una lista append-only por
    operacion), solo que de origen humano en vez de un `PluginEvent`."""

    @abstractmethod
    def append(self, action: OperatorAction) -> None: ...

    @abstractmethod
    def list_for_operation(self, operation_id: str) -> list[OperatorAction]: ...

    @abstractmethod
    def verify(self, operation_id: str) -> AuditVerification: ...


class JSONFileOperatorActionRepository(OperatorActionRepository):
    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def append(self, action: OperatorAction) -> None:
        path = self._path_for(action.operation_id)
        with exclusive_file_lock(path.with_suffix(".lock")):
            actions = self.list_for_operation(action.operation_id)
            previous_hashed = next((item for item in reversed(actions) if item.entry_hash), None)
            action.previous_hash = previous_hashed.entry_hash if previous_hashed else None
            action.entry_hash = action.compute_entry_hash()
            actions.append(action)
            write_text_atomically(path, json.dumps([a.to_dict() for a in actions], indent=2, ensure_ascii=False))

    def list_for_operation(self, operation_id: str) -> list[OperatorAction]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [OperatorAction.from_dict(d) for d in data]

    def verify(self, operation_id: str) -> AuditVerification:
        """Verifica la porción encadenada del historial, sin inventar
        integridad retrospectiva para entradas heredadas sin hash."""

        previous_hash: str | None = None
        has_chain = False
        unchained = 0
        for index, action in enumerate(self.list_for_operation(operation_id)):
            if action.entry_hash is None:
                unchained += 1
                continue
            has_chain = True
            if action.previous_hash != previous_hash:
                return AuditVerification(
                    status="broken",
                    broken_index=index,
                    broken_action_id=action.id,
                    reason="El enlace con la entrada anterior no coincide.",
                    unchained_count=unchained,
                )
            if action.entry_hash != action.compute_entry_hash():
                return AuditVerification(
                    status="broken",
                    broken_index=index,
                    broken_action_id=action.id,
                    reason="El contenido de la entrada no coincide con su hash.",
                    unchained_count=unchained,
                )
            previous_hash = action.entry_hash
        if not has_chain:
            return AuditVerification(status="no_chain", unchained_count=unchained)
        return AuditVerification(status="valid", unchained_count=unchained)
