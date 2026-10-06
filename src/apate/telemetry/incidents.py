"""`Incident` -- agrupacion manual de eventos de telemetria ya
observados, para correlacion (primera de una tanda de mejoras de UI/UX
con referencia CounterCraft, ver docs/roadmap.md: su consola real deja
agrupar eventos relacionados en un "Incident" para estudiarlos en
conjunto, en vez de verlos como lista plana).

Deliberadamente manual, nunca automatico: el motor de reglas no crea
ni modifica ningun Incident, ni depende de ellos para nada -- es una
herramienta de analisis del operador humano sobre telemetria ya
persistida, mismo criterio de "asiste, nunca decide" que ya aplican
`apate.reporting.dry_run`/`apate.web._narrative_coherence`. Por el
mismo motivo que la Fase 2/3 post-BlackHat (medir `success_metric`,
incorporar TTPs al perfil de adversario) no generan un
`OperatorAction`: agrupar eventos ya observados es edicion de un dato
de analisis, no una accion de sistema sobre infraestructura real
(`apate.audit.OperatorAction` sigue reservado a deploy/rotate/retire/
start/stop, sin tocar aca).

Mismo patron de persistencia que `apate.audit.OperatorAction` -- un
archivo JSON por operacion -- pero a diferencia de ese repositorio
(append-only), un Incident se edita y se borra: `save()` hace upsert
por id, `delete()` remueve por id sin lanzar si ya no existe."""

from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union
from ..atomic_write import write_text_atomically


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Incident:
    """Un grupo de eventos de telemetria (IDs de `TelemetryRecord`)
    correlacionados a mano por el operador, con nombre y notas libres.
    `event_ids` no se valida contra ningun `TelemetryCollector` en el
    propio modelo (no tiene visibilidad de la telemetria real) -- eso
    se resuelve en la capa web, mismo criterio que
    `PluginBinding.scenario_id` resolviendose via
    `Operation.find_scenario()` en vez de validarse en el dataclass."""

    operation_id: str
    name: str
    notes: str = ""
    event_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    id: str = field(default_factory=_new_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operation_id": self.operation_id,
            "name": self.name,
            "notes": self.notes,
            "event_ids": list(self.event_ids),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        return cls(
            id=data.get("id", _new_id()),
            operation_id=data["operation_id"],
            name=data["name"],
            notes=data.get("notes", ""),
            event_ids=list(data.get("event_ids", [])),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data.get("updated_at", data["created_at"])),
        )


class IncidentRepository(ABC):
    """Contrato minimo: listar los incidentes de una operacion,
    guardar (crear o actualizar) uno, borrar uno por id."""

    @abstractmethod
    def list_for_operation(self, operation_id: str) -> list[Incident]: ...

    @abstractmethod
    def save(self, incident: Incident) -> None:
        """Upsert por `incident.id`: lo agrega si es nuevo, lo
        reemplaza si ya existia."""

    @abstractmethod
    def delete(self, operation_id: str, incident_id: str) -> None:
        """No-op si `incident_id` no existe -- mismo criterio de
        idempotencia que el resto de las rutas de borrado del
        proyecto (ej. `dolost_delete_decoy`)."""


class JSONFileIncidentRepository(IncidentRepository):
    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def list_for_operation(self, operation_id: str) -> list[Incident]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [Incident.from_dict(d) for d in data]

    def _write(self, operation_id: str, incidents: list[Incident]) -> None:
        path = self._path_for(operation_id)
        write_text_atomically(path, json.dumps([i.to_dict() for i in incidents], indent=2, ensure_ascii=False))

    def save(self, incident: Incident) -> None:
        incidents = self.list_for_operation(incident.operation_id)
        for index, existing in enumerate(incidents):
            if existing.id == incident.id:
                incidents[index] = incident
                break
        else:
            incidents.append(incident)
        self._write(incident.operation_id, incidents)

    def delete(self, operation_id: str, incident_id: str) -> None:
        incidents = self.list_for_operation(operation_id)
        remaining = [i for i in incidents if i.id != incident_id]
        if len(remaining) != len(incidents):
            self._write(operation_id, remaining)
