"""`TlpClassification` -- clasificacion manual de Traffic Light Protocol
(TLP, estandar de FIRST) sobre telemetria ya observada (segunda de la
tanda de mejoras de UI/UX con referencia CounterCraft, ver
docs/roadmap.md: la consola real de CounterCraft permite marcar TLP
sobre IoCs/eventos para decidir con quien se puede compartir cada
dato).

Mismo criterio que `apate.telemetry.incidents` (primera de la tanda,
modulo hermano): overlay manual del operador sobre telemetria ya
persistida -- el motor de reglas no crea ni usa ninguna clasificacion
para nada, "asiste, nunca decide". Por el mismo motivo que ya dejo
afuera de `apate.audit.OperatorAction` a Incidentes y a la Fase 2/3
post-BlackHat (medir `success_metric`, incorporar TTPs al perfil de
adversario): es edicion de un dato de analisis, no una accion de
sistema sobre infraestructura real.

Un `TelemetryRecord` tiene `id` propio, pero un `IoC` no -- se
deduplica al vuelo por (`type`, `value`) en
`TelemetryCollector.list_iocs()`/la vista de Telemetria, sin id
persistido. `ioc_subject_key()` arma la clave estable (`"tipo:valor"`)
que identifica un IoC como sujeto de clasificacion -- unica funcion que
la construye en toda la app, reusada tal cual por `apate.reporting.stix`
para decidir que `indicator` del bundle STIX 2.1 marcar (el unico otro
consumidor que necesita reconstruir esa misma clave).

Solo puede haber una clasificacion vigente por sujeto (operacion +
tipo + clave): `save()` hace upsert por esa tripleta, no append-only --
mismo patron de persistencia (un archivo JSON por operacion) que
`apate.telemetry.incidents.JSONFileIncidentRepository`, pero sin
concepto de `id` propio (la tripleta ya es la clave natural, a
diferencia de `Incident`, que puede repetirse por nombre)."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Union
from ..atomic_write import write_text_atomically


class TlpLevel(str, Enum):
    """Los cuatro niveles clasicos de TLP (FIRST) -- deliberadamente
    sin TLP:CLEAR ni AMBER+STRICT (agregados en TLP 2.0): los
    `marking-definition` de STIX 2.1 solo tienen un ID fijo y
    reconocido para estos cuatro (ver `apate.reporting.stix`)."""

    RED = "red"
    AMBER = "amber"
    GREEN = "green"
    WHITE = "white"


# Los dos unicos tipos de sujeto que puede tener una clasificacion --
# telemetria normalizada (M4) no tiene ningun otro tipo de dato que
# clasificar todavia.
SUBJECT_TYPES = ("event", "ioc")


def ioc_subject_key(ioc_type: str, value: str) -> str:
    """Clave estable para clasificar un IoC (sin id propio, a
    diferencia de un evento). Misma convencion usada por
    `apate.web.blueprints.telemetry` (arma la clave al renderizar la
    tabla de IoCs) y `apate.reporting.stix` (la reconstruye para
    resolver que `indicator` marcar en el bundle STIX)."""

    return f"{ioc_type}:{value}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TlpClassification:
    """Clasificacion TLP de un sujeto puntual (`subject_type` +
    `subject_key`) dentro de una operacion. `subject_key` no se valida
    contra telemetria real en el propio modelo (no tiene visibilidad
    del `TelemetryCollector`) -- eso es responsabilidad de quien la
    guarda (capa web), mismo criterio que `Incident.event_ids`."""

    operation_id: str
    subject_type: str
    subject_key: str
    level: TlpLevel
    set_by: str = ""
    set_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "subject_type": self.subject_type,
            "subject_key": self.subject_key,
            "level": self.level.value if isinstance(self.level, TlpLevel) else self.level,
            "set_by": self.set_by,
            "set_at": self.set_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TlpClassification":
        return cls(
            operation_id=data["operation_id"],
            subject_type=data["subject_type"],
            subject_key=data["subject_key"],
            level=TlpLevel(data["level"]),
            set_by=data.get("set_by", ""),
            set_at=datetime.fromisoformat(data["set_at"]),
        )


class TlpClassificationRepository(ABC):
    """Contrato minimo: listar las clasificaciones de una operacion,
    guardar (crear o actualizar) una, o limpiar una (volver a "sin
    clasificar")."""

    @abstractmethod
    def list_for_operation(self, operation_id: str) -> list[TlpClassification]: ...

    @abstractmethod
    def save(self, classification: TlpClassification) -> None:
        """Upsert por (`operation_id`, `subject_type`, `subject_key`)
        -- solo puede haber una clasificacion vigente por sujeto."""

    @abstractmethod
    def clear(self, operation_id: str, subject_type: str, subject_key: str) -> None:
        """Vuelve el sujeto a "sin clasificar". No-op si no habia
        ninguna clasificacion guardada, mismo criterio de idempotencia
        que `IncidentRepository.delete()`."""


class JSONFileTlpClassificationRepository(TlpClassificationRepository):
    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def list_for_operation(self, operation_id: str) -> list[TlpClassification]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [TlpClassification.from_dict(d) for d in data]

    def _write(self, operation_id: str, classifications: list[TlpClassification]) -> None:
        path = self._path_for(operation_id)
        write_text_atomically(path, json.dumps([c.to_dict() for c in classifications], indent=2, ensure_ascii=False))

    def save(self, classification: TlpClassification) -> None:
        classifications = [
            existing
            for existing in self.list_for_operation(classification.operation_id)
            if not (
                existing.subject_type == classification.subject_type
                and existing.subject_key == classification.subject_key
            )
        ]
        classifications.append(classification)
        self._write(classification.operation_id, classifications)

    def clear(self, operation_id: str, subject_type: str, subject_key: str) -> None:
        classifications = self.list_for_operation(operation_id)
        remaining = [
            c for c in classifications if not (c.subject_type == subject_type and c.subject_key == subject_key)
        ]
        if len(remaining) != len(classifications):
            self._write(operation_id, remaining)
