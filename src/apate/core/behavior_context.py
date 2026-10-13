"""Fuentes reutilizables de contexto de comportamiento.

El contenido extraído es material de preparación: vive como recurso
compartido con identidad e integridad propias, separado de telemetría y de
la configuración global del proveedor que lo haya producido.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional, Union

from ..i18n import gettext as _
from ..atomic_write import write_text_atomically


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _es_hora_del_dia(clave: Any) -> bool:
    """`True` para una clave que es una hora (0-23) y por lo tanto no identifica."""

    try:
        return 0 <= int(clave) <= 23
    except (TypeError, ValueError):
        return False


def _fingerprint(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class BehaviorContextStatus(str, Enum):
    """Estado de revisión de una fuente compartida."""

    PENDING = "pending"
    ACTIVE = "active"
    ARCHIVED = "archived"


@dataclass
class BehaviorContextSource:
    """Resultado UEBA versionado e inmutable después de confirmarse."""

    name: str
    data: dict[str, Any]
    provenance: str
    origin_filename: str = ""
    status: BehaviorContextStatus = BehaviorContextStatus.PENDING
    pending_operation_id: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    integrity_sha256: str = ""
    created_at: datetime = field(default_factory=_utcnow)
    confirmed_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.integrity_sha256:
            self.integrity_sha256 = _fingerprint(self.data)

    @property
    def integrity_ok(self) -> bool:
        return self.integrity_sha256 == _fingerprint(self.data)

    def confirm(self) -> None:
        """Activa el candidato sin modificar los datos extraídos."""

        if self.status != BehaviorContextStatus.PENDING:
            raise ValueError(_("Solo una fuente pendiente puede confirmarse."))
        if not self.integrity_ok:
            raise ValueError(_("La integridad de la fuente no coincide con su huella registrada."))
        self.status = BehaviorContextStatus.ACTIVE
        self.confirmed_at = _utcnow()

    def archive(self) -> None:
        """Impide selecciones nuevas conservando referencias históricas."""

        if self.status != BehaviorContextStatus.ACTIVE:
            raise ValueError(_("Solo una fuente activa puede archivarse."))
        self.status = BehaviorContextStatus.ARCHIVED
        self.archived_at = _utcnow()

    def prompt_summary(self) -> dict[str, Any]:
        """Proyección sin identificadores, para mandar a un modelo externo.

        **Por qué existe.** El extracto UEBA tiene nombres de usuario, IPs
        internas y nombres de equipos del cliente. Un modelo que genera un tipo
        de actividad plausible necesita la *forma* del comportamiento normal --
        a qué horas hay actividad, cuánta gente, qué tan dispareja es la
        distribución -- y no necesita ninguna de esas identidades. Mandar el
        volcado crudo es regalarle el censo de la red a un tercero sin ninguna
        ganancia en la respuesta.

        **Permite por construcción, no por lista de prohibidos.** No hay un
        catálogo de campos a excluir, porque el extractor puede sumar campos
        nuevos y una lista así se queda vieja en silencio. En cambio, cada
        valor se reduce a su forma: las listas se vuelven un conteo; los
        diccionarios conservan sus claves **solo** si todas son horas del día
        (lo único que se sabe no identificatorio), y si no, sobrevive la
        distribución de sus valores sin las claves; los textos sueltos no
        sobreviven. Un campo nuevo cae en el caso general y no filtra nada.
        """

        resumen: dict[str, Any] = {}
        for clave, valor in sorted(self.data.items()):
            if isinstance(valor, dict):
                if valor and all(_es_hora_del_dia(k) for k in valor):
                    # `work_hours`: las claves son la hora, no una persona.
                    resumen[clave] = {str(k): valor[k] for k in sorted(valor, key=lambda h: int(h))}
                else:
                    # `login_frequencies`: las claves son nombres de usuario.
                    # Sobrevive cuánta actividad hay y qué tan dispareja es.
                    conteos = sorted((v for v in valor.values() if isinstance(v, (int, float))), reverse=True)
                    resumen[clave] = {
                        "entradas": len(valor),
                        "total": sum(conteos),
                        "maximo": conteos[0] if conteos else 0,
                        "minimo": conteos[-1] if conteos else 0,
                    }
            elif isinstance(valor, (list, tuple, set)):
                resumen[clave] = {"distintos": len(valor)}
            elif isinstance(valor, bool) or valor is None:
                resumen[clave] = valor
            elif isinstance(valor, (int, float)):
                resumen[clave] = valor
            else:
                # Texto libre: puede contener cualquier cosa, incluido un
                # identificador. Se declara que el campo existe y nada mas.
                resumen[clave] = {"presente": True}
        return resumen

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "data": self.data,
            "provenance": self.provenance,
            "origin_filename": self.origin_filename,
            "status": self.status.value,
            "pending_operation_id": self.pending_operation_id,
            "integrity_sha256": self.integrity_sha256,
            "created_at": self.created_at.isoformat(),
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehaviorContextSource":
        return cls(
            id=data["id"],
            name=data["name"],
            data=dict(data.get("data", {})),
            provenance=data.get("provenance", "desconocida"),
            origin_filename=data.get("origin_filename", ""),
            status=BehaviorContextStatus(data.get("status", BehaviorContextStatus.PENDING.value)),
            pending_operation_id=data.get("pending_operation_id"),
            integrity_sha256=data.get("integrity_sha256", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
            confirmed_at=datetime.fromisoformat(data["confirmed_at"]) if data.get("confirmed_at") else None,
            archived_at=datetime.fromisoformat(data["archived_at"]) if data.get("archived_at") else None,
        )


class JSONFileBehaviorContextRepository:
    """Persistencia legible: un JSON por versión de fuente."""

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, source_id: str) -> Path:
        return self._dir / f"{source_id}.json"

    def save(self, source: BehaviorContextSource) -> None:
        write_text_atomically(self._path_for(source.id), json.dumps(source.to_dict(), indent=2, ensure_ascii=False))

    def get(self, source_id: str) -> BehaviorContextSource:
        path = self._path_for(source_id)
        if not path.exists():
            raise KeyError(source_id)
        return BehaviorContextSource.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> Iterator[BehaviorContextSource]:
        for path in sorted(self._dir.glob("*.json")):
            yield BehaviorContextSource.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def delete_pending(self, source_id: str) -> None:
        source = self.get(source_id)
        if source.status != BehaviorContextStatus.PENDING:
            raise ValueError(_("Solo los candidatos pendientes pueden eliminarse físicamente."))
        self._path_for(source_id).unlink()

    def import_legacy(self, path: Union[str, Path]) -> Optional[BehaviorContextSource]:
        """Copia una vez el `context.json` histórico, sin eliminarlo."""

        legacy_path = Path(path)
        if not legacy_path.is_file():
            return None
        data = json.loads(legacy_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data:
            return None
        provenance = f"legacy:{legacy_path.resolve()}"
        existing = next((item for item in self.list() if item.provenance == provenance), None)
        if existing is not None:
            return existing
        now = _utcnow()
        source = BehaviorContextSource(
            name="Contexto heredado",
            data=data,
            provenance=provenance,
            origin_filename=legacy_path.name,
            status=BehaviorContextStatus.ACTIVE,
            confirmed_at=now,
        )
        self.save(source)
        return source
