"""Telemetria y correlacion - normalizacion de eventos del bus
(documento de diseno, seccion 4.3; roadmap M4).

Decisiones de esquema para TelemetryRecord (se documentan aca porque
el documento de diseno no fija el formato exacto, solo pide "formato
IoC/TTP"):

- Un TelemetryRecord por evento del bus: en este hito no se
  correlacionan ni agregan eventos entre si (eso, si hace falta,
  queda para M4b/M6); normalizar es solo darle una forma estructurada
  comun a interaction/ttp_observed.
- `ttp_id` se toma de `payload["ttp_id"]` sin importar el
  `event_type`: no se asume que solo los eventos `ttp_observed`
  puedan traer una TTP (un plugin real podria reportarla junto con
  una interaction).
- `iocs` es una lista, no un unico campo: un evento puede traer mas
  de un indicador (por ejemplo IP + hash), y forzar un unico (tipo,
  valor) por registro perderia informacion.
- La extraccion de IoCs es por convencion de nombres de payload
  conocidos (`_IOC_PAYLOAD_KEYS`). Si un plugin usa una clave no
  listada ahi, ese dato no se pierde: sigue disponible en
  `TelemetryRecord.payload` (el payload crudo), solo no se promueve a
  la lista estructurada de IoCs. Se prioriza no perder informacion
  frente a un esquema de extraccion todavia incompleto, en linea con
  el enfoque auditable de la seccion 8 del documento de diseno.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..plugins.base import EventType, PluginEvent


def _new_id() -> str:
    return str(uuid.uuid4())


# Claves de payload conocidas -> tipo de IoC que representan.
_IOC_PAYLOAD_KEYS: dict[str, str] = {
    "source_ip": "ip",
    "ip": "ip",
    "hash": "hash",
    "file_hash": "hash",
    "credential": "credential",
    "domain": "domain",
    "url": "url",
}


@dataclass
class IoC:
    """Indicador de compromiso extraido de un evento: tipo (ip, hash,
    credential, domain, url, ...) y valor."""

    type: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IoC":
        return cls(type=data["type"], value=data["value"])


@dataclass
class TelemetryRecord:
    """Registro normalizado de un evento del bus, listo para
    correlacion y para el informe post-operacion (M6). Conserva el
    payload crudo ademas de los campos estructurados (ver decisiones
    de esquema en el docstring del modulo)."""

    event_type: EventType
    operation_id: str
    plugin_id: str
    surface: str
    timestamp: datetime
    source_event_id: str
    resource_id: Optional[str] = None
    ttp_id: Optional[str] = None
    iocs: list[IoC] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=_new_id)

    @classmethod
    def from_event(cls, event: PluginEvent) -> "TelemetryRecord":
        """Normaliza un PluginEvent del bus de M2 a un TelemetryRecord."""

        iocs = [
            IoC(type=ioc_type, value=str(event.payload[key]))
            for key, ioc_type in _IOC_PAYLOAD_KEYS.items()
            if key in event.payload
        ]
        return cls(
            event_type=event.event_type,
            operation_id=event.operation_id,
            plugin_id=event.plugin_id,
            surface=event.surface,
            timestamp=event.timestamp,
            source_event_id=event.id,
            resource_id=event.resource_id,
            ttp_id=event.payload.get("ttp_id"),
            iocs=iocs,
            payload=dict(event.payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "operation_id": self.operation_id,
            "plugin_id": self.plugin_id,
            "surface": self.surface,
            "timestamp": self.timestamp.isoformat(),
            "source_event_id": self.source_event_id,
            "resource_id": self.resource_id,
            "ttp_id": self.ttp_id,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TelemetryRecord":
        return cls(
            id=data.get("id", _new_id()),
            event_type=EventType(data["event_type"]),
            operation_id=data["operation_id"],
            plugin_id=data["plugin_id"],
            surface=data["surface"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_event_id=data["source_event_id"],
            resource_id=data.get("resource_id"),
            ttp_id=data.get("ttp_id"),
            iocs=[IoC.from_dict(i) for i in data.get("iocs", [])],
            payload=dict(data.get("payload", {})),
        )
