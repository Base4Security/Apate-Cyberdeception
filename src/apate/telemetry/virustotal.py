"""Enriquecimiento opt-in de IoCs observados mediante VirusTotal.

Es un overlay analitico sobre telemetria ya persistida: solo una accion
explicita del operador hace la consulta HTTP y guarda el resumen. No publica
eventos, no invoca plugins ni participa del motor de reglas. Por el mismo
criterio que Incidentes y TLP, tampoco genera ``OperatorAction``: no modifica
infraestructura de engaño, aunque consuma cuota de un servicio externo.

La credencial vive en una configuracion propia y global, separada de BUDA. El
repositorio de resultados mantiene un archivo JSON por operacion e identifica
cada IoC con ``ioc_subject_key()``.
"""

from __future__ import annotations

import base64
import ipaddress
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union
from urllib.parse import quote, urlsplit

import requests

from ..i18n import gettext as _
from .classifications import ioc_subject_key
from ..atomic_write import write_text_atomically

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_GUI_BASE = "https://www.virustotal.com/gui"
SUPPORTED_IOC_TYPES = ("hash", "ip", "domain", "url")


class PrivateIoCError(ValueError):
    """El IoC parece interno y no debe compartirse con un tercero."""


def ensure_ioc_can_be_shared(ioc_type: str, value: str) -> None:
    """Bloquea indicadores internos obvios antes de consultar VirusTotal."""

    host = ""
    if ioc_type == "ip":
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise PrivateIoCError(_("La dirección IP del IoC no es válida.")) from exc
        if not address.is_global:
            raise PrivateIoCError(_("El IoC pertenece a una red privada o reservada y no se enviará a VirusTotal."))
        return
    if ioc_type == "url":
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PrivateIoCError(_("La URL del IoC no es válida para compartir."))
        host = parsed.hostname
    elif ioc_type == "domain":
        host = value.strip().rstrip(".")
    else:
        return

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        normalized = host.casefold()
        if "." not in normalized or normalized == "localhost" or normalized.endswith(
            (".local", ".localhost", ".internal", ".test", ".invalid")
        ):
            raise PrivateIoCError(_("El IoC parece un nombre interno y no se enviará a VirusTotal."))
    else:
        if not address.is_global:
            raise PrivateIoCError(_("El IoC apunta a una red privada o reservada y no se enviará a VirusTotal."))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class VirusTotalEnrichment:
    """Resumen persistible de la ultima consulta para un IoC."""

    operation_id: str
    subject_key: str
    ioc_type: str
    ioc_value: str
    malicious: int
    suspicious: int
    total: int
    result_url: str
    queried_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "subject_key": self.subject_key,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "total": self.total,
            "result_url": self.result_url,
            "queried_at": self.queried_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VirusTotalEnrichment":
        return cls(
            operation_id=data["operation_id"],
            subject_key=data["subject_key"],
            ioc_type=data["ioc_type"],
            ioc_value=data["ioc_value"],
            malicious=int(data["malicious"]),
            suspicious=int(data["suspicious"]),
            total=int(data["total"]),
            result_url=data["result_url"],
            queried_at=datetime.fromisoformat(data["queried_at"]),
        )


class VirusTotalEnrichmentRepository(ABC):
    @abstractmethod
    def list_for_operation(self, operation_id: str) -> list[VirusTotalEnrichment]: ...

    @abstractmethod
    def save(self, enrichment: VirusTotalEnrichment) -> None:
        """Upsert por ``subject_key`` dentro de la operacion."""


class JSONFileVirusTotalEnrichmentRepository(VirusTotalEnrichmentRepository):
    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, operation_id: str) -> Path:
        return self._dir / f"{operation_id}.json"

    def list_for_operation(self, operation_id: str) -> list[VirusTotalEnrichment]:
        path = self._path_for(operation_id)
        if not path.exists():
            return []
        return [
            VirusTotalEnrichment.from_dict(item)
            for item in json.loads(path.read_text(encoding="utf-8"))
        ]

    def save(self, enrichment: VirusTotalEnrichment) -> None:
        items = [
            item
            for item in self.list_for_operation(enrichment.operation_id)
            if item.subject_key != enrichment.subject_key
        ]
        items.append(enrichment)
        write_text_atomically(self._path_for(enrichment.operation_id), json.dumps([item.to_dict() for item in items], indent=2, ensure_ascii=False))


class VirusTotalConfigRepository:
    """Configuracion global propia; la API key nunca se devuelve al HTML."""

    def __init__(self, path: Union[str, Path]):
        self._path = Path(path)

    def load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return {"api_key": str(data.get("api_key", ""))}

    def save_api_key(self, api_key: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(self._path, json.dumps({"api_key": api_key}, indent=2))


def _resource(ioc_type: str, value: str) -> tuple[str, str]:
    if ioc_type not in SUPPORTED_IOC_TYPES:
        raise ValueError(_("Tipo de IoC no compatible: %(ioc_type)s", ioc_type=ioc_type))
    if ioc_type == "url":
        identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"urls/{identifier}", f"url/{identifier}"
    segment = quote(value, safe="")
    if ioc_type == "hash":
        return f"files/{segment}", f"file/{segment}"
    if ioc_type == "ip":
        return f"ip_addresses/{segment}", f"ip-address/{segment}"
    return f"domains/{segment}", f"domain/{segment}"


def query_virustotal(
    operation_id: str, ioc_type: str, value: str, api_key: str
) -> VirusTotalEnrichment:
    """Consulta un reporte existente; nunca sube ni reanaliza el IoC."""

    ensure_ioc_can_be_shared(ioc_type, value)
    api_resource, gui_resource = _resource(ioc_type, value)
    response = requests.get(
        f"{VIRUSTOTAL_API_BASE}/{api_resource}",
        headers={"x-apikey": api_key},
        timeout=8.0,
    )
    response.raise_for_status()
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return VirusTotalEnrichment(
        operation_id=operation_id,
        subject_key=ioc_subject_key(ioc_type, value),
        ioc_type=ioc_type,
        ioc_value=value,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        total=sum(int(count) for count in stats.values()),
        result_url=f"{VIRUSTOTAL_GUI_BASE}/{gui_resource}",
    )
