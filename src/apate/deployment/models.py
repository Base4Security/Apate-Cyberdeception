"""Modelos neutrales para planificar y registrar despliegues.

Separan tres conceptos que hasta ahora quedaban juntos dentro de
``PluginBinding.config``: el activo que se protege, el destino técnico
alcanzable y la ejecución concreta realizada por un conector. Ningún modelo
de este módulo conoce Flask, Docker, WinRM ni Active Directory.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from ..i18n import gettext as _
from .exceptions import InvalidDeploymentTransitionError


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value) if value else None


class DeploymentAction(str, Enum):
    """Cambios que un plan puede declarar antes de tocar infraestructura."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NOOP = "noop"


class DeploymentStatus(str, Enum):
    """Estado persistido de una ejecución, no del plugin que la solicitó."""

    PLANNED = "planned"
    APPLYING = "applying"
    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    ROTATING = "rotating"
    RETIRING = "retiring"
    RETIRED = "retired"


_ALLOWED_TRANSITIONS: dict[DeploymentStatus, set[DeploymentStatus]] = {
    DeploymentStatus.PLANNED: {DeploymentStatus.APPLYING, DeploymentStatus.FAILED},
    DeploymentStatus.APPLYING: {
        DeploymentStatus.ACTIVE,
        DeploymentStatus.DEGRADED,
        DeploymentStatus.FAILED,
    },
    DeploymentStatus.ACTIVE: {
        DeploymentStatus.DEGRADED,
        DeploymentStatus.FAILED,
        DeploymentStatus.ROTATING,
        DeploymentStatus.RETIRING,
        DeploymentStatus.RETIRED,
    },
    DeploymentStatus.DEGRADED: {
        DeploymentStatus.APPLYING,
        DeploymentStatus.ACTIVE,
        DeploymentStatus.FAILED,
        DeploymentStatus.ROTATING,
        DeploymentStatus.RETIRING,
        DeploymentStatus.RETIRED,
    },
    DeploymentStatus.FAILED: {
        DeploymentStatus.APPLYING,
        DeploymentStatus.ACTIVE,
        DeploymentStatus.DEGRADED,
        DeploymentStatus.RETIRING,
        DeploymentStatus.RETIRED,
    },
    DeploymentStatus.ROTATING: {
        DeploymentStatus.ACTIVE,
        DeploymentStatus.DEGRADED,
        DeploymentStatus.FAILED,
    },
    DeploymentStatus.RETIRING: {
        DeploymentStatus.ACTIVE,
        DeploymentStatus.RETIRED,
        DeploymentStatus.DEGRADED,
        DeploymentStatus.FAILED,
    },
    DeploymentStatus.RETIRED: set(),
}


@dataclass
class DeploymentTarget:
    """Destino técnico sobre el que sabe actuar un conector.

    ``asset_id`` relaciona el destino con el inventario, pero no reemplaza
    ``address``: inventariar un servidor no prueba que APATE pueda alcanzarlo.
    ``credential_ref`` identifica un secreto gestionado fuera de este objeto;
    ``config`` solo admite parámetros no secretos aptos para persistir.
    """

    name: str
    connector_kind: str
    address: str
    asset_id: Optional[str] = None
    credential_ref: Optional[str] = None
    config: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=_new_id)
    revision: int = 1

    def __post_init__(self) -> None:
        for field_name, value in (
            ("name", self.name),
            ("connector_kind", self.connector_kind),
            ("address", self.address),
        ):
            if not value.strip():
                raise ValueError(
                    _("El campo '%(field_name)s' del destino de despliegue es obligatorio.", field_name=field_name)
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "connector_kind": self.connector_kind,
            "address": self.address,
            "asset_id": self.asset_id,
            "credential_ref": self.credential_ref,
            "config": dict(self.config),
            "revision": self.revision,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeploymentTarget":
        return cls(
            id=data.get("id", _new_id()),
            name=data["name"],
            connector_kind=data["connector_kind"],
            address=data["address"],
            asset_id=data.get("asset_id"),
            credential_ref=data.get("credential_ref"),
            config=dict(data.get("config", {})),
            revision=int(data.get("revision", 1)),
        )


@dataclass(frozen=True)
class PlannedChange:
    """Cambio concreto y legible que el operador confirmará."""

    action: DeploymentAction
    resource_type: str
    resource_name: str
    summary: str
    destructive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "summary": self.summary,
            "destructive": self.destructive,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedChange":
        return cls(
            action=DeploymentAction(data["action"]),
            resource_type=data["resource_type"],
            resource_name=data["resource_name"],
            summary=data["summary"],
            destructive=bool(data.get("destructive", False)),
        )


@dataclass
class DeploymentPlan:
    """Instantánea persistible del plan anterior a su confirmación.

    ``parameters`` contiene únicamente datos no secretos necesarios para que
    el conector ejecute exactamente lo mostrado. Los secretos se resuelven por
    ``DeploymentTarget.credential_ref`` en una capa posterior.
    """

    operation_id: str
    plugin_id: str
    target: DeploymentTarget
    changes: list[PlannedChange]
    parameters: dict[str, Any] = field(default_factory=dict)
    valid_until: Optional[datetime] = None
    id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)

    @property
    def target_id(self) -> str:
        return self.target.id

    @property
    def connector_kind(self) -> str:
        return self.target.connector_kind

    @property
    def has_destructive_changes(self) -> bool:
        return any(change.destructive for change in self.changes)

    def is_expired(self, *, now: Optional[datetime] = None) -> bool:
        return self.valid_until is not None and (now or _utcnow()) >= self.valid_until

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operation_id": self.operation_id,
            "plugin_id": self.plugin_id,
            "target": self.target.to_dict(),
            "changes": [change.to_dict() for change in self.changes],
            "parameters": dict(self.parameters),
            "valid_until": _iso(self.valid_until),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeploymentPlan":
        return cls(
            id=data.get("id", _new_id()),
            operation_id=data["operation_id"],
            plugin_id=data["plugin_id"],
            target=DeploymentTarget.from_dict(data["target"]),
            changes=[PlannedChange.from_dict(item) for item in data.get("changes", [])],
            parameters=dict(data.get("parameters", {})),
            valid_until=_parse_dt(data.get("valid_until")),
            created_at=_parse_dt(data.get("created_at")) or _utcnow(),
        )


@dataclass(frozen=True)
class ConnectorResult:
    """Observación normalizada devuelta por cualquier conector."""

    status: DeploymentStatus
    detail: str = ""
    external_resource_ids: list[str] = field(default_factory=list)
    observed_at: datetime = field(default_factory=_utcnow)


@dataclass
class DeploymentRecord:
    """Evidencia persistida de una ejecución y de su último estado real."""

    plan_id: str
    operation_id: str
    plugin_id: str
    target_id: str
    connector_kind: str
    status: DeploymentStatus = DeploymentStatus.PLANNED
    external_resource_ids: list[str] = field(default_factory=list)
    detail: str = ""
    last_error: str = ""
    id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    @classmethod
    def from_plan(cls, plan: DeploymentPlan) -> "DeploymentRecord":
        return cls(
            plan_id=plan.id,
            operation_id=plan.operation_id,
            plugin_id=plan.plugin_id,
            target_id=plan.target_id,
            connector_kind=plan.connector_kind,
        )

    def transition_to(self, new_status: DeploymentStatus) -> None:
        if new_status == self.status:
            self.updated_at = _utcnow()
            return
        if new_status not in _ALLOWED_TRANSITIONS[self.status]:
            raise InvalidDeploymentTransitionError(
                _(
                    "Transición de despliegue inválida: %(current)s -> %(new)s.",
                    current=self.status.value,
                    new=new_status.value,
                )
            )
        self.status = new_status
        self.updated_at = _utcnow()

    def apply_result(self, result: ConnectorResult) -> None:
        self.transition_to(result.status)
        self.external_resource_ids = list(result.external_resource_ids)
        self.detail = result.detail
        self.last_error = result.detail if result.status is DeploymentStatus.FAILED else ""
        self.updated_at = result.observed_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "plan_id": self.plan_id,
            "operation_id": self.operation_id,
            "plugin_id": self.plugin_id,
            "target_id": self.target_id,
            "connector_kind": self.connector_kind,
            "status": self.status.value,
            "external_resource_ids": list(self.external_resource_ids),
            "detail": self.detail,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeploymentRecord":
        return cls(
            id=data.get("id", _new_id()),
            plan_id=data["plan_id"],
            operation_id=data["operation_id"],
            plugin_id=data["plugin_id"],
            target_id=data["target_id"],
            connector_kind=data["connector_kind"],
            status=DeploymentStatus(data.get("status", DeploymentStatus.PLANNED.value)),
            external_resource_ids=list(data.get("external_resource_ids", [])),
            detail=data.get("detail", ""),
            last_error=data.get("last_error", ""),
            created_at=_parse_dt(data.get("created_at")) or _utcnow(),
            updated_at=_parse_dt(data.get("updated_at")) or _utcnow(),
        )
