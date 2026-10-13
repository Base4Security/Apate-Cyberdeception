"""Contrato técnico para conectores de despliegue.

Un conector actúa sobre infraestructura; no autentica operadores de APATE.
Esto lo mantiene separado de ``apate.identity.IdentityProvider`` y evita
confundir el futuro login LDAP con la creación de honeyusers en AD.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from .models import ConnectorResult, DeploymentPlan, DeploymentRecord, DeploymentTarget


_ACTIONS = frozenset({"deploy", "rotate", "retire"})
_OBSERVATIONS = frozenset({"status", "events"})


@dataclass(frozen=True)
class ConnectorManifest:
    """Capacidades declaradas; no certifica una integración física."""

    kind: str
    contract_version: int
    actions: frozenset[str]
    observations: frozenset[str]

    def __post_init__(self) -> None:
        if (not isinstance(self.kind, str) or not self.kind.strip() or
                type(self.contract_version) is not int or self.contract_version not in {1, 2} or
                not isinstance(self.actions, frozenset) or not self.actions or
                not self.actions <= _ACTIONS or
                not isinstance(self.observations, frozenset) or not self.observations or
                not self.observations <= _OBSERVATIONS):
            raise ValueError("invalid_connector_manifest")

    def to_dict(self) -> dict[str, object]:
        """Entrega un contrato ordenado y apto para pruebas de conformidad."""
        return {"kind": self.kind, "contract_version": self.contract_version,
                "actions": sorted(self.actions), "observations": sorted(self.observations),
                "external_validation": "not_asserted"}


class DeploymentConnector(ABC):
    """Interfaz mínima para planificar, ejecutar y reconciliar recursos."""

    kind: ClassVar[str]
    manifest: ClassVar[ConnectorManifest | None] = None

    @classmethod
    def contract(cls) -> ConnectorManifest:
        """Conserva compatibilidad con conectores v1 sin manifiesto."""
        declared = cls.manifest
        if declared is None:
            return ConnectorManifest(cls.kind, 1, _ACTIONS, frozenset({"status"}))
        if declared.kind != cls.kind:
            raise ValueError("connector_manifest_kind_mismatch")
        return declared

    @abstractmethod
    def validate(self, target: DeploymentTarget, configuration: dict[str, Any]) -> None:
        """Valida conectividad/configuración sin modificar infraestructura."""

    @abstractmethod
    def plan(
        self,
        *,
        operation_id: str,
        plugin_id: str,
        target: DeploymentTarget,
        configuration: dict[str, Any],
    ) -> DeploymentPlan:
        """Devuelve los cambios exactos que un operador podrá confirmar."""

    @abstractmethod
    def deploy(self, plan: DeploymentPlan) -> ConnectorResult:
        """Ejecuta exclusivamente el plan confirmado."""

    @abstractmethod
    def status(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        """Consulta el estado real de los recursos ya conocidos."""

    @abstractmethod
    def rotate(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        """Rota identidad, secreto o contenido sin cambiar la intención."""

    @abstractmethod
    def retire(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        """Retira los recursos y devuelve evidencia del resultado."""
