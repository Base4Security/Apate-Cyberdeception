"""`OperatorAction` (Fase 1 post-BlackHat, ver docs/roadmap.md) --
registro de acciones manuales de un operador humano.

Deliberadamente NO es lo mismo que `RuleFiring`/`RuleEngine.history`
(`apate.rules.models`): eso registra que hizo el motor de reglas de
forma autonoma y queda además en el repositorio de decisiones.
`OperatorAction` es lo simetrico para decisiones humanas -- cuando un
operador clickea Deploy/Rotar/Retirar/Start/Stop a mano en los paneles
nativos de `apate.web.blueprints.operations`, esa accion no quedaba
atribuida a nadie ni auditada en ningun lado. Se persiste, un archivo
JSON por operacion, mismo patron que `apate.telemetry.repository`.

La accion manual en si no pasa por la guarda de RoE (ver revision de
seguridad post-vendorizado: `RulesOfEngagement.permits()` gobierna la
automatizacion, no el click humano). Lo que si ocurre desde la opcion B
del backlog post-BlackHat es que el evento publicado por esa accion se
evalua contra las reglas globales con un motor efimero por request
(`apate.web._rule_engine_runtime`), y cualquier accion derivada de una
regla si pasa por las tres guardas.

Es atribución, no autorización: sin usuarios configurados conserva el
nombre libre de sesión (`POST /operator`); desde la Fase 02 comercial,
la aplicación toma el `display_name` de la identidad autenticada. El
campo persistido sigue siendo texto para poder leer acciones históricas
que existían antes de crear usuarios."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class OperatorAction:
    """Una accion manual disparada por un operador humano desde la UI
    nativa, fuera del motor de reglas. `outcome` es `"success"`/
    `"error"` (texto simple, no un enum -- mismo criterio minimalista
    que otros campos de texto libre del proyecto, ej.
    `StrategicDecisions.resource_estimate`); `detail` reutiliza el
    mismo mensaje que ya se le muestra al operador via `flash()`, sin
    duplicar logica de formateo. `plugin_id`/`target` quedan `None`
    para acciones que no son sobre un plugin/decoy puntual (ninguna
    hoy, pero deja la forma abierta)."""

    operation_id: str
    action: str
    operator: str
    outcome: str
    detail: str
    plugin_id: Optional[str] = None
    target: Optional[str] = None
    timestamp: datetime = field(default_factory=_utcnow)
    id: str = field(default_factory=_new_id)
    previous_hash: Optional[str] = None
    entry_hash: Optional[str] = None

    def hash_payload(self) -> dict[str, Any]:
        """Devuelve los datos canónicos que cubre el hash de la entrada.

        ``entry_hash`` queda afuera para que sea posible recalcularlo y
        ``previous_hash`` queda adentro: así cada entrada queda enlazada a
        la anterior de la misma cadena.
        """

        return {
            "id": self.id,
            "operation_id": self.operation_id,
            "action": self.action,
            "operator": self.operator,
            "outcome": self.outcome,
            "detail": self.detail,
            "plugin_id": self.plugin_id,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash,
        }

    def compute_entry_hash(self) -> str:
        """Calcula el hash SHA-256 estable de esta entrada."""

        serialized = json.dumps(
            self.hash_payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operation_id": self.operation_id,
            "action": self.action,
            "operator": self.operator,
            "outcome": self.outcome,
            "detail": self.detail,
            "plugin_id": self.plugin_id,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OperatorAction":
        return cls(
            id=data.get("id", _new_id()),
            operation_id=data["operation_id"],
            action=data["action"],
            operator=data["operator"],
            outcome=data["outcome"],
            detail=data["detail"],
            plugin_id=data.get("plugin_id"),
            target=data.get("target"),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            previous_hash=data.get("previous_hash"),
            entry_hash=data.get("entry_hash"),
        )


@dataclass(frozen=True)
class AuditVerification:
    """Resultado de verificar la cadena de auditoría de una operación.

    ``status`` vale ``"valid"`` si se verificó una cadena, ``"no_chain"``
    para datos heredados sin hashes y ``"broken"`` cuando el primer enlace
    inconsistente se pudo identificar.

    ``unchained_count`` es la cantidad de entradas anteriores a la cadena, que
    la verificación **no cubre**: se escribieron antes de que existieran los
    hashes y alterarlas no rompe ningún enlace. Sin ese dato, un historial
    mixto informaba ``"valid"`` a secas y quien lo leyera concluiría que todo
    el registro está íntegro -- confirmado alterando una entrada heredada y
    viendo que la verificación seguía diciendo "válido". Una auditoría que se
    presenta como completa cuando cubre solo una parte es peor que una
    honesta: alguien va a apoyar una decisión en ella.
    """

    status: str
    broken_index: Optional[int] = None
    broken_action_id: Optional[str] = None
    reason: Optional[str] = None
    unchained_count: int = 0

    @property
    def is_valid(self) -> bool:
        return self.status == "valid"

    @property
    def covers_everything(self) -> bool:
        """True solo si la cadena verificada abarca todo el historial."""

        return self.status == "valid" and self.unchained_count == 0
