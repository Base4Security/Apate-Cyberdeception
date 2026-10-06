"""Núcleo de operación de Apate Core.

Implementa el objeto "Operacion" definido en la seccion 4.2 del
documento de diseno: perfil de adversario, Rules of Engagement,
narrativa, escenarios vinculados a TTPs, plugins asociados y
criterios de cierre. Es la unica fuente de verdad que consultan el
resto de los módulos incluidos (motor de decisión y telemetría).

Cada dataclass expone to_dict()/from_dict() propios en lugar de
apoyarse en dataclasses.asdict genérico, porque hay enums y datetimes
anidados que requieren conversion explicita: se prioriza que la
serializacion sea auditable y facil de seguir por sobre la brevedad.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .exceptions import InvalidTransitionError


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value) if value else None


class OperationStatus(str, Enum):
    """Ciclo de vida de una operacion."""

    PLANNING = "planning"
    ACTIVE = "active"
    COMPROMISED = "compromised"
    CLOSED = "closed"


# Transiciones de estado permitidas. Cualquier combinacion fuera de
# este mapa se rechaza explicitamente (ver InvalidTransitionError),
# para que el historial de una operacion sea siempre auditable
# (seccion 8 del documento de diseno).
_ALLOWED_TRANSITIONS: dict[OperationStatus, set[OperationStatus]] = {
    OperationStatus.PLANNING: {OperationStatus.ACTIVE, OperationStatus.CLOSED},
    OperationStatus.ACTIVE: {OperationStatus.COMPROMISED, OperationStatus.CLOSED},
    OperationStatus.COMPROMISED: {OperationStatus.CLOSED},
    OperationStatus.CLOSED: set(),
}


class DeceptionLevel(str, Enum):
    """Nivel de engano de un escenario, tomado de Cyber Deception
    Playground (seccion 6.3 del documento de diseno) y reutilizado
    tambien en operaciones de produccion."""

    NONE = "none"
    BASIC = "basic"
    AMBIGUOUS = "ambiguous"


class Environment(str, Enum):
    """Entorno de despliegue de la operacion (paso 2 de la metodologia
    CTI-a-ciberengano)."""

    ISOLATED = "isolated"
    NEAR_PRODUCTION = "near_production"
    PRODUCTION = "production"
    PLAYGROUND = "playground"


@dataclass
class AdversaryProfile:
    """Producto del paso 1 de la metodologia: perfil de amenaza y TTPs
    priorizadas."""

    name: str
    motivation: str = ""
    skill_level: str = "unknown"  # basic | intermediate | advanced | unknown
    expected_ttps: list[str] = field(default_factory=list)  # IDs ATT&CK, ej. "T1046"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "motivation": self.motivation,
            "skill_level": self.skill_level,
            "expected_ttps": list(self.expected_ttps),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AdversaryProfile":
        return cls(
            name=data["name"],
            motivation=data.get("motivation", ""),
            skill_level=data.get("skill_level", "unknown"),
            expected_ttps=list(data.get("expected_ttps", [])),
            notes=data.get("notes", ""),
        )


@dataclass
class RulesOfEngagement:
    """Producto del paso 2: limites operativos, legales y eticos de la
    operacion."""

    environment: Environment = Environment.ISOLATED
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    legal_constraints: list[str] = field(default_factory=list)
    escalation_contact: str = ""

    def permits(self, *signatures: str) -> bool:
        """Aplica las restricciones de acciones del motor de reglas."""

        if any(signature in self.forbidden_actions for signature in signatures):
            return False
        return not self.allowed_actions or any(
            signature in self.allowed_actions for signature in signatures
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment.value,
            "allowed_actions": list(self.allowed_actions),
            "forbidden_actions": list(self.forbidden_actions),
            "legal_constraints": list(self.legal_constraints),
            "escalation_contact": self.escalation_contact,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RulesOfEngagement":
        return cls(
            environment=Environment(data.get("environment", Environment.ISOLATED.value)),
            allowed_actions=list(data.get("allowed_actions", [])),
            forbidden_actions=list(data.get("forbidden_actions", [])),
            legal_constraints=list(data.get("legal_constraints", [])),
            escalation_contact=data.get("escalation_contact", ""),
        )


@dataclass
class Narrative:
    """Historia unica compartida por todos los plugins activos en la
    operacion (paso 5 de la metodologia, seccion 4.2 del diseno)."""

    name: str
    description: str = ""
    similarity_percentage: int = 100  # 0-100, concepto tomado de BUDA
    story_elements: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0 <= self.similarity_percentage <= 100:
            raise ValueError("similarity_percentage debe estar entre 0 y 100")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "similarity_percentage": self.similarity_percentage,
            "story_elements": list(self.story_elements),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Narrative":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            similarity_percentage=data.get("similarity_percentage", 100),
            story_elements=list(data.get("story_elements", [])),
        )


@dataclass
class Scenario:
    """Escenario de engano vinculado a una o mas TTPs (paso 3 de la
    metodologia)."""

    description: str
    related_ttps: list[str] = field(default_factory=list)
    deception_level: DeceptionLevel = DeceptionLevel.BASIC
    id: str = field(default_factory=_new_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "related_ttps": list(self.related_ttps),
            "deception_level": self.deception_level.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scenario":
        return cls(
            id=data.get("id", _new_id()),
            description=data["description"],
            related_ttps=list(data.get("related_ttps", [])),
            deception_level=DeceptionLevel(data.get("deception_level", DeceptionLevel.BASIC.value)),
        )


@dataclass
class PluginBinding:
    """Referencia a un plugin de capacidad (DOLOS-T, BUDA, honeytokens,
    o un mock) asociado a la operacion, con su configuracion
    especifica. La interfaz real del plugin se define en el modulo de
    integracion (M2 del roadmap); aqui solo se registra la asociacion."""

    plugin_id: str
    surface: str  # "network" | "identity" | "data" | otra (seccion 4.4)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "surface": self.surface,
            "config": dict(self.config),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PluginBinding":
        return cls(
            plugin_id=data["plugin_id"],
            surface=data["surface"],
            config=dict(data.get("config", {})),
        )


@dataclass
class ClosureCriteria:
    """Condiciones de cierre de la operacion."""

    end_date: Optional[datetime] = None
    conditions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "end_date": _iso(self.end_date),
            "conditions": list(self.conditions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClosureCriteria":
        return cls(
            end_date=_parse_dt(data.get("end_date")),
            conditions=list(data.get("conditions", [])),
        )


@dataclass
class Operation:
    """Objeto central de APATE. Agrupa todo lo necesario para que el
    motor de decision, la telemetria y el modo Playground operen sobre
    una misma fuente de verdad (seccion 4.2 del documento de diseno)."""

    name: str
    adversary_profile: AdversaryProfile
    roe: RulesOfEngagement
    narrative: Narrative
    scenarios: list[Scenario] = field(default_factory=list)
    plugins: list[PluginBinding] = field(default_factory=list)
    closure_criteria: ClosureCriteria = field(default_factory=ClosureCriteria)
    status: OperationStatus = OperationStatus.PLANNING
    id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    closed_at: Optional[datetime] = None

    # -- Transiciones de estado ------------------------------------------

    def transition_to(self, new_status: OperationStatus) -> None:
        """Aplica una transicion de estado si es valida; si no, lanza
        InvalidTransitionError. Centralizar esto es lo que permite que
        el motor de reglas (M3) dispare acciones sin poder dejar la
        operacion en un estado inconsistente."""

        allowed = _ALLOWED_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise InvalidTransitionError(
                f"Transicion no permitida: {self.status.value} -> {new_status.value} "
                f"(permitidas desde '{self.status.value}': "
                f"{sorted(s.value for s in allowed) or 'ninguna'})"
            )
        self.status = new_status
        self.updated_at = _utcnow()
        if new_status == OperationStatus.CLOSED:
            self.closed_at = _utcnow()

    def mark_active(self) -> None:
        self.transition_to(OperationStatus.ACTIVE)

    def mark_compromised(self) -> None:
        self.transition_to(OperationStatus.COMPROMISED)

    def close(self) -> None:
        self.transition_to(OperationStatus.CLOSED)

    # -- Composicion ------------------------------------------------------

    def add_scenario(self, scenario: Scenario) -> None:
        self.scenarios.append(scenario)
        self.updated_at = _utcnow()

    def bind_plugin(self, binding: PluginBinding) -> None:
        self.plugins.append(binding)
        self.updated_at = _utcnow()

    def is_past_due(self, *, now: Optional[datetime] = None) -> bool:
        """True si la operacion supero su fecha de cierre planificada
        sin haberse cerrado. Es la condicion que dispara el caso de uso
        'Cierre automatico y retroalimentacion' del documento de
        diseno (seccion 7)."""

        if self.closure_criteria.end_date is None:
            return False
        reference = now or _utcnow()
        return self.status != OperationStatus.CLOSED and reference >= self.closure_criteria.end_date

    # -- Serializacion ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "adversary_profile": self.adversary_profile.to_dict(),
            "roe": self.roe.to_dict(),
            "narrative": self.narrative.to_dict(),
            "scenarios": [s.to_dict() for s in self.scenarios],
            "plugins": [p.to_dict() for p in self.plugins],
            "closure_criteria": self.closure_criteria.to_dict(),
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
            "closed_at": _iso(self.closed_at),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Operation":
        return cls(
            id=data.get("id", _new_id()),
            name=data["name"],
            status=OperationStatus(data.get("status", OperationStatus.PLANNING.value)),
            adversary_profile=AdversaryProfile.from_dict(data["adversary_profile"]),
            roe=RulesOfEngagement.from_dict(data["roe"]),
            narrative=Narrative.from_dict(data["narrative"]),
            scenarios=[Scenario.from_dict(s) for s in data.get("scenarios", [])],
            plugins=[PluginBinding.from_dict(p) for p in data.get("plugins", [])],
            closure_criteria=ClosureCriteria.from_dict(data.get("closure_criteria", {})),
            created_at=_parse_dt(data.get("created_at")) or _utcnow(),
            updated_at=_parse_dt(data.get("updated_at")) or _utcnow(),
            closed_at=_parse_dt(data.get("closed_at")),
        )
