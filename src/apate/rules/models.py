"""Motor de decision - formato de reglas condicion-accion (documento de
diseno, seccion 4.3; roadmap M3).

Las reglas se definen en YAML para que un operador pueda editarlas sin
tocar codigo (paso 3 de la metodologia CTI-a-ciberengano: analisis de
TTPs y escenarios de engano). Cada regla tiene una condicion (`when`)
evaluada contra un evento del bus de M2 o contra el estado de la
Operacion, y una o mas acciones (`then`) sobre los plugins registrados
y/o sobre las transiciones de estado de la Operacion. Se usa
yaml.safe_load (nunca yaml.load) porque las reglas son configuracion
editada por un operador, no codigo de confianza (seccion 8 del
documento de diseno, riesgos de seguridad).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import yaml

from ..core.models import OperationStatus
from ..i18n import gettext as _
from ..plugins.base import EventType, PluginEvent
from .exceptions import RuleDefinitionError


def _new_id() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

# Unicos destinos de transicion que una regla puede disparar (ver
# Operation.mark_active/mark_compromised/close en el Nucleo de
# Operacion). PLANNING queda afuera a proposito: ninguna transicion
# vuelve a ese estado.
_VALID_TRANSITION_TARGETS = {
    OperationStatus.ACTIVE,
    OperationStatus.COMPROMISED,
    OperationStatus.CLOSED,
}


class ActionKind(str, Enum):
    """Tipo de accion que puede disparar una regla."""

    DEPLOY = "deploy"
    ROTATE = "rotate"
    RETIRE = "retire"
    TRANSITION = "transition"


class RejectionKind(str, Enum):
    """Motivo estable por el que el motor no ejecuto una accion."""

    ROE = "roe"
    CASCADE_LIMIT = "cascade_limit"
    EXECUTION_ERROR = "execution_error"

    @property
    def label(self) -> str:
        """Etiqueta breve para las vistas de decisiones del motor."""

        return {
            RejectionKind.ROE: "RoE",
            RejectionKind.CASCADE_LIMIT: "Tope de cascada",
            RejectionKind.EXECUTION_ERROR: "Error de ejecución",
        }[self]

    @classmethod
    def from_legacy_reason(cls, reason: str) -> "RejectionKind":
        """Clasifica filas anteriores a ``rejection_kind`` por su prosa.

        Es compatibilidad de persistencia: los rechazos nuevos siempre se
        tipan en RuleEngine, que es el unico lugar que conoce su causa.
        """

        if "Rules of Engagement" in reason:
            return cls.ROE
        if "Tope de acciones por cadena" in reason:
            return cls.CASCADE_LIMIT
        return cls.EXECUTION_ERROR


@dataclass
class Condition:
    """Condicion de disparo de una regla. Es o bien una condicion sobre
    un evento del bus (event_type, y opcionalmente plugin_id y un
    subconjunto de payload a matchear - por ejemplo un TTP observado)
    o una condicion sobre el estado de la Operacion (closure_due, para
    el cierre automatico por vencimiento) - nunca ambas: una regla se
    dispara por eventos o por el chequeo periodico de estado, no por
    los dos caminos a la vez."""

    event_type: Optional[EventType] = None
    plugin_id: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)
    closure_due: bool = False

    def __post_init__(self) -> None:
        if self.event_type is not None and self.closure_due:
            raise RuleDefinitionError(
                _("Una condicion no puede combinar 'event_type' con 'closure_due'.")
            )
        if self.event_type is None and not self.closure_due:
            raise RuleDefinitionError(
                _("Una condicion debe definir 'event_type' o 'closure_due: true'.")
            )

    def matches_event(self, event: PluginEvent) -> bool:
        if self.event_type is None or event.event_type != self.event_type:
            return False
        if self.plugin_id is not None and event.plugin_id != self.plugin_id:
            return False
        return all(event.payload.get(key) == value for key, value in self.payload.items())

    def matches_closure(self, *, is_past_due: bool) -> bool:
        return self.closure_due and is_past_due

    def to_dict(self) -> dict[str, Any]:
        # Simetrico a from_dict(): agregado en M12f porque
        # ClosureCriteria.trigger_conditions (apate.core.models) ahora
        # persiste Condition dentro del JSON de la Operacion -- hasta
        # entonces nadie necesitaba serializar una Condition de vuelta,
        # las reglas solo se cargaban desde YAML.
        return {
            "event_type": self.event_type.value if self.event_type is not None else None,
            "plugin_id": self.plugin_id,
            "payload": dict(self.payload),
            "closure_due": self.closure_due,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Condition":
        # data.get(...) is not None (no solo "event_type" in data): to_dict()
        # ahora escribe la clave explicitamente incluso cuando vale None,
        # asi que un chequeo de sola presencia rompería el roundtrip de una
        # condicion closure_due=True (event_type=None) via EventType(None).
        event_type = EventType(data["event_type"]) if data.get("event_type") is not None else None
        return cls(
            event_type=event_type,
            plugin_id=data.get("plugin_id"),
            payload=dict(data.get("payload", {})),
            closure_due=bool(data.get("closure_due", False)),
        )


@dataclass
class Action:
    """Accion disparada por una regla. plugin_id=None en una accion de
    plugin (deploy/rotate/retire) significa 'todos los plugins
    registrados en el motor' - por ejemplo, el retiro masivo al cerrar
    la operacion."""

    kind: ActionKind
    plugin_id: Optional[str] = None
    to: Optional[OperationStatus] = None

    def __post_init__(self) -> None:
        if self.kind == ActionKind.TRANSITION:
            if self.to is None:
                raise RuleDefinitionError(_("Una accion 'transition' requiere el campo 'to'."))
            if self.to not in _VALID_TRANSITION_TARGETS:
                raise RuleDefinitionError(
                    _(
                        "'to' invalido para 'transition': '%(value)s' "
                        "(valores permitidos: %(allowed)s).",
                        value=self.to.value,
                        allowed=sorted(s.value for s in _VALID_TRANSITION_TARGETS),
                    )
                )
        elif self.to is not None:
            raise RuleDefinitionError(_("El campo 'to' solo es valido en acciones 'transition'."))

    def signatures(self) -> list[str]:
        """Representaciones en string de esta accion, para contrastar
        contra RulesOfEngagement.forbidden_actions/allowed_actions
        (M9, seccion 8 del documento de diseno): el tipo de accion
        solo (`"retire"`), el tipo mas el plugin_id (`"retire:mock-1"`)
        si aplica, y el tipo mas el destino si es una transicion
        (`"transition:closed"`). Una RoE puede prohibir/permitir a
        cualquiera de estos tres niveles de granularidad."""

        signatures = [self.kind.value]
        if self.plugin_id is not None:
            signatures.append(f"{self.kind.value}:{self.plugin_id}")
        if self.kind == ActionKind.TRANSITION and self.to is not None:
            signatures.append(f"{self.kind.value}:{self.to.value}")
        return signatures

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        kind = ActionKind(data["action"])
        to = OperationStatus(data["to"]) if "to" in data else None
        return cls(kind=kind, plugin_id=data.get("plugin_id"), to=to)


@dataclass
class Rule:
    """Una regla condicion-accion completa, con nombre para trazabilidad
    (queda registrado cual regla disparo cada accion, en linea con el
    enfoque auditable de la seccion 8 del documento de diseno)."""

    name: str
    when: Condition
    then: list[Action]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        # Se centraliza aca el manejo de errores de parseo (campo
        # faltante o valor invalido de un enum) para que quien cargue
        # reglas desde YAML solo tenga que atajar RuleDefinitionError,
        # sin conocer que Condition/Action puedan levantar KeyError o
        # ValueError por separado.
        try:
            return cls(
                name=data["name"],
                when=Condition.from_dict(data["when"]),
                then=[Action.from_dict(a) for a in data["then"]],
            )
        except KeyError as exc:
            raise RuleDefinitionError(_("Falta el campo obligatorio %(field)s en una regla.", field=exc)) from exc
        except ValueError as exc:
            raise RuleDefinitionError(_("Valor invalido en una regla: %(error)s", error=exc)) from exc


@dataclass
class RuleFiring:
    """Registro de que una regla se disparo y que acciones ejecuto.
    Pensado para la vista de defensor del modo Playground (M5,
    seccion 6.4 del diseno): esa vista necesita mostrar las decisiones
    tomadas por el motor de reglas, no solo la telemetria cruda que ya
    cubre la vista de Telemetria de M4b. Es un registro en memoria del
    RuleEngine (ver RuleEngine.history), no persistido a disco -- se
    documenta como limitacion conocida en docs/roadmap.md (M5)."""

    rule_name: str
    actions: list[Action]
    timestamp: datetime = field(default_factory=_utcnow)
    triggering_event_id: Optional[str] = None
    id: str = field(default_factory=_new_id)


@dataclass
class RejectedAction:
    """Registro de una accion que el RuleEngine NO ejecuto porque la
    RoE de la operacion la prohibe, se alcanzo el tope de acciones por
    cadena de eventos, o fallo al ejecutarse en un runtime que convierte
    esos errores en rechazo. Separado de RuleFiring/history a proposito:
    una revision de seguridad puede consultar especificamente que se
    bloqueo, sin inspeccionar cada disparo de regla uno por uno. Se
    conserva en memoria y, cuando el motor tiene repositorio, tambien se
    persiste por operacion junto al evento que lo disparo."""

    rule_name: str
    action: Action
    reason: str
    kind: RejectionKind
    timestamp: datetime = field(default_factory=_utcnow)
    triggering_event_id: Optional[str] = None
    id: str = field(default_factory=_new_id)


def parse_rules(yaml_text: str) -> list[Rule]:
    """Parsea un documento YAML con la forma {rules: [...]} a una lista
    de Rule. Cualquier problema con el documento -- sintaxis YAML
    invalida, una forma inesperada (el documento no es un mapping), o
    una regla mal formada -- se reporta como RuleDefinitionError: quien
    llama a parse_rules no necesita distinguir un error de YAML de un
    error de esquema de reglas (relevante para quien edita las reglas
    a mano, por ejemplo desde la interfaz web de M4b)."""

    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as exc:
        raise RuleDefinitionError(_("YAML invalido: %(error)s", error=exc)) from exc

    if not isinstance(data, dict):
        raise RuleDefinitionError(
            _(
                "El documento YAML debe ser un mapping con una clave 'rules', no %(tipo)s.",
                tipo=type(data).__name__,
            )
        )

    raw_rules = data.get("rules", [])
    return [Rule.from_dict(r) for r in raw_rules]


def load_rules(path: str) -> list[Rule]:
    """Carga y parsea un archivo YAML de reglas desde disco."""

    with open(path, "r", encoding="utf-8") as f:
        return parse_rules(f.read())
