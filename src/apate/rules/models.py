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

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import yaml

from ..core.models import OperationStatus
from ..plugins.base import EventType, PluginEvent
from .exceptions import RuleDefinitionError

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
                "Una condicion no puede combinar 'event_type' con 'closure_due'."
            )
        if self.event_type is None and not self.closure_due:
            raise RuleDefinitionError(
                "Una condicion debe definir 'event_type' o 'closure_due: true'."
            )

    def matches_event(self, event: PluginEvent) -> bool:
        if self.event_type is None or event.event_type != self.event_type:
            return False
        if self.plugin_id is not None and event.plugin_id != self.plugin_id:
            return False
        return all(event.payload.get(key) == value for key, value in self.payload.items())

    def matches_closure(self, *, is_past_due: bool) -> bool:
        return self.closure_due and is_past_due

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Condition":
        event_type = EventType(data["event_type"]) if "event_type" in data else None
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
                raise RuleDefinitionError("Una accion 'transition' requiere el campo 'to'.")
            if self.to not in _VALID_TRANSITION_TARGETS:
                raise RuleDefinitionError(
                    f"'to' invalido para 'transition': '{self.to.value}' "
                    f"(valores permitidos: {sorted(s.value for s in _VALID_TRANSITION_TARGETS)})."
                )
        elif self.to is not None:
            raise RuleDefinitionError("El campo 'to' solo es valido en acciones 'transition'.")

    def signatures(self) -> list[str]:
        """Devuelve las claves de autorización general y específica."""

        result = [self.kind.value]
        if self.plugin_id is not None:
            result.append(f"{self.kind.value}:{self.plugin_id}")
        if self.kind == ActionKind.TRANSITION and self.to is not None:
            result.append(f"{self.kind.value}:{self.to.value}")
        return result

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
            raise RuleDefinitionError(f"Falta el campo obligatorio {exc} en una regla.") from exc
        except ValueError as exc:
            raise RuleDefinitionError(f"Valor invalido en una regla: {exc}") from exc


def parse_rules(yaml_text: str) -> list[Rule]:
    """Parsea un documento YAML con la forma {rules: [...]} a una lista
    de Rule."""

    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as exc:
        raise RuleDefinitionError(f"YAML inválido: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules", []), list):
        raise RuleDefinitionError("El documento debe contener una lista 'rules'.")
    raw_rules = data.get("rules", [])
    return [Rule.from_dict(r) for r in raw_rules]


def load_rules(path: str) -> list[Rule]:
    """Carga y parsea un archivo YAML de reglas desde disco."""

    with open(path, "r", encoding="utf-8") as f:
        return parse_rules(f.read())
