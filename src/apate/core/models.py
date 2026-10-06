"""Nucleo de Operacion - modelo de datos central de APATE.

Implementa el objeto "Operacion" definido en la seccion 4.2 del
documento de diseno: perfil de adversario, Rules of Engagement,
narrativa, escenarios vinculados a TTPs, plugins asociados y
criterios de cierre. Es la unica fuente de verdad que consultan el
resto de los modulos (motor de decision, telemetria, Playground).

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
from typing import TYPE_CHECKING, Any, Optional

from ..i18n import gettext as _
from .exceptions import InvalidClosureCriteriaError, InvalidPluginBindingError, InvalidTransitionError

if TYPE_CHECKING:
    # Solo para chequeo de tipos -- ver el import diferido dentro de
    # ClosureCriteria.from_dict() y el docstring de ClosureCriteria para
    # por que esto no puede ser un import de nivel de modulo (ciclo
    # apate.core <-> apate.rules: apate.rules.models/engine ya importan
    # de apate.core.models al cargarse).
    from ..rules.models import Condition


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
    tambien en operaciones de produccion. Los cuatro valores son los
    profiles reales del docker-compose del Playground (ver
    docs/analisis-repos-existentes.md): no son tres como se asumio en
    una version anterior del diseno antes de revisar el repo real."""

    NONE = "none"
    BASIC = "basic"
    COMPLETE = "complete"
    IMPOSSIBLE = "impossible"


class Environment(str, Enum):
    """Entorno de despliegue de la operacion (paso 2 de la metodologia
    CTI-a-ciberengano)."""

    ISOLATED = "isolated"
    NEAR_PRODUCTION = "near_production"
    PRODUCTION = "production"
    PLAYGROUND = "playground"


class StrategicObjective(str, Enum):
    """Las cinco categorias de objetivo estrategico que exige el paso 2
    de la metodologia (paper Pacheco & Staino, ver
    docs/analisis-metodologia-cti.md) -- lista cerrada, no texto libre,
    para que `StrategicDecisions.objectives` sea consultable (ej. por
    apate.reporting en un hito futuro) en vez de texto sin estructura."""

    EARLY_DETECTION = "early_detection"
    INTELLIGENCE_COLLECTION = "intelligence_collection"
    DETERRENCE_ATTRITION = "deterrence_attrition"
    ATTRIBUTION = "attribution"
    CONTROLS_VALIDATION = "controls_validation"


@dataclass
class AdversaryProfile:
    """Producto del paso 1 de la metodologia: perfil de amenaza y TTPs
    priorizadas, contra que activos (M10 -- `target_assets`, ver
    docs/analisis-metodologia-cti.md: el paso 3 depende de saber contra
    que activos operar para mapear TTPs al entorno interno)."""

    name: str
    motivation: str = ""
    skill_level: str = "unknown"  # basic | intermediate | advanced | unknown
    expected_ttps: list[str] = field(default_factory=list)  # IDs ATT&CK, ej. "T1046"
    target_assets: list[str] = field(default_factory=list)  # activos criticos objetivo (M10)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "motivation": self.motivation,
            "skill_level": self.skill_level,
            "expected_ttps": list(self.expected_ttps),
            "target_assets": list(self.target_assets),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AdversaryProfile":
        return cls(
            name=data["name"],
            motivation=data.get("motivation", ""),
            skill_level=data.get("skill_level", "unknown"),
            expected_ttps=list(data.get("expected_ttps", [])),
            target_assets=list(data.get("target_assets", [])),
            notes=data.get("notes", ""),
        )


@dataclass
class RulesOfEngagement:
    """Producto del paso 2: limites operativos, legales y eticos de la
    operacion.

    `allowed_actions`/`forbidden_actions` no eran mas que texto
    guardado sin ningun efecto hasta M9 (hardening, seccion 8 del
    documento de diseno: "limites explicitos de accion para el motor
    de reglas"). `permits()` es el unico punto donde se interpretan:
    el RuleEngine (M3) lo consulta antes de ejecutar cada Action."""

    environment: Environment = Environment.ISOLATED
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    legal_constraints: list[str] = field(default_factory=list)
    escalation_contact: str = ""

    def permits(self, *signatures: str) -> bool:
        """True si ninguna de las `signatures` (ver Action.signatures()
        en apate.rules.models) figura en `forbidden_actions`, y -- si
        `allowed_actions` no esta vacia -- al menos una figura en
        `allowed_actions`. Una `allowed_actions` vacia NO restringe
        nada por defecto (en vez de bloquear todo): la mayoria de las
        operaciones nunca configuran una allowlist explicita, y
        tratarla como "nada permitido" romperia ese caso por defecto
        en lugar de dejarlo sin restringir, que es el comportamiento
        esperado hasta que un operador defina una allowlist a
        proposito."""

        if any(sig in self.forbidden_actions for sig in signatures):
            return False
        if self.allowed_actions and not any(sig in self.allowed_actions for sig in signatures):
            return False
        return True

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
class StrategicDecisions:
    """Los otros tres componentes del "documento de decisiones
    estrategicas" del paso 2 (M10, ver docs/analisis-metodologia-cti.md):
    RulesOfEngagement ya cubria entorno y reglas de interaccion/limites,
    pero no objetivos, roles ni estimacion de recursos -- se modela
    aparte, no se mezcla en RulesOfEngagement, porque el paper distingue
    "por que se hace" (objetivos) de "que se permite/prohibe" (RoE)."""

    objectives: list[StrategicObjective] = field(default_factory=list)
    roles: dict[str, str] = field(default_factory=dict)  # rol -> responsable (texto libre)
    resource_estimate: str = ""  # texto libre: nota de planificacion, no vale la pena estructurar mas

    def to_dict(self) -> dict[str, Any]:
        return {
            "objectives": [o.value for o in self.objectives],
            "roles": dict(self.roles),
            "resource_estimate": self.resource_estimate,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StrategicDecisions":
        return cls(
            objectives=[StrategicObjective(o) for o in data.get("objectives", [])],
            roles=dict(data.get("roles", {})),
            resource_estimate=data.get("resource_estimate", ""),
        )


@dataclass
class Narrative:
    """Historia unica compartida por todos los plugins activos en la
    operacion (paso 5 de la metodologia, seccion 4.2 del diseno)."""

    name: str
    description: str = ""
    similarity_percentage: int = 100  # 0-100, concepto tomado de BUDA
    story_elements: list[str] = field(default_factory=list)
    psychological_impact: str = ""  # sesgo cognitivo que la narrativa busca explotar (M10)

    def __post_init__(self) -> None:
        if not 0 <= self.similarity_percentage <= 100:
            raise ValueError(_("similarity_percentage debe estar entre 0 y 100"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "similarity_percentage": self.similarity_percentage,
            "story_elements": list(self.story_elements),
            "psychological_impact": self.psychological_impact,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Narrative":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            similarity_percentage=data.get("similarity_percentage", 100),
            story_elements=list(data.get("story_elements", [])),
            psychological_impact=data.get("psychological_impact", ""),
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
class DeceptionEffect:
    """Triple "Ver-Pensar-Hacer" de MITRE Engage que el paso 4 de la
    metodologia exige como contenido minimo de cada engano planificado
    (M10, ver docs/analisis-metodologia-cti.md). Lo que el adversario
    debe "Ver" ya esta representado por el propio plugin desplegado --
    no hay un campo para eso aca. Todos los campos default a "" (o
    lista vacia) para no romper `PluginBinding` existentes que no
    tenian esta informacion.

    `engage_activity_ids` (M12c, ver docs/analisis-engage-integral.md)
    vincula este efecto al catalogo real de actividades de MITRE
    Engage (`apate.engage`, M12a) -- IDs de `Activity`, no texto libre.
    Complementa, no reemplaza, los tres campos de texto libre de
    arriba: el catalogo da la actividad (el "que"), esos campos siguen
    dando el matiz especifico de esta operacion (el "como" puntual).
    Deliberadamente sin validar aca que cada id exista en el catalogo
    ni que sea de `kind == "engagement"` -- mismo criterio que
    `scenario_id` en `PluginBinding`: el dataclass no tiene por que
    conocer `apate.engage`, esa responsabilidad es de quien arma el
    formulario (el `<select>` de la interfaz web solo ofrece
    actividades `engagement` reales, ver apate.web.blueprints.
    operations.add_plugin_binding).

    `measured_outcome`/`measured_at`/`measured_by` (Fase 2 post-
    BlackHat, ver docs/roadmap.md) cierran el lazo que quedaba abierto
    desde M10: `success_metric` decia como reconocer el exito, pero
    nada registraba si eso efectivamente paso. Texto libre igual que
    `success_metric` (no un booleano "exitoso/fallido") porque lo que
    interesa auditar es la nota humana de que se observo, no solo un
    si/no. `measured_by` reusa el mismo operador de sesion que
    `apate.audit.OperatorAction` (Fase 1) sin ser un `OperatorAction`
    en si -- esto es un campo mas del dominio (como `success_metric`),
    no una accion de sistema contra un plugin/decoy real, asi que no
    entra en ese log de auditoria (mismo criterio que ya excluyo de
    ahi las altas de config como `add_scenario`/`add_plugin_binding`)."""

    expected_adversary_belief: str = ""  # Pensar
    expected_adversary_action: str = ""  # Hacer
    success_metric: str = ""
    engage_activity_ids: list[str] = field(default_factory=list)
    measured_outcome: str = ""
    measured_at: Optional[datetime] = None
    measured_by: str = ""
    evidence_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_adversary_belief": self.expected_adversary_belief,
            "expected_adversary_action": self.expected_adversary_action,
            "success_metric": self.success_metric,
            "engage_activity_ids": list(self.engage_activity_ids),
            "measured_outcome": self.measured_outcome,
            "measured_at": _iso(self.measured_at),
            "measured_by": self.measured_by,
            "evidence_event_ids": list(self.evidence_event_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeceptionEffect":
        return cls(
            expected_adversary_belief=data.get("expected_adversary_belief", ""),
            expected_adversary_action=data.get("expected_adversary_action", ""),
            success_metric=data.get("success_metric", ""),
            engage_activity_ids=list(data.get("engage_activity_ids", [])),
            measured_outcome=data.get("measured_outcome", ""),
            measured_at=_parse_dt(data.get("measured_at")),
            measured_by=data.get("measured_by", ""),
            evidence_event_ids=list(data.get("evidence_event_ids", [])),
        )


@dataclass
class PluginBinding:
    """Referencia a un plugin de capacidad (DOLOS-T, BUDA, honeytokens,
    o un mock) asociado a la operacion, con su configuracion
    especifica. La interfaz real del plugin se define en el modulo de
    integracion (M2 del roadmap); aqui solo se registra la asociacion.

    `scenario_id` (M10) vincula este binding al `Scenario` (paso 3) que
    implementa -- paso 4 de la metodologia. Deliberadamente sin
    validar aca que `scenario_id` exista en `Operation.scenarios`: el
    dataclass no tiene visibilidad de la `Operation` que lo contiene
    (se construye antes de o independiente de `bind_plugin()`), asi
    que esa validacion es responsabilidad de quien arma el binding --
    hoy, el formulario web de `apate.web` (que solo ofrece los
    escenarios ya cargados en la operacion via <select>); un
    `scenario_id` invalido no rompe nada estructuralmente, solo deja
    de resolver a un escenario real (ver `Operation.find_scenario()`).

    `plugin_kind` (M12h, ver `apate.plugins.registry.PluginRegistry`)
    declara explicitamente de que tipo es este binding (`"mock"`,
    `"honeytoken"`, `"dolost"`, `"buda"`...) -- reemplaza la convencion
    informal de prefijo de `plugin_id` (`_plugin_kind()` en
    `apate.web.blueprints.operations`, M11) que hasta ahora era la
    unica forma de resolver el tipo de un binding ya persistido.
    Deliberadamente sin validar aca contra `PluginRegistry.list_kinds()`
    (mismo criterio que `scenario_id`): el dataclass no tiene por que
    conocer `apate.plugins`, un kind invalido o `None` simplemente no
    resuelve a nada (`PluginRegistry.get()` sigue siendo quien valida,
    si y cuando algo intenta construir el plugin real a partir del
    kind). `None` por default a proposito -- es el estado real de todo
    binding persistido antes de M12h, y sigue siendo valido despues:
    el fallback heuristico de `_plugin_kind()` no desaparece, solo deja
    de ser la unica fuente de verdad.

    `leads_to_plugin_id` (referencia declarada: CounterCraft -- los
    "breadcrumbs" son las migas que acortan el camino del adversario
    hasta el engaño, conceptualmente distintas del recurso al que
    llevan). Relacion "esta capacidad ES la miga que lleva a aquella
    otra ya vinculada", opcional -- APATE ya tenia el vocabulario
    (`HoneytokenPlugin` coloca migas de archivo de verdad; el catalogo
    de Engage trae "Lures", EAC0005) pero nada en el modelo decia
    explicitamente que binding lleva a cual. Se evaluo una entidad
    `Breadcrumb` propia (mas grande) contra este campo de relacion (mas
    chico) sobre `PluginBinding` -- se eligio el campo: un honeytoken ya
    ES un `PluginBinding` como cualquier otro, no hace falta un tipo
    nuevo solo para decir a donde apunta, y cualquier binding (no solo
    honeytokens) puede en principio ser la miga que lleva a otro.

    Mismo criterio de validacion que `scenario_id`, con una excepcion
    deliberada: "el destino no existe" y "hay un ciclo" (A lleva a B,
    B lleva a A) necesitan visibilidad de `Operation.plugins`, que este
    dataclass no tiene -- no se validan aca, se resuelven con
    `Operation.find_plugin_binding()` y la capa de presentacion decide
    como mostrar una referencia rota o un ciclo (nunca revienta: un
    ciclo de un solo salto por binding no arriesga un recorrido
    recursivo, cada arista "lleva a" es independiente). "Apunta a si
    mismo" es distinto: es un invariante local (no depende de que mas
    haya en la Operacion), asi que SI se valida aca, en __post_init__,
    igual que `Condition`/`Action` (apate.rules.models) ya validan sus
    propios invariantes autocontenidos."""

    plugin_id: str
    surface: str  # "network" | "identity" | "data" | otra (seccion 4.4)
    config: dict[str, Any] = field(default_factory=dict)
    scenario_id: Optional[str] = None
    effect: DeceptionEffect = field(default_factory=DeceptionEffect)
    plugin_kind: Optional[str] = None
    leads_to_plugin_id: Optional[str] = None
    # Relación explícita con el inventario global: una capacidad concreta,
    # no el escenario que la agrupa, declara qué activo protege. Lista
    # aditiva para cargar bindings persistidos antes del mapa de activos.
    protected_asset_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.leads_to_plugin_id is not None and self.leads_to_plugin_id == self.plugin_id:
            raise InvalidPluginBindingError(
                _(
                    "'%(plugin_id)s' no puede ser su propio breadcrumb "
                    "(leads_to_plugin_id no puede coincidir con plugin_id).",
                    plugin_id=self.plugin_id,
                )
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "surface": self.surface,
            "config": dict(self.config),
            "scenario_id": self.scenario_id,
            "effect": self.effect.to_dict(),
            "plugin_kind": self.plugin_kind,
            "leads_to_plugin_id": self.leads_to_plugin_id,
            "protected_asset_ids": list(self.protected_asset_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PluginBinding":
        return cls(
            plugin_id=data["plugin_id"],
            surface=data["surface"],
            config=dict(data.get("config", {})),
            scenario_id=data.get("scenario_id"),
            effect=DeceptionEffect.from_dict(data.get("effect", {})),
            plugin_kind=data.get("plugin_kind"),
            leads_to_plugin_id=data.get("leads_to_plugin_id"),
            protected_asset_ids=list(data.get("protected_asset_ids", [])),
        )


@dataclass
class ExternalTelemetrySource:
    """Puente de telemetria externo configurable (primera de una tanda
    de tres tareas para ampliar el ecosistema que APATE orquesta --
    ver docs/roadmap.md). Generaliza `apate.playground.events.
    PlaygroundEventBridge`, que ya prueba que ese SEGUNDO modelo de
    integracion funciona: APATE tiene dos formas de sumar una
    herramienta externa, no una -- un `PluginBinding`/`DeceptionPlugin`
    completo (APATE controla el ciclo de vida: deploy/rotate/retire) o
    un puente de telemetria que solo INGIERE eventos, sin desplegar ni
    controlar nada. Este dataclass modela ese segundo caso a nivel de
    `Operation`, deliberadamente separado de `Operation.plugins` (una
    lista aparte, `Operation.telemetry_bridges`) en vez de reusar
    `PluginBinding`/`PluginRegistry` -- forzarlo a ese camino habria
    exigido una subclase de `DeceptionPlugin` con `deploy()`/`rotate()`/
    `retire()` sin sentido real (no hay ningun recurso que desplegar ni
    controlar), justo la distincion arquitectonica que esta tarea pide
    preservar explicitamente.

    `field_mapping` es el mapeo declarativo pedido: `dict[str, str]`
    de clave de payload (las mismas claves de convencion que ya
    reconoce el resto de APATE -- `ttp_id`/`detail`/`source_ip`/
    `credential`/`hash`/`domain`/`url`/`kind`, ver
    docs/plugin-event-contract.md seccion 3.3) a la ruta con puntos del
    campo real en el documento fuente (ej. `{"ttp_id": "mitre.
    technique_id", "detail": "message"}`). Deliberadamente NO es un
    motor de transformacion -- sin funciones, sin expresiones, un
    campo origen por cada clave de payload reconocida, exactamente lo
    que pidio la tarea. La traduccion real vive en
    `apate.telemetry.external_bridge.ExternalTelemetryBridge`, no aca
    -- este dataclass es solo la configuracion persistida.

    `last_fetch_at` (a diferencia de `PlaygroundSession.
    _last_elastic_fetch`, que vive solo en memoria porque una sesion de
    Playground es por definicion efimera) SI se persiste -- una
    Operacion real es de larga duracion, y perder el cursor en cada
    reinicio del proceso reingeriria documentos ya vistos cada vez
    (`TelemetryCollector` no deduplica, ver `PlaygroundSession`). `None`
    significa "nunca se consulto": quien orquesta el fetch (la ruta web)
    debe interpretar eso como "arrancar desde ahora", igual que ya hace
    `PlaygroundSession.create()`."""

    name: str
    elastic_url: str
    index: str
    surface: str = "network"
    timestamp_field: str = "@timestamp"
    field_mapping: dict[str, str] = field(default_factory=dict)
    last_fetch_at: Optional[datetime] = None
    id: str = field(default_factory=_new_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "elastic_url": self.elastic_url,
            "index": self.index,
            "surface": self.surface,
            "timestamp_field": self.timestamp_field,
            "field_mapping": dict(self.field_mapping),
            "last_fetch_at": _iso(self.last_fetch_at),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExternalTelemetrySource":
        return cls(
            id=data.get("id", _new_id()),
            name=data["name"],
            elastic_url=data["elastic_url"],
            index=data["index"],
            surface=data.get("surface", "network"),
            timestamp_field=data.get("timestamp_field", "@timestamp"),
            field_mapping=dict(data.get("field_mapping", {})),
            last_fetch_at=_parse_dt(data.get("last_fetch_at")),
        )


@dataclass
class ClosureCriteria:
    """Condiciones de cierre de la operacion -- "Gating Criteria" del paso 2
    de la metodologia (SAC0005 en el catalogo de MITRE Engage, ver
    `apate/data/mitre_engage_matrix.json`: "the unnegotiable pause or
    conclusion to the operation").

    `conditions: list[str]` es texto libre historico (M1), sin ningun
    efecto sobre el motor -- documenta intencion, no la aplica. `end_date`
    si tiene efecto real via `Operation.is_past_due()`, consultado desde
    `RuleEngine.check_closure()`.

    `trigger_conditions` (M12f, ver docs/analisis-engage-integral.md)
    cierra ese gap para el caso event-driven: reusa
    `apate.rules.models.Condition` (M3) en vez de reinventar un formato de
    condicion propio, para que "que dispara el cierre" quede en un formato
    estructurado y ejecutable, no solo documentado en `conditions`. Cada
    entrada debe ser una Condition orientada a evento (`event_type`
    definido, `closure_due=False`) -- una Condition con `closure_due=True`
    aca no tiene sentido, esa semantica de vencimiento ya la cubre
    `end_date`/`is_past_due()` por un camino completamente aparte
    (`RuleEngine.check_closure()`, sin acceso a eventos individuales).
    `RuleEngine.handle_event()` (no `check_closure()`) es quien evalua
    estas condiciones, una por evento entrante -- ver el docstring de
    `RuleEngine` sobre por que el cierre resultante NO pasa por
    `RulesOfEngagement.permits()`, a diferencia de una `Action` de una
    `Rule` comun."""

    end_date: Optional[datetime] = None
    conditions: list[str] = field(default_factory=list)
    trigger_conditions: list["Condition"] = field(default_factory=list)

    def __post_init__(self) -> None:
        for condition in self.trigger_conditions:
            self._validate_trigger_condition(condition)

    @staticmethod
    def _validate_trigger_condition(condition: "Condition") -> None:
        """Aplica el invariante event-driven también al mutar la lista.

        ``__post_init__`` protege la construcción/deserialización; el
        editor web necesita la misma validación antes de hacer append
        sobre un ``ClosureCriteria`` ya existente.
        """

        if condition.closure_due or condition.event_type is None:
            raise InvalidClosureCriteriaError(
                _(
                    "ClosureCriteria.trigger_conditions solo admite condiciones orientadas "
                    "a evento (event_type definido, closure_due=False) -- el cierre por "
                    "vencimiento ya se modela aparte con end_date/is_past_due()."
                )
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "end_date": _iso(self.end_date),
            "conditions": list(self.conditions),
            "trigger_conditions": [c.to_dict() for c in self.trigger_conditions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClosureCriteria":
        # Import diferido (no de nivel de modulo) para evitar el ciclo
        # apate.core <-> apate.rules -- ver el comentario junto al import
        # bajo TYPE_CHECKING, arriba en este archivo.
        from ..rules.models import Condition

        return cls(
            end_date=_parse_dt(data.get("end_date")),
            conditions=list(data.get("conditions", [])),
            trigger_conditions=[Condition.from_dict(c) for c in data.get("trigger_conditions", [])],
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
    telemetry_bridges: list[ExternalTelemetrySource] = field(default_factory=list)
    closure_criteria: ClosureCriteria = field(default_factory=ClosureCriteria)
    strategic_decisions: StrategicDecisions = field(default_factory=StrategicDecisions)
    behavior_context_source_ids: list[str] = field(default_factory=list)
    team_id: Optional[str] = None
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
                _(
                    "Transicion no permitida: %(current)s -> %(target)s "
                    "(permitidas desde '%(current)s': %(allowed)s)",
                    current=self.status.value,
                    target=new_status.value,
                    allowed=sorted(s.value for s in allowed) or _("ninguna"),
                )
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

    def add_trigger_condition(self, condition: "Condition") -> None:
        """Agrega una Gating Criteria event-driven y actualiza la operación."""

        self.closure_criteria._validate_trigger_condition(condition)
        self.closure_criteria.trigger_conditions.append(condition)
        self.updated_at = _utcnow()

    def remove_trigger_condition(self, index: int) -> None:
        """Elimina una Gating Criteria por su posición visible en la UI."""

        if index < 0 or index >= len(self.closure_criteria.trigger_conditions):
            raise IndexError(_("Índice de Gating Criteria fuera de rango: %(index)s.", index=index))
        del self.closure_criteria.trigger_conditions[index]
        self.updated_at = _utcnow()

    def add_telemetry_bridge(self, source: ExternalTelemetrySource) -> None:
        self.telemetry_bridges.append(source)
        self.updated_at = _utcnow()

    def select_behavior_context(self, source_ids: list[str]) -> None:
        """Reemplaza explícitamente las fuentes de preparación elegidas."""

        self.behavior_context_source_ids = list(dict.fromkeys(source_ids))
        self.updated_at = _utcnow()

    def find_scenario(self, scenario_id: Optional[str]) -> Optional[Scenario]:
        """Resuelve un `PluginBinding.scenario_id` (M10) al `Scenario`
        real, si existe -- `None` tanto si `scenario_id` es `None` como
        si no matchea ningun escenario cargado (ver el docstring de
        `PluginBinding` sobre por que eso no se valida al construir el
        binding). Pensado para que las vistas web y `apate.reporting`
        no dupliquen esta busqueda lineal."""

        if scenario_id is None:
            return None
        return next((s for s in self.scenarios if s.id == scenario_id), None)

    def find_plugin_binding(self, plugin_id: Optional[str]) -> Optional[PluginBinding]:
        """Resuelve un `plugin_id` (ej. `PluginBinding.leads_to_plugin_id`)
        al `PluginBinding` real, si existe -- `None` tanto si `plugin_id`
        es `None` como si no matchea ningun binding vinculado (mismo
        criterio que `find_scenario()`: la referencia no se valida al
        construir el binding, se resuelve aca). Pensado para que las
        vistas web no dupliquen esta busqueda lineal al mostrar la
        relacion "breadcrumb -> recurso"."""

        if plugin_id is None:
            return None
        return next((b for b in self.plugins if b.plugin_id == plugin_id), None)

    def find_telemetry_bridge(self, source_id: Optional[str]) -> Optional[ExternalTelemetrySource]:
        """Resuelve el `id` de un `ExternalTelemetrySource` al objeto
        real, si existe -- mismo criterio que `find_plugin_binding()`."""

        if source_id is None:
            return None
        return next((s for s in self.telemetry_bridges if s.id == source_id), None)

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
            "telemetry_bridges": [t.to_dict() for t in self.telemetry_bridges],
            "closure_criteria": self.closure_criteria.to_dict(),
            "strategic_decisions": self.strategic_decisions.to_dict(),
            "behavior_context_source_ids": list(self.behavior_context_source_ids),
            "team_id": self.team_id,
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
            telemetry_bridges=[
                ExternalTelemetrySource.from_dict(t) for t in data.get("telemetry_bridges", [])
            ],
            closure_criteria=ClosureCriteria.from_dict(data.get("closure_criteria", {})),
            strategic_decisions=StrategicDecisions.from_dict(data.get("strategic_decisions", {})),
            behavior_context_source_ids=list(data.get("behavior_context_source_ids", [])),
            team_id=data.get("team_id"),
            created_at=_parse_dt(data.get("created_at")) or _utcnow(),
            updated_at=_parse_dt(data.get("updated_at")) or _utcnow(),
            closed_at=_parse_dt(data.get("closed_at")),
        )
