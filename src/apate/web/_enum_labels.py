"""Etiquetas legibles en espanol para enums que se mostraban crudos en
la UI -- hallazgo real del usuario: varios enums tienen valores
snake_case de mas de una palabra (`StrategicObjective.EARLY_DETECTION`
= "early_detection", `Environment.NEAR_PRODUCTION` = "near_production",
`EventType.TTP_OBSERVED` = "ttp_observed") que, mostrados tal cual, se
leen como nombre de variable en vez de una frase. Frases cortas y
claras, no traducciones literales forzadas.

Los valores que forman parte de contratos editables, como las palabras
clave de `ActionKind` en el YAML, permanecen crudos. Los estados de
operacion y recursos, en cambio, se traducen solo en su texto visible;
su valor tecnico se conserva en clases CSS, formularios y atributos de
filtrado para no alterar ningun contrato.

Registradas como funciones de contexto Jinja globales
(`apate.web.create_app()`, `_inject_enum_labels()`) en vez de pasarse
por cada `render_template()`: los enums aparecen en templates de
blueprints distintos (`operations/form.html`/`detail.html`,
`playground/attacker.html`/`defender.html`, `telemetry/detail.html`) --
un unico context_processor evita repetir el cableo en cada vista,
mismo patron que `_inject_current_operator()` (Fase 1 post-BlackHat).
Cada funcion devuelve el valor crudo si el diccionario no lo cubre
(ej. un miembro de enum nuevo agregado sin actualizar este modulo) --
degradado, nunca un error de plantilla."""

from __future__ import annotations

from ..i18n import gettext as _
from ..i18n import gettext_noop as N_


TACTIC_LABELS: dict[str, str] = {
    "collection": N_("Recolección"),
    "command-and-control": N_("Comando y control"),
    "credential-access": N_("Acceso a credenciales"),
    "defense-evasion": N_("Evasión de defensas"),
    "discovery": N_("Descubrimiento"),
    "execution": N_("Ejecución"),
    "exfiltration": N_("Exfiltración"),
    "impact": N_("Impacto"),
    "initial-access": N_("Acceso inicial"),
    "lateral-movement": N_("Movimiento lateral"),
    "persistence": N_("Persistencia"),
    "privilege-escalation": N_("Escalada de privilegios"),
    "resource-development": N_("Desarrollo de recursos"),
}

STRATEGIC_OBJECTIVE_LABELS: dict[str, str] = {
    "early_detection": N_("Detección temprana"),
    "intelligence_collection": N_("Recolección de inteligencia"),
    "deterrence_attrition": N_("Disuasión y desgaste"),
    "attribution": N_("Atribución"),
    "controls_validation": N_("Validación de controles"),
}

ENVIRONMENT_LABELS: dict[str, str] = {
    "isolated": N_("Aislado"),
    "near_production": N_("Cercano a producción"),
    "production": N_("Producción"),
    "playground": N_("Playground"),
}

EVENT_TYPE_LABELS: dict[str, str] = {
    "interaction": N_("Interacción"),
    "ttp_observed": N_("TTP observada"),
}

OPERATION_STATUS_LABELS: dict[str, str] = {
    "planning": N_("En preparación"),
    "active": N_("Activa"),
    "compromised": N_("Comprometida"),
    "closed": N_("Cerrada"),
}

RESOURCE_STATUS_LABELS: dict[str, str] = {
    "pending": N_("Pendiente"),
    "active": N_("Activa"),
    "archived": N_("Archivada"),
}

OUTCOME_LABELS: dict[str, str] = {
    "success": N_("Completada"),
    "failed": N_("Fallida"),
}

DECEPTION_LEVEL_LABELS: dict[str, str] = {
    "none": N_("Sin engaño"),
    "basic": N_("Básico"),
    "complete": N_("Completo"),
    "impossible": N_("Imposible"),
}


def strategic_objective_label(value: str) -> str:
    return _(STRATEGIC_OBJECTIVE_LABELS[value]) if value in STRATEGIC_OBJECTIVE_LABELS else value


def environment_label(value: str) -> str:
    return _(ENVIRONMENT_LABELS[value]) if value in ENVIRONMENT_LABELS else value


def event_type_label(value: str) -> str:
    return _(EVENT_TYPE_LABELS[value]) if value in EVENT_TYPE_LABELS else value


def operation_status_label(value: str) -> str:
    return _(OPERATION_STATUS_LABELS[value]) if value in OPERATION_STATUS_LABELS else value


def resource_status_label(value: str) -> str:
    return _(RESOURCE_STATUS_LABELS[value]) if value in RESOURCE_STATUS_LABELS else value


def outcome_label(value: str) -> str:
    return _(OUTCOME_LABELS[value]) if value in OUTCOME_LABELS else value


def deception_level_label(value: str) -> str:
    """Etiqueta visible del nivel de engaño sin alterar su valor persistido."""

    return _(DECEPTION_LEVEL_LABELS[value]) if value in DECEPTION_LEVEL_LABELS else value


def tactic_label(value: str) -> str:
    return _(TACTIC_LABELS[value]) if value in TACTIC_LABELS else value

def capability_kind_label(kind: str) -> str:
    """Nombre legible de un `kind` de capacidad, para mostrarlo en vez del
    valor tecnico. La fuente es el registro de capacidades, no un diccionario
    propio: duplicarlo aca obligaria a mantener dos listas en sync.

    El `kind` en si (`"dolost"`, `"buda"`) no cambia nunca -- es la clave de
    los entry points, se persiste en `PluginBinding.plugin_kind` y viaja en
    los formularios. Solo se traduce el texto visible, mismo criterio que el
    resto de este modulo. Un kind que el registro no conoce vuelve crudo.
    """

    from ..plugins import PluginRegistry
    from ..plugins.exceptions import PluginConfigError

    if not kind:
        return kind
    try:
        return PluginRegistry.describe(kind).display_name
    except PluginConfigError:
        return kind


PROVIDER_LABELS: dict[str, str] = {"APATE": "Apate"}


def provider_label(value: str) -> str:
    """Nombre visible del proveedor de una capacidad.

    El proveedor distingue lo que viene con la herramienta de lo que aporta un
    tercero (Canarytokens, OpenCanary). El valor interno sigue siendo
    `"APATE"` **a proposito**: viaja como parametro de URL
    (`/telemetry/<id>?provider=APATE`), se compara contra los filtros del
    catalogo y de Telemetria, y queda guardado en las vistas de filtros que el
    operador se arma en su navegador. Traducir el valor romperia esos enlaces
    y esas vistas; traducir solo el texto no rompe nada.

    Es el mismo criterio que el resto de este modulo aplica a los estados de
    operacion y a los `kind` de capacidad, y la razon por la que el renombre
    del producto a Apate no toco ningun contrato tecnico (ver
    `docs/plan-renombre-parallax.md`, fase 4).
    """

    return PROVIDER_LABELS.get(value, value)


def criticality_label(value: str) -> str:
    """Criticidad de un activo tal como la muestra el resto de la aplicacion.

    La fuente es `apate.assets.CRITICALITY_LABELS`, no un diccionario propio:
    el inventario ya traduce con ese mismo mapa en sus tres pantallas, y
    duplicarlo aca es exactamente lo que dejo divergir los dos vocabularios la
    vez anterior (el CSV rechazaba las etiquetas que la interfaz mostraba).

    El valor persistido (`"critical"`) no cambia: es contrato, viaja en el CSV
    y en el `value` de los `<option>`. Solo se traduce el texto visible, mismo
    criterio que el resto de este modulo.
    """

    from ..assets import CRITICALITY_LABELS

    return CRITICALITY_LABELS.get(value, value)
