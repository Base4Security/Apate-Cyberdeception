"""Árbol visual de solo lectura de una operación (referencia declarada:
CounterCraft, cuyo producto usa el "attack tree" como estructura base de
cada campaña -- toda la operación de un vistazo, con estado por nodo).

**Confirmado antes de construir esto: no había ningún grafo real en toda
la app.** `apate.web._deception_path` (M-anterior, "Camino visual de
engaño") ya arma nodos/aristas persistidos, pero los renderiza como
columnas de botones por capa (`.deception-graph`) más una tabla aparte de
relaciones -- nunca dibuja una línea real conectando un nodo con otro. Y
la cadena plegable de `operations/detail.html` ("Relaciones de la
operación") es apenas un resumen de 5 números con flechas de texto, sin
un nodo por item. Ninguno de los dos es un árbol.

**Este módulo no reemplaza a ninguno de los dos -- conviven, cada uno
responde una pregunta distinta:**
- "Relaciones de la operación" (resumen): cuántos hay, de un vistazo,
  sin cargar nada más.
- "Camino visual de engaño" (`_deception_path`): lente EVIDENCIAL --
  adversario/TTPs/capacidades/recursos/eventos observados, para razonar
  sobre qué pasó.
- Este árbol (`_operation_tree`): lente ESTRUCTURAL -- exactamente la
  jerarquía de configuración de la metodología (paso 3 → paso 4 → lo que
  cada binding produce), para ver de un vistazo CÓMO está armada la
  operación, no qué se observó. Deliberadamente no incluye eventos/TTPs
  del adversario como nodos propios (ver diseño abajo) -- eso ya lo
  cubren los otros dos.

**Forma exigida por la tarea:** Operación → Escenario (paso 3) →
PluginBinding (paso 4) → {actividades de Engage, efecto Ver-Pensar-Hacer
+ resultado medido, recurso concreto con su estado real}. Un
`PluginBinding` sin escenario asignado cuelga de un bucket "Sin escenario
asignado" explícito -- nunca desaparece.

**Decisión de agrupamiento del cuarto nivel:** en vez de tres líneas de
conector por binding (una por actividad de Engage, una por el efecto, una
por cada recurso), las tres se agrupan en UNA sola tarjeta de detalle por
binding, conectada 1:1. Mismo contenido completo que pedía la tarea, sin
explotar en decenas de nodos diminutos cuando un binding tiene varias
actividades de Engage o varios decoys -- más escaneable, sigue mostrando
el estado individual de cada recurso (cada decoy/perfil/honeytoken/
Canarytoken/OpenCanary conserva su propio estado real) dentro de esa
tarjeta.

**Resolución de estado de recursos, reusada, no reimplementada:**
`apate.web._deception_path.capability_state()`/`capability_resources()`
(extraídas de esa misma lógica que `build_deception_path()` ya tenía
inline) interpretan los cinco paneles de despliegue exactamente igual
acá que en el camino de engaño -- si esa interpretación cambia, un solo
lugar para actualizar.

**Resolución de kind, deliberadamente NO la misma que usa
`build_deception_path()`:** ese módulo usa el heurístico más simple
posible (`binding.plugin_kind or plugin_id.split("-", 1)[0]`, sin validar
contra el registro). Acá se usa
`apate.web._portfolio._resolve_portfolio_plugin_kind()` (M13g, ya
importada así por `_engage_preparation.py`) -- valida contra
`PluginRegistry.list_kinds()` y documenta su propio fallback. Confirmado
que las dos coinciden en todos los casos que le importan a
`capability_state()`/`capability_resources()` (dispatch por kind
canónico); solo difieren para bindings
legacy sin `plugin_kind` explícito y con prefijo "honeytoken-"/"mock-",
un caso que no puede existir en la práctica -- la convención informal de
prefijo pre-M12h (`_plugin_kind()`, `apate.web.blueprints.operations`)
documenta explícitamente que solo cubrió "dolost"/"buda"."""

from __future__ import annotations

from typing import Any, Optional

from ..core.models import Operation, PluginBinding
from ..i18n import gettext as _
from ..i18n import gettext_noop as N_
from ..engage import get_activity
from ..plugins import PluginRegistry
from ..plugins.exceptions import PluginConfigError
from ..reporting import compare_ttps
from ._deception_path import capability_resources, capability_state
from ._portfolio import _resolve_portfolio_plugin_kind

# Se marcan con `gettext_noop` y se traducen al leerlas: el diccionario se
# construye al importar el modulo, cuando todavia no hay request ni idioma
# resuelto. Mismo criterio que `_enum_labels`.
STATE_LABELS = {
    "planned": N_("Planificado"),
    "deployed": N_("Desplegado"),
    "active": N_("Activo"),
    "observed": N_("Observado"),
    "unknown": N_("Estado desconocido"),
}


def state_label(state: Optional[str]) -> Optional[str]:
    """Etiqueta traducida de un estado de capacidad, con degradado al valor
    crudo si no esta cubierto -- mismo criterio que `_enum_labels`."""
    if state is None:
        return None
    etiqueta = STATE_LABELS.get(state)
    return _(etiqueta) if etiqueta else state

# Kinds con un concepto real de "recurso concreto desplegado" -- mock no
# administra ningún recurso externo (ver docstring de
# `MockHoneypotPlugin.retire()`, M9), así que no tiene sentido mostrarle
# un placeholder "sin recurso configurado": simplemente no aplica.
_KINDS_WITH_RESOURCES = {"dolost", "buda", "honeytoken", "canarytoken", "opencanary"}


def _binding_kind(binding: PluginBinding) -> Optional[str]:
    return _resolve_portfolio_plugin_kind(binding)


def _kind_label(kind: Optional[str]) -> Optional[str]:
    """Nombre legible de un kind de capacidad, tomado del registro. Devuelve
    None si no hay kind (el template ya cae a "Capacidad"), y el valor crudo
    si el registro no lo conoce -- mismo degradado que `_enum_labels`."""

    if not kind:
        return None
    try:
        return PluginRegistry.describe(kind).display_name
    except PluginConfigError:
        # El kind puede venir del heuristico de prefijo del plugin_id
        # (`_resolve_portfolio_plugin_kind`), que no valida contra el
        # registro: un binding "midecoy-1" produce "midecoy". Mostrar el
        # valor crudo es preferible a tirar abajo el arbol entero.
        return kind


def _binding_entry(
    binding: PluginBinding,
    *,
    operation: Operation,
    plugin_ids_with_events: set[str],
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict],
    opencanary_panels: dict[str, dict],
    leads_from_plugin_ids: list[str],
) -> dict[str, Any]:
    kind = _binding_kind(binding)
    dispatch_kind = binding.plugin_kind or binding.plugin_id.split("-", 1)[0]
    observed = binding.plugin_id in plugin_ids_with_events
    state = capability_state(
        dispatch_kind,
        binding.plugin_id,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        observed=observed,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    resources = capability_resources(
        dispatch_kind,
        binding,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    engage_activities = [
        activity
        for activity in (get_activity(activity_id) for activity_id in binding.effect.engage_activity_ids)
        if activity is not None
    ]
    effect_has_content = bool(
        binding.effect.expected_adversary_belief
        or binding.effect.expected_adversary_action
        or binding.effect.success_metric
    )
    leads_to_target = operation.find_plugin_binding(binding.leads_to_plugin_id)
    return {
        "binding": binding,
        "anchor_id": f"capability:{binding.plugin_id}",
        "kind": kind,
        # Etiqueta visible: el `kind` es el valor tecnico ("dolost", "buda")
        # y se mostraba crudo en el nodo, en mayuscula por CSS ("DOLOST").
        # La fuente unica del nombre legible es el registro de capacidades,
        # no un diccionario paralelo que haya que mantener en sync.
        "kind_label": _kind_label(kind),
        "state": state,
        "state_label": state_label(state),
        "engage_activities": engage_activities,
        "effect_has_content": effect_has_content,
        "resources": resources,
        "resource_supported": dispatch_kind in _KINDS_WITH_RESOURCES,
        # Breadcrumbs (referencia declarada: CounterCraft) -- "lleva a"
        # (saliente, PluginBinding.leads_to_plugin_id) y "recibe una
        # miga de" (entrante, calculado una sola vez en
        # build_operation_tree() invirtiendo el mapa saliente) se
        # muestran los dos: sin esto, el destino de una miga no tendria
        # forma de saber que algo lo señala sin recorrer todos los
        # demas bindings.
        "leads_to_plugin_id": binding.leads_to_plugin_id,
        "leads_to_target_anchor_id": f"capability:{leads_to_target.plugin_id}" if leads_to_target else None,
        "leads_to_broken": binding.leads_to_plugin_id is not None and leads_to_target is None,
        "leads_from_plugin_ids": leads_from_plugin_ids,
    }


def build_operation_tree(
    operation: Operation,
    telemetry_records: list,
    *,
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict] | None = None,
    opencanary_panels: dict[str, dict] | None = None,
) -> dict[str, Any]:
    """Arma la jerarquía Operación → Escenario → PluginBinding →
    detalle, con estado en vivo por nodo donde exista el dato. Solo
    lectura -- no muta nada, capa de presentación pura sobre lo que
    `Operation`/los paneles de mecánica específica ya exponen."""

    canarytoken_panels = canarytoken_panels or {}
    opencanary_panels = opencanary_panels or {}
    observed_ttp_ids = {record.ttp_id for record in telemetry_records if record.ttp_id}
    plugin_ids_with_events = {record.plugin_id for record in telemetry_records}

    # Mapa entrante (destino -> lista de plugin_id que le "llevan" una
    # miga), invertido una sola vez acá -- solo cuenta una referencia
    # que SI resuelve a un binding real (una rota no es "recibida" por
    # nadie, ver leads_to_broken en _binding_entry()).
    incoming_breadcrumbs: dict[str, list[str]] = {}
    for source in operation.plugins:
        if source.leads_to_plugin_id and operation.find_plugin_binding(source.leads_to_plugin_id) is not None:
            incoming_breadcrumbs.setdefault(source.leads_to_plugin_id, []).append(source.plugin_id)

    bindings_by_scenario: dict[Optional[str], list[PluginBinding]] = {}
    for binding in operation.plugins:
        scenario = operation.find_scenario(binding.scenario_id)
        key = scenario.id if scenario is not None else None
        bindings_by_scenario.setdefault(key, []).append(binding)

    scenarios: list[dict[str, Any]] = []
    for scenario in operation.scenarios:
        ttp_stats = None
        if scenario.related_ttps:
            comparison = compare_ttps(scenario.related_ttps, observed_ttp_ids)
            ttp_stats = {
                "matched": len(comparison.matched_ttps),
                "not_observed": len(comparison.ttps_not_observed),
                "total": len(scenario.related_ttps),
            }
        scenarios.append(
            {
                "scenario": scenario,
                "unassigned": False,
                "label": scenario.description,
                "anchor_id": f"scenario:{scenario.id}",
                "ttp_stats": ttp_stats,
                "bindings": [
                    _binding_entry(
                        binding,
                        operation=operation,
                        plugin_ids_with_events=plugin_ids_with_events,
                        dolost_panels=dolost_panels,
                        buda_panels=buda_panels,
                        honeytoken_panels=honeytoken_panels,
                        canarytoken_panels=canarytoken_panels,
                        opencanary_panels=opencanary_panels,
                        leads_from_plugin_ids=incoming_breadcrumbs.get(binding.plugin_id, []),
                    )
                    for binding in bindings_by_scenario.get(scenario.id, [])
                ],
            }
        )

    unassigned_bindings = bindings_by_scenario.get(None, [])
    if unassigned_bindings:
        scenarios.append(
            {
                "scenario": None,
                "unassigned": True,
                "label": "Sin escenario asignado",
                "anchor_id": "scenario:unassigned",
                "ttp_stats": None,
                "bindings": [
                    _binding_entry(
                        binding,
                        operation=operation,
                        plugin_ids_with_events=plugin_ids_with_events,
                        dolost_panels=dolost_panels,
                        buda_panels=buda_panels,
                        honeytoken_panels=honeytoken_panels,
                        canarytoken_panels=canarytoken_panels,
                        opencanary_panels=opencanary_panels,
                        leads_from_plugin_ids=incoming_breadcrumbs.get(binding.plugin_id, []),
                    )
                    for binding in unassigned_bindings
                ],
            }
        )

    has_content = bool(operation.scenarios) or bool(operation.plugins)
    return {"scenarios": scenarios, "has_content": has_content}
