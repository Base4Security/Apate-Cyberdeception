"""Vista de Operaciones (M4b): listar, crear, ver detalle y disparar
transiciones de estado sobre el Nucleo de Operacion (M1). No agrega
logica de negocio nueva - solo expone JSONFileOperationRepository y
los metodos de Operation ya existentes (mark_active/mark_compromised/
close) a traves de formularios HTML.

Desde la fase de construccion de la UI oscura unificada, este modulo
tambien arma el Despliegue contextual anidado bajo cada operacion: el
mapa por escenario/superficie y los paneles de decoys, narrativas,
perfiles, actividades y honeytokens que correspondan a sus bindings.
Mantiene la clasificacion "operacion" vs. "mecanica especifica":
las pantallas de gestion de operationsdb.json (DOLOS-T) y del
title/objective/attacker_profile/end_date de Narrative (BUDA) quedan
fuera de la navegacion de APATE -- lo que si necesitaba pantalla
nuevo es el control de esos recursos dentro del objeto Operation.

Nota sobre el ciclo de vida de los plugins en estas rutas: cada accion
HTTP construye una instancia nueva del plugin (no hay
un registro de instancias vivas entre requests, a diferencia del
`plugins={...}` que arma RuleEngine dentro de una PlaygroundSession) --
`PluginLifecycleState` arranca en CREATED en cada instancia nueva, sin
importar el estado real. Eso alcanza sin ajustes para deploy()
(siempre espera CREATED), pero rotate()/retire() esperan DEPLOYED:
para esos casos se reconcilia el estado real justo antes de invocar el
metodo, contra la fuente de verdad externa que corresponda -- el
`Narrative.is_running` persistido de BUDA para el panel de narrativa
(confiable), la existencia completa de archivos para HoneytokenPlugin,
o simplemente forzando el estado para DOLOS-T (no hay un
bit persistido equivalente a nivel de PluginBinding, simplificacion
deliberada de esta tanda, ver resumen de la construccion de UI)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
from flask import Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from BUDA.app import db as _buda_db
from BUDA.models import Activity as BudaActivity
from BUDA.models import Narrative as BudaNarrative
from BUDA.models import UserProfile as BudaUserProfile
from DOLOST.blueprints.api import clean_decoy as _dolost_clean_decoy, deploy_decoy as _dolost_deploy_decoy
from DOLOST.services.docker_manager import DockerManager as _DolostDockerManager

from ...attack import list_groups as _list_attack_groups
from ...attack import catalog_provenance as _attack_catalog_provenance
from ...attack import list_techniques as _list_attack_techniques
from ...audit import OperatorAction
from ...assets import (
    Asset,
    AssetNotFoundError,
    CRITICALITY_LABELS,
    list_suggestible_asset_types as _list_suggestible_asset_types,
    suggest_capabilities_for_asset as _suggest_capabilities_for_asset,
)
from ...core import (
    AdversaryProfile,
    BehaviorContextStatus,
    ClosureCriteria,
    DeceptionEffect,
    DeceptionLevel,
    Environment,
    ExternalTelemetrySource,
    Narrative,
    Operation,
    OperationNotFoundError,
    OperationStatus,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
    StrategicDecisions,
    StrategicObjective,
)
from ...core.exceptions import InvalidClosureCriteriaError, InvalidPluginBindingError, InvalidTransitionError
from ...cti import CTIExtractionError, extract_candidates, extract_text
from ...engage import get_activity as _get_engage_activity
from ...engage import list_activities as _list_engage_activities
from ...engage import list_approaches as _list_engage_approaches
from ...engage import list_goals as _list_engage_goals
from ...engage import suggest_activities as _suggest_engage_activities
from ...engage import suggest_activities_for_objectives as _suggest_engage_activities_for_objectives
from ...i18n import gettext as _
from ...plugins import (
    BudaPlugin,
    CanarytokenPlugin,
    DeceptionPlugin,
    DolosTPlugin,
    EventBus,
    EventType,
    HoneytokenPlugin,
    OpenCanaryPlugin,
    PluginConfigError,
    PluginLifecycleState,
    PluginRegistry,
    PluginStateError,
)
from ...plugins.exceptions import CanarytokenAPIError, OpenCanaryError
from ...plugins.opencanary_client import container_name as _opencanary_container_name
from ...plugins.opencanary_client import container_status as _opencanary_container_status
from ...plugins.operation import build_operation_plugins
from ...reporting import OperationReport, compare_ttps, generate_report, generate_workshop_kit, simulate_dry_run
from ...rules import Condition, RuleDefinitionError, RuleEngine, parse_rules
from ...telemetry import ExternalTelemetryBridge
from ...telemetry.exceptions import ExternalTelemetryError
from .._dashboard import dashboard_kpis as _dashboard_kpis
from .._asset_coverage import build_asset_coverage
from .._rule_engine_runtime import attach_operation_save_listener, build_rule_bus, build_rule_engine
from ..access import visible_operations
from .._enum_labels import operation_status_label
from .._engage_preparation import preparation_coverage as _preparation_coverage
from .._deception_path import build_deception_path
from .._narrative_coherence import build_narrative_coherence
from .._operational_metrics import build_operation_metrics
from .._operation_center import build_operation_center, build_operation_list_attention
from .._operation_timeline import operation_timeline as _operation_timeline
from .._operation_timeline import recent_rule_firings as _recent_rule_firings
from .._operation_templates import describe_next_steps as _describe_template_next_steps
from .._operation_templates import get_template as _get_operation_template
from .._operation_templates import list_templates as _list_operation_templates
from .._operation_templates import resolve_operation_fields as _resolve_template_operation_fields
from .._operation_tree import build_operation_tree
from .._operation_tree_graphml import operation_tree_to_graphml
from .._portfolio import build_portfolio
from .._ttp_presentation import techniques_by_tactic as _techniques_by_tactic
from .._ttp_presentation import ttp_heatmap as _ttp_heatmap

operations_bp = Blueprint("operations", __name__, url_prefix="/operations")

_SKILL_LEVELS = ["basic", "intermediate", "advanced", "unknown"]
_ROE_ACTION_KINDS = ("deploy", "rotate", "retire", "transition")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

# Campos de un decoy de DOLOS-T, mismo set que ya usa su propio modal
# "Add Decoy" (templates/view_operation.html en DOLOS-T) -- se
# reutiliza el nombre exacto de cada campo para no inventar un formato
# nuevo, ya que termina viviendo tal cual en PluginBinding.config["decoys"]
# y lo consume dolost_plugin.py/DOLOST.blueprints.api sin traducirlo.
_DOLOST_DECOY_FIELDS = [
    "Hostname",
    "Description",
    "IP",
    "Subnet",
    "Gateway",
    "DeceptionNetwork",
    "ServicePorts",
    "Service",
    "DecoyFiles",
]


def _build_dolost_decoy(form) -> Optional[dict]:
    """Arma el dict de un decoy de DOLOS-T a partir de un formulario
    (mismos campos que `_DOLOST_DECOY_FIELDS`) -- compartido entre
    `dolost_add_decoy()` (formulario dedicado de "Mecanica especifica")
    y `add_plugin_binding()` (decoy inline opcional al vincular, ver
    docstring de esa funcion). `None` si no llego ningun `Hostname` --
    deliberadamente no decide aca si eso es un error (lo es para
    `dolost_add_decoy()`, un formulario cuyo unico proposito es cargar
    un decoy) o algo valido y opcional (lo es para `add_plugin_binding()`,
    donde el decoy es un extra sobre el binding en si); esa decision
    queda en cada llamador."""

    decoy = {field: form.get(field, "") for field in _DOLOST_DECOY_FIELDS}
    if not decoy["Hostname"]:
        return None
    return decoy


def _create_buda_narrative_from_operation(operation: Operation) -> BudaNarrative:
    """Obtiene o crea la `Narrative` de BUDA derivada de esta `Operation`.

    El título de una narrativa creada por este flujo es el nombre exacto de la
    operación. Reutilizarlo evita que reintentos del mismo POST, o un seed que
    retoma una operación persistida, acumulen narrativas idénticas sin perder
    la posibilidad de vincular la existente.

    BUDA sigue necesitando su propio title/objective/
    attacker_profile/end_date internamente (no se toca ese repo), asi
    que en vez de pedirselos de nuevo al usuario se completan como
    placeholder a partir de la Operation/AdversaryProfile/Narrative que
    la contiene. Compartido entre `buda_create_narrative()` (formulario
    dedicado de "Mecanica especifica") y `add_plugin_binding()`
    (narrativa inline opcional al vincular). No toca
    `PluginBinding.config` ni guarda la `Operation` -- eso es
    responsabilidad de quien llama, que tiene el binding a mano."""

    existing = BudaNarrative.query.filter_by(title=operation.name).order_by(BudaNarrative.id).first()
    if existing is not None:
        return existing

    end_date = operation.closure_criteria.end_date
    end_date = end_date.date() if end_date is not None else (date.today() + timedelta(days=90))

    objectives = ", ".join(o.value for o in operation.strategic_decisions.objectives)
    attacker_profile = (
        f"{operation.adversary_profile.name} ({operation.adversary_profile.skill_level}) - "
        f"{operation.adversary_profile.motivation or 'sin motivacion registrada'}"
    )

    narrative = BudaNarrative(
        title=operation.name,
        objective=objectives or operation.adversary_profile.motivation or "Sin objetivo definido en la operacion.",
        attacker_profile=attacker_profile,
        deception_activities=operation.narrative.description or "",
        percentage_of_similarity=operation.narrative.similarity_percentage,
        end_date=end_date,
        is_running=False,
    )
    _buda_db.session.add(narrative)
    _buda_db.session.commit()
    return narrative


def _engagement_activities_by_goal() -> list[dict]:
    """Actividades de Engage agrupadas por Goal -> Approach para el
    selector de "Vincular plugin" (M12c) -- solo `kind == "engagement"`
    (las 23 Expose/Affect/Elicit). Las 8 `strategic` (Prepare/Understand)
    quedan afuera a proposito: son de nivel operacion (paso 2: objetivos/
    roles/recursos, ya cubierto por `StrategicDecisions` desde M10), no
    de un `PluginBinding` puntual.

    Una misma Activity puede pertenecer a mas de un Approach (ver
    `apate.engage.catalog`, ej. "Lures" en Detect/Direct/Disrupt) -- por
    eso puede aparecer repetida bajo mas de un grupo, fiel a como la
    matriz visual real de Engage la muestra en mas de una celda. No es
    un error de este agrupado, es el catalogo real."""

    result = []
    for goal in _list_engage_goals():
        if goal.kind != "engagement":
            continue
        approaches = []
        for approach in _list_engage_approaches(goal_id=goal.id):
            activities = _list_engage_activities(approach_id=approach.id, kind="engagement")
            if activities:
                approaches.append({"approach": approach, "activities": activities})
        if approaches:
            result.append({"goal": goal, "approaches": approaches})
    return result


def _parse_end_date(raw: str) -> Optional[datetime]:
    """Convierte el valor de un `<input type="date">` (YYYY-MM-DD, o
    vacio si el operador no lo completo) a un datetime aware en UTC,
    mismo formato que `_iso()`/`_parse_dt()` esperan en
    `ClosureCriteria.end_date` (apate.core.models) -- M12f, gap total de
    UI cerrado ahora que se toco este formulario para trigger_conditions.

    **Apunta al final del dia elegido, no a su comienzo** (E8 de
    docs/improvements.md). Antes devolvia la medianoche de esa fecha, asi
    que elegir la fecha de hoy dejaba la operacion vencida en el instante
    en que se guardaba (`Operation.is_past_due()` compara
    `now >= end_date`). Quien elige una fecha de cierre quiere operar
    *durante* ese dia. Estaba enmascarado porque nada llamaba a
    `RuleEngine.check_closure()` (E7); se corrige antes de conectarlo.
    """

    raw = raw.strip()
    if not raw:
        return None
    return datetime.combine(date.fromisoformat(raw), datetime.max.time(), tzinfo=timezone.utc)


def _parse_comma_list(raw: str) -> list[str]:
    """Mismo parseo que ya usaba `expected_ttps` (unico patron de lista
    que tenia el formulario antes de M10): separado por comas, sin
    entradas vacias. Reutilizado para `target_assets`."""

    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_roe_signatures(raw: str) -> list[str]:
    """Lee firmas de RoE, una por línea, y valida su tipo de acción.

    Una firma puede ser el tipo completo (``retire``) o una variante
    acotada (``retire:mock-1`` / ``transition:closed``). El segundo
    segmento queda libre porque puede ser un ``plugin_id`` real de la
    operación o un destino de transición; lo importante para no guardar
    una regla que el motor jamás podría reconocer es validar el tipo.
    """

    signatures = [line.strip() for line in raw.splitlines() if line.strip()]
    invalid = [signature for signature in signatures if signature.split(":", 1)[0] not in _ROE_ACTION_KINDS]
    if invalid:
        raise ValueError(
            "Las firmas de acciones deben comenzar con deploy, rotate, retire o transition: "
            + ", ".join(invalid)
        )
    if any(signature.endswith(":") for signature in signatures):
        raise ValueError("Cada firma granular debe incluir un identificador después de ':'.")
    return signatures


def _unique_action_signatures(action_kinds: list[str], granular_signatures: str) -> list[str]:
    """Une los checkboxes y el texto libre preservando su orden."""

    return list(dict.fromkeys([*action_kinds, *_parse_roe_signatures(granular_signatures)]))


def _parse_honeytoken_filenames(raw: str) -> list[str]:
    """Valida nombres simples para no escapar del directorio elegido."""

    filenames = [item.strip() for item in raw.replace(",", "\n").splitlines() if item.strip()]
    if not filenames:
        raise ValueError("Configurá al menos un nombre de archivo honeytoken.")
    if any(name in (".", "..") or "/" in name or "\\" in name or Path(name).name != name for name in filenames):
        raise ValueError("Los honeytokens deben usar nombres de archivo simples, sin rutas.")
    return filenames


def _parse_roles(raw: str) -> dict[str, str]:
    """`StrategicDecisions.roles` es un dict (rol -> responsable), no
    una lista -- no encaja en el patron de "un valor por linea" que
    pide el hito para listas. Se usa la misma idea (un textarea, una
    entrada por linea) pero con el formato 'rol: responsable' por
    linea; una linea sin ':' se descarta en silencio (mismo criterio
    minimalista que el resto del formulario, que hoy tampoco valida
    'environment' contra el enum antes de construir RulesOfEngagement)."""

    roles: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        role, _, responsible = line.partition(":")
        role, responsible = role.strip(), responsible.strip()
        if role:
            roles[role] = responsible
    return roles


def _parse_opencanary_services(raw: str) -> dict[str, dict]:
    """Un servicio de OpenCanary por línea, formato `servicio:puerto`
    (ej. `ssh:2222`) -- mismo criterio de textarea simple que
    `_parse_roles()`/`_parse_honeytoken_filenames()`, deliberadamente no
    un JSON/YAML de `opencanary_client.build_config()` completo: cubre
    el caso común (habilitar un servicio en un puerto) sin que el
    operador tenga que conocer el formato interno real de
    `opencanary.conf`. Una línea sin ':' o con un puerto no numérico se
    descarta en silencio (mismo criterio minimalista que `_parse_roles()`).
    Necesidades avanzadas (una clave extra por servicio, ej.
    `ssh.banner`) quedan fuera de este parser -- se pueden agregar
    programáticamente a `PluginBinding.config["services"]`, mismo
    criterio que `extra_fields` de Canarytokens."""

    services: dict[str, dict] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, _, port_raw = line.partition(":")
        name, port_raw = name.strip(), port_raw.strip()
        if not name or not port_raw.isdigit():
            continue
        services[name] = {"enabled": True, "port": int(port_raw)}
    return services


def _format_opencanary_services(services: dict[str, dict]) -> str:
    """Inverso de `_parse_opencanary_services()`, para precargar el
    textarea de configuración -- solo refleja servicios habilitados con
    un `port` simple (el caso que el parser cubre); un `services` armado
    programáticamente con claves extra no se puede reeditar entero desde
    este textarea, mismo límite documentado en el parser."""

    return "\n".join(
        f"{name}:{options['port']}"
        for name, options in services.items()
        if options.get("enabled") and options.get("port")
    )


# Mapea el valor del campo 'to' del formulario de transicion al metodo
# de Operation que lo aplica: centralizarlo aca evita un if/elif largo
# y deja explicito que estas son las unicas tres transiciones que la
# UI puede disparar (igual que hace el motor de reglas en M3).
_TRANSITION_METHODS = {
    "active": Operation.mark_active,
    "compromised": Operation.mark_compromised,
    "closed": Operation.close,
}


# -- Paneles "Decoys DOLOS-T" / "Narrativa BUDA" (ver docstring del modulo) --


def _plugin_kind(binding: PluginBinding) -> Optional[str]:
    """`"dolost"` / `"buda"` / `None`.

    Fuente de verdad primaria (M12h): `binding.plugin_kind`, si esta
    seteado explicitamente -- sin ambiguedad, es lo que el operador (o
    quien armo el binding programaticamente) declaro. Solo se acepta
    tal cual si es uno de los dos kinds que estos paneles entienden
    ("dolost"/"buda"); cualquier otro valor explicito (por ejemplo
    "mock"/"honeytoken", validos en `PluginRegistry` pero sin panel
    propio aca) resuelve a `None`, igual que si no hubiera kind.

    Si `plugin_kind` es `None` (todo binding persistido antes de M12h,
    y sigue siendo un valor valido despues), cae al heuristico de
    prefijo de `plugin_id` **como fallback legacy** -- la convencion
    informal que usaban `examples/quickstart.py` y los tests de M8c
    (`"dolost-1"`, `"buda-1"`) antes de que existiera un campo
    explicito. No se puede "migrar" esos bindings ya persistidos sin
    una migracion aparte (fuera de alcance de M12h), asi que este
    fallback se queda -- documentado como tal, no como el camino
    principal."""

    if binding.plugin_kind in ("dolost", "buda"):
        return binding.plugin_kind
    if binding.plugin_kind is not None:
        return None

    # -- Fallback legacy (pre-M12h): heuristico de prefijo de plugin_id --
    plugin_id = binding.plugin_id.lower()
    if plugin_id.startswith("dolost"):
        return "dolost"
    if plugin_id.startswith("buda"):
        return "buda"
    return None


def _deployment_kind(binding: PluginBinding) -> Optional[str]:
    """Resuelve cualquier kind registrado para organizar Despliegue.

    ``_plugin_kind()`` se mantiene acotado a los dos adaptadores externos
    por compatibilidad histórica. Esta variante incorpora honeytokens,
    mocks y terceros sin cambiar aquel contrato.
    """

    return PluginRegistry.resolve_binding_kind(binding)


def _deployment_groups(operation: Operation) -> list[dict]:
    """Agrupa bindings primero por escenario y luego por superficie."""

    groups: dict[str, dict] = {}
    for binding in operation.plugins:
        scenario = operation.find_scenario(binding.scenario_id)
        key = scenario.id if scenario is not None else "unassigned"
        group = groups.setdefault(
            key,
            {
                "scenario": scenario,
                "label": scenario.description if scenario is not None else "Sin escenario asignado",
                "surfaces": {},
            },
        )
        group["surfaces"].setdefault(binding.surface or "Sin superficie", []).append(
            {"binding": binding, "kind": _deployment_kind(binding)}
        )
    return [
        {**group, "surfaces": [{"name": name, "items": items} for name, items in group["surfaces"].items()]}
        for group in groups.values()
    ]


def _require_plugin_kind(binding: PluginBinding, expected: str) -> None:
    if _plugin_kind(binding) != expected:
        abort(400, f"'{binding.plugin_id}' no resuelve a un plugin de tipo '{expected}'.")


def _find_binding_or_404(operation: Operation, plugin_id: str) -> PluginBinding:
    for binding in operation.plugins:
        if binding.plugin_id == plugin_id:
            return binding
    abort(404)


def _rules_in_operation_scope(operation: Operation) -> tuple[list[dict], Optional[str]]:
    """Clasifica las reglas globales según las capacidades de una operación.

    Esto describe alcance potencial, no ejecuciones ni una instancia nueva
    del motor: fuera de Playground no hay RuleEngine suscripto al bus de la
    operación. Una condición sin ``plugin_id`` puede aplicar a cualquier
    operación; una que sí lo declara solo aplica cuando ese binding existe.
    """

    rules_path = Path(current_app.config["APATE_RULES_PATH"])
    try:
        rules = parse_rules(rules_path.read_text(encoding="utf-8"))
    except (OSError, RuleDefinitionError) as exc:
        return [], _("No se pudo cargar el documento global de reglas: %(exc)s", exc=exc)

    plugin_ids = {binding.plugin_id for binding in operation.plugins}
    scoped_rules = []
    for rule in rules:
        plugin_id = rule.when.plugin_id
        applies = plugin_id is None or plugin_id in plugin_ids
        if plugin_id is None:
            scope_message = _("No filtra por capacidad: puede aplicar a esta operación.")
        elif applies:
            scope_message = _("La condición referencia la capacidad vinculada '%(plugin_id)s'.", plugin_id=plugin_id)
        else:
            scope_message = _("La condición referencia '%(plugin_id)s', que no está vinculada a esta operación.", plugin_id=plugin_id)
        scoped_rules.append({"rule": rule, "applies": applies, "scope_message": scope_message})
    return scoped_rules, None


def _resolve_target_asset_reference(operation: Operation, reference: str, asset_identifier: str) -> None:
    """Sustituye una referencia manual por una ficha elegida explícitamente.

    La sustitución también migra las coberturas que apuntaban exactamente a la
    referencia vieja. No es inferencia: al resolver esa fila, el operador
    afirma que ambos textos representan el mismo activo objetivo. Dejar la
    cobertura en la cadena anterior convertiría una declaración válida en una
    referencia huérfana sin aportar ninguna señal adicional.
    """

    targets = operation.adversary_profile.target_assets
    if reference not in targets:
        abort(400, _("La referencia ya no es un activo objetivo de esta operación."))

    operation.adversary_profile.target_assets = list(
        dict.fromkeys(asset_identifier if target == reference else target for target in targets)
    )
    for binding in operation.plugins:
        binding.protected_asset_ids = list(
            dict.fromkeys(asset_identifier if asset_id == reference else asset_id for asset_id in binding.protected_asset_ids)
        )


def _find_decoy_or_404(binding: PluginBinding, hostname: str) -> dict:
    for decoy in binding.config.get("decoys", []):
        if decoy.get("Hostname") == hostname:
            return decoy
    abort(404)


def _plugin_bus() -> EventBus:
    """Bus efímero con telemetría para una acción HTTP o un puente externo."""

    bus = EventBus()
    current_app.config["TELEMETRY_COLLECTOR"].attach(bus)
    return bus


def _manual_plugin(
    operation: Operation,
    binding: PluginBinding,
    plugin_class: type[DeceptionPlugin],
) -> DeceptionPlugin:
    """Construye la instancia manual y la registra ante el motor del request.

    La misma instancia se entrega al motor mediante ``supplied``: evitar una
    segunda instancia para el mismo recurso conserva el estado local que la
    ruta acaba de reconciliar antes de publicar el evento. Las reglas globales
    se leen en cada request, sin caché ni estado persistente de motor.
    """

    bus = build_rule_bus()
    executor = current_app.config["OPERATION_EXECUTOR"]
    if executor.managed(operation.id):
        from ...ledger.plugins import approved_plugins
        from ...ledger import LedgerError
        plugins = approved_plugins(executor, operation.id, bus)
        plugin = plugins.get(binding.plugin_id)
        if plugin is None or not isinstance(plugin.plugin, plugin_class):
            raise LedgerError("approved_capability_required")
    else:
        plugin = plugin_class.from_binding(binding, operation_id=operation.id, bus=bus)
    engine = build_rule_engine(
        operation=operation,
        bus=bus,
        plugins=build_operation_plugins(operation, bus, supplied={binding.plugin_id: plugin}),
    )
    if engine is not None:
        attach_operation_save_listener(bus, operation)
    return plugin


def _log_operator_action(
    operation_id: str,
    *,
    action: str,
    outcome: str,
    detail: str,
    plugin_id: Optional[str] = None,
    target: Optional[str] = None,
) -> None:
    """Registra una accion manual de operador (Fase 1 post-BlackHat,
    ver docs/roadmap.md) -- distinto de `RuleFiring`/`RuleEngine.
    history`, que audita al motor de reglas y se persiste aparte en
    `RULE_DECISION_REPOSITORY`. Esto es lo
    simetrico para decisiones humanas: quien hizo que, cuando, sobre que
    capacidad, desde los paneles nativos de despliegue -- ninguno de los
    cuales pasa por la guarda de RoE, aunque el evento que publican si se
    evalua contra las reglas globales (ver revision de seguridad post-
    vendorizado sobre el alcance de RoE). Sin usuarios configurados el
    operador conserva el texto libre histórico; desde el primer usuario,
    la sesión guarda solo `identity_id` y se resuelve su display_name.
    El fallback conserva la atribución aunque una sesión inválida llegue a
    esta función fuera de la guarda global."""

    repo = current_app.config["OPERATOR_ACTION_REPOSITORY"]
    identity_id = session.get("identity_id")
    identity = (
        current_app.config["IDENTITY_PROVIDER"].get(identity_id)
        if isinstance(identity_id, str)
        else None
    )
    repo.append(
        OperatorAction(
            operation_id=operation_id,
            action=action,
            operator=(identity.display_name if identity else session.get("operator")) or _("sin especificar"),
            outcome=outcome,
            detail=detail,
            plugin_id=plugin_id,
            target=target,
        )
    )


def _available_identity_teams() -> list[str]:
    """Devuelve las etiquetas de equipo ya existentes en identidades locales.

    Un equipo no es una entidad independiente: se deriva de las identidades
    para no adelantar un CRUD ni inventar datos que nadie usa todavía.
    """

    identities = getattr(current_app.config["IDENTITY_PROVIDER"], "list", None)
    if not callable(identities):
        return []
    return sorted(
        {identity.team_id for identity in identities() if identity.team_id},
        key=str.casefold,
    )


def _deploy_one_binding(operation: Operation, binding: PluginBinding, *, strict: bool) -> dict[str, str]:
    """Despliega un binding y devuelve un reporte normalizado.

    ``strict=True`` conserva el comportamiento de las rutas
    individuales (estado no preparado => fallo explícito). ``strict=False``
    es el modo de campaña completa: estado no preparado => salteado.
    """

    kind = _deployment_kind(binding)
    executor = current_app.config["OPERATION_EXECUTOR"]
    if executor.managed(operation.id) and kind in {"opencanary", "dolost", "buda", "playground"}:
        from ...ledger.plugins import approved_plugins
        bus = build_rule_bus()
        try:
            plugins = approved_plugins(executor, operation.id, bus)
            build_rule_engine(operation=operation, bus=bus, plugins=plugins)
            plugins[binding.plugin_id].deploy()
        except Exception as exc:
            return {"kind": kind, "action": "deploy", "outcome": "failed", "detail": str(exc), "plugin_id": binding.plugin_id}
        return {"kind": kind, "action": "deploy", "outcome": "success", "detail": _("La acción aprobada terminó; consultá el registro para verificar su resultado."), "plugin_id": binding.plugin_id}
    if kind is None:
        return {
            "kind": "unknown",
            "action": "deploy",
            "outcome": "skipped" if not strict else "failed",
            "detail": _("No se pudo resolver tipo de binding para '%(plugin_id)s'.", plugin_id=binding.plugin_id),
            "plugin_id": binding.plugin_id,
        }

    if kind == "mock":
        return {
            "kind": "mock",
            "action": "deploy",
            "outcome": "skipped",
            "detail": _("'%(plugin_id)s' no tiene despliegue manual.", plugin_id=binding.plugin_id),
            "plugin_id": binding.plugin_id,
        }

    if kind == "honeytoken":
        plugin = _manual_plugin(operation, binding, HoneytokenPlugin)
        try:
            paths = plugin.configured_paths()
        except Exception as exc:
            detail = _("No se detectó configuración de honeytokens de '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc)
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "failed" if strict else "skipped",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        if not paths:
            detail = _("No se pudo desplegar honeytokens de '%(plugin_id)s': no está configurado.", plugin_id=binding.plugin_id)
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "failed" if strict else "skipped",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        existing = [path for path in paths if path.exists()]
        if existing:
            # Un honeytoken es indistinguible de un archivo real por
            # contenido (a propósito, ver HoneytokenPlugin) -- "el path ya
            # existe" NUNCA alcanza para asumir "ya lo desplegamos nosotros".
            # Solo lo tratamos como ya desplegado si el propio binding trae
            # el flag que ESTE deploy dejó la vez anterior; cualquier otro
            # archivo preexistente (real o de otro origen) sigue fallando
            # cerrado, igual que la ruta individual original.
            if binding.config.get("_apate_deployed") and all(path in existing for path in paths):
                return {
                    "kind": kind,
                    "action": "honeytoken_deploy",
                    "outcome": "already_deployed",
                    "detail": _("Honeytokens de '%(plugin_id)s' ya estaban desplegados.", plugin_id=binding.plugin_id),
                    "plugin_id": binding.plugin_id,
                }
            detail = _("El despliegue no sobrescribe archivos existentes: %(paths)s", paths=", ".join(str(path) for path in existing))
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "failed",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        try:
            directory = Path(binding.config["directory"])
        except Exception:
            detail = _("No se pudo desplegar honeytokens de '%(plugin_id)s': directorio inválido.", plugin_id=binding.plugin_id)
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "failed",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        try:
            directory_existed = directory.exists()
            plugin.deploy()
            binding.config["_apate_created_directory"] = not directory_existed
            binding.config["_apate_deployed"] = True
            # Las credenciales senuelo se generan por despliegue (E5 de
            # docs/improvements.md) y `self.config` del plugin es una copia
            # de la del binding, asi que hay que traerlas de vuelta: sin
            # esto, un rotate() posterior -- instancia nueva -- generaria
            # credenciales distintas de las que hay en el archivo.
            # getattr: los dobles de prueba del dispatcher son stand-ins
            # minimos que solo implementan lo que la ruta necesita, y no
            # tienen por que crecer para esto.
            generadas = getattr(plugin, "config", {}).get("fake_credentials")
            if generadas:
                binding.config["fake_credentials"] = generadas
            # Punto de referencia inicial para check_access() (E2): sin
            # esto el primer chequeo solo puede fijar el baseline "ahora"
            # -- la instancia del deploy muere con el request -- y el
            # primer acceso real se pierde en silencio.
            exportar = getattr(plugin, "export_baseline", None)
            if callable(exportar):
                binding.config["_apate_access_baseline"] = exportar()
            current_app.config["OPERATION_REPOSITORY"].save(operation)
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "success",
                "detail": _("Honeytokens de '%(plugin_id)s' desplegados (%(count)s archivo(s)).", plugin_id=binding.plugin_id, count=len(paths)),
                "plugin_id": binding.plugin_id,
            }
        except Exception as exc:
            return {
                "kind": kind,
                "action": "honeytoken_deploy",
                "outcome": "failed",
                "detail": _("No se pudieron desplegar los honeytokens de '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc),
                "plugin_id": binding.plugin_id,
            }

    if kind == "canarytoken":
        panel = _canarytoken_panel_data(binding)
        if panel["deployed"]:
            return {
                "kind": kind,
                "action": "canarytoken_deploy",
                "outcome": "already_deployed",
                "detail": _("Canarytoken de '%(plugin_id)s' ya estaba creado.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        if not panel["configured"]:
            detail = _("No se pudo crear el canarytoken de '%(plugin_id)s': falta configuración previa.", plugin_id=binding.plugin_id)
            return {
                "kind": kind,
                "action": "canarytoken_deploy",
                "outcome": "failed" if strict else "skipped",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        plugin = _manual_plugin(operation, binding, CanarytokenPlugin)
        try:
            plugin.deploy()
            binding.config.update(plugin.config)
            current_app.config["OPERATION_REPOSITORY"].save(operation)
            return {
                "kind": kind,
                "action": "canarytoken_deploy",
                "outcome": "success",
                "detail": _("Canarytoken de '%(plugin_id)s' creado.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        except (PluginConfigError, PluginStateError, CanarytokenAPIError) as exc:
            return {
                "kind": kind,
                "action": "canarytoken_deploy",
                "outcome": "failed",
                "detail": _("No se pudo crear el canarytoken de '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc),
                "plugin_id": binding.plugin_id,
            }

    if kind == "opencanary":
        panel = _opencanary_panel_data(binding)
        if panel["deployed"]:
            return {
                "kind": kind,
                "action": "opencanary_deploy",
                "outcome": "already_deployed",
                "detail": _("OpenCanary de '%(plugin_id)s' ya estaba desplegado.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        if not panel["configured"]:
            detail = _("No se pudo desplegar OpenCanary de '%(plugin_id)s': no está configurado.", plugin_id=binding.plugin_id)
            return {
                "kind": kind,
                "action": "opencanary_deploy",
                "outcome": "failed" if strict else "skipped",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }

        plugin = _manual_plugin(operation, binding, OpenCanaryPlugin)
        try:
            plugin.deploy()
            binding.config.update(plugin.config)
            current_app.config["OPERATION_REPOSITORY"].save(operation)
            return {
                "kind": kind,
                "action": "opencanary_deploy",
                "outcome": "success",
                "detail": _("OpenCanary de '%(plugin_id)s' desplegado.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        except (PluginStateError, OpenCanaryError) as exc:
            return {
                "kind": kind,
                "action": "opencanary_deploy",
                "outcome": "failed",
                "detail": _("No se pudo desplegar OpenCanary de '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc),
                "plugin_id": binding.plugin_id,
            }

    if kind == "dolost":
        plugin = _manual_plugin(operation, binding, DolosTPlugin)
        try:
            plugin.deploy()
            return {
                "kind": kind,
                "action": "dolost_deploy",
                "outcome": "success",
                "detail": _("Decoys de red: collector y decoys de '%(plugin_id)s' desplegados.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        except Exception as exc:
            return {
                "kind": kind,
                "action": "dolost_deploy",
                "outcome": "failed",
                "detail": _("No se pudo desplegar '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc),
                "plugin_id": binding.plugin_id,
            }

    if kind == "buda":
        narrative = _resolve_buda_narrative(binding)
        if narrative is None:
            detail = _('Esta operación no tiene ninguna narrativa de comportamiento vinculada.')
            return {
                "kind": kind,
                "action": "buda_start",
                "outcome": "failed" if strict else "skipped",
                "detail": detail,
                "plugin_id": binding.plugin_id,
            }
        if narrative.is_running:
            return {
                "kind": kind,
                "action": "buda_start",
                "outcome": "already_deployed",
                "detail": _("La narrativa ya está corriendo."),
                "plugin_id": binding.plugin_id,
            }

        plugin = _manual_plugin(operation, binding, BudaPlugin)
        try:
            plugin.deploy()
            return {
                "kind": kind,
                "action": "buda_start",
                "outcome": "success",
                "detail": _("Comportamiento simulado: narrativa de '%(plugin_id)s' iniciada.", plugin_id=binding.plugin_id),
                "plugin_id": binding.plugin_id,
            }
        except (PluginConfigError, PluginStateError) as exc:
            return {
                "kind": kind,
                "action": "buda_start",
                "outcome": "failed",
                "detail": str(exc),
                "plugin_id": binding.plugin_id,
            }
        except Exception as exc:
            return {
                "kind": kind,
                "action": "buda_start",
                "outcome": "failed",
                "detail": _("No se pudo iniciar la narrativa de '%(plugin_id)s': %(exc)s", plugin_id=binding.plugin_id, exc=exc),
                "plugin_id": binding.plugin_id,
            }

    return {
        "kind": kind,
        "action": "deploy",
        "outcome": "failed" if strict else "skipped",
        "detail": _("Tipo '%(kind)s' de '%(plugin_id)s' no soportado para despliegue.", kind=kind, plugin_id=binding.plugin_id),
        "plugin_id": binding.plugin_id,
    }


def _dolost_panel_data(binding: PluginBinding) -> dict:
    """Decoys configurados (`PluginBinding.config["decoys"]`) mas su
    estado real en Docker, calculado igual que `DOLOST.blueprints.
    views::view_operation()` (mismo prefijo `/DolosT-<Hostname>` sobre
    `DockerManager.get_containers()`) -- no se reimplementa el acceso
    a Docker, se reutiliza el mismo `DockerManager` que ya usa
    `dolost_plugin.py`. Si Docker no esta configurado/alcanzable,
    `docker_available` queda en False y cada decoy se muestra con
    estado desconocido en vez de que la pagina rompa con un 500."""

    from .._managed_panels import managed_panel
    managed = managed_panel(binding)
    if managed is not None:
        return managed
    decoys = binding.config.get("decoys", [])
    try:
        containers = _DolostDockerManager.get_instance().get_containers(all=True)
    except Exception:
        containers = None

    rows = []
    for decoy in decoys:
        hostname = decoy.get("Hostname", "")
        container_name = f"/DolosT-{hostname}"
        # Los dos textos de respaldo se traducen; el que devuelve Docker no
        # ("Up 3 minutes"), y es el unico que alimenta la deteccion de `up`.
        status = _("desconocido")
        up = None
        if containers is not None:
            status = _("no desplegado")
            up = False
            for container in containers:
                if container_name in container.get("Names", []):
                    status = container.get("Status", _("desconocido"))
                    up = status.lower().startswith("up")
                    break
        rows.append({"decoy": decoy, "hostname": hostname, "status": status, "up": up})

    return {"decoys": rows, "docker_available": containers is not None}


def _resolve_buda_narrative(binding: PluginBinding):
    """`None` si el binding todavia no tiene `narrative_id` en su
    config, o si ese id ya no resuelve a una Narrative real de BUDA
    (por ejemplo, borrada desde /buda/narratives/ directamente)."""

    narrative_id = binding.config.get("narrative_id")
    if narrative_id is None:
        return None
    return _buda_db.session.get(BudaNarrative, narrative_id)


def _buda_panel_data(binding: PluginBinding) -> dict:
    """Solo expone `is_running` y los `UserProfile` vinculados (id/
    nombre/rol/servidor WinRM, mas los tipos de actividad ya asignados
    a cada uno -- M14d, "vista de revision" nativa, ver
    docs/roadmap.md seccion M14) -- nunca `title`/`objective`/
    `attacker_profile`/`end_date` de la Narrative de BUDA (quedan
    redundantes con la Operation que contiene el binding, decision de
    la clasificacion ya acordada) ni `winrm_username`/`winrm_password`
    (nunca se leen esos atributos aca, para no descifrarlos siquiera
    de forma incidental -- mismo criterio de no-exposicion que
    `HoneytokenPlugin`, ver M9; el original `narrative_review.html` de
    BUDA si muestra `winrm_username` en texto plano, a proposito no
    replicado aca)."""

    from .._managed_panels import managed_panel
    managed = managed_panel(binding)
    if managed is not None:
        return managed
    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        return {"found": False, "narrative_id": binding.config.get("narrative_id"), "is_running": None, "user_profiles": []}

    return {
        "found": True,
        "narrative_id": narrative.id,
        "is_running": narrative.is_running,
        "user_profiles": [
            {
                "id": profile.id,
                "name": profile.name,
                "role": profile.role,
                "winrm_server": profile.winrm_server,
                "credentials_recoverable": profile.credentials_recoverable,
                "activities": [
                    {"id": activity.id, "activity_type": activity.activity_type, "details": activity.details}
                    for activity in profile.activities
                ],
            }
            for profile in narrative.user_profiles
        ],
    }


def _honeytoken_panel_data(binding: PluginBinding, operation_id: str) -> dict:
    """Estado de archivos real sin leer su contenido ni credenciales."""

    plugin = HoneytokenPlugin.from_binding(binding, operation_id=operation_id, bus=EventBus())
    try:
        paths = plugin.configured_paths()
    except Exception:
        paths = []
    existing = [path.is_file() for path in paths]
    return {
        "configured": bool(paths),
        "directory": binding.config.get("directory", ""),
        "filenames": [path.name for path in paths],
        "ttp_id": binding.config.get("ttp_id", "T1552.001"),
        "paths": [{"path": str(path), "exists": exists} for path, exists in zip(paths, existing)],
        "deployed": bool(paths) and all(existing),
        "partial": any(existing) and not all(existing),
    }


def _canarytoken_panel_data(binding: PluginBinding) -> dict:
    """Estado real de un binding de Canarytokens, leído solo de
    `binding.config` -- a diferencia de `_honeytoken_panel_data()` (que
    sí consulta el filesystem), acá no hace falta ninguna consulta real
    (ni de red, ni de disco) para saber si está configurado/desplegado:
    la identidad completa (`token`/`auth_token`) vive en config. Nunca
    incluye `auth_token` -- mismo criterio que `_buda_panel_data()` con
    `winrm_username`/`winrm_password`."""

    config = binding.config
    return {
        "base_url": config.get("base_url", ""),
        "token_type": config.get("token_type", ""),
        "memo": config.get("memo", ""),
        "email": config.get("email", ""),
        "ttp_id": config.get("ttp_id", ""),
        "configured": bool(config.get("base_url") and config.get("token_type") and config.get("memo") and config.get("email")),
        "deployed": bool(config.get("token") and config.get("auth_token")),
        "token": config.get("token", ""),
        "token_url": config.get("token_url", ""),
        "hostname": config.get("hostname", ""),
        "last_hit_time": config.get("last_hit_time"),
    }


def _opencanary_panel_data(binding: PluginBinding) -> dict:
    """Servicios configurados (`PluginBinding.config["services"]`) mas
    el estado EN VIVO del contenedor Docker -- nunca un bit persistido,
    mismo criterio que `_dolost_panel_data()`: Docker es la única
    fuente de verdad de si está corriendo o no (a diferencia de
    `_canarytoken_panel_data()`, que no necesita ninguna consulta real
    porque la identidad de un canarytoken no puede "caerse" sola).
    Cliente Docker propio (`opencanary_client`), no `DockerManager` de
    DOLOS-T -- por eso, a diferencia de los paneles de DOLOS-T/BUDA, NO
    depende de `APATE_MOUNT_EXTERNAL_TOOLS`."""

    from .._managed_panels import managed_panel
    managed = managed_panel(binding)
    if managed is not None:
        return managed
    status = _opencanary_container_status(name=_opencanary_container_name(binding.plugin_id))
    services = binding.config.get("services", {})
    return {
        "services": services,
        "services_text": _format_opencanary_services(services),
        "network_mode": binding.config.get("network_mode", "bridge"),
        "node_id": binding.config.get("node_id", ""),
        "ttp_id": binding.config.get("ttp_id", ""),
        "configured": bool(services),
        "docker_available": status["docker_available"],
        "deployed": bool(status["up"]),
        "container_status": status["status"],
        "last_checked_at": binding.config.get("last_checked_at"),
    }


def _bulk_deployment_status(operations: list[Operation], *, external_tools_mounted: bool) -> dict[str, dict]:
    """Estado en vivo agregado (decoys/narrativas/honeytokens) para
    VARIAS operaciones a la vez -- UNA sola consulta a Docker (no una
    por binding/operacion como haria repetir `_dolost_panel_data()`) y
    UNA sola consulta a la base de BUDA (`IN (...)`, no una por
    narrativa). Pensada para `deployment_status()` (tarjetas de
    "Estado en vivo" del listado, `operations/list.html`), pedida por
    `fetch()` DESPUES de pintar la pagina -- nunca desde
    `list_operations()` en si, que sigue sin tocar Docker/BUDA
    sincronicamente (mismo criterio ya establecido por
    `_dashboard.dashboard_kpis()`, M13d: evitar pagar I/O externo por
    fila en una pantalla de listado).

    Docker inalcanzable/no montado nunca hace que un decoy se muestre
    "abajo" -- `docker_available=False` dice explicito que no se pudo
    determinar, y el llamador decide como mostrar eso (nunca asumir
    fuera de servicio). Igual con BUDA: `buda_available` refleja
    `external_tools_mounted` tal cual (mismo criterio que
    `unavailable_external_bindings`/`buda_tools_mounted` ya usan en
    otras vistas de este mismo modulo) -- si esta montada se asume
    alcanzable (es una base local, no un servicio externo que pueda
    estar caido de forma independiente), con un try/except igual como
    defensa en profundidad."""

    containers = None
    legacy_operations = [o for o in operations if not current_app.config["OPERATION_EXECUTOR"].managed(o.id)]
    if external_tools_mounted and legacy_operations:
        try:
            containers = _DolostDockerManager.get_instance().get_containers(all=True)
        except Exception:
            containers = None
    docker_available = containers is not None
    container_status_by_name = {
        name: container.get("Status", "")
        for container in (containers or [])
        for name in container.get("Names", [])
    }

    narrative_ids = {
        binding.config["narrative_id"]
        for operation in legacy_operations
        for binding in operation.plugins
        if _deployment_kind(binding) == "buda" and binding.config.get("narrative_id") is not None
    }
    narratives_by_id: dict = {}
    if external_tools_mounted and narrative_ids:
        try:
            narratives_by_id = {
                narrative.id: narrative
                for narrative in BudaNarrative.query.filter(BudaNarrative.id.in_(narrative_ids)).all()
            }
        except Exception:
            narratives_by_id = {}
    buda_available = external_tools_mounted

    status_by_operation: dict[str, dict] = {}
    for operation in operations:
        decoys_up = decoys_down = decoys_unknown = 0
        operation_buda_available = buda_available
        narratives_running = narratives_configured = 0
        honeytokens_deployed = honeytokens_configured = 0
        has_any_capability = False

        for binding in operation.plugins:
            kind = _deployment_kind(binding)
            if kind in {"dolost", "buda"}:
                from .._managed_panels import managed_panel
                managed = managed_panel(binding, operation.id)
                if managed is not None:
                    has_any_capability = True
                    if kind == "dolost":
                        for row in managed["decoys"]:
                            decoys_up += row["up"] is True
                            decoys_down += row["up"] is False
                            decoys_unknown += row["up"] is None
                    else:
                        narratives_configured += managed["found"]
                        narratives_running += managed["is_running"] is True
                        operation_buda_available = operation_buda_available and managed["is_running"] is not None
                    continue
            if kind == "dolost":
                for decoy in binding.config.get("decoys", []):
                    has_any_capability = True
                    if not docker_available:
                        decoys_unknown += 1
                        continue
                    status = container_status_by_name.get(f"/DolosT-{decoy.get('Hostname', '')}")
                    if status is not None and status.lower().startswith("up"):
                        decoys_up += 1
                    else:
                        decoys_down += 1
            elif kind == "buda":
                narrative_id = binding.config.get("narrative_id")
                if narrative_id is None:
                    continue
                has_any_capability = True
                narratives_configured += 1
                narrative = narratives_by_id.get(narrative_id)
                if narrative is not None and narrative.is_running:
                    narratives_running += 1
            elif kind == "honeytoken":
                panel = _honeytoken_panel_data(binding, operation.id)
                if panel["paths"]:
                    has_any_capability = True
                honeytokens_configured += len(panel["paths"])
                honeytokens_deployed += sum(1 for item in panel["paths"] if item["exists"])

        status_by_operation[operation.id] = {
            "has_any_capability": has_any_capability,
            "docker_available": docker_available,
            "decoys": {"up": decoys_up, "down": decoys_down, "unknown": decoys_unknown},
            "buda_available": operation_buda_available,
            "narratives": {"running": narratives_running, "configured": narratives_configured},
            "honeytokens": {"deployed": honeytokens_deployed, "configured": honeytokens_configured},
        }

    return status_by_operation


@operations_bp.route("/")
def list_operations():
    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(visible_operations(getattr(g, "current_identity", None), repo.list()), key=lambda op: op.created_at, reverse=True)
    telemetry_by_operation = current_app.config["TELEMETRY_COLLECTOR"].list_events_by_operation(
        [operation.id for operation in operations]
    )
    operation_attention = {
        operation.id: build_operation_list_attention(
            operation,
            event_count=len(telemetry_by_operation.get(operation.id, [])),
        )
        for operation in operations
    }
    sessions = current_app.config["PLAYGROUND_SESSIONS"]
    # "Estado en vivo" (tarjetas, referencia CounterCraft): solo
    # ACTIVE/COMPROMISED entran -- PLANNING no tiene nada desplegado
    # todavia por definicion, CLOSED deberia haber retirado todo. Ver
    # deployment_status() para donde se resuelve el estado real (nunca
    # aca, de forma sincrona -- ver docstring de _bulk_deployment_status()).
    live_operations = [op for op in operations if op.status in (OperationStatus.ACTIVE, OperationStatus.COMPROMISED)]
    return render_template(
        "operations/list.html",
        operations=operations,
        live_operations=live_operations,
        operation_attention=operation_attention,
        attention_operation_count=sum(item["count"] > 0 for item in operation_attention.values()),
        kpis=_dashboard_kpis(operations),
        recent_rule_firings=_recent_rule_firings(
            operations, current_app.config["RULE_DECISION_REPOSITORY"]
        ),
        active_playground_session_count=len(sessions),
        # Buscador/filtro/orden de la tabla de abajo (post-BlackHat): los
        # cuatro valores reales de OperationStatus para el <select> de
        # filtro -- crudos a proposito, mismo criterio documentado en
        # apate/web/_enum_labels.py (palabra unica en ingles, sin el
        # problema de snake_case que motiva ese modulo).
        operation_statuses=[status.value for status in OperationStatus],
    )


@operations_bp.route("/deployment-status")
def deployment_status():
    """`fetch()` desde `operations/list.html` DESPUES de pintar la
    pagina -- nunca bloquea el listado inicial, nunca lo rompe si
    Docker/BUDA no responden (ver `_bulk_deployment_status()`).
    `ids` es una lista separada por comas de `Operation.id` (las
    tarjetas de "Estado en vivo" ya renderizadas, tipicamente
    ACTIVE/COMPROMISED); un id desconocido/borrado entre el render y
    este pedido se ignora en silencio, no rompe el resto del lote."""

    ids = [value for value in request.args.get("ids", "").split(",") if value]
    operations_by_id = {
        operation.id: operation
        for operation in visible_operations(
            getattr(g, "current_identity", None), current_app.config["OPERATION_REPOSITORY"].list()
        )
    }
    operations = [operations_by_id[id_] for id_ in ids if id_ in operations_by_id]
    status = _bulk_deployment_status(operations, external_tools_mounted=current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"])
    return jsonify(status)


@operations_bp.route("/portfolio")
def portfolio():
    """Vista de portafolio (M13g): cobertura agregada entre TODAS las
    operaciones -- ruta mas dentro de `operations_bp` en vez de un
    blueprint propio (a diferencia de `plugins_bp` en M13i): esta vista
    es fundamentalmente una agregacion de `Operation`, usa el mismo
    `OPERATION_REPOSITORY`/`TELEMETRY_COLLECTOR` que `list_operations()`/
    `detail()`, y no tiene la razon que si justifico separar el
    catalogo de plugins (quedar disponible aunque
    `APATE_MOUNT_EXTERNAL_TOOLS` este en `False`) -- no depende de
    DOLOS-T/BUDA para nada.

    Todo el detalle de las agregaciones (semantica de conteo del
    heatmap, filtro de que operaciones entran, costo de
    `generate_report()` aceptado a proposito) vive documentado en
    `apate.web._portfolio`, no aca."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    inventory_assets = current_app.config["ASSET_REPOSITORY"].list()
    operations = visible_operations(getattr(g, "current_identity", None), repo.list())
    return render_template(
        "operations/portfolio.html",
        portfolio=build_portfolio(operations, telemetry, inventory_assets=inventory_assets),
        criticality_labels=CRITICALITY_LABELS,
    )


@operations_bp.route("/compare")
def compare_operations():
    """Comparación descriptiva entre dos operaciones, sin ranking."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(visible_operations(getattr(g, "current_identity", None), repo.list()), key=lambda op: op.created_at, reverse=True)
    by_id = {operation.id: operation for operation in operations}
    left = by_id.get(request.args.get("left", ""))
    right = by_id.get(request.args.get("right", ""))
    comparison = None
    if left is not None and right is not None and left.id != right.id:
        telemetry = current_app.config["TELEMETRY_COLLECTOR"]
        left_observed = telemetry.list_ttps(left.id)
        right_observed = telemetry.list_ttps(right.id)
        comparison = {
            "left": left,
            "right": right,
            "left_ttps": compare_ttps(left.adversary_profile.expected_ttps, left_observed),
            "right_ttps": compare_ttps(right.adversary_profile.expected_ttps, right_observed),
            "left_observed": left_observed,
            "right_observed": right_observed,
        }
    return render_template(
        "operations/compare.html",
        operations=operations,
        selected_left=request.args.get("left", ""),
        selected_right=request.args.get("right", ""),
        comparison=comparison,
    )


def _render_new_operation_form(*, prefill: Optional[dict] = None, template: Optional[dict] = None):
    """Comun a `new_operation_form()` (formulario en blanco o precargado
    desde una plantilla del catalogo, ver `_get_operation_template()`),
    `reoperate()` (M12g, precargado a partir de una operacion cerrada) y
    `templates_gallery()` -- el template Jinja es el mismo en los tres
    casos, solo cambia si hay `prefill`/`template` o no.

    `template` (distinto de `prefill`) es la plantilla completa del
    catalogo (`apate.web._operation_templates`), pasada aparte para que
    `operations/form.html` pueda mostrar el banner "Plantilla aplicada"
    y la vista informativa de que sigue en los pasos 3/4
    (`describe_next_steps()`) -- `prefill` en si es solo el sub-dict
    `operation`, sin la metadata de catalogo (`id`/`summary`/
    `scenario`/`plugins`)."""

    attack_groups = _list_attack_groups()
    inventory_assets = sorted(
        current_app.config["ASSET_REPOSITORY"].list(), key=lambda asset: (asset.name.lower(), asset.identifier.lower())
    )
    return render_template(
        "operations/form.html",
        environments=list(Environment),
        skill_levels=_SKILL_LEVELS,
        strategic_objectives=list(StrategicObjective),
        techniques_by_tactic=_techniques_by_tactic(),
        attack_groups=attack_groups,
        attack_catalog_provenance=_attack_catalog_provenance(),
        # Plano/serializable para el <script> del formulario (M12j) --
        # los dataclasses de apate.attack no tienen to_dict(), a
        # proposito (catalogo de solo lectura, ver catalog.py), asi que
        # se arma el dict aca en vez de forzarles ese metodo.
        attack_groups_json=[
            {
                "id": group.id,
                "name": group.name,
                "aliases": group.aliases,
                "description": group.description,
                "technique_ids": group.technique_ids,
            }
            for group in attack_groups
        ],
        inventory_assets=inventory_assets,
        prefill=prefill,
        template=template,
        template_next_steps=_describe_template_next_steps(template) if template else None,
    )


@operations_bp.route("/cti-extract", methods=["POST"])
def cti_extract():
    """Fase 6 post-BlackHat (ver docs/roadmap.md): cierra el
    placeholder de M12k. Ruta AJAX (llamada por fetch() desde
    operations/form.html, no un submit de formulario normal) -- sube
    un informe de CTI (.txt/.pdf) y devuelve sugerencias de TTPs/grupo
    por matching determinista (apate.cti), sin aplicar nada por si
    sola ni crear/modificar ninguna Operation. El operador aplica lo
    que quiera desde el formulario (mismo criterio de "asistir, nunca
    decidir" que ya usan el selector de grupo APT de M12j y la
    incorporacion de TTPs de la Fase 3 de este backlog)."""

    uploaded = request.files.get("cti_report_file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "No se selecciono ningun archivo."}), 400

    filename = secure_filename(uploaded.filename)
    data = uploaded.read()

    try:
        text = extract_text(filename, data)
        result = extract_candidates(text)
    except CTIExtractionError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(
        {
            "technique_matches": [
                {
                    "id": match.technique.id,
                    "name": match.technique.name,
                    "matched_via": match.matched_via,
                    "raw_match": match.raw_match,
                }
                for match in result.technique_matches
            ],
            "group_matches": [
                {
                    "id": match.group.id,
                    "name": match.group.name,
                    "raw_match": match.raw_match,
                }
                for match in result.group_matches
            ],
        }
    )


@operations_bp.route("/templates")
def templates_gallery():
    """Catalogo de plantillas de operacion (referencia declarada:
    CounterCraft Campaign Builder) -- solo lectura, ver
    `apate.web._operation_templates` para el diseno completo. Elegir
    una plantilla navega a `new_operation_form()` con `?template=<id>`,
    que precarga el wizard -- esta vista no crea nada por si sola."""

    templates = _list_operation_templates()
    return render_template(
        "operations/templates.html",
        templates=templates,
        next_steps_by_id={template["id"]: _describe_template_next_steps(template) for template in templates},
    )


@operations_bp.route("/new", methods=["GET"])
def new_operation_form():
    template_id = request.args.get("template")
    if not template_id:
        return _render_new_operation_form()

    template = _get_operation_template(template_id)
    if template is None:
        flash(_("La plantilla '%(template_id)s' no existe.", template_id=template_id), "error")
        return _render_new_operation_form()

    return _render_new_operation_form(prefill=_resolve_template_operation_fields(template), template=template)


@operations_bp.route("/new", methods=["POST"])
def create_operation():
    repo = current_app.config["OPERATION_REPOSITORY"]
    form = request.form

    # Las selecciones del inventario guardan su identificador estable y el
    # texto libre sigue permitido para activos aún no inventariados. El
    # contrato histórico continúa siendo list[str], sin objetos embebidos.
    expected_ttps = form.getlist("expected_ttps")
    target_assets = list(
        dict.fromkeys(form.getlist("inventory_target_assets") + _parse_comma_list(form.get("target_assets", "")))
    )
    objectives = [StrategicObjective(value) for value in form.getlist("objectives")]

    operation = Operation(
        name=form["name"],
        adversary_profile=AdversaryProfile(
            name=form["adversary_name"],
            motivation=form.get("adversary_motivation", ""),
            skill_level=form.get("adversary_skill_level", "unknown"),
            expected_ttps=expected_ttps,
            target_assets=target_assets,
            notes=form.get("adversary_notes", ""),
        ),
        roe=RulesOfEngagement(environment=Environment(form.get("environment", Environment.ISOLATED.value))),
        narrative=Narrative(
            name=form["narrative_name"],
            description=form.get("narrative_description", ""),
            psychological_impact=form.get("psychological_impact", ""),
        ),
        strategic_decisions=StrategicDecisions(
            objectives=objectives,
            roles=_parse_roles(form.get("roles", "")),
            resource_estimate=form.get("resource_estimate", ""),
        ),
        closure_criteria=ClosureCriteria(end_date=_parse_end_date(form.get("end_date", ""))),
        team_id=(getattr(g, "current_identity", None).team_id if getattr(g, "current_identity", None) else None),
    )
    repo.save(operation)
    flash(_("Operación '%(name)s' creada.", name=operation.name), "success")
    return redirect(url_for("operations.detail", operation_id=operation.id))


@operations_bp.route("/<operation_id>")
def detail(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    inventory_assets_by_identifier = {
        asset.identifier: asset for asset in current_app.config["ASSET_REPOSITORY"].list()
    }
    inventory_assets = list(inventory_assets_by_identifier.values())
    resolved_target_assets = [
        {"reference": reference, "asset": inventory_assets_by_identifier.get(reference)}
        for reference in operation.adversary_profile.target_assets
    ]
    resolved_inventory_target_ids = [target["asset"].identifier for target in resolved_target_assets if target["asset"]]
    asset_coverage = build_asset_coverage(operation, inventory_assets)
    for target in asset_coverage["uncovered"]:
        target["placement_suggestions"] = (
            _suggest_capabilities_for_asset(target["asset"]) if target["asset"] is not None else []
        )
    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    telemetry_records = telemetry.list_events(operation.id)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    open_signals = sorted(
        (signal for signal in current_app.config["ATTENTION_REPOSITORY"].list_signals(operation.id) if signal.status == "open"),
        key=lambda signal: (-severity_order[signal.severity], signal.created_at),
    )[:3]
    events_by_plugin = {}
    for event in reversed(telemetry_records):
        events_by_plugin.setdefault(event.plugin_id, []).append(event)
    evidence_candidates = {}
    for binding in operation.plugins:
        linked = set(binding.effect.evidence_event_ids)
        matching = events_by_plugin.get(binding.plugin_id, [])
        evidence_candidates[binding.plugin_id] = [
            event for index, event in enumerate(matching) if index < 12 or event.id in linked
        ]
    operation_metrics = build_operation_metrics(
        operation,
        telemetry_records,
        telemetry_source=type(telemetry.repository).__name__,
    )

    # Los paneles de DOLOS-T/BUDA necesitan Docker/la base de BUDA
    # montados (mount_dolost()/mount_buda(), ver apate.web.external) --
    # sin eso (APATE_MOUNT_EXTERNAL_TOOLS=False, como usan los tests
    # del resto de APATE) no se consultan esos proveedores. El binding
    # sigue visible con enlace a Salud, y los honeytokens nativos se
    # muestran siempre porque no dependen de ese montaje.
    dolost_panels: dict[str, dict] = {}
    buda_panels: dict[str, dict] = {}
    honeytoken_panels: dict[str, dict] = {}
    canarytoken_panels: dict[str, dict] = {}
    opencanary_panels: dict[str, dict] = {}
    buda_narratives = []
    buda_user_profiles = []
    buda_activities = []
    unavailable_external_bindings = []
    for binding in operation.plugins:
        kind = _deployment_kind(binding)
        if kind == "honeytoken":
            honeytoken_panels[binding.plugin_id] = _honeytoken_panel_data(binding, operation.id)
        elif kind == "canarytoken":
            # No depende de APATE_MOUNT_EXTERNAL_TOOLS ni de ninguna
            # consulta de red -- ver docstring de _canarytoken_panel_data().
            canarytoken_panels[binding.plugin_id] = _canarytoken_panel_data(binding)
        elif kind == "opencanary":
            # Tampoco depende de APATE_MOUNT_EXTERNAL_TOOLS -- cliente
            # Docker propio, no DockerManager de DOLOS-T (ver docstring
            # de _opencanary_panel_data()).
            opencanary_panels[binding.plugin_id] = _opencanary_panel_data(binding)
        elif kind in ("dolost", "buda") and not current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"]:
            unavailable_external_bindings.append({"binding": binding, "kind": kind})
    if current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"]:
        for binding in operation.plugins:
            kind = _plugin_kind(binding)
            if kind == "dolost":
                dolost_panels[binding.plugin_id] = _dolost_panel_data(binding)
            elif kind == "buda":
                buda_panels[binding.plugin_id] = _buda_panel_data(binding)
        buda_narratives = BudaNarrative.query.order_by(BudaNarrative.id.desc()).all()
        # M14d: para el <select multiple> de "Asignar perfiles" del panel
        # -- los UserProfile en sí se crean/editan/borran desde
        # /capabilities/identity-profiles, no desde acá.
        buda_user_profiles = BudaUserProfile.query.order_by(BudaUserProfile.name).all()
        buda_activities = BudaActivity.query.order_by(BudaActivity.activity_type).all()

    # M12d: sugerencia indicativa nomas, nunca pre-marcada -- ver
    # apate.engage.suggest_activities(). El template solo la usa para
    # resaltar visualmente que checkboxes del selector de M12c
    # coinciden con las expected_ttps de esta operacion.
    #
    # Segunda mejora de Engage (post-M12): misma logica, pero a partir
    # de los objetivos estrategicos (paso 2) en vez de las TTPs (paso
    # 1) -- ver apate.engage.suggest_activities_for_objectives(). Dos
    # sets separados (no fusionados) para que el template pueda marcar
    # el origen real de cada sugerencia -- ver docstring de esa funcion
    # sobre por que la señal por objetivo es un juicio interpretativo
    # de APATE, no una extraccion verificada como la de TTPs.
    suggested_activity_ids = {
        activity.id for activity in _suggest_engage_activities(operation.adversary_profile.expected_ttps)
    }
    suggested_activity_ids_by_objective = {
        activity.id
        for activity in _suggest_engage_activities_for_objectives(
            [objective.value for objective in operation.strategic_decisions.objectives]
        )
    }

    # M13a: heatmap de TTPs, generado al vuelo (mismo patron que
    # report()/workshop_kit(), sin persistir nada) -- solo tiene
    # sentido junto con el resto de la seccion de informe, que ya
    # estaba gateada a operaciones CLOSED.
    #
    # Fase 3 post-BlackHat: perfil de adversario vivo -- mismo
    # generate_report() de arriba, pero para ACTIVE/COMPROMISED en vez
    # de CLOSED, reusando unexpected_ttps (TTPs observadas por
    # telemetria que no estan en AdversaryProfile.expected_ttps) como
    # sugerencia para incorporar al perfil. Nunca PLANNING (sin
    # telemetria real todavia) ni CLOSED (el heatmap ya cubre esa
    # comparacion final; para "aprender" ahi esta Reoperar, M12g) --
    # los dos casos son mutuamente excluyentes con el status real de
    # una Operacion, asi que generate_report() se llama una sola vez
    # por request como mucho.
    ttp_heatmap = None
    suggested_ttps: list[dict] = []
    if operation.status != OperationStatus.PLANNING:
        report = generate_report(operation, telemetry)
        if operation.status == OperationStatus.CLOSED:
            ttp_heatmap = _ttp_heatmap(report)
        else:
            technique_by_id = {technique.id: technique for technique in _list_attack_techniques()}
            suggested_ttps = [
                {"id": ttp_id, "name": technique_by_id[ttp_id].name if ttp_id in technique_by_id else None}
                for ttp_id in report.unexpected_ttps
            ]

    # Fase 1 post-BlackHat: historial de acciones manuales de operador
    # (deploy/rotate/retire/start/stop/delete sobre los paneles nativos),
    # separado de RuleEngine.history -- ver _log_operator_action(). Mas
    # reciente primero, mismo criterio que un log de auditoria.
    operator_actions = list(reversed(current_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id)))
    rule_firings = current_app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operation_id)
    operation_timeline = _operation_timeline(
        operation,
        telemetry_records,
        operator_actions,
        rule_firings,
    )

    # Vista de "Preparacion" (Goals Prepare/Understand de MITRE Engage) --
    # reusa buda_panels ya calculado arriba, sin una segunda consulta a
    # BUDA. Ver apate.web._engage_preparation para el mapeo completo.
    preparation_coverage_rows = _preparation_coverage(
        operation, buda_panels=buda_panels, buda_tools_mounted=current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"]
    )
    context_repository = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    context_sources = {source.id: source for source in context_repository.list()}
    selected_context_sources = [
        {"id": source_id, "source": context_sources.get(source_id)}
        for source_id in operation.behavior_context_source_ids
    ]
    available_context_sources = [
        source
        for source in context_sources.values()
        if source.status == BehaviorContextStatus.ACTIVE
        and source.integrity_ok
        and source.id not in operation.behavior_context_source_ids
    ]
    pending_context_sources = [
        source
        for source in context_sources.values()
        if source.status == BehaviorContextStatus.PENDING
        and source.pending_operation_id == operation.id
    ]
    deception_path = build_deception_path(
        operation,
        telemetry_records,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    operation_tree = build_operation_tree(
        operation,
        telemetry_records,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    # Ensayo en seco (referencia declarada: CounterCraft -- simular
    # sobre el diseño, sin clonar infraestructura/digital twins): capa
    # de solo lectura puramente sobre `Operation`, sin telemetria ni
    # paneles de mecanica especifica -- ver apate.reporting.dry_run
    # sobre por que eso hace la ausencia de side effects estructural, no
    # solo disciplinada.
    operation_dry_run = simulate_dry_run(operation)
    # Coherencia de la ficcion (referencia declarada: CounterCraft) --
    # reusa los mismos paneles ya calculados arriba para el arbol/camino
    # de engaño, sin ninguna consulta nueva a Docker/BUDA. Ver
    # apate.web._narrative_coherence.
    narrative_coherence = build_narrative_coherence(
        operation,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    roe_allowed_granular_signatures = [
        signature for signature in operation.roe.allowed_actions if signature not in _ROE_ACTION_KINDS
    ]
    roe_forbidden_granular_signatures = [
        signature for signature in operation.roe.forbidden_actions if signature not in _ROE_ACTION_KINDS
    ]
    operation_rules, operation_rules_error = _rules_in_operation_scope(operation)

    operation_center = build_operation_center(
        operation,
        operation_metrics=operation_metrics,
        operation_timeline=operation_timeline,
        preparation_coverage=preparation_coverage_rows,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        dry_run=operation_dry_run,
        narrative_coherence=narrative_coherence,
        operation_rules=operation_rules,
        operation_rules_error=operation_rules_error,
    )

    plugin_descriptions = PluginRegistry.list_descriptions()

    return render_template(
        "operations/detail.html",
        operation=operation,
        resolved_target_assets=resolved_target_assets,
        resolved_inventory_target_ids=resolved_inventory_target_ids,
        inventory_assets=inventory_assets,
        criticality_labels=CRITICALITY_LABELS,
        suggestible_asset_types=_list_suggestible_asset_types(),
        asset_coverage=asset_coverage,
        available_teams=_available_identity_teams(),
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
        deployment_groups=_deployment_groups(operation),
        unavailable_external_bindings=unavailable_external_bindings,
        buda_narratives=buda_narratives,
        buda_user_profiles=buda_user_profiles,
        buda_activities=buda_activities,
        deception_levels=list(DeceptionLevel),
        techniques_by_tactic=_techniques_by_tactic(),
        event_types=list(EventType),
        engagement_activities_by_goal=_engagement_activities_by_goal(),
        get_engage_activity=_get_engage_activity,
        suggested_engage_activity_ids=suggested_activity_ids,
        suggested_engage_activity_ids_by_objective=suggested_activity_ids_by_objective,
        plugin_kinds=[description.kind for description in plugin_descriptions],
        plugin_surfaces={description.kind: description.surface for description in plugin_descriptions},
        ttp_heatmap=ttp_heatmap,
        operator_actions=operator_actions,
        operator_audit_verification=current_app.config["OPERATOR_ACTION_REPOSITORY"].verify(operation_id),
        operation_timeline=operation_timeline,
        operation_metrics=operation_metrics,
        operation_center=operation_center,
        open_signals=open_signals,
        evidence_candidates=evidence_candidates,
        deception_path=deception_path,
        operation_tree=operation_tree,
        operation_dry_run=operation_dry_run,
        narrative_coherence=narrative_coherence,
        suggested_ttps=suggested_ttps,
        preparation_coverage=preparation_coverage_rows,
        selected_context_sources=selected_context_sources,
        available_context_sources=sorted(available_context_sources, key=lambda item: item.name.lower()),
        pending_context_sources=sorted(pending_context_sources, key=lambda item: item.created_at, reverse=True),
        siem_soar_configured=bool(current_app.config["SIEM_SOAR_CONFIG_REPOSITORY"].load().get("webhook_url")),
        roe_action_kinds=_ROE_ACTION_KINDS,
        roe_allowed_granular_signatures=roe_allowed_granular_signatures,
        roe_forbidden_granular_signatures=roe_forbidden_granular_signatures,
        operation_rules=operation_rules,
        operation_rules_error=operation_rules_error,
        rejected_actions=current_app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation_id),
    )


@operations_bp.route("/<operation_id>/team", methods=["POST"])
def assign_team(operation_id: str):
    """Asigna una operación a un equipo existente por decisión administrativa."""

    operation = _get_operation_or_404(operation_id)
    requested_team = request.form.get("team_id", "").strip() or None
    available_teams = _available_identity_teams()
    if requested_team is not None and requested_team not in available_teams:
        flash(_('El equipo elegido no existe entre las identidades configuradas.'), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    previous_team = operation.team_id
    if previous_team == requested_team:
        flash(_('La operación ya tiene ese equipo asignado.'), "success")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    operation.team_id = requested_team
    current_app.config["OPERATION_REPOSITORY"].save(operation)
    previous_label = previous_team or _("sin equipo (solo administración)")
    current_label = requested_team or _("sin equipo (solo administración)")
    detail = _("Equipo de la operación cambiado de '%(previous_label)s' a '%(current_label)s'.", previous_label=previous_label, current_label=current_label)
    _log_operator_action(operation_id, action="assign_team", outcome="success", detail=detail)
    flash(detail, "success")
    return redirect(url_for("operations.detail", operation_id=operation_id))


def _redirect_to_detail(operation_id: str, tab: Optional[str] = None):
    """`redirect(url_for("operations.detail", ...))`, opcionalmente con
    un fragmento `#tab-...` (M13e, ver detail.html/theme.css para los
    ids reales) -- el JS de tabs de `detail.html` lo lee al cargar
    para reactivar la seccion correcta. Sin esto, cualquier submit de
    los formularios de Escenarios/Plugins vinculados/Mecanica
    especifica (todos POST-y-vuelven-al-detalle) devolvia al operador
    siempre al primer tab (Perfil de adversario) en vez de a donde
    estaba trabajando -- perceptible de inmediato en una demo en vivo,
    mismo tipo de problema de UX que motivo el `novalidate` del wizard
    de M12e (validacion nativa bloqueando en silencio), aunque la
    causa raiz sea distinta ahi es "un campo oculto bloquea el
    submit", aca es "el redirect no recuerda donde estaba el
    operador". `tab=None` (transiciones de estado, informe, reoperar --
    acciones de cabecera, no de un tab puntual) deja la URL sin
    fragmento, que carga en el primer tab como siempre."""

    return redirect(url_for("operations.detail", operation_id=operation_id, _anchor=tab))


@operations_bp.route("/<operation_id>/roe", methods=["POST"])
def update_roe(operation_id: str):
    """Actualiza los límites operativos de Rules of Engagement desde la web."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    try:
        operation.roe.allowed_actions = _unique_action_signatures(
            request.form.getlist("allowed_actions"), request.form.get("allowed_action_signatures", "")
        )
        operation.roe.forbidden_actions = _unique_action_signatures(
            request.form.getlist("forbidden_actions"), request.form.get("forbidden_action_signatures", "")
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-roe")

    operation.roe.legal_constraints = [
        line.strip() for line in request.form.get("legal_constraints", "").splitlines() if line.strip()
    ]
    operation.roe.escalation_contact = request.form.get("escalation_contact", "").strip()
    repo.save(operation)
    flash(_('Reglas de interacción actualizadas.'), "success")
    return _redirect_to_detail(operation_id, tab="tab-roe")


@operations_bp.route("/<operation_id>/closure-criteria/trigger-conditions", methods=["POST"])
def add_trigger_condition(operation_id: str):
    """Agrega una Gating Criteria estructurada desde el tab de RoE.

    El formulario refleja el subconjunto event-driven de ``Condition``:
    tipo de evento obligatorio, plugin opcional y como máximo un par
    clave/valor de payload. Nunca ofrece ``closure_due`` porque ese caso
    ya está modelado por ``ClosureCriteria.end_date``.
    """

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    raw_event_type = request.form.get("event_type", "").strip()
    try:
        event_type = EventType(raw_event_type)
    except ValueError:
        flash(_('Seleccioná un tipo de evento válido para la Gating Criteria.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-roe")

    payload_key = request.form.get("payload_key", "").strip()
    payload_value = request.form.get("payload_value", "").strip()
    if payload_value and not payload_key:
        flash(_('Indicá la clave del payload o dejá ambos campos vacíos.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-roe")

    condition = Condition(
        event_type=event_type,
        plugin_id=request.form.get("plugin_id", "").strip() or None,
        payload={payload_key: payload_value} if payload_key else {},
    )
    try:
        operation.add_trigger_condition(condition)
    except InvalidClosureCriteriaError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-roe")

    repo.save(operation)
    flash(_('Gating Criteria agregada a la operación.'), "success")
    return _redirect_to_detail(operation_id, tab="tab-roe")


@operations_bp.route(
    "/<operation_id>/closure-criteria/trigger-conditions/<int:index>/delete",
    methods=["POST"],
)
def delete_trigger_condition(operation_id: str, index: int):
    """Quita una Gating Criteria por el índice mostrado en el detalle."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    try:
        operation.remove_trigger_condition(index)
    except IndexError:
        flash(_('La Gating Criteria indicada ya no existe.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-roe")

    repo.save(operation)
    flash(_('Gating Criteria eliminada de la operación.'), "success")
    return _redirect_to_detail(operation_id, tab="tab-roe")


@operations_bp.route("/<operation_id>/adversary-profile/incorporate-ttps", methods=["POST"])
def incorporate_suggested_ttps(operation_id: str):
    """Fase 3 post-BlackHat (ver docs/roadmap.md): "perfil de
    adversario vivo" -- incorpora TTPs observadas-no-esperadas
    (`generate_report().unexpected_ttps`, ver `detail()`) a
    `AdversaryProfile.expected_ttps` de una operacion en curso, en vez
    de esperar a Reoperar (M12g, que reinicia el ciclo entero) para
    "aprender" algo nuevo sobre el adversario.

    Nunca automatico: el operador elige explicitamente que TTPs
    incorporar via checkboxes, ninguno pre-marcado en el template --
    mismo criterio de "asistir, nunca decidir" que ya usan
    `apate.engage.suggest_activities()` (M12d) y el prefill de
    Reoperar (M12g). Es una edicion de campo del dominio (como
    `success_metric`/`measured_outcome` en la Fase 2), no una accion
    de sistema contra un plugin/decoy real -- no genera una entrada en
    `OPERATOR_ACTION_REPOSITORY`, mismo criterio que ya establecio esa
    frontera en la Fase 1/2.

    Gateada a ACTIVE/COMPROMISED -- mismo status que `detail()` usa
    para calcular la sugerencia en si (ver ese docstring): PLANNING no
    tiene telemetria real todavia, CLOSED ya cerro el ciclo."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)

    if operation.status not in (OperationStatus.ACTIVE, OperationStatus.COMPROMISED):
        flash(_('Solo se pueden incorporar TTPs sugeridas en una operación activa o comprometida.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-profile")

    selected = set(request.form.getlist("incorporate_ttps"))
    if not selected:
        flash(_('No se seleccionó ninguna TTP para incorporar.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-profile")

    profile = operation.adversary_profile
    profile.expected_ttps = sorted(set(profile.expected_ttps) | selected)
    repo.save(operation)
    flash(_('TTPs incorporadas al perfil de adversario: %(value)s.', value=', '.join(sorted(selected))), "success")
    return _redirect_to_detail(operation_id, tab="tab-profile")


@operations_bp.route("/<operation_id>/scenarios", methods=["POST"])
def add_scenario(operation_id: str):
    """Agrega un Scenario a la operacion (paso 3, M1) -- unica via web
    para hacerlo, ya que M4b nunca expuso un formulario para esto
    (solo se creaba programaticamente, ej. examples/quickstart.py).
    Sin esto el <select> de `scenario_id` del formulario de "vincular
    plugin" (M10) queda siempre vacio, que era la limitacion conocida
    documentada desde entonces. Mismo criterio de parseo de listas que
    `expected_ttps`/`target_assets` (`_parse_comma_list()`, reusado tal
    cual) y misma validacion minima que `dolost_add_decoy()`: un campo
    requerido vacio flashea error y no crea nada, en vez de guardar un
    Scenario sin contenido."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    form = request.form

    description = form.get("description", "").strip()
    if not description:
        flash(_('El escenario necesita una descripción.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-scenarios")

    try:
        deception_level = DeceptionLevel(form.get("deception_level", DeceptionLevel.BASIC.value))
    except ValueError:
        flash(_("Nivel de engaño inválido: '%(value)s'.", value=form.get('deception_level')), "error")
        return _redirect_to_detail(operation_id, tab="tab-scenarios")

    scenario = Scenario(
        description=description,
        related_ttps=list(
            dict.fromkeys(
                [ttp.strip() for ttp in form.getlist("catalog_related_ttps") if ttp.strip()]
                + _parse_comma_list(form.get("related_ttps", ""))
            )
        ),
        deception_level=deception_level,
    )
    operation.add_scenario(scenario)
    repo.save(operation)
    flash(_("Escenario '%(description)s' agregado a la operación.", description=scenario.description), "success")
    return _redirect_to_detail(operation_id, tab="tab-scenarios")


@operations_bp.route("/<operation_id>/plugins", methods=["POST"])
def add_plugin_binding(operation_id: str):
    """Vincula un nuevo PluginBinding a la operacion (paso 4, M10) --
    unica forma de asociar `scenario_id`/`effect` (el triple
    Ver-Pensar-Hacer) desde la interfaz web, ya que M4b nunca expuso un
    formulario para PluginBinding (solo se creaba programaticamente,
    ej. examples/quickstart.py). `scenario_id` sale de un <select> con
    `operation.scenarios` -- si la operacion no tiene escenarios
    cargados (hoy no hay UI para agregarlos, gap preexistente y fuera
    de alcance de M10), el select queda vacio y el binding se crea sin
    escenario asociado, igual que si se hubiera dejado en blanco.

    Correccion de flujo (posterior a M14): disenar la estrategia
    (vincular el plugin) y configurar su mecanica especifica seguian
    siendo dos pasos desconectados -- "Vincular plugin" no tocaba
    decoys/narrativas, esas solo existian como formularios aparte en
    la tab "Mecanica especifica". Ahora, si `plugin_kind == "dolost"` y
    el form trae un `Hostname` no vacio, se agrega ese decoy al binding
    reciennacido en la misma request (`_build_dolost_decoy()`,
    compartido con `dolost_add_decoy()`) -- opcional, sin `Hostname` no
    pasa nada, el binding se crea igual, configurable despues desde
    "Mecanica especifica" como siempre. Si `plugin_kind == "buda"` y el
    checkbox `create_buda_narrative` viene marcado, se crea una
    Narrative de BUDA a partir de la Operacion
    (`_create_buda_narrative_from_operation()`, compartido con
    `buda_create_narrative()`) y se vincula. Un unico `repo.save()`
    cubre binding + decoy/narrativa -- "Mecanica especifica" sigue
    siendo el lugar para *operar* lo ya configurado (deploy/rotar/
    retirar, iniciar/detener, agregar mas decoys/perfiles despues), no
    el unico punto de entrada."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    form = request.form

    # M12c: mismo mecanismo que expected_ttps/objectives (M10/M12j) --
    # getlist() entrega los checkboxes marcados. set() porque una misma
    # actividad puede aparecer bajo mas de un Approach en el selector
    # (ver _engagement_activities_by_goal()) y quedar marcada en mas de
    # una fila; sin dedup, form.getlist() devolveria el mismo id
    # repetido. Sin validar contra el catalogo -- mismo criterio que
    # expected_ttps en M12j, sigue siendo list[str] libre a nivel de
    # esquema.
    engage_activity_ids = sorted(set(form.getlist("engage_activity_ids")))
    protected_asset_ids = list(
        dict.fromkeys(asset_id.strip() for asset_id in form.getlist("protected_asset_ids") if asset_id.strip())
    )

    plugin_kind = form.get("plugin_kind") or None
    try:
        binding = PluginBinding(
            plugin_id=form["plugin_id"],
            surface=form["surface"],
            scenario_id=form.get("scenario_id") or None,
            plugin_kind=plugin_kind,
            leads_to_plugin_id=form.get("leads_to_plugin_id") or None,
            protected_asset_ids=protected_asset_ids,
            effect=DeceptionEffect(
                expected_adversary_belief=form.get("expected_adversary_belief", ""),
                expected_adversary_action=form.get("expected_adversary_action", ""),
                success_metric=form.get("success_metric", ""),
                engage_activity_ids=engage_activity_ids,
            ),
        )
    except InvalidPluginBindingError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-plugins")
    operation.bind_plugin(binding)

    message = _("Capacidad '%(plugin_id)s' vinculada a la operación.", plugin_id=binding.plugin_id)
    if plugin_kind == "dolost":
        decoy = _build_dolost_decoy(form)
        if decoy is not None:
            binding.config.setdefault("decoys", []).append(decoy)
            message = _("Capacidad '%(plugin_id)s' vinculada a la operación. Decoy '%(hostname)s' agregado.", plugin_id=binding.plugin_id, hostname=decoy["Hostname"])
    elif plugin_kind == "buda" and form.get("create_buda_narrative"):
        narrative = _create_buda_narrative_from_operation(operation)
        binding.config["narrative_id"] = narrative.id
        message = _("Capacidad '%(plugin_id)s' vinculada a la operación. Narrativa de comportamiento #%(narrative_id)s creada a partir de esta operación.", plugin_id=binding.plugin_id, narrative_id=narrative.id)
    elif plugin_kind == "honeytoken" and form.get("honeytoken_directory", "").strip():
        try:
            filenames = _parse_honeytoken_filenames(
                form.get("honeytoken_filenames", "credenciales.csv\npasswords_backup.txt")
            )
        except ValueError as exc:
            flash(str(exc), "error")
            return _redirect_to_detail(operation_id, tab="tab-plugins")
        binding.config.update(
            {
                "directory": form.get("honeytoken_directory", "").strip(),
                "filenames": filenames,
                "ttp_id": form.get("honeytoken_ttp_id", "T1552.001").strip() or "T1552.001",
            }
        )
        message = _("Capacidad '%(plugin_id)s' vinculada a la operación. Configuración de honeytokens preparada; el despliegue requiere confirmación aparte.", plugin_id=binding.plugin_id)
    elif plugin_kind == "canarytoken" and form.get("canarytoken_base_url", "").strip():
        binding.config.update(
            {
                "base_url": form.get("canarytoken_base_url", "").strip(),
                "token_type": form.get("canarytoken_token_type", "").strip(),
                "memo": form.get("canarytoken_memo", "").strip(),
                "email": form.get("canarytoken_email", "").strip(),
                "ttp_id": form.get("canarytoken_ttp_id", "").strip(),
            }
        )
        message = _("Capacidad '%(plugin_id)s' vinculada a la operación. Configuración de Canarytokens preparada; la creación del token requiere confirmación aparte.", plugin_id=binding.plugin_id)
    elif plugin_kind == "opencanary" and form.get("opencanary_services", "").strip():
        services = _parse_opencanary_services(form.get("opencanary_services", ""))
        binding.config.update(
            {
                "services": services,
                "network_mode": form.get("opencanary_network_mode", "bridge"),
                "ttp_id": form.get("opencanary_ttp_id", "").strip(),
            }
        )
        message = _("Capacidad '%(plugin_id)s' vinculada a la operación. Configuración de OpenCanary preparada (%(count)s servicio(s)); el despliegue requiere confirmación aparte.", plugin_id=binding.plugin_id, count=len(services))

    repo.save(operation)
    flash(message, "success")
    return _redirect_to_detail(operation_id, tab="tab-plugins")


@operations_bp.route("/<operation_id>/telemetry-bridges", methods=["POST"])
def add_telemetry_bridge(operation_id: str):
    """Agrega un `ExternalTelemetrySource` a la operacion (primera de
    una tanda de tres tareas para ampliar el ecosistema que APATE
    orquesta -- ver docs/roadmap.md). Distinto, a proposito, de
    `add_plugin_binding()`: un puente de telemetria no es un
    `PluginBinding` (ver docstring de `ExternalTelemetrySource`,
    `apate.core.models`, para el argumento completo de por que).

    `field_mapping` usa el mismo patron "una entrada por linea,
    'clave: valor'" que ya usa `roles` (`StrategicDecisions`,
    `_parse_roles()`) -- reutilizado tal cual, sin inventar un formato
    nuevo: cada linea es `clave_de_payload: ruta.con.puntos`, ej.
    `ttp_id: mitre.technique_id`. Al menos un mapeo es obligatorio --
    una fuente sin ningun campo mapeado no podria traducir nunca un
    solo evento (ver `ExternalTelemetryBridge.ingest_hit()`, que
    descarta un hit si el mapeo no resolvio nada)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    form = request.form

    name = form.get("name", "").strip()
    elastic_url = form.get("elastic_url", "").strip()
    index = form.get("index", "").strip()
    if not name or not elastic_url or not index:
        flash(_('Nombre, URL de Elasticsearch e índice son obligatorios.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-plugins")

    field_mapping = _parse_roles(form.get("field_mapping", ""))
    if not field_mapping:
        flash(_("Configurá al menos un mapeo de campo ('clave_de_payload: ruta.en.el.documento')."), "error")
        return _redirect_to_detail(operation_id, tab="tab-plugins")

    source = ExternalTelemetrySource(
        name=name,
        elastic_url=elastic_url,
        index=index,
        surface=form.get("surface", "network").strip() or "network",
        timestamp_field=form.get("timestamp_field", "@timestamp").strip() or "@timestamp",
        field_mapping=field_mapping,
    )
    operation.add_telemetry_bridge(source)
    repo.save(operation)
    flash(_("Fuente de telemetría externa '%(name)s' agregada.", name=source.name), "success")
    return _redirect_to_detail(operation_id, tab="tab-plugins")


@operations_bp.route("/<operation_id>/telemetry-bridges/<source_id>/fetch", methods=["POST"])
def fetch_telemetry_bridge(operation_id: str, source_id: str):
    """Dispara un ciclo de "consultar y traducir" contra la fuente
    externa (`ExternalTelemetryBridge.fetch_and_ingest()`) -- via real
    y alcanzable, a diferencia del gap real que tuvo el puente del
    Playground hasta la verificacion manual de M5 (`fetch_and_ingest_
    elastic()` existia pero nadie lo llamaba desde la app real, ver
    docs/roadmap.md). Publica sobre un bus efímero de request con el
    `TelemetryCollector` central suscripto -- los
    eventos quedan persistidos de inmediato, correlacionables contra
    `AdversaryProfile.expected_ttps` por la infraestructura de informes
    ya existente (`generate_report()`/heatmap de TTPs), sin logica
    nueva para eso.

    La consulta sigue siendo una acción manual atribuida al operador,
    pero la telemetría que devuelve puede disparar el `RuleEngine` si
    `APATE_TELEMETRY_RULES_ENABLED` está activo. La acción humana no se
    somete al motor ni a RoE; el motor solo reacciona al evento publicado.

    `since` usa `source.last_fetch_at` si ya se consulto antes, o
    "ahora" si nunca se consulto -- mismo criterio que
    `PlaygroundSession.create()`, pero PERSISTIDO (a diferencia de la
    sesion de Playground, efimera por diseno) porque una Operacion real
    es de larga duracion: perder el cursor en cada reinicio del proceso
    reingeriria eventos ya vistos (`TelemetryCollector` no deduplica)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    executor = current_app.config["OPERATION_EXECUTOR"]
    if executor.managed(operation_id):
        approved_plan, operation = executor.snapshot(operation_id)
        source = operation.find_telemetry_bridge(source_id)
        if source is None:
            from ...ledger import LedgerError
            raise LedgerError("approved_source_required")
        # Reconsultar desde la adopción evita avanzar sobre intervalos incompletos.
        # La identidad estable de fuente deduplica; el límite no prueba cobertura.
        from datetime import datetime
        since = datetime.fromisoformat(executor.ledger.operation(operation_id)["created_at"])
    else:
        source = operation.find_telemetry_bridge(source_id)
        if source is None:
            abort(404)
        since = source.last_fetch_at or _utcnow()
    bus = build_rule_bus()
    engine = None
    if current_app.config["APATE_TELEMETRY_RULES_ENABLED"]:
        plugins = build_operation_plugins(operation, bus)
        engine = build_rule_engine(operation=operation, bus=bus, plugins=plugins)
        if engine is not None:
            attach_operation_save_listener(bus, operation)
    bridge = ExternalTelemetryBridge(source=source, bus=bus, operation_id=operation.id)
    try:
        if executor.managed(operation_id):
            events = executor.query(operation_id, source.id, lambda: bridge.fetch_and_ingest(since=since),
                window={"since": since.isoformat(), "size_limit": 500})
        else:
            events = bridge.fetch_and_ingest(since=since)
    except ExternalTelemetryError as exc:
        flash(str(exc), "error")
        _log_operator_action(
            operation_id, action="telemetry_bridge_fetch", outcome="error", detail=str(exc), plugin_id=source.id
        )
        return _redirect_to_detail(operation_id, tab="tab-plugins")

    if not executor.managed(operation_id):
        source.last_fetch_at = _utcnow()
        repo.save(operation)
    detail = _("%(count)s evento(s) ingerido(s) desde '%(name)s'.", count=len(events), name=source.name)
    if engine is not None and engine.rejected_actions:
        rejection = engine.rejected_actions[-1]
        detail += f" La regla '{rejection.rule_name}' no pudo actuar: {rejection.reason}"
        flash(detail, "warning")
    else:
        flash(detail, "success")
    _log_operator_action(
        operation_id, action="telemetry_bridge_fetch", outcome="success", detail=detail, plugin_id=source.id
    )
    return _redirect_to_detail(operation_id, tab="tab-plugins")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/effect/measure", methods=["POST"])
def record_measured_outcome(operation_id: str, plugin_id: str):
    """Fase 2 post-BlackHat (ver docs/roadmap.md): cierra el lazo entre
    lo planificado (`DeceptionEffect.success_metric`, paso 4 de la
    metodologia, M10) y lo efectivamente medido -- hasta ahora nada
    registraba si el efecto esperado se cumplio de verdad.

    Es una edicion de campo del dominio (como `success_metric` en si),
    no una accion de sistema contra un plugin/decoy real -- a
    diferencia de deploy/rotate/retire/start/stop (ver
    `_log_operator_action()`), esto no se registra en
    `OPERATOR_ACTION_REPOSITORY`: mismo criterio que ya dejo afuera de
    ese log a las altas de config como `add_scenario`/
    `add_plugin_binding`. `measured_by` si reusa el operador de sesion
    de la Fase 1 (atribucion, no auditoria de accion) -- texto libre,
    sin gate si nadie lo seteo todavia."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)

    measured_outcome = request.form.get("measured_outcome", "").strip()
    if not measured_outcome:
        flash(_('El resultado medido no puede estar vacío.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-plugins")

    known_events = {
        event.id
        for event in current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
        if event.plugin_id == plugin_id
    }
    evidence_event_ids = list(dict.fromkeys(request.form.getlist("evidence_event_ids")))
    if any(event_id not in known_events for event_id in evidence_event_ids):
        abort(400, _("La evidencia elegida no pertenece a esta capacidad y operación."))
    binding.effect.measured_outcome = measured_outcome
    binding.effect.evidence_event_ids = evidence_event_ids
    binding.effect.measured_at = _utcnow()
    binding.effect.measured_by = session.get("operator") or "sin especificar"
    repo.save(operation)
    flash(_("Resultado medido registrado para '%(plugin_id)s'.", plugin_id=plugin_id), "success")
    return _redirect_to_detail(operation_id, tab="tab-plugins")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/asset-coverage", methods=["POST"])
def update_plugin_asset_coverage(operation_id: str, plugin_id: str):
    """Actualiza la relación explícita activo-capacidad ya vinculada.

    Sigue el patrón de ``record_measured_outcome()``: edita un campo de un
    ``PluginBinding`` existente, persiste la operación y no ejecuta ni
    registra una acción contra infraestructura. Solo acepta activos que ya
    son objetivos de la operación y resuelven contra el inventario; mandar la
    lista vacía limpia la cobertura declarada.
    """

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    inventory_ids = {asset.identifier for asset in current_app.config["ASSET_REPOSITORY"].list()}
    allowed_ids = set(operation.adversary_profile.target_assets) & inventory_ids
    protected_asset_ids = list(
        dict.fromkeys(asset_id.strip() for asset_id in request.form.getlist("protected_asset_ids") if asset_id.strip())
    )
    # Una referencia vieja que ya tenía este binding puede conservarse hasta
    # que el operador la quite de forma explícita en el selector. Aceptar una
    # referencia nueva fuera del inventario, en cambio, volvería a abrir la
    # vía silenciosa que el mapa intenta hacer visible.
    allowed_ids |= set(binding.protected_asset_ids)
    invalid_ids = set(protected_asset_ids) - allowed_ids
    if invalid_ids:
        flash(_('Solo se pueden declarar activos objetivo que existan en el inventario.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-plugins")

    binding.protected_asset_ids = protected_asset_ids
    repo.save(operation)
    flash(_("Cobertura declarada actualizada para '%(plugin_id)s'.", plugin_id=plugin_id), "success")
    return _redirect_to_detail(operation_id, tab="tab-plugins")


@operations_bp.route("/<operation_id>/target-assets/resolve", methods=["POST"])
def resolve_target_asset(operation_id: str):
    """Apunta una referencia libre a una ficha de inventario existente."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    assets = current_app.config["ASSET_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    reference = request.form.get("reference", "")
    asset_identifier = request.form.get("asset_identifier", "").strip()
    try:
        assets.get(asset_identifier)
    except AssetNotFoundError:
        flash(_('Elegí una ficha existente del inventario para resolver la referencia.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-profile")

    _resolve_target_asset_reference(operation, reference, asset_identifier)
    repo.save(operation)
    flash(_("La referencia '%(reference)s' ahora apunta a '%(asset_identifier)s'.", reference=reference, asset_identifier=asset_identifier), "success")
    return _redirect_to_detail(operation_id, tab="tab-profile")


@operations_bp.route("/<operation_id>/target-assets/create-and-resolve", methods=["POST"])
def create_and_resolve_target_asset(operation_id: str):
    """Crea una ficha global y resuelve una única referencia contra ella."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    assets = current_app.config["ASSET_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    reference = request.form.get("reference", "")
    identifier = request.form.get("identifier", "").strip()
    try:
        assets.get(identifier)
    except AssetNotFoundError:
        pass
    else:
        flash(_('Ese identificador ya existe; elegí la ficha existente para resolver la referencia.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-profile")

    try:
        asset = Asset(
            identifier=identifier,
            name=request.form.get("name", ""),
            asset_type=request.form.get("asset_type", ""),
            criticality=request.form.get("criticality", ""),
            technical_identifier=request.form.get("technical_identifier", ""),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-profile")

    _resolve_target_asset_reference(operation, reference, asset.identifier)
    assets.save(asset)
    repo.save(operation)
    flash(_("Ficha '%(identifier)s' creada y referencia '%(reference)s' resuelta.", identifier=asset.identifier, reference=reference), "success")
    return _redirect_to_detail(operation_id, tab="tab-profile")


# -- Contexto de comportamiento en Preparación -----------------------------


@operations_bp.post("/<operation_id>/preparation/behavior-context/select")
def behavior_context_select(operation_id: str):
    """Reemplaza la selección con fuentes activas e íntegras."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    source_repo = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    requested_ids = list(dict.fromkeys(request.form.getlist("source_ids")))
    accepted_ids: list[str] = []
    for source_id in requested_ids:
        try:
            source = source_repo.get(source_id)
        except KeyError:
            continue
        if source.status == BehaviorContextStatus.ACTIVE and source.integrity_ok:
            accepted_ids.append(source.id)
    if len(accepted_ids) != len(requested_ids):
        flash(_('Alguna fuente ya no está activa o no conserva su integridad.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-preparation")

    operation.select_behavior_context(accepted_ids)
    repo.save(operation)
    detail = _('Selección de contexto actualizada: %(count)s fuente(s).', count=len(accepted_ids))
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="behavior_context_select",
        outcome="success",
        detail=detail,
        target=",".join(accepted_ids) or "sin fuentes",
    )
    return _redirect_to_detail(operation_id, tab="tab-preparation")


@operations_bp.post("/<operation_id>/preparation/behavior-context/upload")
def behavior_context_upload(operation_id: str):
    """Extrae un candidato asociado al flujo, pero todavía no lo usa."""

    _get_operation_or_404(operation_id)
    # Import diferido para no acoplar el orden de registro de blueprints.
    from .plugins import _behavior_context_upload_response

    return _behavior_context_upload_response(pending_operation_id=operation_id)


@operations_bp.post("/<operation_id>/preparation/behavior-context/<source_id>/confirm")
def behavior_context_confirm(operation_id: str, source_id: str):
    """Confirma el candidato y lo vincula en una segunda acción explícita."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    source_repo = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    try:
        source = source_repo.get(source_id)
    except KeyError:
        abort(404)
    if source.pending_operation_id != operation.id:
        abort(404)
    if request.form.get("confirm") != "CONFIRMAR":
        flash(_('Revisá el resultado y marcá la confirmación antes de utilizarlo.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-preparation")
    try:
        source.confirm()
    except ValueError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-preparation")

    operation.select_behavior_context([*operation.behavior_context_source_ids, source.id])
    source_repo.save(source)
    repo.save(operation)
    detail = _("Fuente de contexto '%(name)s' confirmada y vinculada.", name=source.name)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="behavior_context_confirm",
        outcome="success",
        detail=detail,
        target=source.id,
    )
    return _redirect_to_detail(operation_id, tab="tab-preparation")


@operations_bp.post("/<operation_id>/preparation/behavior-context/<source_id>/discard")
def behavior_context_discard(operation_id: str, source_id: str):
    operation = _get_operation_or_404(operation_id)
    source_repo = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    try:
        source = source_repo.get(source_id)
    except KeyError:
        abort(404)
    if source.pending_operation_id != operation.id:
        abort(404)
    try:
        source_repo.delete_pending(source.id)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        detail = _("Candidato de contexto '%(name)s' descartado.", name=source.name)
        flash(detail, "success")
        _log_operator_action(
            operation_id,
            action="behavior_context_discard",
            outcome="success",
            detail=detail,
            target=source.id,
        )
    return _redirect_to_detail(operation_id, tab="tab-preparation")


# -- Panel "Honeytokens de archivo" -----------------------------------------


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/honeytoken/configure", methods=["POST"])
def honeytoken_configure(operation_id: str, plugin_id: str):
    """Configura rutas sin desplegar ni sobrescribir archivos."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "honeytoken":
        abort(400)

    current_panel = _honeytoken_panel_data(binding, operation.id)
    if current_panel["deployed"] or current_panel["partial"]:
        detail = _('Retirá o resolvé los archivos existentes antes de cambiar la configuración.')
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="honeytoken_configure", outcome="error", detail=detail, plugin_id=plugin_id
        )
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    directory = request.form.get("directory", "").strip()
    try:
        filenames = _parse_honeytoken_filenames(request.form.get("filenames", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")
    if not directory:
        flash(_('Configurá el directorio donde se crearán los honeytokens.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    binding.config.update(
        {
            "directory": directory,
            "filenames": filenames,
            "ttp_id": request.form.get("ttp_id", "T1552.001").strip() or "T1552.001",
        }
    )
    binding.config.pop("_apate_created_directory", None)
    repo.save(operation)
    detail = _('Configuración de honeytokens actualizada (%(count)s archivo(s)).', count=len(filenames))
    flash(detail, "success")
    _log_operator_action(
        operation_id, action="honeytoken_configure", outcome="success", detail=detail, plugin_id=plugin_id
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/honeytoken/deploy", methods=["POST"])
def honeytoken_deploy(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "honeytoken":
        abort(400)
    result = _deploy_one_binding(operation, binding, strict=True)
    if result["outcome"] == "success":
        flash(result["detail"], "success")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="success",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    else:
        flash(result["detail"], "error")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="error",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/honeytoken/rotate", methods=["POST"])
def honeytoken_rotate(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "honeytoken":
        abort(400)
    plugin = _manual_plugin(operation, binding, HoneytokenPlugin)
    try:
        plugin.restore_deployed_state()
        plugin.rotate()
        detail = _("Honeytokens de '%(plugin_id)s' rotados.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="honeytoken_rotate", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except Exception as exc:
        detail = _("No se pudieron rotar los honeytokens de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="honeytoken_rotate", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/honeytoken/check-access", methods=["POST"])
def honeytoken_check_access(operation_id: str, plugin_id: str):
    """Comprobación manual de acceso a los señuelos (polling).

    `HoneytokenPlugin.check_access()` existía desde M7, con tests, y **no la
    llamaba nadie**: era la única capacidad nativa sin ninguna vía de
    observación, mientras Canarytokens y OpenCanary sí tienen su chequeo
    (`check-hits`/`check-activity`). Encontrado recorriendo la metodología
    sobre una instalación limpia: con el honeytoken desplegado se llegaba al
    paso 6 sin nada con qué observar.

    El baseline se persiste en `binding.config` porque cada request construye
    una instancia nueva y `restore_deployed_state()` vuelve a snapshotear; sin
    guardarlo, la comparación sería contra el instante actual y no detectaría
    nunca nada. Mismo patrón de cursor que `last_hit_time` en Canarytokens.
    """

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "honeytoken":
        abort(400)
    plugin = _manual_plugin(operation, binding, HoneytokenPlugin)
    try:
        plugin.restore_deployed_state()
        almacenado = binding.config.get("_apate_access_baseline", {})
        plugin.load_baseline(almacenado)
        events = plugin.check_access()
        binding.config["_apate_access_baseline"] = plugin.export_baseline()
        repo.save(operation)
        if almacenado:
            detail = _("%(count)s acceso(s) nuevo(s) detectado(s) en '%(plugin_id)s'.", count=len(events), plugin_id=plugin_id)
        else:
            # Sin baseline guardado no hay contra qué comparar: este chequeo
            # fija el punto de referencia. Decirlo evita leer un "0 accesos"
            # como si fuera una comprobación real.
            detail = (
                _("Punto de referencia fijado para '%(plugin_id)s': el próximo chequeo ya compara contra este momento.", plugin_id=plugin_id)
            )
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="honeytoken_check_access", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except Exception as exc:
        detail = _("No se pudo comprobar el acceso a los honeytokens de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="honeytoken_check_access", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/honeytoken/retire", methods=["POST"])
def honeytoken_retire(operation_id: str, plugin_id: str):
    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "honeytoken":
        abort(400)
    plugin = _manual_plugin(operation, binding, HoneytokenPlugin)
    try:
        plugin.restore_deployed_state()
        plugin.retire()
        binding.config.pop("_apate_created_directory", None)
        repo.save(operation)
        detail = _("Honeytokens de '%(plugin_id)s' retirados.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="honeytoken_retire", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except Exception as exc:
        detail = _("No se pudieron retirar los honeytokens de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="honeytoken_retire", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


# -- Panel "Canarytokens (Thinkst)" -------------------------------------


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/canarytoken/configure", methods=["POST"])
def canarytoken_configure(operation_id: str, plugin_id: str):
    """Configura la creación (URL base/tipo/memo/email) sin crear el
    token todavía -- mismo patrón que `honeytoken_configure()`: guardar
    solo prepara el recurso, nunca despliega."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "canarytoken":
        abort(400)

    current_panel = _canarytoken_panel_data(binding)
    if current_panel["deployed"]:
        detail = _('Retirá el canarytoken desplegado antes de cambiar la configuración.')
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="canarytoken_configure", outcome="error", detail=detail, plugin_id=plugin_id
        )
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    base_url = request.form.get("base_url", "").strip()
    token_type = request.form.get("token_type", "").strip()
    memo = request.form.get("memo", "").strip()
    email = request.form.get("email", "").strip()
    missing = [
        name
        for name, value in (("URL base", base_url), ("tipo de token", token_type), ("memo", memo), ("email", email))
        if not value
    ]
    if missing:
        flash(_("Faltan campos obligatorios: %(fields)s.", fields=", ".join(missing)), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    binding.config.update(
        {
            "base_url": base_url,
            "token_type": token_type,
            "memo": memo,
            "email": email,
            "ttp_id": request.form.get("ttp_id", "").strip(),
        }
    )
    repo.save(operation)
    detail = _("Configuración de Canarytokens de '%(plugin_id)s' actualizada.", plugin_id=plugin_id)
    flash(detail, "success")
    _log_operator_action(
        operation_id, action="canarytoken_configure", outcome="success", detail=detail, plugin_id=plugin_id
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/canarytoken/deploy", methods=["POST"])
def canarytoken_deploy(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "canarytoken":
        abort(400)
    result = _deploy_one_binding(operation, binding, strict=True)
    if result["outcome"] == "success":
        flash(result["detail"], "success")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="success",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    else:
        flash(result["detail"], "error")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="error",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/canarytoken/rotate", methods=["POST"])
def canarytoken_rotate(operation_id: str, plugin_id: str):
    """Sin equivalente nativo en Canarytokens -- ver
    `CanarytokenPlugin.rotate()`. Igual pasa por la ruta real (no un
    botón deshabilitado) para que quede el mismo registro de auditoría
    que cualquier otra acción manual, con el motivo explícito en el
    evento publicado."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "canarytoken":
        abort(400)
    try:
        plugin = _manual_plugin(operation, binding, CanarytokenPlugin)
        plugin.restore_deployed_state()
        plugin.rotate()
        detail = _("'%(plugin_id)s': Canarytokens no tiene rotación nativa -- ver el detalle en Telemetría.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="canarytoken_rotate", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginConfigError, PluginStateError) as exc:
        detail = _("No se pudo procesar la rotación de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="canarytoken_rotate", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/canarytoken/retire", methods=["POST"])
def canarytoken_retire(operation_id: str, plugin_id: str):
    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "canarytoken":
        abort(400)
    try:
        plugin = _manual_plugin(operation, binding, CanarytokenPlugin)
        plugin.restore_deployed_state()
        plugin.retire()
        for key in ("token", "auth_token", "token_url", "hostname", "last_hit_time"):
            binding.config.pop(key, None)
        repo.save(operation)
        detail = _("Canarytoken de '%(plugin_id)s' eliminado.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="canarytoken_retire", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginConfigError, PluginStateError, CanarytokenAPIError) as exc:
        detail = _("No se pudo eliminar el canarytoken de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="canarytoken_retire", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/canarytoken/check-hits", methods=["POST"])
def canarytoken_check_hits(operation_id: str, plugin_id: str):
    """Consulta manual del historial (polling, ver docstring de
    `CanarytokenPlugin`/`canarytoken_client` sobre por qué no hay un
    webhook entrante). El cursor de deduplicación
    (`binding.config["last_hit_time"]`) se lee antes y se persiste
    después, mismo patrón que `ExternalTelemetrySource.last_fetch_at`
    (primera tarea de esta misma tanda)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "canarytoken":
        abort(400)
    try:
        plugin = _manual_plugin(operation, binding, CanarytokenPlugin)
        plugin.restore_deployed_state()
        since = binding.config.get("last_hit_time")
        events = plugin.check_hits(since=since)
        binding.config["last_hit_time"] = plugin.config.get("last_hit_time")
        repo.save(operation)
        detail = _("%(count)s hit(s) nuevo(s) de '%(plugin_id)s'.", count=len(events), plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="canarytoken_check_hits", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginConfigError, PluginStateError, CanarytokenAPIError) as exc:
        detail = _("No se pudo consultar el historial de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="canarytoken_check_hits", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


# -- Panel "OpenCanary (Thinkst)" ----------------------------------------


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/opencanary/configure", methods=["POST"])
def opencanary_configure(operation_id: str, plugin_id: str):
    """Configura servicios/red sin desplegar todavía -- mismo patrón que
    `canarytoken_configure()`/`honeytoken_configure()`: guardar solo
    prepara el recurso, nunca despliega."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "opencanary":
        abort(400)

    current_panel = _opencanary_panel_data(binding)
    if current_panel["deployed"]:
        detail = _('Retirá el contenedor desplegado antes de cambiar la configuración.')
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="opencanary_configure", outcome="error", detail=detail, plugin_id=plugin_id
        )
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    services = _parse_opencanary_services(request.form.get("services", ""))
    network_mode = request.form.get("network_mode", "bridge")
    if network_mode not in ("bridge", "host"):
        network_mode = "bridge"

    binding.config.update(
        {
            "services": services,
            "network_mode": network_mode,
            "ttp_id": request.form.get("ttp_id", "").strip(),
        }
    )
    repo.save(operation)
    detail = _("Configuración de OpenCanary de '%(plugin_id)s' actualizada (%(count)s servicio(s)).", plugin_id=plugin_id, count=len(services))
    flash(detail, "success")
    _log_operator_action(
        operation_id, action="opencanary_configure", outcome="success", detail=detail, plugin_id=plugin_id
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/opencanary/deploy", methods=["POST"])
def opencanary_deploy(operation_id: str, plugin_id: str):
    """Ciclo de vida completo -- no hace falta reconciliación de estado:
    una instancia recién construida ya arranca en CREATED, que es lo
    que deploy() espera (mismo comentario que dolost_deploy())."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "opencanary":
        abort(400)
    result = _deploy_one_binding(operation, binding, strict=True)
    if result["outcome"] == "success":
        flash(result["detail"], "success")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="success",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    else:
        flash(result["detail"], "error")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="error",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/opencanary/rotate", methods=["POST"])
def opencanary_rotate(operation_id: str, plugin_id: str):
    """Sin bit de estado persistido a nivel de PluginBinding (mismo
    criterio que DOLOS-T, ver docstring de OpenCanaryPlugin) -- se
    fuerza el estado antes de invocar rotate(), en vez de reconciliar
    contra una consulta a Docker redundante con la que ya hace el panel."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "opencanary":
        abort(400)
    plugin = _manual_plugin(operation, binding, OpenCanaryPlugin)
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        plugin.rotate()
        detail = _("OpenCanary de '%(plugin_id)s' reiniciado (node_id/claves SSH host renovadas).", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="opencanary_rotate", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginStateError, OpenCanaryError) as exc:
        detail = _("No se pudo reiniciar OpenCanary de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="opencanary_rotate", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/opencanary/retire", methods=["POST"])
def opencanary_retire(operation_id: str, plugin_id: str):
    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "opencanary":
        abort(400)
    plugin = _manual_plugin(operation, binding, OpenCanaryPlugin)
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        plugin.retire()
        binding.config.pop("last_checked_at", None)
        repo.save(operation)
        detail = _("OpenCanary de '%(plugin_id)s' retirado.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="opencanary_retire", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginStateError, OpenCanaryError) as exc:
        detail = _("No se pudo retirar OpenCanary de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="opencanary_retire", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/opencanary/check-activity", methods=["POST"])
def opencanary_check_activity(operation_id: str, plugin_id: str):
    """Consulta manual de logs (polling, ver docstring de
    `OpenCanaryPlugin`/`opencanary_client` sobre por qué no hay un
    endpoint entrante). El cursor de deduplicación
    (`binding.config["last_checked_at"]`) se lee antes y se persiste
    después, mismo patrón que `canarytoken_check_hits()`."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    if _deployment_kind(binding) != "opencanary":
        abort(400)
    plugin = _manual_plugin(operation, binding, OpenCanaryPlugin)
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        since = binding.config.get("last_checked_at")
        events = plugin.check_activity(since=since)
        binding.config["last_checked_at"] = plugin.config.get("last_checked_at")
        repo.save(operation)
        detail = _("%(count)s evento(s) nuevo(s) de '%(plugin_id)s'.", count=len(events), plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="opencanary_check_activity", outcome="success", detail=detail, plugin_id=plugin_id
        )
    except (PluginStateError, OpenCanaryError) as exc:
        detail = _("No se pudo consultar la actividad de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="opencanary_check_activity", outcome="error", detail=detail, plugin_id=plugin_id
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/deploy-all", methods=["POST"])
def deploy_all_campaign(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    counts = {"success": 0, "already_deployed": 0, "skipped": 0, "failed": 0}
    failed_messages: list[str] = []

    for binding in operation.plugins:
        result = _deploy_one_binding(operation, binding, strict=False)
        counts[result["outcome"]] += 1

        if result["outcome"] == "success":
            _log_operator_action(
                operation_id,
                action=result["action"],
                outcome="success",
                detail=result["detail"],
                plugin_id=result["plugin_id"],
            )
        elif result["outcome"] == "failed":
            failed_messages.append(f"{result['plugin_id']}: {result['detail']}")
            _log_operator_action(
                operation_id,
                action=result["action"],
                outcome="error",
                detail=result["detail"],
                plugin_id=result["plugin_id"],
            )

    detail = (
        _('Resumen de despliegue de campaña: %(value)s desplegados, %(value2)s ya estaban desplegados, %(value3)s sin configurar/saltados, %(value4)s fallidos.', value=counts['success'], value2=counts['already_deployed'], value3=counts['skipped'], value4=counts['failed'])
    )
    if failed_messages:
        detail += " | Fallas: " + "; ".join(failed_messages)
        flash(detail, "error")
    else:
        flash(detail, "success")

    return _redirect_to_detail(operation_id, tab="tab-mechanics")


# -- Panel "Decoys DOLOS-T" ---------------------------------------------


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/deploy", methods=["POST"])
def dolost_deploy(operation_id: str, plugin_id: str):
    """Ciclo de vida completo (collector + todos los decoys
    configurados) via DolosTPlugin.deploy() -- no reconciliacion de
    estado necesaria, una instancia recien construida ya arranca en
    CREATED, que es lo que deploy() espera."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")

    result = _deploy_one_binding(operation, binding, strict=True)
    if result["outcome"] == "success":
        flash(result["detail"], "success")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="success",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    else:
        flash(result["detail"], "error")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="error",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/rotate", methods=["POST"])
def dolost_rotate(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")

    plugin = _manual_plugin(operation, binding, DolosTPlugin)
    # Reconciliacion documentada en el docstring del modulo: sin un bit
    # persistido de "esta desplegado" a nivel de PluginBinding para
    # DOLOS-T, se fuerza el estado para poder invocar rotate().
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        plugin.rotate()
        detail = _("Decoys de red: decoys de '%(plugin_id)s' reiniciados.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(operation_id, action="dolost_rotate", outcome="success", detail=detail, plugin_id=plugin_id)
    except Exception as exc:
        detail = _("No se pudo rotar '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(operation_id, action="dolost_rotate", outcome="error", detail=detail, plugin_id=plugin_id)
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/retire", methods=["POST"])
def dolost_retire(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")

    plugin = _manual_plugin(operation, binding, DolosTPlugin)
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        plugin.retire()
        detail = _("Decoys de red: collector y decoys de '%(plugin_id)s' retirados.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(operation_id, action="dolost_retire", outcome="success", detail=detail, plugin_id=plugin_id)
    except Exception as exc:
        detail = _("No se pudo retirar '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(operation_id, action="dolost_retire", outcome="error", detail=detail, plugin_id=plugin_id)
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys", methods=["POST"])
def dolost_add_decoy(operation_id: str, plugin_id: str):
    """Agrega un decoy a `PluginBinding.config["decoys"]` -- sin esto,
    el panel nunca tendria nada que listar/desplegar (M4b nunca tuvo
    una vista para configurar decoys, ni siquiera antes de esta
    tanda)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")

    decoy = _build_dolost_decoy(request.form)
    if decoy is None:
        flash(_('El decoy necesita al menos un Hostname.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    binding.config.setdefault("decoys", []).append(decoy)
    repo.save(operation)
    detail = _("Decoy '%(value)s' agregado a '%(plugin_id)s'.", value=decoy['Hostname'], plugin_id=plugin_id)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="dolost_add_decoy",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=decoy["Hostname"],
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys/<hostname>/deploy", methods=["POST"])
def dolost_deploy_decoy(operation_id: str, plugin_id: str, hostname: str):
    """Deploy individual de un decoy -- mas fino que lo que expone
    DolosTPlugin (que solo despliega la lista completa configurada),
    asi que llama directo a `DOLOST.blueprints.api.deploy_decoy()`, la
    misma funcion que ya usa `DolosTPlugin.deploy()` internamente, en
    vez de reimplementar el acceso a Docker."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")
    decoy = _find_decoy_or_404(binding, hostname)

    try:
        _dolost_deploy_decoy(decoy)
        detail = _("Decoy '%(hostname)s' desplegado.", hostname=hostname)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="dolost_deploy_decoy", outcome="success", detail=detail, plugin_id=plugin_id, target=hostname
        )
    except Exception as exc:
        detail = _("No se pudo desplegar el decoy '%(hostname)s': %(exc)s", hostname=hostname, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="dolost_deploy_decoy", outcome="error", detail=detail, plugin_id=plugin_id, target=hostname
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys/<hostname>/undeploy", methods=["POST"])
def dolost_undeploy_decoy(operation_id: str, plugin_id: str, hostname: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")
    decoy = _find_decoy_or_404(binding, hostname)

    try:
        _dolost_clean_decoy(decoy)
        detail = _("Decoy '%(hostname)s' retirado.", hostname=hostname)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="dolost_undeploy_decoy", outcome="success", detail=detail, plugin_id=plugin_id, target=hostname
        )
    except Exception as exc:
        detail = _("No se pudo retirar el decoy '%(hostname)s': %(exc)s", hostname=hostname, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="dolost_undeploy_decoy", outcome="error", detail=detail, plugin_id=plugin_id, target=hostname
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys/<hostname>/start", methods=["POST"])
def dolost_start_decoy(operation_id: str, plugin_id: str, hostname: str):
    """Inicia (`docker start`) el contenedor ya existente de un decoy,
    sin reconstruirlo -- gap real de M14a: `DockerManager.start()`
    solo se usaba internamente dentro de `DolosTPlugin.rotate()` (M8c,
    aproximacion de "rotar" sin equivalente nativo en DOLOS-T), nunca
    expuesto como accion independiente. Mismo identificador de
    contenedor que ya usa `rotate()`/`_dolost_panel_data()`
    (`"DolosT-<Hostname>"`, no el hash de Docker -- la API de
    `docker-py` acepta nombre o id indistintamente)."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")
    _find_decoy_or_404(binding, hostname)

    try:
        _DolostDockerManager.get_instance().start(container_id=f"DolosT-{hostname}")
        detail = _("Decoy '%(hostname)s' iniciado.", hostname=hostname)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="dolost_start_decoy", outcome="success", detail=detail, plugin_id=plugin_id, target=hostname
        )
    except Exception as exc:
        detail = _("No se pudo iniciar el decoy '%(hostname)s': %(exc)s", hostname=hostname, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="dolost_start_decoy", outcome="error", detail=detail, plugin_id=plugin_id, target=hostname
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys/<hostname>/stop", methods=["POST"])
def dolost_stop_decoy(operation_id: str, plugin_id: str, hostname: str):
    """`docker stop` del contenedor de un decoy sin eliminarlo -- mismo
    gap y mismo criterio de identificador que `dolost_start_decoy()`."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")
    _find_decoy_or_404(binding, hostname)

    try:
        _DolostDockerManager.get_instance().stop(container_id=f"DolosT-{hostname}")
        detail = _("Decoy '%(hostname)s' detenido.", hostname=hostname)
        flash(detail, "success")
        _log_operator_action(
            operation_id, action="dolost_stop_decoy", outcome="success", detail=detail, plugin_id=plugin_id, target=hostname
        )
    except Exception as exc:
        detail = _("No se pudo detener el decoy '%(hostname)s': %(exc)s", hostname=hostname, exc=exc)
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="dolost_stop_decoy", outcome="error", detail=detail, plugin_id=plugin_id, target=hostname
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/dolost/decoys/<hostname>/delete", methods=["POST"])
def dolost_delete_decoy(operation_id: str, plugin_id: str, hostname: str):
    """Saca la entrada del decoy de `PluginBinding.config["decoys"]` --
    distinto de `dolost_undeploy_decoy()`, que solo actua sobre el
    contenedor Docker y nunca toca la config. Gap real de M14a:
    `dolost_add_decoy()` (M11 fase 1) nunca tuvo ruta inversa.

    Decision de seguridad (M14b, pedida explicitamente, no dejada
    implicita): si el contenedor del decoy **todavia existe en
    Docker** (confirmado, no solo sospechado), se rechaza el borrado
    con un flash de error en vez de dejarlo huerfano -- una vez que la
    entrada desaparece de `config["decoys"]`, `_dolost_panel_data()`
    ya no vuelve a mirar ese hostname nunca mas (itera la config, no
    Docker), asi que un contenedor huerfano en ese escenario quedaria
    invisible para el resto de la UI, no solo "no borrado". El
    operador tiene que hacer `undeploy` primero (un click mas, accion
    ya expuesta). Si Docker no esta configurado/alcanzable
    (`containers is None`, mismo criterio que `_dolost_panel_data()`),
    no se puede confirmar nada en ningun sentido -- se permite el
    borrado en vez de bloquear una accion de limpieza de config
    valida solo porque Docker no esta disponible en este proceso."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "dolost")
    _find_decoy_or_404(binding, hostname)

    try:
        containers = _DolostDockerManager.get_instance().get_containers(all=True)
    except Exception:
        containers = None

    container_name = f"/DolosT-{hostname}"
    if containers is not None and any(container_name in c.get("Names", []) for c in containers):
        detail = (
            _("'%(hostname)s' todavia tiene un contenedor Docker desplegado -- retiralo (undeploy) antes de borrar su configuracion.", hostname=hostname)
        )
        flash(detail, "error")
        _log_operator_action(
            operation_id, action="dolost_delete_decoy", outcome="error", detail=detail, plugin_id=plugin_id, target=hostname
        )
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    binding.config["decoys"] = [d for d in binding.config.get("decoys", []) if d.get("Hostname") != hostname]
    repo.save(operation)
    detail = _("Decoy '%(hostname)s' eliminado de la configuracion.", hostname=hostname)
    flash(detail, "success")
    _log_operator_action(
        operation_id, action="dolost_delete_decoy", outcome="success", detail=detail, plugin_id=plugin_id, target=hostname
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


# -- Panel "Narrativa BUDA" -----------------------------------------------


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/start", methods=["POST"])
def buda_start(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    result = _deploy_one_binding(operation, binding, strict=True)
    if result["outcome"] == "success":
        flash(result["detail"], "success")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="success",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    else:
        flash(result["detail"], "error")
        _log_operator_action(
            operation_id,
            action=result["action"],
            outcome="error",
            detail=result["detail"],
            plugin_id=plugin_id,
        )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/stop", methods=["POST"])
def buda_stop(operation_id: str, plugin_id: str):
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    narrative = _resolve_buda_narrative(binding)
    if narrative is None or not narrative.is_running:
        detail = _('La narrativa no está corriendo.')
        flash(detail, "error")
        _log_operator_action(operation_id, action="buda_stop", outcome="error", detail=detail, plugin_id=plugin_id)
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    plugin = _manual_plugin(operation, binding, BudaPlugin)
    # Reconciliacion: a diferencia de DOLOS-T, aca si hay una fuente de
    # verdad persistida y confiable (Narrative.is_running, ya
    # consultada arriba) -- se usa esa, no un estado forzado a ciegas.
    plugin.state = PluginLifecycleState.DEPLOYED
    try:
        plugin.retire()
        detail = _("Comportamiento simulado: narrativa de '%(plugin_id)s' detenida.", plugin_id=plugin_id)
        flash(detail, "success")
        _log_operator_action(operation_id, action="buda_stop", outcome="success", detail=detail, plugin_id=plugin_id)
    except (PluginConfigError, PluginStateError) as exc:
        detail = str(exc)
        flash(detail, "error")
        _log_operator_action(operation_id, action="buda_stop", outcome="error", detail=detail, plugin_id=plugin_id)
    except Exception as exc:
        detail = _("No se pudo detener la narrativa de '%(plugin_id)s': %(exc)s", plugin_id=plugin_id, exc=exc)
        flash(detail, "error")
        _log_operator_action(operation_id, action="buda_stop", outcome="error", detail=detail, plugin_id=plugin_id)
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/narrative/link", methods=["POST"])
def buda_link_narrative(operation_id: str, plugin_id: str):
    """Vincula una Narrative de BUDA ya existente (creada via su propia
    UI, /buda/narratives/ -- no enlazada desde la navegacion principal
    pero sigue respondiendo, ver apate.web.external) a este binding."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    try:
        narrative_id = int(request.form.get("narrative_id", ""))
    except ValueError:
        flash(_('Id de narrativa de comportamiento invalido.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    binding.config["narrative_id"] = narrative_id
    repo.save(operation)
    detail = _("Narrativa #%(narrative_id)s vinculada a '%(plugin_id)s'.", narrative_id=narrative_id, plugin_id=plugin_id)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_link_narrative",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=str(narrative_id),
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/narrative/create", methods=["POST"])
def buda_create_narrative(operation_id: str, plugin_id: str):
    """Crea una Narrative de BUDA nueva a partir de esta Operacion, via
    `_create_buda_narrative_from_operation()` (compartido con el flujo
    inline de `add_plugin_binding()`) -- placeholders derivados de la
    Operation/AdversaryProfile/Narrative que contienen al binding, en
    vez de pedirselos de nuevo al usuario. No pide perfiles de usuario
    (WinRM) aca -- esa asignacion sigue siendo mecanica especifica de
    BUDA, se hace desde `buda_update_narrative_profiles()` (mismo
    archivo, panel de abajo -- la ruta `/buda/narratives/edit/<id>` que
    mencionaba esta docstring antes de M14e ya no responde, el
    blueprint de BUDA esta retirado del todo)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    narrative = _create_buda_narrative_from_operation(operation)
    binding.config["narrative_id"] = narrative.id
    repo.save(operation)
    detail = (
        _("Narrativa #%(id)s creada desde la operación y vinculada a '%(plugin_id)s'. Asigná perfiles de identidad antes de iniciarla.", id=narrative.id, plugin_id=plugin_id)
    )
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_create_narrative",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=str(narrative.id),
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/narrative/profiles", methods=["POST"])
def buda_update_narrative_profiles(operation_id: str, plugin_id: str):
    """Asigna/desasigna `UserProfile`s ya existentes a la `Narrative`
    vinculada -- gap real confirmado en M14c: `buda_create_narrative()`
    (M11 fase 1) documentaba esto como "sigue siendo mecánica
    específica de BUDA, se hace desde /buda/narratives/edit/<id>".
    Reemplaza la relacion `Narrative.user_profiles` por lo que venga
    marcado en el `<select multiple>`, mismo mecanismo que ya usa
    `narratives_bp.edit_narrative()` del lado de BUDA -- no se crea
    ningún `UserProfile` acá, esos se administran desde
    `/capabilities/identity-profiles`."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        flash(_('Esta operación no tiene ninguna narrativa de comportamiento vinculada.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    profile_ids = request.form.getlist("user_profile_ids")
    narrative.user_profiles = BudaUserProfile.query.filter(BudaUserProfile.id.in_(profile_ids)).all()
    _buda_db.session.commit()
    detail = _('Perfiles de identidad actualizados para la narrativa #%(id)s.', id=narrative.id)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_update_narrative_profiles",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=",".join(profile_ids) or "sin perfiles",
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/profiles", methods=["POST"])
def buda_create_profile(operation_id: str, plugin_id: str):
    """Crea un perfil reutilizable y lo vincula a esta narrativa."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")
    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        flash(_('Creá o vinculá una narrativa antes de agregar perfiles.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    name = request.form.get("name", "").strip()
    role = request.form.get("role", "").strip()
    server = request.form.get("winrm_server", "").strip()
    username = request.form.get("winrm_username", "").strip()
    password = request.form.get("winrm_password", "")
    if not (name and role and server and username and password):
        flash(_('Nombre, rol, servidor, usuario y contraseña WinRM son obligatorios.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    profile = BudaUserProfile(
        name=name,
        role=role,
        behavior_pattern=request.form.get("behavior_pattern", "").strip(),
        winrm_server=server,
        winrm_username=username,
        winrm_password=password,
    )
    narrative.user_profiles.append(profile)
    _buda_db.session.add(profile)
    _buda_db.session.commit()
    detail = _("Perfil de identidad '%(name)s' creado y vinculado a la narrativa #%(id)s.", name=name, id=narrative.id)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_create_profile",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=str(profile.id),
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/activities", methods=["POST"])
def buda_create_activity(operation_id: str, plugin_id: str):
    """Crea una actividad y la asigna solo a perfiles de la narrativa."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")
    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        flash(_('Creá o vinculá una narrativa antes de agregar actividades.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    activity_type = request.form.get("activity_type", "").strip()
    selected = set(request.form.getlist("profile_ids"))
    profiles = [profile for profile in narrative.user_profiles if str(profile.id) in selected]
    if not activity_type or not profiles:
        flash(_('Indicá el tipo de actividad y al menos un perfil de esta narrativa.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    activity = BudaActivity(
        activity_type=activity_type,
        details=request.form.get("details", "").strip(),
    )
    activity.user_profiles = profiles
    _buda_db.session.add(activity)
    _buda_db.session.commit()
    detail = _("Actividad '%(activity_type)s' creada y asignada a %(count)s perfil(es).", activity_type=activity_type, count=len(profiles))
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_create_activity",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=str(activity.id),
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route(
    "/<operation_id>/plugins/<plugin_id>/buda/profiles/<int:profile_id>/activities",
    methods=["POST"],
)
def buda_update_profile_activities(operation_id: str, plugin_id: str, profile_id: int):
    """Reemplaza la selección de actividades de un perfil vinculado."""

    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")
    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        abort(404)
    profile = next((item for item in narrative.user_profiles if item.id == profile_id), None)
    if profile is None:
        abort(404)

    activity_ids = request.form.getlist("activity_ids")
    profile.activities = BudaActivity.query.filter(BudaActivity.id.in_(activity_ids)).all()
    _buda_db.session.commit()
    detail = _("Actividades actualizadas para el perfil '%(name)s'.", name=profile.name)
    flash(detail, "success")
    _log_operator_action(
        operation_id,
        action="buda_update_profile_activities",
        outcome="success",
        detail=detail,
        plugin_id=plugin_id,
        target=str(profile.id),
    )
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/plugins/<plugin_id>/buda/narrative/delete", methods=["POST"])
def buda_delete_narrative(operation_id: str, plugin_id: str):
    """Borra la `Narrative` de BUDA vinculada -- gap real confirmado en
    M14c (`narratives_bp.delete_narrative()` sin equivalente nativo).

    Rechazada mientras `is_running` (mismo criterio de seguridad que
    `dolost_delete_decoy()`, M14b: borrar de abajo del hilo de fondo de
    `narrative_engine()`, que ya tiene el objeto `Narrative` cargado en
    memoria y sigue commiteando sobre el, es peor que pedirle al
    operador un click mas de "Detener" primero)."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)
    binding = _find_binding_or_404(operation, plugin_id)
    _require_plugin_kind(binding, "buda")

    narrative = _resolve_buda_narrative(binding)
    if narrative is None:
        flash(_('Esta operación no tiene ninguna narrativa de comportamiento vinculada.'), "error")
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    if narrative.is_running:
        detail = _('La narrativa está corriendo -- detenela antes de borrarla.')
        flash(detail, "error")
        _log_operator_action(operation_id, action="buda_delete_narrative", outcome="error", detail=detail, plugin_id=plugin_id)
        return _redirect_to_detail(operation_id, tab="tab-mechanics")

    narrative_id = narrative.id
    _buda_db.session.delete(narrative)
    _buda_db.session.commit()

    binding.config.pop("narrative_id", None)
    repo.save(operation)
    detail = _('Narrativa de comportamiento #%(narrative_id)s eliminada.', narrative_id=narrative_id)
    flash(detail, "success")
    _log_operator_action(operation_id, action="buda_delete_narrative", outcome="success", detail=detail, plugin_id=plugin_id)
    return _redirect_to_detail(operation_id, tab="tab-mechanics")


@operations_bp.route("/<operation_id>/report")
def report(operation_id: str):
    """Informe post-operacion (M6): TTPs esperadas vs. observadas e
    IoCs, generado a partir de OperationRepository (M1) y
    TelemetryCollector (M4). Solo se ofrece para operaciones cerradas
    -- roadmap M6 lo describe como "informe post-operacion"-- aunque
    generate_report() en si no lo exige."""

    operation = _get_operation_or_404(operation_id)
    if operation.status != OperationStatus.CLOSED:
        flash(_('El informe post-operación solo está disponible para operaciones cerradas.'), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    operation_report = generate_report(operation, telemetry)

    fmt = request.args.get("format", "markdown")
    if fmt == "json":
        body, mimetype, filename = operation_report.to_json(), "application/json", f"informe-{operation_id}.json"
    elif fmt == "pdf":
        body, mimetype, filename = operation_report.to_pdf(), "application/pdf", f"informe-{operation_id}.pdf"
    elif fmt == "stix":
        # application/stix+json: media type registrado por la
        # especificacion OASIS (STIX 2.1, seccion 2 "Content Type") para
        # un bundle -- distinto de "application/json" a proposito, para
        # que un consumidor pueda diferenciarlo del JSON propio de APATE
        # sin tener que inspeccionar el contenido.
        # tlp_classifications (segunda de la tanda de mejoras de UI/UX
        # con referencia CounterCraft, ver docs/roadmap.md): overlay
        # manual del operador sobre IoCs de esta operacion, reflejado
        # como object_marking_refs en cada indicator correspondiente.
        tlp_classifications = current_app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation(operation_id)
        body, mimetype, filename = (
            operation_report.to_stix(tlp_classifications=tlp_classifications),
            "application/stix+json",
            f"informe-{operation_id}-stix.json",
        )
    else:
        body, mimetype, filename = operation_report.to_markdown(), "text/markdown", f"informe-{operation_id}.md"

    response = Response(body, mimetype=mimetype)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@operations_bp.post("/<operation_id>/report/send-siem-soar")
def send_report_to_siem_soar(operation_id: str):
    """Envía manualmente el bundle STIX a un webhook configurado."""

    operation = _get_operation_or_404(operation_id)
    if operation.status != OperationStatus.CLOSED:
        flash(_('El informe post-operación solo está disponible para operaciones cerradas.'), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    config = current_app.config["SIEM_SOAR_CONFIG_REPOSITORY"].load()
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        flash(_('Configurá el webhook de SIEM/SOAR antes de enviar el bundle STIX.'), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    operation_report = generate_report(operation, telemetry)
    tlp_classifications = current_app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation(operation_id)
    headers = {"Content-Type": "application/stix+json"}
    auth_token = config.get("auth_token", "")
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        response = requests.post(
            webhook_url,
            data=operation_report.to_stix(tlp_classifications=tlp_classifications),
            headers=headers,
            timeout=8.0,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        current_app.logger.warning("Falló el envío STIX a SIEM/SOAR: %s", type(exc).__name__)
        flash(_('No se pudo enviar el bundle STIX a SIEM/SOAR.'), "error")
    else:
        flash(_('Bundle STIX 2.1 enviado a SIEM/SOAR.'), "success")
    return redirect(url_for("operations.detail", operation_id=operation_id))


@operations_bp.route("/<operation_id>/workshop-kit")
def workshop_kit(operation_id: str):
    """Kit de taller colaborativo (M12i): ficha de perfil de amenaza,
    heatmap de TTPs y plantilla en blanco por escenario (paso 3 +
    preguntas Ver-Pensar-Hacer de paso 4), generado al vuelo -- mismo
    patron que report() (M6), pero a diferencia de ese, disponible en
    cualquier estado de la operacion: es material para preparar/usar
    durante el taller, no solo un cierre post-operacion."""

    operation = _get_operation_or_404(operation_id)
    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    kit = generate_workshop_kit(operation, telemetry)

    # M13h: unica variante nueva es PDF -- el caso de uso real de este
    # kit (imprimir y completar a mano). `to_json()` existe desde M12i
    # (simetria con OperationReport) pero sin consumidor real todavia;
    # no se le suma un botón/ruta que nadie pidio.
    fmt = request.args.get("format", "markdown")
    if fmt == "pdf":
        body, mimetype, extension = kit.to_pdf(), "application/pdf", "pdf"
    else:
        body, mimetype, extension = kit.to_markdown(), "text/markdown", "md"

    response = Response(body, mimetype=mimetype)
    response.headers["Content-Disposition"] = f'attachment; filename="kit-taller-{operation_id}.{extension}"'
    return response


def _tree_deployment_panels(
    operation: Operation,
) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict], dict[str, dict], dict[str, dict]]:
    """Mismos cinco paneles de recursos que `detail()` ya
    calcula para `build_operation_tree()`/`build_deception_path()` --
    recalculados acá en vez de reusar los de `detail()` porque la ruta
    de descarga GraphML (tercera de la tanda de mejoras de UI/UX con
    referencia CounterCraft, ver docs/roadmap.md) es un request HTTP
    aparte, sin acceso al estado de ese otro request. No incluye
    `unavailable_external_bindings`/`buda_narratives`/etc. que sí
    calcula `detail()` porque el árbol no los consume."""

    dolost_panels: dict[str, dict] = {}
    buda_panels: dict[str, dict] = {}
    honeytoken_panels: dict[str, dict] = {}
    canarytoken_panels: dict[str, dict] = {}
    opencanary_panels: dict[str, dict] = {}
    for binding in operation.plugins:
        kind = _deployment_kind(binding)
        if kind == "honeytoken":
            honeytoken_panels[binding.plugin_id] = _honeytoken_panel_data(binding, operation.id)
        elif kind == "canarytoken":
            canarytoken_panels[binding.plugin_id] = _canarytoken_panel_data(binding)
        elif kind == "opencanary":
            opencanary_panels[binding.plugin_id] = _opencanary_panel_data(binding)
    if current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"]:
        for binding in operation.plugins:
            kind = _plugin_kind(binding)
            if kind == "dolost":
                dolost_panels[binding.plugin_id] = _dolost_panel_data(binding)
            elif kind == "buda":
                buda_panels[binding.plugin_id] = _buda_panel_data(binding)
    return (
        dolost_panels,
        buda_panels,
        honeytoken_panels,
        canarytoken_panels,
        opencanary_panels,
    )


@operations_bp.route("/<operation_id>/tree.graphml")
def operation_tree_graphml(operation_id: str):
    """Export GraphML (abre en Gephi) del árbol de la operación --
    tercera de la tanda de mejoras de UI/UX con referencia CounterCraft
    (ver docs/roadmap.md: Deception Director exporta a Gephi). Generado
    al vuelo, sin persistir nada -- mismo patrón que report()/
    workshop_kit(), pero a diferencia de esos dos, un solo formato de
    salida (GraphML no tiene el mismo abanico de consumidores que un
    informe post-operación), así que no hay `?format=` ni ruta
    compartida con ninguna otra descarga."""

    operation = _get_operation_or_404(operation_id)
    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    telemetry_records = telemetry.list_events(operation.id)
    (
        dolost_panels,
        buda_panels,
        honeytoken_panels,
        canarytoken_panels,
        opencanary_panels,
    ) = _tree_deployment_panels(operation)
    tree = build_operation_tree(
        operation,
        telemetry_records,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
        canarytoken_panels=canarytoken_panels,
        opencanary_panels=opencanary_panels,
    )
    body = operation_tree_to_graphml(operation, tree)

    # Sin `application/graphml+xml` registrado en IANA (a diferencia de
    # `application/stix+json`, que sí define la especificación OASIS de
    # STIX 2.1) -- se sirve como `application/xml`, con la extensión
    # `.graphml` en el nombre de archivo (lo que Gephi/yEd/NetworkX
    # reconocen en la práctica, ver docstring de
    # apate.web._operation_tree_graphml).
    response = Response(body, mimetype="application/xml")
    response.headers["Content-Disposition"] = f'attachment; filename="arbol-{operation_id}.graphml"'
    return response


def _build_reoperate_prefill(operation: Operation, operation_report: OperationReport) -> dict:
    """Precarga para 'Reoperar' (M12g, paso 7 -> paso 1 del ciclo que
    describe la metodologia CTI-a-ciberengano: "posteriormente, se
    podra recomenzar desde el primer paso con mas informacion sobre el
    atacante"). No crea nada -- solo calcula los valores con los que
    `reoperate()` precarga `operations/form.html`.

    expected_ttps = union de lo esperado original
    (AdversaryProfile.expected_ttps) y lo observado-y-no-esperado
    (OperationReport.unexpected_ttps, informacion nueva real sobre el
    adversario). matched_ttps no se suma aparte: ya esta incluido en
    expected_ttps original. target_assets se copia tal cual (se asume
    que siguen siendo relevantes, el operador los puede editar antes
    de confirmar).

    Clave `adversary_notes` (no `notes`) a proposito: el catalogo de
    plantillas de operacion (`apate.web._operation_templates`) tambien
    produce un `prefill` para este mismo formulario, y sus claves ya
    coinciden 1:1 con los `name="..."` de `operations/form.html` (mismo
    dict que se postea directo en `examples/seed_demo.py`) -- alinear
    esta clave evita que el template tenga que aceptar dos nombres
    distintos para el mismo campo segun de donde venga el prefill."""

    expected_ttps = set(operation.adversary_profile.expected_ttps) | set(operation_report.unexpected_ttps)

    reference = f"Reoperada a partir de '{operation.name}' (id: {operation.id})."
    original_notes = operation.adversary_profile.notes.strip()
    notes = f"{original_notes}\n\n{reference}" if original_notes else reference

    return {
        "expected_ttps": expected_ttps,
        "target_assets": ", ".join(operation.adversary_profile.target_assets),
        "adversary_notes": notes,
    }


@operations_bp.route("/<operation_id>/reoperate")
def reoperate(operation_id: str):
    """Precarga el formulario de creacion (M12g) a partir del informe
    post-operacion de una operacion cerrada -- solo tiene sentido
    sobre `CLOSED`, mismo patron que `report()`. No crea la Operacion
    nueva directamente: renderiza `operations/form.html` con los
    valores calculados por `_build_reoperate_prefill()`, y el operador
    confirma (o edita antes de confirmar) con el submit normal de
    `create_operation()` -- mismo criterio de "asiste, nunca decide"
    de toda la seccion 8 del diseno, aca aplicado a "reoperar" en vez
    de a un LLM."""

    operation = _get_operation_or_404(operation_id)
    if operation.status != OperationStatus.CLOSED:
        flash(_('Solo se puede reoperar a partir de una operación cerrada.'), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    operation_report = generate_report(operation, telemetry)
    prefill = _build_reoperate_prefill(operation, operation_report)

    return _render_new_operation_form(prefill=prefill)


@operations_bp.route("/<operation_id>/transition", methods=["POST"])
def transition(operation_id: str):
    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)

    to = request.form.get("to", "")
    method = _TRANSITION_METHODS.get(to)
    if method is None:
        flash(_("Transición desconocida: '%(to)s'.", to=to), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    try:
        method(operation)
    except InvalidTransitionError as exc:
        flash(str(exc), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    repo.save(operation)
    flash(_("Operación transicionada a '%(value)s'.", value=operation_status_label(operation.status.value)), "success")
    return redirect(url_for("operations.detail", operation_id=operation_id))


def _get_operation_or_404(operation_id: str) -> Operation:
    repo = current_app.config["OPERATION_REPOSITORY"]
    try:
        return repo.get(operation_id)
    except OperationNotFoundError:
        abort(404)
