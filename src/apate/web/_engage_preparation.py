"""Vista de "Preparación" (Goals `Prepare`/`Understand` de MITRE
Engage, `kind == "strategic"`) -- capa de presentación pura sobre
campos que ya existen en `Operation`, mismo criterio que el heatmap de
TTPs (M13a, `_ttp_presentation.py`) o "Esperado vs. observado" del
Playground (M14f): ninguna de las 8 actividades estratégicas del
catálogo (`apate.engage`, M12a) tiene un campo nuevo dedicado -- se
cruzan contra los campos reales que ya existían, confirmado leyendo
`apate.core.models` antes de escribir esto, no asumido.

**Mapeo confirmado, actividad por actividad** (SAC0001-SAC0012, orden
del dataset -- ver `apate/data/mitre_engage_matrix.json`):

- **SAC0001 Operational Objective -> `StrategicDecisions.objectives`.**
- **SAC0002 Persona Creation -> perfiles de usuario (`UserProfile`) de
  BUDA, vía el mismo `buda_panels` que ya arma `operations.py::detail()`
  para el panel "Narrativa de comportamiento simulado".** Investigado
  antes de asumir: `Narrative` (paso 5) es la historia compartida por
  todos los plugins ("IT support impersonation targeting HR"), no un
  usuario ficticio puntual con datos plantados -- la descripción real
  de SAC0002 ("a fictitious human user through a combination of
  planted data and revealed behavior patterns") es exactamente lo que
  ya modela `BUDA.UserProfile` (nombre/rol/servidor WinRM), aunque sea
  a nivel de plugin, no de `Operation` -- no hay ningún campo a nivel
  de `Operation` que lo represente mejor. Requiere que
  `APATE_MOUNT_EXTERNAL_TOOLS` esté activo para poder consultarlo
  (mismo gate que ya tiene `buda_panels` en `detail()`); si está
  apagado, el estado queda `"not_covered"` con el motivo explícito en
  el detalle en vez de asumir que no hay nada.
- **SAC0003 Storyboarding -> `Scenario` (paso 3).** `Narrative` (paso
  5) queda deliberadamente afuera de este cruce -- son dos pasos
  distintos de la metodología (la corrección ya documentada en M12i
  sobre "el paso 3 es el Scenario en sí" aplica igual acá), y
  `Narrative` ya tiene su propio tab en el detalle de la operación, no
  se pierde por no aparecer también en esta tabla.
- **SAC0004 Cyber Threat Intelligence -> `AdversaryProfile`
  (`expected_ttps`/`motivation`/`notes`).** Cubre tanto la carga manual
  como el resultado del pipeline de `apate.cti` (Fase 6 post-BlackHat)
  -- ese pipeline nunca persiste "se usó IA acá", solo el resultado ya
  aplicado a estos mismos campos, así que no hay nada más que cruzar.
- **SAC0005 Gating Criteria -> `ClosureCriteria`.** Ya citado
  explícitamente en el código (`apate.core.models`, docstring de M12f):
  *"the unnegotiable pause or conclusion to the operation"*, el mismo
  concepto -- se reusa tal cual, sin reinterpretarlo.
- **SAC0006 After-Action Review -> el informe post-operación
  (`apate.reporting.generate_report()`, M6).** No se llama
  `generate_report()` acá (necesitaría telemetría real solo para un
  chequeo de cobertura) -- la señal real es `operation.status`: el
  informe se vuelve un artefacto real y descargable recién con la
  operación `CLOSED` (mismo gate que ya usan los botones de descarga
  en `operations/detail.html` desde M6).
- **SAC0009 Threat Model -> sin campo equivalente.** Investigado
  explícitamente: es una autoevaluación de fortalezas/debilidades
  organizacionales *propias*, no del adversario -- `AdversaryProfile`
  (TTPs/activos objetivo) describe al adversario y lo que está en
  juego, no una evaluación de riesgo de la propia organización.
  Ningún campo de `apate.core.models` representa esto hoy. Se marca
  explícito en la vista (`status == "no_field"`), sin forzar un mapeo
  que no existe -- mismo criterio de honestidad que usó M14g con el
  escenario fijo del Playground.
- **SAC0012 Engagement Environment -> `RulesOfEngagement.environment`
  (+ `allowed_actions`/`forbidden_actions`/`legal_constraints`/
  `escalation_contact`).** `environment` siempre tiene un valor real
  (default `Environment.ISOLATED`, nunca vacío) -- "cubierta" exige
  además una decisión deliberada más allá del default (un entorno
  distinto de `isolated`, o al menos una restricción de RoE cargada),
  para que esta fila no quede trivialmente "cubierta" siempre sin
  decir nada.

Sin escala de color nueva (pedido explícito): reusa `.tag`/`.tag.accent`
ya existentes (M12d/M13b) -- "cubierta" en acento, "parcial"/"sin
cubrir" en tag plano, "sin campo equivalente" sin badge (solo texto
`.muted`), para que la ausencia de mapeo se note visualmente distinta
de "campo vacío"."""

from __future__ import annotations

from ..core.models import Environment, Operation, OperationStatus
from ..engage import list_activities
from ..i18n import gettext as _
from ._enum_labels import environment_label, strategic_objective_label
from ._portfolio import _resolve_portfolio_plugin_kind

# Unica actividad estrategica sin campo real al que mapear -- ver
# docstring del modulo (SAC0009 Threat Model).
NO_FIELD_ACTIVITY_IDS = {"SAC0009"}


def _operational_objective(operation: Operation) -> tuple[str, str]:
    decisions = operation.strategic_decisions
    if decisions.objectives:
        labels = ", ".join(strategic_objective_label(o.value) for o in decisions.objectives)
        return "covered", _("Objetivos estratégicos definidos: %(labels)s.", labels=labels)
    if decisions.roles or decisions.resource_estimate:
        return "partial", _("Roles y/o estimación de recursos cargados, pero sin ningún objetivo estratégico seleccionado.")
    return "not_covered", _("Sin objetivos estratégicos, roles ni estimación de recursos cargados.")


def _persona_creation(operation: Operation, *, buda_panels: dict, buda_tools_mounted: bool) -> tuple[str, str]:
    buda_bindings = [binding for binding in operation.plugins if _resolve_portfolio_plugin_kind(binding) == "buda"]
    if not buda_bindings:
        return "not_covered", _("Sin ningún plugin de identidad/comportamiento vinculado a esta operación.")
    if not buda_tools_mounted:
        return (
            "not_covered",
            _("Hay un plugin de identidad/comportamiento vinculado, pero la mecánica específica no está disponible en este servidor -- no se puede consultar si tiene personas (perfiles de usuario) configuradas desde acá."),
        )
    profile_count = sum(len(buda_panels.get(binding.plugin_id, {}).get("user_profiles", [])) for binding in buda_bindings)
    if profile_count:
        return "covered", _("%(count)s perfil(es) de usuario configurados en la narrativa de comportamiento simulado.", count=profile_count)
    return "partial", _("Hay un plugin de identidad/comportamiento vinculado, pero todavía sin ningún perfil de usuario asignado.")


def _storyboarding(operation: Operation) -> tuple[str, str]:
    if not operation.scenarios:
        return "not_covered", _("Sin ningún escenario cargado (paso 3).")
    with_ttps = [s for s in operation.scenarios if s.related_ttps]
    if with_ttps:
        return "covered", _("%(scenario_count)s escenario(s) cargado(s), %(ttp_count)s con TTPs relacionadas.", scenario_count=len(operation.scenarios), ttp_count=len(with_ttps))
    return "partial", _("%(count)s escenario(s) cargado(s), pero ninguno con TTPs relacionadas todavía.", count=len(operation.scenarios))


def _cyber_threat_intelligence(operation: Operation) -> tuple[str, str]:
    profile = operation.adversary_profile
    if profile.expected_ttps:
        return "covered", _("%(count)s TTP(s) esperada(s) cargada(s) en el perfil de adversario.", count=len(profile.expected_ttps))
    if profile.motivation or profile.notes:
        return "partial", _("Motivación y/o notas cargadas, pero sin ninguna TTP esperada todavía.")
    return "not_covered", _("Perfil de adversario sin TTPs, motivación ni notas cargadas.")


def _gating_criteria(operation: Operation) -> tuple[str, str]:
    criteria = operation.closure_criteria
    if criteria.end_date is not None or criteria.trigger_conditions:
        parts = []
        if criteria.end_date is not None:
            parts.append(_("fecha de cierre planificada (%(date)s)", date=criteria.end_date.date()))
        if criteria.trigger_conditions:
            parts.append(_("%(count)s condición(es) de disparo por evento (M12f)", count=len(criteria.trigger_conditions)))
        return "covered", _("Gating Criteria real: %(parts)s.", parts=_(" y ").join(parts))
    if criteria.conditions:
        return "partial", _("Solo condiciones de cierre en texto libre (sin efecto real sobre el motor) -- sin fecha ni condiciones de disparo.")
    return "not_covered", _("Sin fecha de cierre, condiciones de disparo ni condiciones en texto libre.")


def _after_action_review(operation: Operation) -> tuple[str, str]:
    if operation.status == OperationStatus.CLOSED:
        return "covered", _("Operación cerrada -- el informe post-operación (M6) es un artefacto real, descargable desde la cabecera.")
    if operation.status in (OperationStatus.ACTIVE, OperationStatus.COMPROMISED):
        return "partial", _("Operación todavía no cerrada -- el informe post-operación recién se genera al cerrarla.")
    return "not_covered", _("Operación en planificación -- todavía no hay nada que revisar.")


def _threat_model() -> tuple[str, str]:
    return "no_field", _("Sin campo equivalente en el modelo todavía -- ver docstring de apate.web._engage_preparation.")


def _engagement_environment(operation: Operation) -> tuple[str, str]:
    roe = operation.roe
    has_constraints = bool(roe.allowed_actions or roe.forbidden_actions or roe.legal_constraints or roe.escalation_contact)
    environment = environment_label(roe.environment.value)
    if has_constraints:
        return "covered", _("Entorno: %(environment)s. Con restricciones de Rules of Engagement configuradas.", environment=environment)
    if roe.environment != Environment.ISOLATED:
        return "covered", _("Entorno: %(environment)s.", environment=environment)
    return "partial", _("Entorno: %(environment)s. Entorno por defecto (aislado), sin restricciones adicionales de RoE.", environment=environment)


# activity.id -> funcion que calcula (status, detail) para esa actividad.
# _threat_model() no toma `operation`: no depende de ningun dato real.
_CALCULATORS = {
    "SAC0001": lambda operation, **_: _operational_objective(operation),
    "SAC0002": lambda operation, *, buda_panels, buda_tools_mounted, **_: _persona_creation(
        operation, buda_panels=buda_panels, buda_tools_mounted=buda_tools_mounted
    ),
    "SAC0003": lambda operation, **_: _storyboarding(operation),
    "SAC0004": lambda operation, **_: _cyber_threat_intelligence(operation),
    "SAC0005": lambda operation, **_: _gating_criteria(operation),
    "SAC0006": lambda operation, **_: _after_action_review(operation),
    "SAC0009": lambda operation, **_: _threat_model(),
    "SAC0012": lambda operation, **_: _engagement_environment(operation),
}

# Destino real donde el operador puede completar o revisar cada señal.
# SAC0009 no tiene destino porque tampoco existe un campo equivalente.
_ACTIVITY_TARGETS = {
    "SAC0001": ("tab-roe", _("Completar decisiones estratégicas")),
    "SAC0002": ("tab-plugins", _("Configurar identidad y comportamiento")),
    "SAC0003": ("tab-scenarios", _("Completar escenarios")),
    "SAC0004": ("tab-profile", _("Revisar perfil de adversario")),
    "SAC0005": ("tab-roe", _("Revisar criterios de cierre")),
    "SAC0006": ("operation-resources", _("Revisar resultados")),
    "SAC0012": ("tab-roe", _("Revisar Rules of Engagement")),
}


def preparation_coverage(operation: Operation, *, buda_panels: dict, buda_tools_mounted: bool) -> list[dict]:
    """Una fila por actividad estratégica del catálogo (`apate.engage`,
    `kind == "strategic"`, orden del dataset), con `status` en
    `"covered"`/`"partial"`/`"not_covered"`/`"no_field"` y `detail`
    (texto explicando la evidencia real, o por qué no hay ninguna)."""

    rows = []
    for activity in list_activities(kind="strategic"):
        calculator = _CALCULATORS[activity.id]
        status, detail = calculator(operation, buda_panels=buda_panels, buda_tools_mounted=buda_tools_mounted)
        target = _ACTIVITY_TARGETS.get(activity.id)
        rows.append(
            {
                "activity": activity,
                "status": status,
                "detail": detail,
                "target": target[0] if target else None,
                "target_label": target[1] if target else None,
            }
        )
    return rows
