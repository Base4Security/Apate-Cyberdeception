"""Centro operativo derivado de evidencia ya disponible en APATE.

Esta capa solo prepara presentacion: no persiste estados nuevos, no
calcula scores y no ejecuta acciones. Las recomendaciones son reglas
deterministas visibles y siempre requieren confirmacion del operador.
"""

from __future__ import annotations

from ..core.models import Environment, Operation, OperationStatus
from ..i18n import gettext as _
from ..i18n import gettext_noop as N_
from ._enum_labels import operation_status_label


# `gettext_noop` y no `gettext`: este diccionario se construye al importar el
# modulo, cuando todavia no hay request ni idioma resuelto, asi que una
# traduccion real quedaria congelada en el idioma original. Se traduce al
# leerla, en `_state_label`. Mismo criterio que `_enum_labels` y que
# `PluginDescription` con `lazy_gettext`.
_STATE_LABELS = {
    "not_started": N_("Sin iniciar"),
    "pending": N_("Con pendientes"),
    "ready": N_("Lista"),
    "active": N_("Con actividad"),
}


def _state_label(state: str) -> str:
    return _(_STATE_LABELS[state])


def _step(key: str, label: str, state: str, detail: str, target: str, action_label: str) -> dict:
    return {
        "key": key,
        "label": label,
        "state": state,
        "state_label": _state_label(state),
        "detail": detail,
        "target": target,
        "action_label": action_label,
        "external_url": None,
    }


def _binding_kind(binding) -> str:
    """Resuelve el tipo con la misma compatibilidad para bindings antiguos."""

    return binding.plugin_kind or binding.plugin_id.casefold().split("-", 1)[0]


def _deployment_snapshot(
    operation: Operation,
    *,
    dolost_panels: dict,
    buda_panels: dict,
    honeytoken_panels: dict,
) -> dict:
    """Resume solo estados que cada proveedor puede demostrar."""

    active = 0
    configured = 0
    pending = 0
    for binding in operation.plugins:
        kind = _binding_kind(binding)
        if kind == "dolost":
            panel = dolost_panels.get(binding.plugin_id)
            if panel and any(decoy.get("up") for decoy in panel.get("decoys", [])):
                active += 1
            elif panel and panel.get("docker_available"):
                configured += 1
            else:
                pending += 1
        elif kind == "buda":
            panel = buda_panels.get(binding.plugin_id)
            if panel and panel.get("found") and panel.get("is_running"):
                active += 1
            elif panel and panel.get("found"):
                configured += 1
            else:
                pending += 1
        elif kind == "honeytoken":
            panel = honeytoken_panels.get(binding.plugin_id, {})
            if panel.get("deployed"):
                active += 1
            elif panel.get("configured"):
                configured += 1
            else:
                pending += 1
        else:
            # Un binding prueba asociacion/configuracion, no despliegue real.
            configured += 1

    total = len(operation.plugins)
    if not total:
        state = "not_started"
        detail = _("Sin capacidades vinculadas.")
    elif active:
        state = "active"
        detail = _("%(total)s vinculada(s): %(active)s activa(s), %(configured)s lista(s) y %(pending)s pendiente(s) de verificar.", total=total, active=active, configured=configured, pending=pending)
    elif pending:
        state = "pending"
        detail = _("%(total)s vinculada(s): ninguna activa y %(pending)s pendiente(s) de verificar.", total=total, pending=pending)
    else:
        state = "ready"
        detail = _("%(total)s capacidad(es) vinculada(s) y configurada(s), todavía sin actividad demostrada.", total=total)
    return {
        "state": state,
        "state_label": _state_label(state),
        "detail": detail,
        "total": total,
        "active": active,
        "configured": configured,
        "pending": pending,
    }


def _cycle_steps(
    operation: Operation,
    metrics: dict,
    coverage: list[dict],
    deployment: dict,
    *,
    dry_run,
    narrative_coherence,
    operation_rules: list[dict],
    operation_rules_error: str | None,
) -> list[dict]:
    profile = operation.adversary_profile
    if profile.expected_ttps and profile.target_assets:
        profile_state = "ready"
        profile_detail = _("%(ttp_count)s TTP(s) y %(asset_count)s activo(s) objetivo definidos.", ttp_count=len(profile.expected_ttps), asset_count=len(profile.target_assets))
    elif profile.expected_ttps or profile.motivation or profile.notes:
        profile_state = "pending"
        profile_detail = _("El perfil tiene evidencia parcial; faltan TTPs o activos objetivo.")
    else:
        profile_state = "not_started"
        profile_detail = _("Sin TTPs, motivación, notas ni activos objetivo.")

    roe = operation.roe
    roe_signals = bool(
        roe.allowed_actions or roe.forbidden_actions or roe.legal_constraints or roe.escalation_contact
    )
    strategy_signals = bool(
        operation.strategic_decisions.objectives
        and operation.strategic_decisions.roles
        and operation.strategic_decisions.resource_estimate
    )
    if roe_signals and strategy_signals:
        roe_state = "ready"
        roe_detail = _("RoE, objetivos, responsables y recursos definidos.")
    elif roe_signals or operation.strategic_decisions.objectives or roe.environment != Environment.ISOLATED:
        roe_state = "pending"
        roe_detail = _("Hay decisiones cargadas, pero el marco operativo todavía es parcial.")
    else:
        roe_state = "not_started"
        roe_detail = _("Solo está el entorno aislado por defecto, sin decisiones estratégicas.")

    narrative = operation.narrative
    if narrative.description and (narrative.story_elements or narrative.psychological_impact):
        narrative_state = "ready"
        narrative_detail = _("Historia y mecanismo narrativo definidos.")
    elif narrative.description or narrative.story_elements or narrative.psychological_impact:
        narrative_state = "pending"
        narrative_detail = _("Narrativa cargada de forma parcial.")
    else:
        narrative_state = "not_started"
        narrative_detail = _("Sin historia, elementos ni impacto psicológico definidos.")

    coverage_rows = [row for row in coverage if row["status"] != "no_field"]
    covered = sum(row["status"] == "covered" for row in coverage_rows)
    partial = sum(row["status"] == "partial" for row in coverage_rows)
    if metrics["measured_effect_count"]:
        engage_state = "active"
        engage_detail = _("%(count)s efecto(s) con resultado humano registrado.", count=metrics["measured_effect_count"])
    elif coverage_rows and covered == len(coverage_rows):
        engage_state = "ready"
        engage_detail = _("%(covered)s/%(total)s actividades estratégicas con evidencia.", covered=covered, total=len(coverage_rows))
    elif covered or partial or operation.plugins:
        engage_state = "pending"
        engage_detail = _("%(covered)s/%(total)s actividades cubiertas; quedan evidencias por completar.", covered=covered, total=len(coverage_rows))
    else:
        engage_state = "not_started"
        engage_detail = _("Sin actividades cubiertas ni efectos vinculados.")

    if operation.scenarios and all(scenario.related_ttps for scenario in operation.scenarios):
        scenario_state = "ready"
        scenario_detail = _("%(count)s escenario(s), todos vinculados a TTPs.", count=len(operation.scenarios))
    elif operation.scenarios:
        scenario_state = "pending"
        scenario_detail = _("%(count)s escenario(s), con vínculos a TTPs pendientes.", count=len(operation.scenarios))
    else:
        scenario_state = "not_started"
        scenario_detail = _("Sin escenarios cargados.")

    if metrics["event_count"]:
        observation_state = "active"
        observation_detail = _("%(count)s evento(s) persistido(s) en Telemetría.", count=metrics["event_count"])
    elif operation.status in (OperationStatus.ACTIVE, OperationStatus.COMPROMISED, OperationStatus.CLOSED):
        observation_state = "ready"
        observation_detail = _("La operación puede observarse, pero aún no tiene eventos persistidos.")
    else:
        observation_state = "not_started"
        observation_detail = _("La observación comenzará cuando la operación genere telemetría.")

    design_states = (profile_state, roe_state, narrative_state, engage_state, scenario_state)
    design_state = "not_started" if "not_started" in design_states else "pending" if "pending" in design_states else "ready"
    design_detail = _("El diseño reúne perfil, RoE, narrativa, Engage y escenarios.")
    steps = [_step("design", _("Diseño"), design_state, design_detail, "tab-design", _("Completar diseño"))]

    if operation.scenarios and operation.plugins:
        coherence_checks = narrative_coherence["checks"]
        validation_count = len(dry_run.findings) + len(coherence_checks)
        validation_detail = (
            _("Sin huecos detectados; %(checks)s chequeo(s) de coherencia para revisar.", checks=len(coherence_checks))
            if not dry_run.findings
            else _("%(count)s hallazgo(s): %(dry)s de ensayo y %(coherence)s de coherencia.", count=validation_count, dry=len(dry_run.findings), coherence=len(coherence_checks))
        )
        steps.append(
            _step(
                "validation",
                _("Validación"),
                "pending" if dry_run.findings else "ready",
                validation_detail,
                "tab-review",
                _("Validar el diseño"),
            )
        )

        applicable_rules = sum(rule["applies"] for rule in operation_rules)
        if operation_rules_error:
            rules_state = "pending"
            rules_detail = operation_rules_error
        elif applicable_rules:
            rules_state = "ready"
            rules_detail = _("%(count)s regla(s) global(es) aplican a esta operación.", count=applicable_rules)
        else:
            rules_state = "pending"
            rules_detail = _("No hay reglas globales que apliquen a esta operación.")
        rules_step = _step(
            "rules", _("Reglas"), rules_state, rules_detail, "tab-roe", _("Revisar reglas")
        )
        if not operation_rules_error and not applicable_rules:
            rules_step["external_url"] = "rules"
        steps.append(rules_step)

    if operation.status in (OperationStatus.ACTIVE, OperationStatus.COMPROMISED, OperationStatus.CLOSED):
        steps.append(_step("deployment", _("Despliegue"), deployment["state"], deployment["detail"], "tab-plugins", _("Revisar capacidades")))
        steps.append(_step("observation", _("Observación"), observation_state, observation_detail, "operation-timeline", _("Abrir actividad")))
    if operation.status in (OperationStatus.COMPROMISED, OperationStatus.CLOSED):
        steps.append(
            _step(
                "closure",
                _("Cierre"),
                "ready" if operation.status == OperationStatus.CLOSED else "pending",
                _("La transición de cierre requiere confirmación humana.")
                if operation.status != OperationStatus.CLOSED
                else _("Operación cerrada; los informes permanecen disponibles."),
                "tab-resultados",
                _("Revisar y cerrar"),
            )
        )
    return steps


def _next_action(operation: Operation, steps: list[dict], metrics: dict) -> dict:
    """Elige una acción permitida; nunca la ejecuta ni cambia el dominio."""

    if operation.status == OperationStatus.CLOSED:
        return {
            "kind": "reoperate",
            "label": _("Reoperar"),
            "reason": _("La operación está cerrada; su estado es irreversible y la continuidad requiere una nueva operación."),
        }

    pending_steps = [step for step in steps if step["state"] in ("not_started", "pending")]
    if operation.status == OperationStatus.PLANNING:
        validation_step = next(
            (step for step in steps if step["key"] == "validation" and step["state"] == "pending"),
            None,
        )
        if validation_step:
            return {
                "kind": "anchor",
                "label": validation_step["action_label"],
                "target": validation_step["target"],
                "reason": validation_step["detail"],
            }
        if pending_steps:
            selected = pending_steps[0]
            if selected["external_url"] == "rules":
                return {"kind": "rules", "label": _("Escribir la primera regla"), "reason": selected["detail"]}
            return {
                "kind": "anchor",
                "label": selected["action_label"],
                "target": selected["target"],
                "reason": _("%(label)s: %(detail)s", label=selected["label"], detail=selected["detail"]),
            }
        return {
            "kind": "transition",
            "transition": "active",
            "label": _("Marcar activa"),
            "reason": _("Los seis pasos de preparación no muestran pendientes explícitos."),
        }

    deployment_step = next(step for step in steps if step["key"] == "deployment")
    if operation.status == OperationStatus.ACTIVE:
        if deployment_step["state"] in ("not_started", "pending"):
            return {
                "kind": "anchor",
                "label": deployment_step["action_label"],
                "target": deployment_step["target"],
                "reason": deployment_step["detail"],
            }
        if not metrics["event_count"]:
            return {
                "kind": "telemetry",
                "label": _("Abrir telemetría"),
                "reason": _("No hay eventos persistidos todavía; conviene verificar la observación antes de cambiar el estado."),
            }
        return {
            "kind": "transition",
            "transition": "compromised",
            "label": _("Marcar comprometida"),
            "reason": _("Hay %(count)s evento(s) persistido(s); el cambio de estado requiere confirmación humana.", count=metrics["event_count"]),
        }

    return {
        "kind": "transition",
        "transition": "closed",
        "label": _("Revisar y cerrar"),
        "reason": _("La operación está comprometida; cerrar es la transición permitida restante y es irreversible."),
    }


def build_operation_center(
    operation: Operation,
    *,
    operation_metrics: dict,
    operation_timeline: list[dict],
    preparation_coverage: list[dict],
    dolost_panels: dict,
    buda_panels: dict,
    honeytoken_panels: dict,
    dry_run,
    narrative_coherence,
    operation_rules: list[dict],
    operation_rules_error: str | None,
) -> dict:
    """Construye la primera lectura operativa desde hechos existentes."""

    deployment = _deployment_snapshot(
        operation,
        dolost_panels=dolost_panels,
        buda_panels=buda_panels,
        honeytoken_panels=honeytoken_panels,
    )
    steps = _cycle_steps(
        operation,
        operation_metrics,
        preparation_coverage,
        deployment,
        dry_run=dry_run,
        narrative_coherence=narrative_coherence,
        operation_rules=operation_rules,
        operation_rules_error=operation_rules_error,
    )
    attention = [step for step in steps if step["state"] in ("not_started", "pending")][:3]
    recent_activity = []
    for entry in operation_timeline[:3]:
        presented = dict(entry)
        if entry["source"] == "operation" and entry["detail"].startswith("Estado inicial: "):
            raw_status = entry["detail"].removeprefix("Estado inicial: ")
            presented["detail"] = _("Estado inicial: %(status)s", status=operation_status_label(raw_status))
        elif entry["source"] == "operation" and entry["detail"].startswith("Estado actual: "):
            raw_status = entry["detail"].removeprefix("Estado actual: ")
            presented["detail"] = _("Estado actual: %(status)s", status=operation_status_label(raw_status))
        recent_activity.append(presented)

    return {
        "steps": steps,
        "attention": attention,
        "next_action": _next_action(operation, steps, operation_metrics),
        "deployment": deployment,
        "recent_activity": recent_activity,
    }


def build_operation_list_attention(operation: Operation, *, event_count: int) -> dict:
    """Resume para el listado los mismos pendientes nominales del Centro.

    El listado no consulta proveedores externos ni el filesystem. Por eso
    cualquier despliegue que necesite esa evidencia queda pendiente de
    verificar; nunca se presenta como activo por tener solo un binding.
    """

    metrics = {
        "event_count": event_count,
        "measured_effect_count": sum(bool(binding.effect.measured_outcome) for binding in operation.plugins),
    }
    deployment = _deployment_snapshot(
        operation,
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
    )
    # El listado no tiene las revisiones ni el cruce de reglas de la vista de detalle.
    steps = _cycle_steps(
        operation,
        metrics,
        [],
        deployment,
        dry_run=type("DryRun", (), {"findings": []})(),
        narrative_coherence={"checks": []},
        operation_rules=[],
        operation_rules_error=None,
    )
    pending = [step for step in steps if step["state"] in ("not_started", "pending")]
    if operation.status == OperationStatus.CLOSED:
        return {"count": 0, "items": [], "label": _("Cerrada")}
    return {
        "count": len(pending),
        "items": pending[:3],
        "label": _("%(count)s pendiente(s)", count=len(pending)) if pending else _("Sin pendientes"),
    }
