"""Control autenticado del plan aprobado y recuperación explícita."""

from flask import Blueprint, abort, current_app, jsonify, render_template, request

from ...ledger import LedgerError
from ...ledger.plugins import approved_plugins
from ...i18n import gettext as _
from .._rule_engine_runtime import build_rule_bus, build_rule_engine
from .operations import _get_operation_or_404

operation_control_bp = Blueprint("operation_control", __name__, url_prefix="/operations")


@operation_control_bp.get("/<operation_id>/control/overview")
def overview(operation_id):
    """Resume la autoridad vigente sin exponer descriptores ni secretos congelados."""
    operation = _get_operation_or_404(operation_id)
    executor = current_app.config["OPERATION_EXECUTOR"]
    executor.authorize_query(operation_id)
    if not executor.managed(operation_id):
        abort(404)
    ledger = executor.ledger
    state = ledger.operation(operation_id)
    active_plan = ledger.record(operation_id, state["active_plan_id"]) if state["active_plan_id"] else None
    sections = []
    comparison_available = False
    if active_plan:
        try:
            draft = current_app.config["OPERATION_PLAN_SERVICE"].capture_design(operation_id)
        except (LedgerError, OSError, ValueError):
            draft = None
        if draft is not None:
            approved = active_plan["payload"]["content"]
            section_keys = (
                ("name", _("Nombre")),
                ("adversary_profile", _("Perfil de adversario")),
                ("roe", _("Reglas de interacción")),
                ("narrative", _("Narrativa")),
                ("strategic_decisions", _("Decisiones estratégicas")),
                ("scenarios", _("Escenarios")),
                ("plugins", _("Capacidades y efectos planificados")),
                ("telemetry_bridges", _("Fuentes de telemetría")),
                ("closure_criteria", _("Criterios de cierre")),
                ("behavior_context_source_ids", _("Fuentes de contexto")),
                ("team_id", _("Equipo")),
            )
            sections = [{"label": label, "changed": draft["operation"].get(key) != approved["operation"].get(key)}
                        for key, label in section_keys]
            sections.extend((
                {"label": _("Reglas del motor"), "changed": draft["rules"]["sha256"] != approved["rules"]["sha256"]},
                {"label": _("Activos"), "changed": draft["assets"] != approved["assets"]},
                {"label": _("Contexto de comportamiento"), "changed": draft["context_sources"] != approved["context_sources"]},
                {"label": _("Catálogos"), "changed": draft["catalogs"] != approved["catalogs"]},
            ))
            comparison_available = True
    state_labels = {"preparation": _("Preparación"), "active": _("Activa"),
                    "paused": _("Pausada"), "closing": _("En cierre"), "closed": _("Cerrada")}
    return render_template("operations/control_overview.html", operation=operation,
                           state=state, state_label=state_labels.get(state["state"], state["state"]),
                           active_plan=active_plan, sections=sections,
                           changed_count=sum(section["changed"] for section in sections),
                           comparison_available=comparison_available,
                           pending_count=len(ledger.pending_commands(operation_id)))


def _body():
    value = request.get_json()
    if not isinstance(value, dict):
        raise LedgerError("json_object_required")
    return value


def _context(operation_id):
    executor = current_app.config["OPERATION_EXECUTOR"]
    # Incluso antes del primer usuario, este flujo requiere identidad real.
    principal = executor.authorize(operation_id)
    return executor, principal


@operation_control_bp.get("/<operation_id>/control")
def status(operation_id):
    executor, _ = _context(operation_id)
    return jsonify(executor.status(operation_id))


@operation_control_bp.post("/<operation_id>/control/adopt")
def adopt(operation_id):
    executor, principal = _context(operation_id)
    if not principal.administrator:
        abort(403)
    body = request.get_json(silent=True) or {}
    state = current_app.config["OPERATION_PLAN_SERVICE"].adopt(operation_id, actor=principal.actor, quiescence=body.get("quiescence"))
    return jsonify(operation_id=operation_id, state=state["state"]), 201


@operation_control_bp.post("/<operation_id>/control/adoption-check")
def adoption_check(operation_id):
    _, principal = _context(operation_id)
    if not principal.administrator:
        abort(403)
    return jsonify(current_app.config["OPERATION_PLAN_SERVICE"].prepare_adoption(operation_id))


@operation_control_bp.post("/<operation_id>/control/adoption-jobs/<job_id>/reconcile")
def adoption_reconcile(operation_id, job_id):
    _, principal = _context(operation_id)
    if not principal.administrator:
        abort(403)
    body = _body()
    current_app.config["OPERATION_PLAN_SERVICE"].adoption_gate.reconcile(operation_id, job_id,
        actor=principal.actor, reason=body.get("reason"), workers_quiescent=body.get("workers_quiescent"),
        legacy_authority_disabled=body.get("legacy_authority_disabled"))
    return jsonify(job_id=job_id, state="quiescent", basis="administrator_attestation")


@operation_control_bp.post("/<operation_id>/control/close")
def close(operation_id):
    executor, principal = _context(operation_id)
    body = _body()
    from ...ledger.evidence import OperationEvidence
    plan, definition = executor.snapshot(operation_id)
    executor._principal(operation_id, definition, plan["payload"]["content"]["execution_policy"])
    result = OperationEvidence(executor.ledger).close(operation_id, expected_revision=body.get("revision"),
        criterion=body.get("criterion"), judgment=body.get("judgment"), actor=principal.actor)
    return jsonify(result_id=result["id"], cut_sequence=result["payload"]["cut_sequence"], state="closed")


@operation_control_bp.get("/<operation_id>/control/results/<result_id>")
def result(operation_id, result_id):
    executor, principal = _context(operation_id)
    if not principal.administrator:
        abort(403)
    record = executor.ledger.record(operation_id, result_id)
    if record["kind"] != "result":
        raise LedgerError("result_required")
    response = jsonify(record)
    response.headers["Cache-Control"] = "no-store"
    return response


@operation_control_bp.post("/<operation_id>/control/propose")
def propose(operation_id):
    _, principal = _context(operation_id)
    body = _body()
    record = current_app.config["OPERATION_PLAN_SERVICE"].propose(operation_id,
        parent_id=body.get("parent_id"), reason=body.get("reason"), actor=principal.actor,
        dispositions=body.get("dispositions"), execution_policy=body.get("execution_policy"))
    return jsonify(plan_id=record["id"], digest=record["digest"]), 201


@operation_control_bp.get("/<operation_id>/control/plans/<plan_id>")
def review(operation_id, plan_id):
    executor, principal = _context(operation_id)
    if not principal.administrator:
        abort(403)
    record = executor.ledger.record(operation_id, plan_id)
    if record["kind"] != "plan":
        raise LedgerError("plan_required")
    response = jsonify(record)
    response.headers["Cache-Control"] = "no-store"
    return response


@operation_control_bp.post("/<operation_id>/control/plans/<plan_id>/<action>")
def plan_action(operation_id, plan_id, action):
    executor, principal = _context(operation_id)
    body = _body()
    if action == "approve":
        executor.ledger.approve(operation_id, plan_id, expected_digest=body.get("digest"), actor=principal.actor,
            require_distinct_actor=current_app.config["TWO_PERSON_APPROVAL_ENABLED"])
    elif action == "activate":
        executor.ledger.activate(operation_id, plan_id, expected_digest=body.get("digest"), actor=principal.actor)
    else:
        abort(404)
    return jsonify(plan_id=plan_id, action=action)


@operation_control_bp.post("/<operation_id>/control/stop")
def stop(operation_id):
    executor, principal = _context(operation_id)
    body = _body()
    executor.ledger.stop(operation_id, target=body.get("target"), expected_revision=body.get("revision"),
        reason=body.get("reason"), actor=principal.actor)
    return jsonify(state=body["target"])


@operation_control_bp.post("/<operation_id>/control/commands/<command_id>/reconcile")
def reconcile(operation_id, command_id):
    executor, _ = _context(operation_id)
    body = _body()
    if body.get("resolution") == "abandon":
        executor.abandon(operation_id, command_id, reason=body.get("reason"))
    elif body.get("resolution") == "failed":
        executor.reconcile_failed(operation_id, command_id, reason=body.get("reason"),
            executor_quiescent=body.get("executor_quiescent"))
    else:
        raise LedgerError("explicit_resolution_required")
    return jsonify(command_id=command_id, resolution=body["resolution"])


@operation_control_bp.post("/<operation_id>/control/commands/<command_id>/retry")
def retry(operation_id, command_id):
    executor, _ = _context(operation_id)
    body = _body()
    command = executor.ledger.record(operation_id, command_id)
    bus = build_rule_bus()
    plugins = approved_plugins(executor, operation_id, bus)
    _, operation = executor.snapshot(operation_id)
    build_rule_engine(operation=operation, bus=bus, plugins=plugins)
    plugin = plugins.get(command["payload"].get("capability_id"))
    if plugin is None:
        raise LedgerError("controlled_capability_required")
    if command["payload"].get("parameters", {}).get("deployment_plan_id"):
        current_app.config["DEPLOYMENT_SERVICE"].retry_command(operation_id, command_id, reason=body.get("reason"))
    else:
        plugin.retry_command(command_id, reason=body.get("reason"))
    return jsonify(command_id=command_id, result="adapter_returned")
