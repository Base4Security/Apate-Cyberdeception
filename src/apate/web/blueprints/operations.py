"""Vista para listar, crear y consultar operaciones y cambiar su estado."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from ...core import (
    AdversaryProfile,
    Environment,
    Narrative,
    Operation,
    OperationNotFoundError,
    RulesOfEngagement,
)
from ...core.exceptions import InvalidTransitionError
from ..i18n import translate

operations_bp = Blueprint("operations", __name__, url_prefix="/operations")

_SKILL_LEVELS = ["basic", "intermediate", "advanced", "unknown"]

# Mapea el valor del campo 'to' del formulario de transicion al metodo
# de Operation que lo aplica: centralizarlo aca evita un if/elif largo
# y deja explicito que estas son las unicas tres transiciones que la
# UI puede disparar (igual que hace el motor de reglas en M3).
_TRANSITION_METHODS = {
    "active": Operation.mark_active,
    "compromised": Operation.mark_compromised,
    "closed": Operation.close,
}


@operations_bp.route("/")
def list_operations():
    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(repo.list(), key=lambda op: op.created_at, reverse=True)
    return render_template(
        "operations/list.html",
        operations=operations,
        active_count=sum(op.status.value == "active" for op in operations),
        closed_count=sum(op.status.value == "closed" for op in operations),
    )


@operations_bp.route("/new", methods=["GET"])
def new_operation_form():
    return render_template(
        "operations/form.html",
        environments=list(Environment),
        skill_levels=_SKILL_LEVELS,
    )


@operations_bp.route("/new", methods=["POST"])
def create_operation():
    repo = current_app.config["OPERATION_REPOSITORY"]
    form = request.form

    expected_ttps = [ttp.strip() for ttp in form.get("expected_ttps", "").split(",") if ttp.strip()]
    operation = Operation(
        name=form["name"],
        adversary_profile=AdversaryProfile(
            name=form["adversary_name"],
            motivation=form.get("adversary_motivation", ""),
            skill_level=form.get("adversary_skill_level", "unknown"),
            expected_ttps=expected_ttps,
        ),
        roe=RulesOfEngagement(environment=Environment(form.get("environment", Environment.ISOLATED.value))),
        narrative=Narrative(
            name=form["narrative_name"],
            description=form.get("narrative_description", ""),
        ),
    )
    repo.save(operation)
    flash(translate("Operación '{}' creada.").format(operation.name), "success")
    return redirect(url_for("operations.detail", operation_id=operation.id))


@operations_bp.route("/<operation_id>")
def detail(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    return render_template("operations/detail.html", operation=operation)


@operations_bp.route("/<operation_id>/transition", methods=["POST"])
def transition(operation_id: str):
    repo = current_app.config["OPERATION_REPOSITORY"]
    operation = _get_operation_or_404(operation_id)

    to = request.form.get("to", "")
    method = _TRANSITION_METHODS.get(to)
    if method is None:
        flash(translate("Transición desconocida: '{}'.").format(to), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    try:
        method(operation)
    except InvalidTransitionError as exc:
        flash(str(exc), "error")
        return redirect(url_for("operations.detail", operation_id=operation_id))

    repo.save(operation)
    flash(translate("Operación transicionada a '{}'.").format(operation.status.value), "success")
    return redirect(url_for("operations.detail", operation_id=operation_id))


def _get_operation_or_404(operation_id: str) -> Operation:
    repo = current_app.config["OPERATION_REPOSITORY"]
    try:
        return repo.get(operation_id)
    except OperationNotFoundError:
        abort(404)
