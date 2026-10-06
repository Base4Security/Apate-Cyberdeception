"""API JSON con identidad de máquina; las sesiones web no la autorizan."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, g, jsonify, request

from ...core import OperationNotFoundError
from ...deployment import DeploymentError, DeploymentStatus

api_bp = Blueprint("api", __name__)


@api_bp.errorhandler(404)
def not_found(error):
    return jsonify(error="not_found"), 404


@api_bp.errorhandler(400)
def bad_request(error):
    return jsonify(error="invalid_request"), 400


def _operation(operation_id: str):
    try:
        return current_app.config["OPERATION_REPOSITORY"].get(operation_id)
    except OperationNotFoundError:
        abort(404)


def _plan(operation_id: str, plan_id: str):
    try:
        plan = current_app.config["DEPLOYMENT_REPOSITORY"].get_plan(plan_id)
    except DeploymentError:
        abort(404)
    if plan.operation_id != operation_id or plan.connector_kind != "active-directory-honeyuser":
        abort(404)
    return plan


def _record(operation_id: str, record_id: str):
    try:
        record = current_app.config["DEPLOYMENT_REPOSITORY"].get_record(record_id)
    except DeploymentError:
        abort(404)
    if record.operation_id != operation_id or record.connector_kind != "active-directory-honeyuser":
        abort(404)
    return record


def _idempotent(operation_id: str, perform):
    token = g.machine_token
    key = request.headers.get("Idempotency-Key", "").strip()
    if not key or len(key) > 128:
        return jsonify(error="Idempotency-Key es obligatorio y admite hasta 128 caracteres."), 400
    repository = current_app.config["MACHINE_TOKEN_REPOSITORY"]
    try:
        cached = repository.idempotency_lookup(token.id, key, request.method + " " + request.path, request.get_data())
    except ValueError as exc:
        return jsonify(error=str(exc)), 409
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 409
    if cached:
        return jsonify(cached[1]), cached[0]
    try:
        response, status = perform()
    except (DeploymentError, ValueError) as exc:
        # Puede existir un cambio parcial externo: la reserva queda pendiente
        # y el operador debe conciliar antes de reintentar con otra intención.
        current_app.logger.warning("Falló la acción API %s: %s", request.path, type(exc).__name__)
        return jsonify(error="La acción requiere conciliación antes de reintentar."), 503
    repository.idempotency_finish(token.id, key, status, response)
    return jsonify(response), status


@api_bp.after_request
def audit_request(response):
    token = getattr(g, "machine_token", None)
    current_app.config["MACHINE_TOKEN_REPOSITORY"].audit(
        token_id=token.id if token else None, method=request.method, path=request.path,
        outcome="success" if response.status_code < 400 else "rejected", status=response.status_code,
        detail="API de automatización; request_id=" + getattr(g, "apate_request_id", "unknown"),
    )
    return response


@api_bp.get("/api/v1/operations")
def operations():
    allowed = g.machine_token.operation_ids
    result = [operation.to_dict() for operation in current_app.config["OPERATION_REPOSITORY"].list() if operation.id in allowed]
    return jsonify(operations=result)


@api_bp.get("/api/v1/operations/<operation_id>")
def operation_detail(operation_id: str):
    return jsonify(operation=_operation(operation_id).to_dict())


@api_bp.get("/api/v1/operations/<operation_id>/telemetry")
def telemetry(operation_id: str):
    _operation(operation_id)
    if request.args:
        try:
            after = int(request.args.get("after", 0))
            limit = int(request.args.get("limit", 100))
            if set(request.args) - {"after", "limit"}:
                raise ValueError("invalid_pagination")
            page = current_app.config["TELEMETRY_COLLECTOR"].repository.page(operation_id, after=after, limit=limit)
        except ValueError:
            return jsonify(error="invalid_pagination"), 400
        return jsonify(events=[event.to_dict() for event in page["items"]], next_cursor=page["next_cursor"])
    events = current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
    return jsonify(events=[event.to_dict() for event in events])


@api_bp.get("/api/v1/operations/<operation_id>/control")
def control_status(operation_id):
    _operation(operation_id)
    return jsonify(current_app.config["OPERATION_EXECUTOR"].status(operation_id))


@api_bp.get("/api/v1/operations/<operation_id>/readiness")
def operation_readiness(operation_id):
    """Entrega brechas de diseño y estado registrado para revisión humana."""
    operation = _operation(operation_id)
    executor = current_app.config["OPERATION_EXECUTOR"]
    source = "draft"
    approved_deployment_plan_ids = None
    if executor.managed(operation_id):
        state = executor.ledger.operation(operation_id)
        if state["active_plan_id"]:
            active_plan, operation = executor.snapshot(operation_id)
            source = "approved_plan"
            approved_deployment_plan_ids = {item["id"] for item in
                active_plan["payload"]["content"].get("external_resource_versions", {}).get("items", [])
                if item["kind"] == "deployment_plan"}
        else:
            source = "adopted_without_active_plan"
    from .._readiness import build_readiness
    report = build_readiness(operation, current_app.config["ASSET_REPOSITORY"].list(),
        current_app.config["DEPLOYMENT_REPOSITORY"].list_records_for_operation(operation_id), source=source,
        approved_deployment_plan_ids=approved_deployment_plan_ids)
    return jsonify(operation_id=operation_id, review=report)


@api_bp.post("/api/v1/operations/<operation_id>/plans")
def propose_operation_plan(operation_id):
    _operation(operation_id)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="json_object_required"), 400
    def perform():
        principal = current_app.config["OPERATION_EXECUTOR"].authorize(operation_id)
        record = current_app.config["OPERATION_PLAN_SERVICE"].propose(operation_id,
            parent_id=body.get("parent_id"), reason=body.get("reason"), actor=principal.actor,
            dispositions=body.get("dispositions"), execution_policy=body.get("execution_policy"))
        return {"plan_id": record["id"], "digest": record["digest"], "approval": "human_required"}, 201
    return _idempotent(operation_id, perform)


@api_bp.post("/api/v1/operations/<operation_id>/plans/<plan_id>/activate")
def activate_operation_plan(operation_id, plan_id):
    _operation(operation_id)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="json_object_required"), 400
    def perform():
        executor = current_app.config["OPERATION_EXECUTOR"]
        principal = executor.authorize(operation_id)
        executor.ledger.activate(operation_id, plan_id, expected_digest=body.get("digest"), actor=principal.actor)
        return {"plan_id": plan_id, "state": "active"}, 200
    return _idempotent(operation_id, perform)


@api_bp.post("/api/v1/operations/<operation_id>/stop")
def stop_operation(operation_id):
    _operation(operation_id)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="json_object_required"), 400
    def perform():
        executor = current_app.config["OPERATION_EXECUTOR"]
        principal = executor.authorize(operation_id)
        executor.ledger.stop(operation_id, target=body.get("target"), expected_revision=body.get("revision"),
            reason=body.get("reason"), actor=principal.actor)
        return {"state": body.get("target")}, 200
    return _idempotent(operation_id, perform)


@api_bp.post("/api/v1/operations/<operation_id>/capabilities/<capability_id>/<action>")
def execute_capability(operation_id, capability_id, action):
    _operation(operation_id)
    if action not in {"deploy", "rotate", "retire"}:
        abort(404)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="json_object_required"), 400
    def perform():
        from ...ledger.plugins import approved_plugins
        from .._rule_engine_runtime import build_rule_bus, build_rule_engine
        executor = current_app.config["OPERATION_EXECUTOR"]
        executor.authorize(operation_id)
        plan, operation = executor.snapshot(operation_id)
        if body.get("plan_id") != plan["id"]:
            from ...ledger import LedgerError
            raise LedgerError("stale_plan")
        bus = build_rule_bus(operation_id)
        plugins = approved_plugins(executor, operation_id, bus)
        plugin = plugins.get(capability_id)
        if plugin is None:
            abort(404)
        build_rule_engine(operation=operation, bus=bus, plugins=plugins)
        plugin.execute_managed(action, parameters=body.get("parameters"))
        return {"capability_id": capability_id, "outcome": "adapter_returned", "physical_verification": "pending"}, 200
    return _idempotent(operation_id, perform)


@api_bp.get("/api/v1/openapi.json")
def openapi():
    from ...api.openapi import specification
    return jsonify(specification())


@api_bp.post("/api/v1/operations/<operation_id>/honeyusers/plans")
def prepare_honeyuser(operation_id: str):
    _operation(operation_id)
    if current_app.config["TWO_PERSON_APPROVAL_ENABLED"]:
        return jsonify(error="La aprobación de dos personas exige preparación por un operador humano."), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Se requiere un objeto JSON."), 400

    def perform():
        target = current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].get(str(payload.get("target_id", "")))
        if target.connector_kind != "active-directory-honeyuser":
            raise ValueError("El destino no admite honeyusers.")
        configuration = payload.get("configuration")
        if not isinstance(configuration, dict) or not payload.get("plugin_id"):
            raise ValueError("Destino, capacidad y configuración son obligatorios.")
        plan = current_app.config["DEPLOYMENT_SERVICE"].prepare(
            operation_id=operation_id, plugin_id=str(payload["plugin_id"]), target=target, configuration=configuration
        )
        return {"plan": plan.to_dict()}, 201

    return _idempotent(operation_id, perform)


@api_bp.post("/api/v1/operations/<operation_id>/honeyusers/plans/<plan_id>/execute")
def execute_honeyuser(operation_id: str, plan_id: str):
    _operation(operation_id)
    plan = _plan(operation_id, plan_id)

    def perform():
        if current_app.config["TWO_PERSON_APPROVAL_ENABLED"]:
            current_app.config["PLAN_APPROVAL_REPOSITORY"].require_approved(plan)
        record = current_app.config["DEPLOYMENT_SERVICE"].execute(plan.id)
        return {"record": record.to_dict()}, 200

    return _idempotent(operation_id, perform)


@api_bp.get("/api/v1/operations/<operation_id>/honeyusers/records/<record_id>")
def honeyuser_record(operation_id: str, record_id: str):
    _operation(operation_id)
    return jsonify(record=_record(operation_id, record_id).to_dict())


@api_bp.post("/api/v1/operations/<operation_id>/honeyusers/records/<record_id>/<action>")
def honeyuser_action(operation_id: str, record_id: str, action: str):
    operation = _operation(operation_id)
    record = _record(operation_id, record_id)
    if action not in {"refresh", "rotate", "retire", "poll"}:
        abort(404)
    _plan(operation_id, record.plan_id)

    def perform():
        if action == "poll":
            if record.status not in {DeploymentStatus.ACTIVE, DeploymentStatus.DEGRADED}:
                raise ValueError("Solo se monitorean honeyusers activos o degradados.")
            events = current_app.config["HONEYUSER_MONITORING_SERVICE"].poll_record(operation, record)
            return {"new_events": len(events)}, 200
        updated = getattr(current_app.config["DEPLOYMENT_SERVICE"], action)(record.id)
        return {"record": updated.to_dict()}, 200

    return _idempotent(operation_id, perform)


@api_bp.errorhandler(404)
def not_found(error):
    return jsonify(error="Recurso no encontrado."), 404
