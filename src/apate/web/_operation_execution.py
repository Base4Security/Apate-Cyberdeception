"""Frontera HTTP y contexto de identidad de las operaciones adoptadas."""

from __future__ import annotations

from flask import flash, g, has_request_context, jsonify, redirect, request, session, url_for

from ..identity import IdentityRole
from ..ledger import ExecutionPrincipal, LedgerError, OperationExecutor
from ..i18n import gettext as _


BLOCKED_ENDPOINTS = frozenset({
    "operations.buda_delete_narrative",
})
MANAGED_ACTIONS = {
    "operations.opencanary_deploy": ("opencanary", "deploy"),
    "operations.opencanary_rotate": ("opencanary", "rotate"),
    "operations.opencanary_retire": ("opencanary", "retire"),
    "operations.dolost_deploy": ("dolost", "deploy"),
    "operations.dolost_rotate": ("dolost", "rotate"),
    "operations.dolost_retire": ("dolost", "retire"),
    "operations.dolost_deploy_decoy": ("dolost", "deploy"),
    "operations.dolost_undeploy_decoy": ("dolost", "retire"),
    "operations.dolost_start_decoy": ("dolost", "rotate"),
    "operations.dolost_stop_decoy": ("dolost", "retire"),
    "operations.buda_start": ("buda", "deploy"),
    "operations.buda_stop": ("buda", "retire"),
    "playground.start": ("playground", "deploy"),
    "playground.stop": ("playground", "retire"),
    "playground.run_attacker": ("playground", "rotate"),
}
ACTING_ENDPOINTS = BLOCKED_ENDPOINTS | frozenset({
    "operations.honeytoken_deploy", "operations.honeytoken_rotate", "operations.honeytoken_retire",
    "operations.canarytoken_deploy", "operations.canarytoken_rotate", "operations.canarytoken_retire",
    "operations.deploy_all_campaign", "operations.transition",
    "deployments.execute_plan", "deployments.retry", "deployments.rotate", "deployments.retire",
    "api.execute_honeyuser", "api.honeyuser_action",
}) | MANAGED_ACTIONS.keys()
QUERY_ENDPOINTS = frozenset({"operations.fetch_telemetry_bridge", "operations.opencanary_check_activity",
    "operations.honeytoken_check_access", "operations.canarytoken_check_access",
    "operations.dolost_check_activity", "operations.buda_check_activity",
    "deployments.poll", "deployments.refresh"})


def install_execution(app):
    def authorize(operation_id):
        if not has_request_context():
            raise LedgerError("authenticated_principal_required")
        if request.blueprint == "api":
            from .access import machine_scope_for_endpoint
            bearer = request.headers.get("Authorization", "").removeprefix("Bearer ")
            token = app.config["MACHINE_TOKEN_REPOSITORY"].authenticate(bearer)
            scope = machine_scope_for_endpoint(request.endpoint, (request.view_args or {}).get("action"))
            if token is None or scope is None or not token.permits(scope, operation_id):
                raise LedgerError("identity_scope")
            return ExecutionPrincipal(f"machine:{token.id}", token.operation_ids, machine=True)
        identifier = session.get("identity_id")
        identity = app.config["IDENTITY_PROVIDER"].get(identifier) if isinstance(identifier, str) else None
        if identity is None or not identity.active or identity.role not in {IdentityRole.OPERATION, IdentityRole.ADMINISTRATION} or session.get("credential_version", 0) != identity.credential_version:
            raise LedgerError("authenticated_principal_required")
        from .access import can_access_operation
        operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
        if not can_access_operation(identity, operation):
            raise LedgerError("identity_scope")
        return ExecutionPrincipal(f"identity:{identity.id}", frozenset({operation_id}), identity.team_id,
            administrator=identity.role == IdentityRole.ADMINISTRATION)

    executor = OperationExecutor(app.config["OPERATION_LEDGER"], authorize)
    executor.governed_required = app.config.get("APATE_GOVERNED_EXECUTION_REQUIRED", False)
    def authorize_query(operation_id):
        if not has_request_context() or request.blueprint == "api":
            return authorize(operation_id)
        identifier = session.get("identity_id")
        identity = app.config["IDENTITY_PROVIDER"].get(identifier) if isinstance(identifier, str) else None
        from .access import can_access_operation
        if identity is None or not identity.active or session.get("credential_version", 0) != identity.credential_version or not can_access_operation(identity, app.config["OPERATION_REPOSITORY"].get(operation_id)):
            raise LedgerError("authenticated_principal_required")
        return ExecutionPrincipal(f"identity:{identity.id}", frozenset({operation_id}), identity.team_id,
            administrator=identity.role == IdentityRole.ADMINISTRATION)
    executor.authorize_query = authorize_query
    app.config["OPERATION_EXECUTOR"] = executor
    app.config["DEPLOYMENT_SERVICE"].operation_executor = executor
    from .blueprints.operation_control import operation_control_bp
    app.register_blueprint(operation_control_bp)

    @app.before_request
    def fence_legacy_dispatch():
        if request.method != "POST" or request.endpoint not in ACTING_ENDPOINTS:
            return None
        operation_id = (request.view_args or {}).get("operation_id")
        if not operation_id:
            return None
        if executor.managed(operation_id):
            return None
        if executor.governed_required:
            raise LedgerError("governed_operation_required")
        gate = app.config["OPERATION_PLAN_SERVICE"].adoption_gate
        g.legacy_execution_job = gate.enter(operation_id, kind=request.endpoint, actor="http:legacy")
        g.legacy_execution_async = request.endpoint in {"operations.buda_start", "playground.run_attacker"}

    @app.after_request
    def finish_legacy_dispatch(response):
        if getattr(g, "legacy_execution_job", None):
            app.config["OPERATION_PLAN_SERVICE"].adoption_gate.finish(g.legacy_execution_job,
                unknown=g.legacy_execution_async or response.status_code >= 500)
        return response

    @app.context_processor
    def execution_context():
        def control_state(operation_id):
            if not executor.managed(operation_id):
                return None
            state = executor.ledger.operation(operation_id)
            return {"state": state["state"], "plan_id": state["active_plan_id"], "revision": state["revision"]}
        return {"operation_control_state": control_state}

    @app.before_request
    def guard_unfrozen_execution():
        operation_id = (request.view_args or {}).get("operation_id")
        if operation_id and executor.governed_required and request.endpoint in QUERY_ENDPOINTS and not executor.managed(operation_id):
            raise LedgerError("governed_operation_required")
        if not operation_id or not executor.managed(operation_id):
            return None
        if request.method == "POST" and request.endpoint in ACTING_ENDPOINTS:
            authorize(operation_id)
        if request.method == "POST" and request.endpoint in BLOCKED_ENDPOINTS:
            raise LedgerError("adapter_not_frozen")
        if request.method == "POST" and request.endpoint in MANAGED_ACTIONS:
            from ..ledger.plugins import approved_plugins
            from ._rule_engine_runtime import build_rule_bus, build_rule_engine
            kind, action = MANAGED_ACTIONS[request.endpoint]
            plan, operation = executor.snapshot(operation_id)
            identifier = (request.view_args or {}).get("plugin_id")
            if kind == "playground":
                candidates = [b.plugin_id for b in operation.plugins if b.plugin_kind == "playground"]
                if len(candidates) != 1:
                    raise LedgerError("adapter_not_frozen")
                identifier = candidates[0]
            binding = operation.find_plugin_binding(identifier)
            from ..plugins.registry import PluginRegistry
            if binding is None or PluginRegistry.resolve_binding_kind(binding) != kind:
                raise LedgerError("adapter_not_frozen")
            bus = build_rule_bus()
            plugin = approved_plugins(executor, operation_id, bus)[identifier]
            build_rule_engine(operation=operation, bus=bus, plugins={identifier: plugin})
            if kind == "buda" and action == "deploy" and plugin.effective_state.value == "deployed":
                action = "rotate"
            parameters = None
            hostname = (request.view_args or {}).get("hostname")
            if hostname is not None:
                subaction = request.path.rsplit("/", 1)[-1]
                parameters = {"hostname": hostname, "subaction": subaction}
            if kind == "playground":
                if request.endpoint == "playground.start" and request.form.get("level") != plugin.descriptor["level"]:
                    raise LedgerError("approved_playground_level_required")
                if request.endpoint == "playground.run_attacker":
                    parameters = {"subaction": "attacker"}
                    return _start_managed_attacker(app, executor, plugin, authorize(operation_id))
            try:
                plugin.execute_managed(action, parameters=parameters)
            except LedgerError:
                raise
            except Exception as error:
                raise LedgerError("adapter_effect_unknown") from error
            if request.is_json or request.accept_mimetypes.best == "application/json":
                return jsonify(capability_id=identifier, result="adapter_returned")
            flash(_("La acción aprobada terminó; consultá el registro para verificar su resultado."), "success")
            return redirect(url_for("operations.detail", operation_id=operation_id))
        if request.endpoint == "operations.transition" and request.method == "POST":
            principal = authorize(operation_id)
            state = executor.ledger.operation(operation_id)
            if request.form.get("to") != "closed":
                raise LedgerError("approved_activation_required")
            executor.ledger.stop(operation_id, target="closing", expected_revision=state["revision"],
                reason="operator_requested_closure", actor=principal.actor)
            return jsonify(state="closing", terminal_result="pending"), 200
        return None

    @app.errorhandler(LedgerError)
    def ledger_error(error):
        return jsonify(error=error.code, message=_("La operación adoptada requiere ejecución autorizada sobre un plan aprobado.")), 409

    return executor


def _start_managed_attacker(app, executor, plugin, principal):
    """Reservar en HTTP y revalidar la identidad antes del claim del worker."""
    import uuid
    parameters = {"subaction": "attacker"}
    command = executor.admit(plugin.operation_id, expected_plan_id=plugin.plan["id"],
        capability_id=plugin.plugin_id, action="rotate", parameters=parameters,
        idempotency_key="playground:attacker:" + str(uuid.uuid4()))
    identifier = session.get("identity_id")
    version = session.get("credential_version", 0)

    def reauthenticate(operation_id):
        from .access import can_access_operation
        identity = app.config["IDENTITY_PROVIDER"].get(identifier)
        operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
        if identity is None or not identity.active or identity.credential_version != version or identity.role not in {IdentityRole.OPERATION, IdentityRole.ADMINISTRATION} or not can_access_operation(identity, operation):
            raise LedgerError("authenticated_principal_required")
        return ExecutionPrincipal(principal.actor, frozenset({operation_id}), identity.team_id,
            administrator=identity.role == IdentityRole.ADMINISTRATION)

    def worker():
        with app.app_context():
            background = OperationExecutor(executor.ledger, reauthenticate)
            try:
                background.invoke(plugin.operation_id, command, lambda: plugin._call("rotate", parameters), state_capture=plugin._capture)
            except Exception:
                app.logger.warning("La orden Playground %s terminó sin aceptación", command["id"])

    app.extensions["socketio"].start_background_task(worker)
    if request.is_json or request.accept_mimetypes.best == "application/json":
        return jsonify(command_id=command["id"], result="reserved"), 202
    flash(_("Se solicitó la ejecución del atacante. Su estado se registra en la operación."), "success")
    return redirect(url_for("playground.defender_view", operation_id=plugin.operation_id))
