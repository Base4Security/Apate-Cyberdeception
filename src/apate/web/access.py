"""Política central de roles y aislamiento de equipos.

La política es una allowlist de endpoints. Una ruta nueva que no esté
clasificada no recibe un rol y, con autenticación activa, queda denegada.
Así el control no depende de que alguien recuerde modificar cada blueprint.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.models import Operation
from ..identity import Identity, IdentityRole


_ROLE_ORDER = {
    IdentityRole.READ: 0,
    IdentityRole.OPERATION: 1,
    IdentityRole.ADMINISTRATION: 2,
}

_MACHINE_SCOPES = {
    "api.control_status": "operations:read",
    "api.operation_readiness": "operations:read",
    "api.propose_operation_plan": "plans:propose",
    "api.activate_operation_plan": "plans:activate",
    "api.stop_operation": "operations:stop",
    "api.execute_capability": "capabilities:execute",
    "api.openapi": "operations:read",
    "api.operations": "operations:read",
    "api.operation_detail": "operations:read",
    "api.telemetry": "telemetry:read",
    "api.prepare_honeyuser": "honeyuser:prepare",
    "api.execute_honeyuser": "honeyuser:execute",
    "api.honeyuser_record": "honeyuser:read",
}


def machine_scope_for_endpoint(endpoint: str | None, action: str | None = None) -> str | None:
    """Allowlist separada para máquinas; rutas nuevas quedan cerradas."""

    if endpoint == "api.honeyuser_action":
        return f"honeyuser:{action}" if action in {"refresh", "rotate", "retire", "poll"} else None
    return _MACHINE_SCOPES.get(endpoint)

_ADMIN_ENDPOINTS = frozenset(
    {
        "operation_control.adopt", "operation_control.review", "operation_control.reconcile",
        "operation_control.adoption_check", "operation_control.result", "operation_control.adoption_reconcile",
        "capabilities.behavior_activities",
        "assets.create",
        "assets.edit",
        "assets.delete",
        "assets.preview_csv",
        "assets.confirm_csv",
        "capabilities.behavior_activity_delete",
        "capabilities.behavior_activity_edit",
        "capabilities.behavior_activity_generate",
        # Propone un repertorio de comandos; no lo guarda ni lo ejecuta. Va en
        # ADMINISTRATION igual que el resto de la edicion de actividades: lo que
        # se propone termina siendo lo unico que el worker ejecuta sobre hosts
        # reales, asi que proponerlo no es una accion de lectura.
        "capabilities.behavior_activity_generate_commands",
        "capabilities.behavior_context_archive",
        "capabilities.behavior_context_confirm",
        "capabilities.behavior_context_discard",
        "capabilities.behavior_context_upload",
        "capabilities.identity_profile_delete",
        "capabilities.identity_profile_edit",
        "capabilities.identity_profiles",
        "health.behavior_data_reset",
        "health.content_generation",
        "health.content_generation_test",
        "health.create_identity_user",
        "health.identity_users",
        "health.change_identity_password",
        "health.deactivate_identity_user",
        "health.network_host_runtime",
        "health.network_host_runtime_test",
        "health.siem_soar",
        "health.threat_intelligence",
        "deployments.targets",
        "deployments.create_filesystem_target",
        "deployments.update_target_credential",
        "deployments.update_target_scope",
        "operations.assign_team",
        "operations.create_and_resolve_target_asset",
        "rules.save_rules",
        "rules.validate_rules",
    }
)

_READ_ENDPOINTS = frozenset(
    {
        "capabilities.behavior_activities",
        "capabilities.behavior_activity_edit",
        "capabilities.behavior_context",
        "capabilities.catalog",
        "capabilities.identity_profile_edit",
        "capabilities.identity_profiles",
        "capabilities.use_in_operation",
        "health.content_generation",
        "health.index",
        "health.network_host_runtime",
        "health.threat_intelligence",
        "impact.dashboard",
        "index",
        "login",
        # `sbom` NO va en `_PUBLIC_ENDPOINTS`, y la diferencia con `about` es
        # a proposito: el aviso de licencia es una obligacion hacia cualquier
        # usuario remoto (AGPLv3 art. 13), pero el inventario de versiones
        # instaladas es un mapa de superficie de ataque. Cualquier rol
        # autenticado puede leerlo; nadie sin sesion. Ver `apate.web.sbom`.
        "sbom",
        # `sbom` NO va en `_PUBLIC_ENDPOINTS`, y la diferencia con `about` es
        # a proposito: el aviso de licencia es una obligacion hacia cualquier
        # usuario remoto (AGPLv3 art. 13), pero el inventario de versiones
        # instaladas es un mapa de superficie de ataque. Cualquier rol
        # autenticado puede leerlo; nadie sin sesion. Ver `apate.web.sbom`.
        "assets.index",
        "assets.edit",
        "operations.compare_operations",
        "operations.deployment_status",
        "operations.detail",
        "operations.list_operations",
        "operations.new_operation_form",
        "operations.operation_tree_graphml",
        "operations.portfolio",
        "operations.reoperate",
        "operations.report",
        "operations.templates_gallery",
        "operations.workshop_kit",
        "deployments.operation_deployments",
        "deployments.operation_health",
        "attention.index",
        "attention.inbox",
        "attention.case_detail",
        "attention.case_handoff",
        "operation_control.overview",
        "telemetry.download_evidence",
        "playground.attacker_view",
        "playground.defender_view",
        "playground.index",
        "plugins.legacy_catalog",
        "rules.show_rules",
        "rules.replay",
        "telemetry.detail",
        "telemetry.index",
        "telemetry.live_feed",
        "telemetry.live_index",
    }
)

_OPERATION_ENDPOINTS = frozenset(
    {
        "operation_control.status", "operation_control.propose", "operation_control.plan_action",
        "operation_control.stop", "operation_control.retry", "operation_control.close",
        "operations.add_plugin_binding",
        "operations.add_scenario",
        "operations.add_telemetry_bridge",
        "operations.add_trigger_condition",
        "operations.behavior_context_confirm",
        "operations.behavior_context_discard",
        "operations.behavior_context_select",
        "operations.behavior_context_upload",
        "operations.buda_create_activity",
        "operations.buda_create_narrative",
        "operations.buda_create_profile",
        "operations.buda_delete_narrative",
        "operations.buda_link_narrative",
        "operations.buda_start",
        "operations.buda_stop",
        "operations.buda_update_narrative_profiles",
        "operations.buda_update_profile_activities",
        "operations.canarytoken_check_hits",
        "operations.canarytoken_configure",
        "operations.canarytoken_deploy",
        "operations.canarytoken_retire",
        "operations.canarytoken_rotate",
        "operations.create_operation",
        "operations.cti_extract",
        "operations.delete_trigger_condition",
        "operations.deploy_all_campaign",
        "operations.dolost_add_decoy",
        "operations.dolost_delete_decoy",
        "operations.dolost_deploy",
        "operations.dolost_deploy_decoy",
        "operations.dolost_retire",
        "operations.dolost_rotate",
        "operations.dolost_start_decoy",
        "operations.dolost_stop_decoy",
        "operations.dolost_undeploy_decoy",
        "operations.fetch_telemetry_bridge",
        "operations.honeytoken_check_access",
        "operations.honeytoken_configure",
        "operations.honeytoken_deploy",
        "operations.honeytoken_retire",
        "operations.honeytoken_rotate",
        "operations.incorporate_suggested_ttps",
        "operations.opencanary_check_activity",
        "operations.opencanary_configure",
        "operations.opencanary_deploy",
        "operations.opencanary_retire",
        "operations.opencanary_rotate",
        "operations.record_measured_outcome",
        "operations.resolve_target_asset",
        "operations.send_report_to_siem_soar",
        "telemetry.export_external",
        "deployments.approve_plan",
        "operations.transition",
        "operations.update_plugin_asset_coverage",
        "operations.update_roe",
        "playground.run_attacker",
        "playground.start",
        "playground.stop",
        "telemetry.create_incident",
        "telemetry.delete_incident",
        "telemetry.enrich_ioc_with_virustotal",
        "telemetry.remove_incident_event",
        "telemetry.set_tlp_classification",
        "telemetry.update_incident",
        "deployments.execute_plan",
        "deployments.poll",
        "deployments.prepare_honeyuser",
        "deployments.prepare_honeyfile",
        "deployments.refresh",
        "deployments.retry",
        "deployments.retire",
        "deployments.rotate",
        "attention.create_signal",
        "attention.signal_action",
        "attention.create_case",
        "attention.case_action",
    }
)

# `set_locale` es preferencia personal de interfaz, no una accion sobre
# datos de operacion: cualquier rol autenticado debe poder cambiar su
# idioma, igual que `set_operator` no requiere permisos de operacion.
_PUBLIC_ENDPOINTS = frozenset(
    # `about` es el aviso de licencia y la oferta de fuente correspondiente
    # (AGPLv3 art. 13). Va aca y ademas en la allowlist previa a la sesion de
    # `_require_authenticated_identity`: el articulo habla de "todos los
    # usuarios que interactuan remotamente", y quien esta en la pantalla de
    # login ya esta interactuando. No expone ningun dato de operacion.
    {"login", "logout", "oidc_start", "oidc_callback", "static", "set_operator", "set_locale", "about"}
)


def required_role(endpoint: str | None, method: str) -> IdentityRole | None:
    """Devuelve el mínimo rol o ``None`` si la ruta no está clasificada."""

    from flask import current_app, has_app_context
    if has_app_context():
        classified = current_app.extensions.get("apate.endpoint_roles", {}).get((endpoint, method))
        if classified is not None:
            return IdentityRole(classified)
    if endpoint in _PUBLIC_ENDPOINTS:
        return IdentityRole.READ
    if method in {"GET", "HEAD"} and endpoint in _READ_ENDPOINTS:
        return IdentityRole.READ
    if endpoint in _ADMIN_ENDPOINTS:
        return IdentityRole.ADMINISTRATION
    if endpoint in _OPERATION_ENDPOINTS:
        return IdentityRole.OPERATION
    return None


def permits(identity: Identity, required: IdentityRole | None) -> bool:
    """Aplica jerarquía fija y deniega rutas sin clasificar."""

    return required is not None and _ROLE_ORDER[identity.role] >= _ROLE_ORDER[required]


def can_access_operation(identity: Identity, operation: Operation) -> bool:
    """Administración ve todo; cada equipo ve únicamente lo que tiene asignado.

    Las operaciones heredadas sin equipo quedan visibles solo para
    administración hasta que alguien las asigne. Tratarlas como globales
    filtraba datos entre equipos precisamente cuando faltaba clasificación.
    """

    from flask import current_app, has_app_context
    if has_app_context():
        policy = current_app.extensions.get("apate.operation_scope")
        if policy is not None and policy(identity, operation):
            return True
    return (
        identity.role is IdentityRole.ADMINISTRATION
        or (operation.team_id is not None and operation.team_id == identity.team_id)
    )


def visible_operations(identity: Identity | None, operations: Iterable[Operation]) -> list[Operation]:
    """Filtra operaciones cuando hay una identidad autenticada."""

    items = list(operations)
    if identity is None:
        return items
    return [operation for operation in items if can_access_operation(identity, operation)]
