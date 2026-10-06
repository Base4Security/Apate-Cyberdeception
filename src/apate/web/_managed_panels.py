"""Lecturas de recursos aprobados para paneles; ningún nombre global heredado."""

from flask import current_app, has_app_context, has_request_context, request

from ..i18n import gettext as _
from ..ledger.plugins import approved_plugins
from ..plugins import EventBus


def managed_panel(binding, operation_id=None):
    if not has_app_context():
        return None
    operation_id = operation_id or ((request.view_args or {}).get("operation_id") if has_request_context() else None)
    executor = current_app.config.get("OPERATION_EXECUTOR")
    if not operation_id or not executor or not executor.managed(operation_id):
        return None
    try:
        plugin = approved_plugins(executor, operation_id, EventBus()).get(binding.plugin_id)
    except Exception:
        plugin = None
    from ..plugins.registry import PluginRegistry
    kind = PluginRegistry.resolve_binding_kind(binding)
    config = plugin.effective_config if plugin else {}

    def status(role):
        if not plugin:
            return None, _("desconocido")
        resource = plugin.adapter.find(role)
        if resource is None:
            return False, _("no desplegado")
        try:
            def read():
                plugin.adapter.connect()
                return plugin.adapter.checked(resource, missing_ok=True)
            obj = executor.query(operation_id, binding.plugin_id, read, purpose="status")
            if obj is None:
                return False, _("no desplegado")
            return obj.status == "running", obj.status
        except Exception:
            return None, _("desconocido")

    if kind == "opencanary":
        up, text = status("opencanary")
        from .blueprints.operations import _format_opencanary_services
        return {"services": config.get("services", {}), "services_text": _format_opencanary_services(config.get("services", {})),
            "network_mode": config.get("network_mode", "bridge"), "node_id": config.get("node_id", ""),
            "ttp_id": config.get("ttp_id", ""), "configured": bool(config.get("services")),
            "docker_available": up is not None, "deployed": up is True, "container_status": text,
            "last_checked_at": None, "source": "approved_resources"}
    if kind == "dolost":
        rows = []
        for decoy in plugin.descriptor["decoys"] if plugin else []:
            up, text = status("decoy:" + decoy["Hostname"])
            rows.append({"decoy": decoy, "hostname": decoy["Hostname"], "up": up, "status": text})
        return {"decoys": rows, "docker_available": plugin is not None and all(row["up"] is not None for row in rows), "source": "approved_resources"}
    if kind == "buda":
        from ..ledger.buda_adapter import _workers, _workers_lock
        with _workers_lock:
            worker = _workers.get(config.get("_execution_session"))
            running = worker["thread"].is_alive() and not worker["event"].is_set() if worker is not None else None
        if plugin and plugin.effective_state.value == "retired":
            running = False
        profiles = {}
        if plugin:
            for step in plugin.descriptor["steps"]:
                profile = profiles.setdefault(step["profile_id"], {"id": step["profile_id"],
                    "name": step.get("profile_name", _("desconocido")), "role": step.get("profile_role", ""),
                    "winrm_server": step["server"], "credentials_recoverable": True, "activities": []})
                if step["activity_id"] not in {a["id"] for a in profile["activities"]}:
                    profile["activities"].append({"id": step["activity_id"], "activity_type": step.get("activity_type", ""), "details": ""})
        return {"found": plugin is not None, "narrative_id": plugin.descriptor["narrative_id"] if plugin else None,
            "is_running": running, "control_deployed": plugin is not None and plugin.effective_state.value == "deployed",
            "retired": plugin is not None and plugin.effective_state.value == "retired",
            "user_profiles": list(profiles.values()), "source": "approved_resources"}
    return None
