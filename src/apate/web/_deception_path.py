"""Camino visual de engaño derivado solo de relaciones persistidas."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from ..i18n import gettext as _


def capability_state(
    kind: str,
    plugin_id: str,
    *,
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    observed: bool,
    canarytoken_panels: dict[str, dict] | None = None,
    opencanary_panels: dict[str, dict] | None = None,
) -> str:
    """Estado agregado ("planned"/"deployed"/"active"/"observed") de una
    capacidad -- extraido del calculo que `build_deception_path()` ya
    hacia inline para que `apate.web._operation_tree` (arbol de la
    operacion) lo reuse sin reimplementar la interpretacion de
    los paneles de despliegue de DOLOS-T, BUDA, Honeytoken,
    Canarytoken y OpenCanary. Mismo criterio de extraccion que M14f
    (`_ttp_heatmap`/`_techniques_by_tactic`). OpenCanary conserva
    `unknown` cuando Docker no permite determinar su estado."""

    canarytoken_panels = canarytoken_panels or {}
    opencanary_panels = opencanary_panels or {}
    panel = honeytoken_panels.get(plugin_id)
    state = "observed" if observed else "planned"
    if kind == "dolost" and plugin_id in dolost_panels:
        rows = dolost_panels[plugin_id].get("decoys", [])
        state = "active" if any(row.get("up") for row in rows) else ("deployed" if rows else state)
    elif kind == "buda" and plugin_id in buda_panels:
        state = "active" if buda_panels[plugin_id].get("is_running") else ("deployed" if buda_panels[plugin_id].get("found") else state)
    elif kind == "canarytoken" and plugin_id in canarytoken_panels:
        token_panel = canarytoken_panels[plugin_id]
        state = "active" if token_panel.get("deployed") else ("deployed" if token_panel.get("configured") else state)
    elif kind == "opencanary" and plugin_id in opencanary_panels:
        canary_panel = opencanary_panels[plugin_id]
        if not canary_panel.get("docker_available", True):
            state = "unknown"
        elif canary_panel.get("deployed"):
            state = "active"
        elif canary_panel.get("configured"):
            state = "deployed"
    elif panel:
        state = "active" if panel.get("deployed") else ("deployed" if panel.get("configured") else state)
    if observed:
        state = "observed"
    return state


def capability_resources(
    kind: str,
    binding,
    *,
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict] | None = None,
    opencanary_panels: dict[str, dict] | None = None,
) -> list[dict]:
    """Recursos concretos (decoys/honeytokens/perfiles) de una capacidad
    con su estado real -- misma extraccion que `capability_state()`,
    ver docstring de esa funcion.

    `key` identifica cada item para quien necesite correlacionarlo con
    `PluginEvent.resource_id` real (ver `BudaPlugin`/`DolosTPlugin`) --
    **no siempre coincide con `label`**: para un perfil de BUDA,
    `resource_id` usa el id numerico del `UserProfile`
    (`f"profile:{profile_id}"`, ver `buda_plugin.py`), no su nombre
    (que es lo que `label` muestra). Decoy/honeytoken si coinciden
    (hostname/path son a la vez el identificador real y lo que se
    muestra), pero `key` se expone siempre explicito para no depender
    de esa coincidencia accidental."""

    plugin_id = binding.plugin_id
    canarytoken_panels = canarytoken_panels or {}
    opencanary_panels = opencanary_panels or {}
    items: list[dict] = []
    if kind == "dolost":
        decoy_rows = dolost_panels.get(plugin_id, {}).get("decoys")
        if decoy_rows is None:
            decoy_rows = [
                {"hostname": decoy.get("Hostname", ""), "status": _("Configurado; estado no disponible"), "up": None}
                for decoy in binding.config.get("decoys", [])
            ]
        for row in decoy_rows:
            hostname = row.get("hostname") or _("Sin nombre")
            resource_state = "active" if row.get("up") else ("deployed" if row.get("up") is False else "planned")
            items.append({"kind": "decoy", "key": hostname, "label": hostname, "state": resource_state, "detail": row.get("status", _("Estado no disponible"))})
    elif kind == "honeytoken":
        panel = honeytoken_panels.get(plugin_id) or {}
        for item in panel.get("paths", []):
            items.append(
                {
                    "kind": "honeytoken",
                    "key": item["path"],
                    "label": item["path"],
                    "state": "active" if item.get("exists") else "planned",
                    "detail": _("Archivo sintético; contenido no expuesto."),
                }
            )
    elif kind == "buda":
        panel = buda_panels.get(plugin_id, {})
        for profile_row in panel.get("user_profiles", []):
            items.append(
                {
                    "kind": "profile",
                    "key": str(profile_row["id"]),
                    "label": profile_row["name"],
                    "state": "active" if panel.get("is_running") else "deployed",
                    "detail": profile_row.get("role") or _("Identidad vinculada"),
                }
            )
    elif kind == "canarytoken":
        panel = canarytoken_panels.get(plugin_id, {})
        if panel.get("configured"):
            token = panel.get("token") or plugin_id
            label = panel.get("hostname") or panel.get("memo") or panel.get("token_type") or token
            items.append(
                {
                    "kind": "canarytoken",
                    "key": token,
                    "label": label,
                    "state": "active" if panel.get("deployed") else "deployed",
                    "detail": _("Miga Canarytoken · %(token_type)s", token_type=panel.get("token_type") or _("tipo sin definir")),
                }
            )
    elif kind == "opencanary":
        panel = opencanary_panels.get(plugin_id, {})
        if panel.get("configured"):
            services = []
            for service, config in panel.get("services", {}).items():
                if isinstance(config, dict) and not config.get("enabled", True):
                    continue
                port = config.get("port") if isinstance(config, dict) else None
                services.append(f"{service}:{port}" if port else service)
            if not panel.get("docker_available", True):
                resource_state = "unknown"
                detail = _("Docker no disponible; estado del contenedor desconocido.")
            elif panel.get("deployed"):
                resource_state = "active"
                detail = _("Contenedor %(status)s.", status=panel.get("container_status") or _("activo"))
            else:
                resource_state = "deployed"
                detail = _("Servicios configurados; contenedor no desplegado.")
            items.append(
                {
                    "kind": "opencanary",
                    "key": plugin_id,
                    "label": ", ".join(services) or plugin_id,
                    "state": resource_state,
                    "detail": detail,
                }
            )
    return items


def build_deception_path(
    operation,
    telemetry_records: list,
    *,
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict] | None = None,
    opencanary_panels: dict[str, dict] | None = None,
) -> dict[str, Any]:
    """Construye nodos y aristas de lectura sin completar huecos por nombre."""

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()
    summarized_event_count = 0
    individual_event_count = 0

    def add(node_id: str, kind: str, label: str, detail: str, state: str, layer: str, href: str = "") -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append(
            {"id": node_id, "kind": kind, "label": label, "detail": detail, "state": state, "layer": layer, "href": href}
        )

    def connect(source: str, target: str, relation: str) -> None:
        edges.append({"source": source, "target": target, "relation": relation})

    profile = operation.adversary_profile
    add("adversary", _("Adversario"), profile.name, profile.motivation or _("Perfil definido para la operación."), "planned", "adversary")

    observed_ttps = {record.ttp_id for record in telemetry_records if record.ttp_id}
    ttp_ids = set(profile.expected_ttps)
    ttp_ids.update(ttp for scenario in operation.scenarios for ttp in scenario.related_ttps)
    ttp_ids.update(observed_ttps)
    for ttp_id in sorted(ttp_ids):
        add(f"ttp:{ttp_id}", "TTP", ttp_id, _("Técnica esperada, relacionada u observada."), "observed" if ttp_id in observed_ttps else "planned", "ttps", f"/telemetry/{operation.id}?view=events&ttp_id={ttp_id}")
        if ttp_id in profile.expected_ttps:
            connect("adversary", f"ttp:{ttp_id}", _("esperada"))

    records_by_plugin: dict[str, list] = {}
    for record in telemetry_records:
        records_by_plugin.setdefault(record.plugin_id, []).append(record)

    for scenario in operation.scenarios:
        scenario_id = f"scenario:{scenario.id}"
        bound_plugin_ids = {
            binding.plugin_id for binding in operation.plugins if binding.scenario_id == scenario.id
        }
        scenario_observed = any(records_by_plugin.get(plugin_id) for plugin_id in bound_plugin_ids)
        add(scenario_id, _("Escenario"), scenario.description, _("Nivel %(level)s.", level=scenario.deception_level.value), "observed" if scenario_observed else "planned", "scenarios", f"/telemetry/{operation.id}?view=events&scenario_id={scenario.id}")
        for ttp_id in scenario.related_ttps:
            connect(f"ttp:{ttp_id}", scenario_id, _("implementada por"))

    resource_node_ids: dict[tuple[str, str], str] = {}
    for binding in operation.plugins:
        node_id = f"capability:{binding.plugin_id}"
        kind = binding.plugin_kind or binding.plugin_id.split("-", 1)[0]
        observed = bool(records_by_plugin.get(binding.plugin_id))
        state = capability_state(
            kind,
            binding.plugin_id,
            dolost_panels=dolost_panels,
            buda_panels=buda_panels,
            honeytoken_panels=honeytoken_panels,
            observed=observed,
            canarytoken_panels=canarytoken_panels,
            opencanary_panels=opencanary_panels,
        )
        add(node_id, _("Capacidad"), binding.plugin_id, binding.surface or _("Sin superficie"), state, "capabilities", f"/telemetry/{operation.id}?view=events&plugin_id={binding.plugin_id}")
        if binding.scenario_id and operation.find_scenario(binding.scenario_id):
            connect(f"scenario:{binding.scenario_id}", node_id, _("usa"))

        for item in capability_resources(
            kind,
            binding,
            dolost_panels=dolost_panels,
            buda_panels=buda_panels,
            honeytoken_panels=honeytoken_panels,
            canarytoken_panels=canarytoken_panels,
            opencanary_panels=opencanary_panels,
        ):
            resource_key = f"{item['kind']}:{item['key']}"
            resource_id = f"resource:{binding.plugin_id}:{resource_key}"
            resource_kind_label = {
                "decoy": "Decoy",
                "honeytoken": "Honeytoken",
                "profile": _("Perfil"),
                "canarytoken": "Canarytoken",
                "opencanary": "OpenCanary",
            }[item["kind"]]
            add(resource_id, resource_kind_label, item["label"], item["detail"], item["state"], "resources")
            resource_node_ids[(binding.plugin_id, resource_key)] = resource_id
            connect(node_id, resource_id, _("configura"))

        effect = binding.effect
        effect_parts = [effect.expected_adversary_belief, effect.expected_adversary_action, effect.success_metric]
        if any(effect_parts) or effect.measured_outcome:
            effect_id = f"effect:{binding.plugin_id}"
            add(effect_id, _("Efecto"), effect.expected_adversary_action or effect.success_metric or _("Efecto planificado"), effect.measured_outcome or effect.expected_adversary_belief or _("Sin resultado medido"), "observed" if effect.measured_outcome else "planned", "evidence")
            connect(node_id, effect_id, _("busca producir"))

        records = records_by_plugin.get(binding.plugin_id, [])
        # Un mapa con miles de eventos deja de ser legible. Se conservan los
        # recientes como nodos exactos y se agrupan los anteriores por TTP;
        # Telemetría sigue siendo la fuente completa y navegable.
        if len(records) > 30:
            ordered = sorted(records, key=lambda record: (record.timestamp, record.id), reverse=True)
            individual_records = ordered[:12]
            grouped_records = ordered[12:]
        else:
            individual_records = records
            grouped_records = []
        individual_event_count += len(individual_records)
        summarized_event_count += len(grouped_records)
        for record in individual_records:
            event_id = f"event:{record.id}"
            add(event_id, _("Evento"), record.payload.get("detail") or record.payload.get("kind") or record.event_type.value, record.timestamp.isoformat(), "observed", "evidence", f"/telemetry/{operation.id}?view=events&event_id={record.id}")
            resource_node_id = resource_node_ids.get((binding.plugin_id, getattr(record, "resource_id", None) or ""))
            connect(resource_node_id or node_id, event_id, _("observado por"))
            if record.ttp_id:
                connect(event_id, f"ttp:{record.ttp_id}", _("evidencia"))

        groups: dict[str, list] = {}
        for record in grouped_records:
            groups.setdefault(record.ttp_id or "", []).append(record)
        for ttp_id, group in sorted(groups.items()):
            group_id = f"event-group:{binding.plugin_id}:{ttp_id or 'without-ttp'}"
            label = _("%(count)s eventos anteriores · %(ttp)s", count=len(group),
                      ttp=ttp_id or _("sin TTP"))
            first = min(record.timestamp for record in group)
            last = max(record.timestamp for record in group)
            detail = _("Agrupación visual del %(first)s al %(last)s. Abrí Telemetría para ver los eventos exactos.",
                       first=first.isoformat(), last=last.isoformat())
            parameters = {"view": "events", "plugin_id": binding.plugin_id}
            if ttp_id:
                parameters["ttp_id"] = ttp_id
            add(group_id, _("Eventos agrupados"), label, detail, "observed", "evidence",
                f"/telemetry/{operation.id}?{urlencode(parameters)}")
            connect(node_id, group_id, _("agrupa"))
            if ttp_id:
                connect(group_id, f"ttp:{ttp_id}", _("evidencia"))

    layers = [
        {"id": layer_id, "label": label, "nodes": [node for node in nodes if node["layer"] == layer_id]}
        for layer_id, label in (
            ("adversary", _("Adversario")), ("ttps", "TTPs"), ("scenarios", _("Escenarios")),
            ("capabilities", _("Capacidades")), ("resources", _("Recursos")), ("evidence", _("Evidencia y efectos")),
        )
    ]
    return {"nodes": nodes, "edges": edges, "layers": layers, "has_content": len(nodes) > 1,
            "individual_event_count": individual_event_count,
            "summarized_event_count": summarized_event_count,
            "total_event_count": individual_event_count + summarized_event_count}
