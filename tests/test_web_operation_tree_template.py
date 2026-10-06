"""Integración: el árbol de la operación (`#operation-tree`,
`operations/detail.html`) se renderiza de verdad contra el servidor,
incluyendo el bucket "sin escenario", el estado vacío, y el fix de
navegación (`hashchange`) que sus nodos necesitan para ser clickeables."""

from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación con árbol"),
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def test_tree_section_present_with_scenario_and_binding(client, app):
    operation = _operation()
    scenario = Scenario(description="Acceso inicial", related_ttps=["T1078"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="mock-1",
            plugin_kind="mock",
            surface="network",
            scenario_id=scenario.id,
            effect=DeceptionEffect(expected_adversary_belief="Cree que es real", expected_adversary_action="Interactúa"),
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert response.status_code == 200
    assert 'id="operation-tree"' in body
    assert "&Aacute;rbol de la operaci&oacute;n" in body
    assert 'class="op-tree-node op-tree-node-operation"' in body
    assert 'data-tree-id="scenario:%s"' % scenario.id in body
    assert 'data-tree-parent="scenario:%s"' % scenario.id in body
    assert "Acceso inicial" in body
    assert "Cree que es real" in body


def test_tree_shows_explicit_unassigned_bucket_not_silent_drop(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-orphan", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert "Sin escenario asignado" in body
    assert "mock-orphan" in body
    assert 'data-tree-id="scenario:unassigned"' in body


def test_tree_nodes_link_to_real_tabs(client, app):
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert 'href="#tab-scenarios"' in body
    assert 'href="#tab-plugins"' in body


def test_tree_scenario_node_includes_inline_bind_link_when_scenario_exists(client, app):
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert f'prefill_scenario_id={scenario.id}' in body
    assert f'prefill_scenario_id={scenario.id}#tab-plugins' in body
    assert "Vincular capacidad acá" in body


def test_tree_empty_state_for_operation_without_scenarios_or_plugins(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert 'id="operation-tree"' in body
    assert "Agreg" in body and "escenarios y capacidades" in body
    assert 'class="op-tree-node op-tree-node-operation"' not in body


def test_tab_activation_script_listens_for_hashchange(client, app):
    """Sin esto, los nodos del árbol (y cualquier otro enlace interno a
    "#tab-..." ya existente en la página) cambian el fragmento de la URL
    sin activar el panel correspondiente -- ver el comentario agregado
    junto al listener en detail.html."""

    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert 'addEventListener("hashchange"' in body


def test_resource_state_dot_rendered_for_dolost_resource_without_docker(client, app):
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            config={"decoys": [{"Hostname": "srv-finanzas"}]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert "srv-finanzas" in body
    assert 'class="dot dot-unknown"' in body


def test_tree_scenario_unassigned_does_not_get_inline_bind_link(client, app):
    operation = _operation()
    scenario = Scenario(description="Escenario asignado")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="mock-1",
            plugin_kind="mock",
            surface="network",
            scenario_id=scenario.id,
        )
    )
    operation.plugins.append(PluginBinding(plugin_id="mock-orphan", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")
    body = response.data.decode("utf-8")

    assert "Sin escenario asignado" in body
    bucket_start = body.index("Sin escenario asignado")
    bucket_end = body.index("</li>", bucket_start) + len("</li>")
    assert "Vincular capacidad acá" not in body[bucket_start:bucket_end]
