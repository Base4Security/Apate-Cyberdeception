"""Tab "Ensayo en seco" en el detalle de una operación (referencia
declarada: CounterCraft -- simular sobre el diseño, sin clonar
infraestructura). Ver docstring de `apate.reporting.dry_run` para el
diseño completo."""

from __future__ import annotations

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación de ensayo"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def test_tab_present_with_findings_count(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert 'id="tab-dryrun"' in text
    assert 'data-tab="tab-review"' in text
    assert "Ensayo en seco" in text


def test_empty_operation_shows_empty_state_not_error(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert "Agreg" in text and "ensayar un recorrido" in text


def test_well_designed_operation_shows_no_gaps_found(client, app):
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1046"]))
    scenario = Scenario(description="Escenario completo", related_ttps=["T1046"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )
    operation.plugins.append(
        PluginBinding(
            plugin_id="honeytoken-1",
            plugin_kind="honeytoken",
            surface="data",
            scenario_id=scenario.id,
            leads_to_plugin_id="dolost-1",
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Sin huecos detectados" in text
    # La cadena real: honeytoken-1 -> dolost-1.
    assert "honeytoken-1" in text
    assert "dolost-1" in text


def test_operation_with_gaps_lists_them_with_severity_and_link(client, app):
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1046", "T1059.004"]))
    scenario = Scenario(description="Cubre una sola", related_ttps=["T1046"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )
    # Capacidad totalmente desconectada.
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "T1059.004" in text
    assert "no est&aacute; vinculada a ning&uacute;n escenario" in text or "no está vinculada a ningún escenario" in text
    assert 'href="#tab-scenarios"' in text
    assert 'href="#tab-plugins"' in text
    assert "Hueco" in text
    assert "Informativo" in text


def test_broken_breadcrumb_shows_up_as_a_gap_finding(client, app):
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "se corta ac" in text.lower()


def test_chain_shows_declared_effect_and_engage_activities(client, app):
    from apate.core.models import DeceptionEffect

    operation = _operation()
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            effect=DeceptionEffect(
                expected_adversary_belief="Cree que es un host real",
                expected_adversary_action="Se conecta por SSH",
                success_metric="Ingresa credenciales falsas",
                engage_activity_ids=["EAC0005"],
            ),
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Cree que es un host real" in text
    assert "Se conecta por SSH" in text
    assert "Ingresa credenciales falsas" in text
    assert "Lures" in text


def test_two_node_cycle_renders_without_error_and_flags_it(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert "ciclo cerrado sin ning" in text.lower()
    assert "nunca termina" in text.lower()


def test_never_shows_live_deployment_state_language(client, app):
    """Confirma la distincion con "Esperado vs. observado": esta seccion
    no debe usar el vocabulario de estado de despliegue en vivo
    (Planificado/Desplegado/Activo/Observado) que sí usa el árbol."""

    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()
    # Cortamos en el arranque del siguiente tab-panel, no en un id puntual de
    # su contenido: que tab-panel sigue a este depende del orden de los tabs.
    dry_run_section = text.split('id="tab-dryrun"')[1].split('class="tab-panel"')[0]

    assert "op-tree-node-capability" not in dry_run_section
