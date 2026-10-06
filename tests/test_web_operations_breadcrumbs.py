"""Breadcrumbs (referencia declarada: CounterCraft -- las migas que
llevan al adversario hasta el engaño) en el árbol de la operación y en
el formulario "Vincular capacidad". Ver docstring de `PluginBinding`/
`Operation.find_plugin_binding()` (apate.core.models) y
`apate.web._operation_tree` para el diseño completo."""

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación con breadcrumbs"),
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


# -- Árbol: markup real ---------------------------------------------------


def test_tree_node_has_leads_to_data_attribute_for_svg_edge(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert 'data-tree-leads-to="capability:dolost-1"' in text


def test_tree_shows_breadcrumb_hint_on_the_node_itself(client, app):
    """El hint compacto en el propio nodo es la señal que sobrevive en
    mobile, donde no se dibuja ninguna línea SVG por diseño (ver
    docstring del árbol)."""

    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "lleva a dolost-1" in text


def test_tree_shows_incoming_breadcrumb_on_the_target_card(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Recibe una miga de" in text


def test_tree_shows_broken_reference_explicitly_not_silently(client, app):
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "no encontrado en esta operaci" in text
    # Sin arista SVG hacia un destino que no existe.
    assert 'data-tree-leads-to="capability:no-existe"' not in text


def test_tree_without_any_breadcrumb_has_no_breadcrumb_section(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert '<span class="op-tree-kind">Breadcrumbs</span>' not in text


def test_two_node_cycle_renders_without_error(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert 'data-tree-leads-to="capability:a"' in text
    assert 'data-tree-leads-to="capability:b"' in text


# -- Tabla "Plugins vinculados" --------------------------------------------


def test_plugins_table_shows_leads_to_column(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "<th>Lleva a</th>" in text


def test_plugins_table_marks_broken_reference(client, app):
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "no encontrado" in text


# -- Formulario "Vincular capacidad": campo real + POST -----------------------


def _create_operation(client, **overrides):
    form = dict(
        name="Operación de prueba",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046"],
        target_assets="ERP",
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_leads_to_select_offers_existing_bindings(client, app):
    operation_id = _create_operation(client)
    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "dolost-1", "plugin_kind": "dolost", "surface": "network"},
    )

    text = client.get(f"/operations/{operation_id}").data.decode()

    assert 'id="leads_to_plugin_id"' in text
    assert '<option value="dolost-1">dolost-1</option>' in text


def test_add_plugin_binding_sets_leads_to_plugin_id(client, app):
    operation_id = _create_operation(client)
    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "dolost-1", "plugin_kind": "dolost", "surface": "network"},
    )

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "plugin_kind": "honeytoken",
            "surface": "data",
            "leads_to_plugin_id": "dolost-1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    honeytoken_binding = next(b for b in operation.plugins if b.plugin_id == "honeytoken-1")
    assert honeytoken_binding.leads_to_plugin_id == "dolost-1"


def test_add_plugin_binding_without_leads_to_defaults_to_none(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "mock-1", "plugin_kind": "mock", "surface": "network"},
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].leads_to_plugin_id is None


def test_self_reference_via_form_flashes_error_and_creates_nothing(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "plugin_kind": "honeytoken",
            "surface": "data",
            "leads_to_plugin_id": "honeytoken-1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins == []
