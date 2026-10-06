"""Integración web de la cuarta lente del mapa de activos."""

from apate.assets import Asset
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement


def _operation(**kwargs):
    return Operation(
        name="Operación de mapa",
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _asset(identifier="ASSET-CRIT"):
    return Asset(identifier=identifier, name="ERP crítico", asset_type="service", criticality="critical")


def test_asset_lens_shows_covered_uncovered_manual_and_unassigned_capability(client, app):
    app.config["ASSET_REPOSITORY"].save(_asset())
    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-CRIT", "Referencia manual"])
    )
    operation.plugins.extend(
        [
            PluginBinding(plugin_id="decoy-erp", surface="network", protected_asset_ids=["ASSET-CRIT"]),
            PluginBinding(plugin_id="miga-libre", surface="data"),
        ]
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert 'data-map-lens="asset-coverage"' in body
    assert 'id="asset-coverage"' in body
    assert "ERP crítico" in body
    assert "Protegido por:" in body and "decoy-erp" in body
    assert "Referencia manual" in body and "referencia manual no inventariada" in body
    assert "miga-libre" in body and "Capacidades sin activo declarado" in body


def test_asset_lens_has_explicit_empty_state_without_targets_or_capabilities(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Esta operación aún no tiene activos objetivo ni capacidades vinculadas." in body


def test_binding_form_persists_explicit_asset_relation(client, app):
    app.config["ASSET_REPOSITORY"].save(_asset())
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-CRIT"]))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins",
        data={
            "plugin_id": "decoy-erp",
            "surface": "network",
            "protected_asset_ids": ["ASSET-CRIT"],
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert saved.plugins[0].protected_asset_ids == ["ASSET-CRIT"]


def test_asset_lens_shows_the_criticality_the_rest_of_the_interface_shows(client, app):
    """La criticidad se persiste en ingles porque es contrato, pero el
    inventario la muestra traducida en sus tres pantallas. Que el mapa
    mostrara `critical` crudo repetia, del lado de la salida, la misma
    divergencia de vocabulario que ya se corrigio del lado de la entrada
    cuando el CSV rechazaba las etiquetas que la propia interfaz mostraba.
    """

    app.config["ASSET_REPOSITORY"].save(_asset())
    app.config["ASSET_REPOSITORY"].save(
        Asset(identifier="ASSET-LOW", name="Estación de prueba", asset_type="workstation", criticality="low")
    )
    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-CRIT", "ASSET-LOW"])
    )
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-erp", surface="network", protected_asset_ids=["ASSET-CRIT"])
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Crítica" in body and "Baja" in body
    # El valor interno sigue siendo el que viaja: es la clave del inventario.
    assert "· critical" not in body and ", critical (" not in body
    assert ", low (" not in body


def test_existing_capability_coverage_can_be_persisted_and_cleared(client, app):
    app.config["ASSET_REPOSITORY"].save(_asset())
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-CRIT"]))
    operation.plugins.append(PluginBinding(plugin_id="decoy-erp", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    save = client.post(
        f"/operations/{operation.id}/plugins/decoy-erp/asset-coverage",
        data={"protected_asset_ids": ["ASSET-CRIT"]},
    )
    assert save.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0].protected_asset_ids == ["ASSET-CRIT"]
    assert "Activos con capacidad declarada" in client.get(f"/operations/{operation.id}").get_data(as_text=True)

    clear = client.post(f"/operations/{operation.id}/plugins/decoy-erp/asset-coverage", data={})
    assert clear.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0].protected_asset_ids == []


def test_asset_lens_shows_suggestions_without_preselecting_or_creating_a_capacity(client, app):
    app.config["ASSET_REPOSITORY"].save(
        Asset(identifier="ASSET-SRV", name="Servidor crítico", asset_type="server", criticality="critical")
    )
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-SRV"]))
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Sugerencias de colocación, para revisión manual" in body
    assert "Decoys de red" in body
    assert "no crea ni despliega una capacidad" in body
    asset_panel = body[body.index('id="asset-coverage"') : body.index('id="operation-relations"')]
    assert "<input" not in asset_panel
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).plugins == []


def test_asset_lens_keeps_unresolved_coverage_reference_visible(client, app):
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-CRIT"]))
    operation.plugins.append(PluginBinding(plugin_id="decoy-huerfano", surface="network", protected_asset_ids=["FUERA"]))
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Referencias de cobertura fuera de los activos objetivo" in body
    assert "FUERA" in body and "decoy-huerfano" in body
    assert "'asset-coverage'" in body
