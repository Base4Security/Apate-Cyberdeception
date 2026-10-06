"""Resolución explícita de objetivos de texto libre contra el inventario."""

from apate.assets import Asset
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement


def _operation(**kwargs):
    return Operation(
        name="Operación con referencia libre",
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def test_resolving_against_existing_asset_replaces_only_that_reference_and_migrates_coverage(client, app):
    asset = Asset(identifier="ASSET-FIN-01", name="Segmento financiero", asset_type="server", criticality="critical")
    app.config["ASSET_REPOSITORY"].save(asset)
    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Segmento de red financiero", "Otro libre"])
    )
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-fin", surface="network", protected_asset_ids=["Segmento de red financiero"])
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/target-assets/resolve",
        data={"reference": "Segmento de red financiero", "asset_identifier": "ASSET-FIN-01"},
    )

    assert response.status_code == 302
    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert saved.adversary_profile.target_assets == ["ASSET-FIN-01", "Otro libre"]
    assert saved.plugins[0].protected_asset_ids == ["ASSET-FIN-01"]
    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert "Segmento financiero" in body and "Sugerencias de colocación, para revisión manual" not in body
    assert "Activos con capacidad declarada" in body


def test_creating_asset_from_reference_uses_operator_identifier_and_resolves_it(client, app):
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Buzones de correo de RRHH"]))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/target-assets/create-and-resolve",
        data={
            "reference": "Buzones de correo de RRHH",
            "identifier": "ASSET-RRHH-MAIL-01",
            "name": "Correo de RRHH",
            "asset_type": "service",
            "criticality": "high",
            "technical_identifier": "mail.rrhh.example.internal",
        },
    )

    assert response.status_code == 302
    assert app.config["ASSET_REPOSITORY"].get("ASSET-RRHH-MAIL-01").name == "Correo de RRHH"
    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert saved.adversary_profile.target_assets == ["ASSET-RRHH-MAIL-01"]
    assert "Buzones de correo de RRHH" not in saved.adversary_profile.target_assets
    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert "Correo de RRHH" in body
    assert "Sugerencias de colocación, para revisión manual" in body


def test_existing_unresolved_coverage_is_preserved_until_operator_removes_it(client, app):
    asset = Asset(identifier="ASSET-OK", name="Activo", asset_type="server", criticality="high")
    app.config["ASSET_REPOSITORY"].save(asset)
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-OK"]))
    operation.plugins.append(
        PluginBinding(plugin_id="decoy", surface="network", protected_asset_ids=["REFERENCIA VIEJA"])
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    before = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert 'value="REFERENCIA VIEJA" selected' in before

    response = client.post(
        f"/operations/{operation.id}/plugins/decoy/asset-coverage",
        data={"protected_asset_ids": ["ASSET-OK", "REFERENCIA VIEJA"]},
    )

    assert response.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0].protected_asset_ids == [
        "ASSET-OK",
        "REFERENCIA VIEJA",
    ]
