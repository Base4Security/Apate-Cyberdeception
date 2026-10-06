"""Sugerencias deterministas de colocación de activos."""

from apate.assets import Asset, suggest_capabilities_for_asset


def test_known_server_suggests_registered_network_capabilities_and_critical_complement():
    asset = Asset(identifier="SRV-01", name="Servidor", asset_type="server", criticality="critical")

    suggestions = suggest_capabilities_for_asset(asset)

    assert [suggestion.kind for suggestion in suggestions] == ["dolost", "opencanary", "canarytoken", "honeytoken"]
    assert all(suggestion.surface for suggestion in suggestions)


def test_unknown_free_text_type_does_not_invent_a_suggestion():
    asset = Asset(identifier="X-01", name="Especial", asset_type="mainframe cuántico", criticality="critical")

    assert suggest_capabilities_for_asset(asset) == []


def test_criticality_adds_an_option_without_ranking_the_result():
    low = Asset(identifier="SRV-LOW", name="Servidor bajo", asset_type="server", criticality="low")
    high = Asset(identifier="SRV-HIGH", name="Servidor alto", asset_type="server", criticality="high")

    assert [suggestion.kind for suggestion in suggest_capabilities_for_asset(low)] == [
        "dolost",
        "opencanary",
        "canarytoken",
    ]
    assert [suggestion.kind for suggestion in suggest_capabilities_for_asset(high)][-1] == "honeytoken"


def test_the_asset_form_shows_which_types_actually_produce_a_suggestion():
    """El tipo de activo es texto libre y el dataset solo reconoce etiquetas
    literales, asi que "servicio" no sugiere nada mientras "servidor" si. Sin
    exponer la lista, esa frontera solo se descubre por ausencia: el operador
    escribe un tipo razonable, no ve ninguna sugerencia y no tiene forma de
    saber si es que no hay capacidad adecuada o si es que la etiqueta no esta
    reconocida. La lista sale del dataset, nunca copiada a la plantilla.
    """

    from apate.assets import list_suggestible_asset_types
    from apate.assets.recommendations import _SUGGESTION_DATA

    tipos = list_suggestible_asset_types()

    assert tipos == sorted(_SUGGESTION_DATA["asset_type_kind_map"])
    assert "workstation" in tipos  # el placeholder anterior lo omitia


def test_the_inventory_screens_offer_the_recognized_types(client, app):
    from apate.assets import Asset, list_suggestible_asset_types

    app.config["ASSET_REPOSITORY"].save(
        Asset(identifier="srv-1", name="Servidor", asset_type="server", criticality="high")
    )

    for url in ("/assets/", "/assets/srv-1/edit"):
        body = client.get(url).get_data(as_text=True)
        assert 'list="tipos-con-sugerencia"' in body
        for tipo in list_suggestible_asset_types():
            assert f'<option value="{tipo}"></option>' in body
