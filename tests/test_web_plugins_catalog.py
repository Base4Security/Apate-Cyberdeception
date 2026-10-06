"""Tests de integración web para el Catálogo de capacidades.

El catálogo cubre los cuatro kinds de
PluginRegistry, incluidos "mock"/"honeytoken", que no dependen de
DOLOS-T ni BUDA -- confirmado en la fixture `app` (APATE_MOUNT_
EXTERNAL_TOOLS=False de conftest.py) siguiendo funcionando igual."""

from apate.plugins import PluginRegistry


def test_catalog_returns_200(client):
    response = client.get("/capabilities/")
    assert response.status_code == 200
    assert "Cat&aacute;logo de capacidades" in response.get_data(as_text=True)


def test_catalog_available_even_without_external_tools_mounted(client, app):
    # La fixture `app`/`client` de conftest.py ya corre con
    # APATE_MOUNT_EXTERNAL_TOOLS=False -- confirma explicitamente que
    # eso no oculta el catalogo (a diferencia de la seccion
    # "Herramientas", ver base.html).
    assert app.config["APATE_MOUNT_EXTERNAL_TOOLS"] is False
    response = client.get("/capabilities/")
    assert response.status_code == 200


def test_catalog_lists_the_four_registered_kinds(client):
    response = client.get("/capabilities/")
    text = response.data.decode()

    for kind in PluginRegistry.list_kinds():
        assert kind in text


def test_catalog_shows_description_and_surface_for_each_kind(client):
    response = client.get("/capabilities/")
    text = response.data.decode()

    for description in PluginRegistry.list_descriptions():
        # La metadata de plugins se construye al importar su módulo: sus
        # textos son LazyString y recién se resuelven con el locale activo.
        # Jinja hace esa conversión al renderizar; el test debe compararla
        # con el mismo contrato.
        assert str(description.display_name) in text
        assert str(description.description) in text
        assert str(description.surface) in text


def test_plugin_description_surface_is_stable_between_locales(app):
    """La superficie viaja en bindings, eventos y filtros; no es solo copy."""

    app.config["APATE_LOCALE"] = "es"
    with app.test_request_context("/"):
        spanish = {item.kind: str(item.surface) for item in PluginRegistry.list_descriptions()}

    app.config["APATE_LOCALE"] = "en"
    with app.test_request_context("/"):
        english = {item.kind: str(item.surface) for item in PluginRegistry.list_descriptions()}

    assert english == spanish


def test_nav_links_to_the_plugin_catalog(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b'href="/capabilities/"' in response.data


def test_unmounted_catalog_marks_external_engines_unavailable(client):
    text = client.get("/capabilities/?availability=unavailable").get_data(as_text=True)

    assert "Comportamiento de usuario simulado" in text
    assert "Decoys de red" in text
    assert "Honeytoken" not in text
    assert text.count("No disponible") >= 2


def test_historical_plugins_entry_redirects_to_canonical_catalog_with_filters(client):
    response = client.get("/plugins/?provider=APATE")

    assert response.status_code == 302
    assert response.location.endswith("/capabilities/?provider=APATE")
