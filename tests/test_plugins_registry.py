"""Tests para PluginRegistry (M12h) -- ver docs/roadmap.md seccion
M12h. Registro formal kind -> clase, pura metadata de resolucion: no
cambia el comportamiento de ninguna implementacion existente, ni el
mecanismo de construccion (DeceptionPlugin.from_binding(), M2).

Desde M13i, ademas, PluginDescription/describe()/list_descriptions() --
metadata curada legible por operador (catalogo de plugins, ver
apate.web.blueprints.plugins) -- sin tocar get()/list_kinds()."""

import pytest

from apate.core import PluginBinding
from apate.plugins import (
    BudaPlugin,
    CanarytokenPlugin,
    DeceptionPlugin,
    DolosTPlugin,
    HoneytokenPlugin,
    MockHoneypotPlugin,
    OpenCanaryPlugin,
    PluginConfigError,
    PluginDescription,
    PluginRegistry,
)


def test_list_kinds_includes_the_seven_existing_implementations():
    kinds = PluginRegistry.list_kinds()

    assert set(kinds) == {"mock", "honeytoken", "dolost", "buda", "canarytoken", "opencanary", "playground"}


def test_get_resolves_each_kind_to_its_real_class():
    assert PluginRegistry.get("mock") is MockHoneypotPlugin
    assert PluginRegistry.get("honeytoken") is HoneytokenPlugin
    assert PluginRegistry.get("dolost") is DolosTPlugin
    assert PluginRegistry.get("buda") is BudaPlugin
    assert PluginRegistry.get("canarytoken") is CanarytokenPlugin
    assert PluginRegistry.get("opencanary") is OpenCanaryPlugin
    from apate.plugins.playground_plugin import PlaygroundPlugin
    assert PluginRegistry.get("playground") is PlaygroundPlugin


def test_every_registered_class_is_a_deception_plugin_subclass():
    for kind in PluginRegistry.list_kinds():
        assert issubclass(PluginRegistry.get(kind), DeceptionPlugin)


def test_get_unknown_kind_raises_plugin_config_error():
    with pytest.raises(PluginConfigError):
        PluginRegistry.get("no-existe")


def test_resolve_binding_kind_prioritizes_explicit_kind_and_keeps_legacy_prefix():
    assert PluginRegistry.resolve_binding_kind(
        PluginBinding(plugin_id="nombre-libre", surface="network", plugin_kind="mock")
    ) == "mock"
    assert PluginRegistry.resolve_binding_kind(PluginBinding(plugin_id="honeytoken-1", surface="data")) == "honeytoken"
    assert PluginRegistry.resolve_binding_kind(
        PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="no-existe")
    ) is None


# -- PluginDescription / describe() / list_descriptions() (M13i) ------------


def test_describe_returns_a_plugin_description_for_each_registered_kind():
    for kind in PluginRegistry.list_kinds():
        description = PluginRegistry.describe(kind)
        assert isinstance(description, PluginDescription)
        assert description.kind == kind


def test_describe_unknown_kind_raises_plugin_config_error():
    with pytest.raises(PluginConfigError):
        PluginRegistry.describe("no-existe")


def test_description_fields_are_non_empty_for_every_kind():
    # No es una tarjeta de catalogo legible si le falta alguno de estos
    # campos -- confirma que la metadata curada de M13i esta completa,
    # no solo presente.
    for description in PluginRegistry.list_descriptions():
        assert description.display_name.strip()
        assert description.description.strip()
        assert description.surface.strip()


def test_list_descriptions_is_exactly_synchronized_with_list_kinds():
    # Ni falta una descripcion para un kind registrado, ni sobra una
    # para un kind que no existe -- los dos dicts (_REGISTRY/
    # _DESCRIPTIONS) tienen que tener exactamente las mismas claves.
    described_kinds = {description.kind for description in PluginRegistry.list_descriptions()}
    assert described_kinds == set(PluginRegistry.list_kinds())


def test_list_descriptions_follows_the_same_order_as_list_kinds():
    assert [d.kind for d in PluginRegistry.list_descriptions()] == PluginRegistry.list_kinds()
