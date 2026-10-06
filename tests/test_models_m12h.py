"""Tests para `PluginBinding.plugin_kind` (M12h) -- reemplaza la
convencion informal de prefijo de `plugin_id` por un campo explicito.
Ver docs/roadmap.md seccion M12h y apate.plugins.registry.PluginRegistry.

Aditivo: cubre el roundtrip normal y, sobre todo, que un `PluginBinding`
persistido antes de M12h (sin la clave `plugin_kind` en su JSON) siga
cargando con `plugin_kind is None` -- mismo criterio que el resto de
M10/M12."""

from apate.core import PluginBinding


def test_plugin_kind_defaults_to_none():
    binding = PluginBinding(plugin_id="dolost-1", surface="network")
    assert binding.plugin_kind is None


def test_plugin_kind_roundtrip():
    binding = PluginBinding(plugin_id="mi-decoy-custom", surface="network", plugin_kind="dolost")

    restored = PluginBinding.from_dict(binding.to_dict())

    assert restored.plugin_kind == "dolost"
    assert restored.plugin_id == "mi-decoy-custom"


def test_plugin_kind_included_in_to_dict():
    binding = PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda")
    assert binding.to_dict()["plugin_kind"] == "buda"


def test_plugin_binding_from_dict_without_plugin_kind_key_defaults_to_none():
    # Simula un PluginBinding persistido ANTES de M12h -- mismo formato
    # "legacy" que ya usa test_models_m10.py/test_models_m12c.py, sin
    # la clave nueva en absoluto.
    legacy_dict = {"plugin_id": "dolost-1", "surface": "network", "config": {}}

    restored = PluginBinding.from_dict(legacy_dict)

    assert restored.plugin_kind is None
    assert restored.plugin_id == "dolost-1"
