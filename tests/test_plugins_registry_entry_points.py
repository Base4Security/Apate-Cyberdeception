"""Tests para el descubrimiento via entry points de PluginRegistry --
Fase 5 post-BlackHat (ver docs/roadmap.md). A diferencia de
test_plugins_registry.py (contrato get()/list_kinds()/describe()/
list_descriptions() contra los cuatro kinds reales, sin tocar), este
archivo cubre el mecanismo de descubrimiento en si: un plugin de
terceros "instalado" se simula con un EntryPoint real apuntando a una
clase de este mismo modulo (importable via su path punteado
'tests.test_plugins_registry_entry_points:...', porque EntryPoint.load()
hace un import real, no un mock) y monkeypatch sobre
apate.plugins.registry.entry_points."""

from dataclasses import FrozenInstanceError
from importlib.metadata import EntryPoint

import pytest

from apate.plugins import EventBus
from apate.plugins.base import DeceptionPlugin, PluginLifecycleState
from apate.plugins.exceptions import PluginConfigError
from apate.plugins.registry import PluginDescription, PluginRegistry


class _FakeThirdPartyPlugin(DeceptionPlugin):
    """Plugin de terceros de juguete -- sin plugin_description, para
    ejercitar el caso de respaldo de describe()."""

    def deploy(self) -> None:
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        pass

    def retire(self) -> None:
        self.state = PluginLifecycleState.RETIRED


class _FakeThirdPartyPluginWithDescription(DeceptionPlugin):
    """Igual que la anterior, pero declarando su propia metadata de
    catalogo -- confirma que un tercero puede curarla sin tocar
    apate.plugins.registry."""

    plugin_description = PluginDescription(
        kind="fake-with-description",
        display_name="Plugin de juguete",
        description="Plugin de prueba con metadata propia.",
        surface="Prueba",
    )

    def deploy(self) -> None:
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        pass

    def retire(self) -> None:
        self.state = PluginLifecycleState.RETIRED


class _FakeThirdPartyPluginWithMismatchedKind(DeceptionPlugin):
    """plugin_description.kind deliberadamente distinto del kind con el
    que se registra el entry point -- confirma que describe() corrige
    el campo `kind` devuelto (dataclasses.replace()) en vez de confiar
    ciegamente en lo que declaro la clase."""

    plugin_description = PluginDescription(
        kind="otro-kind-copiado-mal",
        display_name="Plugin con kind desactualizado",
        description="El campo kind de esta descripcion no coincide con el entry point real.",
        surface="Prueba",
    )

    def deploy(self) -> None:
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        pass

    def retire(self) -> None:
        self.state = PluginLifecycleState.RETIRED


def _fake_entry_point(name: str, cls: type) -> EntryPoint:
    module = cls.__module__
    return EntryPoint(name=name, value=f"{module}:{cls.__qualname__}", group="apate.plugins")


def _patch_entry_points(monkeypatch, entry_points_list):
    monkeypatch.setattr(
        "apate.plugins.registry.entry_points",
        lambda group: [ep for ep in entry_points_list if ep.group == group],
    )


# -- Descubrimiento de un plugin de terceros, sin tocar codigo de APATE -----


def test_get_resolves_a_third_party_plugin_registered_via_entry_point(monkeypatch):
    _patch_entry_points(monkeypatch, [_fake_entry_point("acme", _FakeThirdPartyPlugin)])

    assert PluginRegistry.get("acme") is _FakeThirdPartyPlugin


def test_list_kinds_includes_third_party_plugin(monkeypatch):
    _patch_entry_points(monkeypatch, [_fake_entry_point("acme", _FakeThirdPartyPlugin)])

    assert PluginRegistry.list_kinds() == ["acme"]


def test_third_party_plugin_resolved_via_entry_point_is_usable_like_any_deception_plugin(monkeypatch):
    # No es solo metadata: la clase resuelta via entry point es
    # exactamente la misma que DeceptionPlugin.from_binding() (M2)
    # instanciaria -- confirma que el mecanismo de construccion real
    # no cambio con la Fase 5.
    _patch_entry_points(monkeypatch, [_fake_entry_point("acme", _FakeThirdPartyPlugin)])

    cls = PluginRegistry.get("acme")
    bus = EventBus()
    plugin = cls(plugin_id="acme-1", surface="test", operation_id="op-1", bus=bus)
    plugin.deploy()

    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_get_unknown_kind_still_raises_with_no_entry_points_registered(monkeypatch):
    _patch_entry_points(monkeypatch, [])

    with pytest.raises(PluginConfigError):
        PluginRegistry.get("no-existe")


# -- describe(): metadata propia vs. respaldo para terceros -----------------


def test_describe_uses_third_party_plugin_description_when_declared(monkeypatch):
    _patch_entry_points(
        monkeypatch, [_fake_entry_point("fake-with-description", _FakeThirdPartyPluginWithDescription)]
    )

    description = PluginRegistry.describe("fake-with-description")

    assert description.display_name == "Plugin de juguete"
    assert description.surface == "Prueba"


def test_describe_builds_fallback_when_third_party_plugin_has_no_description(monkeypatch):
    _patch_entry_points(monkeypatch, [_fake_entry_point("acme", _FakeThirdPartyPlugin)])

    description = PluginRegistry.describe("acme")

    assert isinstance(description, PluginDescription)
    assert description.kind == "acme"
    assert description.display_name  # no vacio
    assert description.description  # no vacio
    assert description.surface  # no vacio


def test_describe_corrects_kind_field_to_match_the_requested_lookup_key(monkeypatch):
    _patch_entry_points(
        monkeypatch, [_fake_entry_point("kind-real", _FakeThirdPartyPluginWithMismatchedKind)]
    )

    description = PluginRegistry.describe("kind-real")

    assert description.kind == "kind-real"


def test_list_descriptions_mixes_declared_and_fallback_descriptions(monkeypatch):
    _patch_entry_points(
        monkeypatch,
        [
            _fake_entry_point("acme", _FakeThirdPartyPlugin),
            _fake_entry_point("fake-with-description", _FakeThirdPartyPluginWithDescription),
        ],
    )

    descriptions = {d.kind: d for d in PluginRegistry.list_descriptions()}

    assert descriptions["fake-with-description"].display_name == "Plugin de juguete"
    assert descriptions["acme"].display_name == _FakeThirdPartyPlugin.__name__


# -- PluginDescription helper --------------------------------------------


def test_plugin_description_is_frozen():
    description = PluginDescription(kind="x", display_name="X", description="d", surface="s")
    with pytest.raises(FrozenInstanceError):
        description.kind = "y"  # type: ignore[misc]
