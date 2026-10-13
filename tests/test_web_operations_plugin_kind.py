"""Tests para `_plugin_kind()` (M12h, `apate.web.blueprints.operations`)
-- prioridad de `PluginBinding.plugin_kind` explicito sobre el
heuristico legacy de prefijo de `plugin_id`. Ver docs/roadmap.md
seccion M12h.

Unit tests directos sobre la funcion (sin pasar por Flask/HTTP): no
necesita ninguno de los fixtures de mounted_app/mounted_client que usa
tests/test_web_operations_panels.py para las pruebas de renderizado de
paneles, porque _plugin_kind() no toca Docker/BUDA ni la app.

La segunda mitad del archivo cubre el <select> nuevo de "Vincular
plugin" (`add_plugin_binding()`), integracion via el `client` real de
tests/conftest.py -- mismo patron que
tests/test_web_operations_m10.py."""

from apate.core import PluginBinding
from apate.web.blueprints.operations import _plugin_kind


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12h",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- Fallback legacy (plugin_kind=None): heuristico de prefijo sin cambios --


def test_falls_back_to_prefix_heuristic_for_dolost_when_kind_not_set():
    binding = PluginBinding(plugin_id="dolost-1", surface="network")
    assert _plugin_kind(binding) == "dolost"


def test_falls_back_to_prefix_heuristic_for_buda_when_kind_not_set():
    binding = PluginBinding(plugin_id="buda-1", surface="identity")
    assert _plugin_kind(binding) == "buda"


def test_falls_back_to_none_for_unrelated_prefix_when_kind_not_set():
    binding = PluginBinding(plugin_id="honeytoken-1", surface="data")
    assert _plugin_kind(binding) is None


# -- Kind explicito (M12h): fuente de verdad primaria ------------------------


def test_explicit_kind_wins_over_prefix_heuristic_when_they_would_disagree():
    # El caso exacto del pedido: plugin_id no sigue la convencion de
    # prefijo (el heuristico legacy le daria None), pero plugin_kind
    # esta seteado explicitamente a "dolost" -- gana el campo explicito.
    binding = PluginBinding(plugin_id="mi-decoy-custom", surface="network", plugin_kind="dolost")
    assert _plugin_kind(binding) == "dolost"


def test_explicit_kind_wins_even_when_prefix_would_suggest_a_different_kind():
    # plugin_id empieza con "buda" (heuristico diria "buda"), pero el
    # binding declara explicitamente "dolost" -- el campo explicito
    # sigue ganando, sin ambiguedad.
    binding = PluginBinding(plugin_id="buda-legacy-1", surface="network", plugin_kind="dolost")
    assert _plugin_kind(binding) == "dolost"


def test_explicit_kind_outside_dolost_buda_resolves_to_none_without_falling_back():
    # "mock"/"honeytoken" son kinds validos en PluginRegistry, pero
    # estos paneles solo entienden dolost/buda -- un kind explicito
    # que no sea ninguno de los dos resuelve a None directamente, sin
    # caer al heuristico de prefijo (que es solo para plugin_kind=None).
    binding = PluginBinding(plugin_id="dolost-1", surface="network", plugin_kind="mock")
    assert _plugin_kind(binding) is None


# -- Formulario web "Vincular plugin" (add_plugin_binding) -------------------


def test_add_plugin_binding_form_lists_registered_plugin_kinds(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    text = response.data.decode()
    # El value conserva el kind tecnico (contrato del formulario); el texto
    # visible pasa a ser el nombre de funcion de la capacidad.
    for kind in ("mock", "honeytoken", "dolost", "buda"):
        assert f'<option value="{kind}"' in text
    assert '<option value="dolost" data-surface="Red / host">Decoys de red</option>' in text
    assert ">dolost</option>" not in text
    assert 'data-surface="Red / host"' in text
    assert "se propone su superficie habitual" in text


def test_binding_keeps_a_persisted_custom_surface_even_if_kind_suggests_another(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "decoy-heredado", "surface": "superficie-legada", "plugin_kind": "dolost"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    binding = app.config["OPERATION_REPOSITORY"].get(operation_id).plugins[0]
    assert binding.surface == "superficie-legada"
    assert b"superficie-legada" in response.data


def test_add_plugin_binding_persists_explicit_plugin_kind(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "mi-decoy-custom", "surface": "network", "plugin_kind": "dolost"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].plugin_kind == "dolost"


def test_add_plugin_binding_without_plugin_kind_selected_leaves_it_none(client, app):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "mock-1", "surface": "network", "plugin_kind": ""},
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].plugin_kind is None
